// The decode spotlight (Winners and Roofline) over real command output,
// checked against the golden `aegis-perf report` of the pinned tag on the
// same fixture DB.
import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import winners from './fixtures/winners-121.json';
import roofline from './fixtures/roofline-121.json';
import goldenReport from '../../../tests/fixtures/golden/report-121.txt?raw';
import type { Roofline, Winner } from '../../perf/types';
import { DecodeSpotlightPanel, spotRowsFromRoofline, spotRowsFromWinners } from '../../components/sections/perf/DecodeSpotlight';

const ws = winners as unknown as Winner[];

function rows() {
  const table = screen.getByText('Decode spotlight (M ≤ 16)').parentElement!.querySelector('table')!;
  return within(table).getAllByRole('row').slice(1);
}
const cell = (r: HTMLElement, col: string) => r.querySelector(`[data-col="${col}"]`)?.textContent ?? null;
const byShape = (rs: HTMLElement[], s: string) => rs.find((r) => r.dataset.shape === s)!;

/** The report's roof table: "M N K impl" -> %roof (last column) and roof. */
function reportRoof(): Map<string, { pct: string; roof: string }> {
  const table = goldenReport.split('%roof\n')[1].split('\n\n')[0];
  const m = new Map<string, { pct: string; roof: string }>();
  for (const l of table.split('\n').slice(1)) {
    const t = l.trim().split(/\s+/);
    if (t.length > 4) m.set(`${t[0]}x${t[1]}x${t[2]} ${t[3]}`, { pct: t[t.length - 1], roof: t[t.length - 4] });
  }
  return m;
}

describe('Decode spotlight', () => {
  it('one row per decode shape; % of the read roof matches aegis-perf report', () => {
    render(<DecodeSpotlightPanel rows={spotRowsFromWinners(ws)} />);
    const rs = rows();
    expect(rs.map((r) => r.dataset.shape)).toEqual(['1x896x896', '1x4864x896', '1x896x4864', '16x896x896', '16x4864x896', '16x896x4864']);
    const report = reportRoof();
    for (const w of ws.filter((x) => x.decode)) {
      const want = report.get(`${w.shape_bucket} ${w.impl}`)!;
      expect(want.roof).toBe('read');
      expect(cell(byShape(rs, w.shape_bucket), 'spot-roof')).toContain(`${want.pct}of the read roof (257.8 GB/s)`);
      expect(cell(byShape(rs, w.shape_bucket), 'spot-dispatch')).toContain('dispatch: AEGIS kernel');
      expect(cell(byShape(rs, w.shape_bucket), 'spot-family')).toContain(w.impl);
    }
    expect(cell(byShape(rs, '1x896x4864'), 'spot-family')).toContain('gemv_tc (tensor_core) · split-K S = 3 (requested)');
    expect(cell(byShape(rs, '1x896x896'), 'spot-family')).toContain('split-K S = 1 (requested)');
  });

  it('every decode win is unreproducible: the paired-ab builds are dirty', () => {
    render(<DecodeSpotlightPanel rows={spotRowsFromWinners(ws)} />);
    const rs = rows();
    const calls = Object.fromEntries(rs.map((r) => [r.dataset.shape, cell(r, 'spot-call')]));
    expect(calls).toEqual({
      '1x896x896': 'win (unreproducible: dirty build)',
      '1x4864x896': 'tie (unreproducible: dirty build)',
      '1x896x4864': 'win (unreproducible: dirty build)',
      '16x896x896': 'win (unreproducible: dirty build)',
      '16x4864x896': 'win (unreproducible: dirty build)',
      '16x896x4864': 'tie (unreproducible: dirty build)',
    });
    const r = byShape(rs, '16x896x896');
    expect(cell(r, 'spot-ab')).toContain('114.8% [113.5, 115.3] of cublaslt_best');
    expect(cell(r, 'spot-ab')).toContain('paired-ab #36, 30 pairs, 0bd0f22a35a6-dirty');
    expect(cell(r, 'spot-kernel')).toContain('110.8% of cublaslt_best, ratio CI [1.109, 1.116]: faster');
    expect(cell(r, 'spot-dispatch-ab')).toContain('aegis::matmul 115.0% [113.6, 115.4] of cublaslt_best · win (unreproducible: dirty build)');
  });

  it('launch-overhead bound only where Core states it, with its source', () => {
    render(<DecodeSpotlightPanel rows={spotRowsFromWinners(ws)} />);
    const rs = rows();
    const diagnosed = rs.filter((r) => cell(r, 'spot-diagnosis') !== null).map((r) => r.dataset.shape);
    expect(diagnosed).toEqual(['1x896x896', '16x896x896']);
    expect(cell(byShape(rs, '1x896x896'), 'spot-diagnosis')).toBe(
      'below floor: launch-overhead boundCore: docs/LOG.md:1977 § 2026-10-17 — Phase C step 4: decode results, winners and dispatch',
    );
    // The 4864 shapes: the number with no diagnosis.
    expect(cell(byShape(rs, '1x4864x896'), 'spot-roof')).toBe('92.3%of the read roof (257.8 GB/s)');
  });

  it('Roofline shows the same rows', () => {
    const fromRoof = spotRowsFromRoofline(roofline as unknown as Roofline);
    const fromWin = spotRowsFromWinners(ws);
    const key = (rs: typeof fromWin) => rs.map((r) => [r.shape, r.impl, r.spot.pct_of_read_roof, r.ab?.kernel?.id]).sort();
    expect(fromRoof).toHaveLength(6);
    expect(key(fromRoof)).toEqual(key(fromWin));
  });

  it('says "not measured" when a source is missing', () => {
    const w = structuredClone(ws.filter((x) => x.decode));
    for (const x of w) {
      x.decode_spotlight = { ...x.decode_spotlight!, pct_of_read_roof: null, read_bw_gbps: null, diagnosis: null, split_k: null };
      x.paired_ab = { kernel: null, dispatch: null };
    }
    render(<DecodeSpotlightPanel rows={spotRowsFromWinners(w)} />);
    const r = rows()[0];
    expect(cell(r, 'spot-roof')).toBe('not measuredof the read roof');
    expect(cell(r, 'spot-ab')).toBe('no paired-ab result');
    expect(cell(r, 'spot-dispatch')).toContain('dispatch not measured');
    expect(cell(r, 'spot-family')).toContain('no split-K');
  });
});

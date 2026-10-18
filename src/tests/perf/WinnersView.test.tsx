// Winners view over real command output (`cargo run --example dump --
// winners 121` on tests/fixtures/), checked against the golden emit-header of
// the pinned tag's CLI on the same DB.
import { render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import winners from './fixtures/winners-121.json';
import goldenHeader from '../../../tests/fixtures/golden/emit-header-sm_121.h?raw';
import { WinnersSection } from '../../components/sections/perf/WinnersSection';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

beforeEach(() => {
  invoke.mockReset();
  invoke.mockImplementation((cmd: string) =>
    Promise.resolve(cmd === 'perf_sources' ? { db: '/f.db', core: '/c', measured_archs: [121] } : winners),
  );
});

async function rows() {
  render(<WinnersSection />);
  const table = (await screen.findByText('Winning config')).closest('table')!;
  return within(table).getAllByRole('row').slice(1);
}

const cell = (row: HTMLElement, col: string) => row.querySelector(`[data-col="${col}"]`)!.textContent!;
const byShape = (rs: HTMLElement[], s: string) => rs.find((r) => r.dataset.shape === s)!;

describe('WinnersSection', () => {
  it('one row per shape, matching the golden header (config, kernel %, tie)', async () => {
    const rs = await rows();
    const header = goldenHeader.split('\n').filter((l) => l.trim().startsWith('{'));
    expect(rs).toHaveLength(14);
    expect(header).toHaveLength(14);
    for (const line of header) {
      const [code, comment] = line.split('//');
      const [m, n, k, impl] = code.replace(/[{}"\s]/g, '').split(',');
      const row = byShape(rs, `${m}x${n}x${k}`);
      expect(row.textContent).toContain(impl);
      const lt = comment.match(/([\d.]+)% of cublaslt_best/)![1];
      expect(cell(row, 'kernel-pct')).toBe(`${lt}%`);
      expect(cell(row, 'tied').startsWith('tied')).toBe(comment.includes('TIED with'));
    }
    expect(invoke).toHaveBeenCalledWith('winners', { sm: 121 });
  });

  it('a cuBLASLt-dispatched shape never shows a dispatch % as the kernel %', async () => {
    const rs = await rows();
    const routed = rs.filter((r) => cell(r, 'dispatch').startsWith('dispatch: cuBLASLt'));
    expect(routed.map((r) => r.dataset.shape)).toEqual(['4096x4096x4096', '512x4864x896']);
    for (const r of routed) {
      expect(cell(r, 'dispatch-pct')).toBe('cuBLASLt path: not measured');
      expect(cell(r, 'dispatch-pct')).not.toContain(cell(r, 'kernel-pct'));
      expect(cell(r, 'kernel-pct')).toMatch(/^\d+\.\d%$/);
    }
    const big = byShape(rs, '4096x4096x4096');
    expect(cell(big, 'kernel-pct')).toBe('73.3%');
    expect(cell(big, 'dispatch')).not.toContain('provisional');
    expect(cell(big, 'dispatch')).toContain('paired CI upper bound 0.743 < 80% floor');
    // A kernel route: the dispatch % is the kernel's own.
    const k = byShape(rs, '1024x1024x1024');
    expect(cell(k, 'dispatch-pct')).toBe(cell(k, 'kernel-pct'));
  });

  it('paired ratio and CI, tie call, runner-up gap, production bar', async () => {
    const rs = await rows();
    const c = byShape(rs, '256x256x256');
    expect(cell(c, 'paired')).toBe('0.888 [0.887, 0.890]');
    expect(cell(c, 'tied')).toBe('no · [1.025, 1.027] vs mma_pipe_64x64x32_2x2_s3');
    expect(cell(c, 'gap')).toBe('+2.70%');
    expect(cell(c, 'bars')).toBe('pass · other bar 80% · clearprovisional');
    const t = byShape(rs, '1x896x4864');
    expect(cell(t, 'tied')).toBe('tied · [1.000, 1.002] vs gemv_tc_16x64x32_1x4_s6_k4');
    expect(cell(t, 'bars')).toContain('pass · decode bar 100% · clear');
    expect(cell(byShape(rs, '2048x2048x2048'), 'bars')).toContain('fail · large bar 90% · clear');
    expect(cell(byShape(rs, '4096x4096x4096'), 'bars')).toContain('fail · large bar 90% · clear; below 80% floor');
    expect(cell(byShape(rs, '512x4864x896'), 'bars')).toContain('fail · other bar 80% · clear; below 80% floor');
    expect(cell(byShape(rs, '512x896x4864'), 'gap')).toBe('+0.12%');
  });
});

describe('WinnersSection: stored cuBLASLt algorithm', () => {
  it('names the algorithm a cuBLASLt-dispatched shape runs, and every baseline\'s', async () => {
    const rs = await rows();
    const big = byShape(rs, '4096x4096x4096');
    expect(cell(big, 'dispatch-algo')).toBe('runs cuBLASLt algo 67 · tile 412 · stages 35 · custom 31');
    expect(cell(big, 'baseline-algo')).toBe('algo 67 · tile 412 · stages 35 · custom 31');
    expect(cell(byShape(rs, '512x4864x896'), 'dispatch-algo')).toBe('runs cuBLASLt algo 21 · tile 23 · stages 9 · custom 0');
    // A split-K algorithm (a baseline here): its non-default fields are shown.
    expect(cell(byShape(rs, '16x896x4864'), 'baseline-algo')).toBe('algo 21 · tile 15 · stages 12 · split-K 3 · reduction 2 · custom 0');
    // A kernel route names no dispatched algorithm, but its baseline still has one.
    const k = byShape(rs, '1024x1024x1024');
    expect(k.querySelector('[data-col="dispatch-algo"]')).toBeNull();
    expect(cell(k, 'baseline-algo')).toBe('algo 21 · tile 24 · stages 9 · custom 0');
    for (const r of rs) expect(cell(r, 'baseline-algo')).toMatch(/^algo \d+/);
  });

  it('says "not stored" when Core has no algorithm for the shape', async () => {
    const w = structuredClone(winners) as Array<Record<string, unknown>>;
    for (const x of w) x.lt_algo = null;
    invoke.mockImplementation((cmd: string) =>
      Promise.resolve(cmd === 'perf_sources' ? { db: '/f.db', core: '/c', measured_archs: [121] } : w),
    );
    const rs = await rows();
    expect(cell(byShape(rs, '4096x4096x4096'), 'dispatch-algo')).toBe('cuBLASLt algorithm not stored');
    expect(cell(byShape(rs, '256x256x256'), 'baseline-algo')).toBe('not stored');
  });
});

describe('WinnersSection: paired and unpaired disagree', () => {
  it('flags 1x896x4864 and 512x4864x896 (median outside the paired CI by > 2 points), not 256x256x256', async () => {
    const rs = await rows();
    const flagged = rs.filter((r) => r.querySelector('[data-col="disagree"]'));
    expect(flagged.map((r) => r.dataset.shape)).toEqual(['1x896x4864', '512x4864x896']);
    expect(cell(flagged[0], 'disagree')).toContain('paired and unpaired disagree: median 109.6%, paired CI [105.4, 105.9]');
    const f = flagged[1];
    expect(cell(f, 'disagree')).toContain('paired and unpaired disagree: median 82.2%, paired CI [78.5, 79.0]');
    expect(cell(f, 'disagree')).toContain('the paired CI is the number of record');
    // The median stays visible, marked secondary.
    expect(cell(f, 'kernel-pct')).toBe('82.2%');
    expect(f.textContent).toContain('unpaired median (secondary)');
    const c = byShape(rs, '256x256x256');
    expect(c.querySelector('[data-col="disagree"]')).toBeNull();
    expect(c.textContent).not.toContain('secondary');
  });
});

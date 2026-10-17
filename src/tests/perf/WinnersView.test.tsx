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
    expect(routed.map((r) => r.dataset.shape)).toEqual(['4096x4096x4096', '1x896x4864', '16x896x4864', '512x4864x896']);
    for (const r of routed) {
      expect(cell(r, 'dispatch-pct')).toBe('cuBLASLt path: not measured');
      expect(cell(r, 'dispatch-pct')).not.toContain(cell(r, 'kernel-pct'));
      expect(cell(r, 'kernel-pct')).toMatch(/^\d+\.\d%$/);
    }
    const big = byShape(rs, '4096x4096x4096');
    expect(cell(big, 'kernel-pct')).toBe('72.2%');
    expect(cell(big, 'dispatch')).toContain('(provisional)');
    expect(cell(big, 'dispatch')).toContain('paired CI upper bound 0.724 < 80% floor');
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
    const t = byShape(rs, '16x4864x896');
    expect(cell(t, 'tied')).toBe('tied · [0.992, 1.002] vs mma_pipe_64x128x32_2x4_s4');
    expect(cell(t, 'bars')).toContain('pass · decode bar 100% · clear');
    expect(cell(byShape(rs, '2048x2048x2048'), 'bars')).toContain('fail · large bar 90% · clear');
    expect(cell(byShape(rs, '4096x4096x4096'), 'bars')).toContain('fail · large bar 90% · clear; below 80% floor');
    expect(cell(byShape(rs, '512x4864x896'), 'bars')).toContain('fail · other bar 80% · clear; below 80% floor');
    expect(cell(byShape(rs, '512x896x4864'), 'gap')).toBe('+0.12%');
  });
});

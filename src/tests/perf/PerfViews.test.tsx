// Device and Roofline views over real command output: the fixtures are
// `cargo run --example dump` (custos-perf) against tests/fixtures/ (no AEGIS_CORE).
import { render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import devices from './fixtures/devices.json';
import archModel from './fixtures/arch_model-121.json';
import roofline from './fixtures/roofline-121.json';
import { ThemeProvider } from '../../contexts/ThemeContext';
import { DeviceSection } from '../../components/sections/perf/DeviceSection';
import { Hover, RooflineSection } from '../../components/sections/perf/RooflineSection';
import goldenRoofline from '../../../tests/fixtures/golden/roofline-121.txt?raw';
import { ci, cudaVersion, num, tieText, vsBaseline } from '../../perf/format';
import type { Roofline } from '../../perf/types';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

const responses: Record<string, unknown> = {
  perf_sources: { db: '/fixture.db', core: '/aegis', measured_archs: [121] },
  devices,
  arch_model: archModel,
  roofline,
};

beforeEach(() => {
  invoke.mockReset();
  invoke.mockImplementation((cmd: string) => Promise.resolve(responses[cmd]));
});

describe('format', () => {
  it('never invents a number', () => {
    expect(num(null)).toBeNull();
    expect(num(Number.NaN)).toBeNull();
    expect(cudaVersion(13000)).toBe('13.0');
    expect(vsBaseline(null)).toBe('not measured');
    expect(tieText(null)).toBe('not measured');
    expect(ci({ ratio_median: 1, lo: 0.99499, hi: 1.00248, pairs: 30, contains_one: true })).toBe('[0.995, 1.002]');
  });
});

describe('DeviceSection', () => {
  it('shows the measured model, each value with what measured it', async () => {
    render(<DeviceSection />);
    expect(await screen.findByText('Measured hardware model, sm_121')).toBeInTheDocument();
    const model = screen.getByText('Measured hardware model, sm_121').closest('div')!;
    const row = (q: string) => within(model).getByText(q).closest('tr')!;
    expect(within(row('SMs')).getByText('48')).toBeInTheDocument();
    expect(within(row('SMs')).getByText('arch file')).toBeInTheDocument();
    expect(within(row('Memory')).getByText('121.7 GiB')).toBeInTheDocument();
    expect(within(row('Memory')).getByText(/manifest tests\/fixtures\/manifest-spark-5822\.json/)).toBeInTheDocument();
    expect(within(row('L2')).getByText('24 MiB')).toBeInTheDocument();
    expect(within(row('Copy bandwidth (roof, M > 16)')).getByText('236.7 GB/s')).toBeInTheDocument();
    expect(within(row('Copy bandwidth (roof, M > 16)')).getByText('run 941ff9215564')).toBeInTheDocument();
    expect(within(row('Read bandwidth (roof, M ≤ 16)')).getByText('257.8 GB/s')).toBeInTheDocument();
    expect(within(row('mma.sync peak (compute roof)')).getByText(/125\.6 TFLOPS/)).toBeInTheDocument();
    expect(within(row('mma.sync peak (compute roof)')).getByText('run eb3e197afc8e')).toBeInTheDocument();
    expect(within(row('Toolchain')).getByText('CUDA 13.0, driver API 13.0')).toBeInTheDocument();
    // No power controls in the arch file, no power mode on any run: "not measured".
    expect(within(row('Power controls')).getByText('not measured')).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith('arch_model', { sm: 121 });
  });

  it('shows latency as cycles = ns at the clock, with the lock state', async () => {
    render(<DeviceSection />);
    expect(await screen.findByText('335.4 cycles = 139.4 ns at 2407 MHz (clocks not locked)')).toBeInTheDocument();
    expect(screen.getByText('956.6 cycles = 397.5 ns at 2407 MHz (clocks not locked)')).toBeInTheDocument();
    const l2 = screen.getByText('L2 latency').closest('tr')!;
    expect(within(l2).getByText(/SM 2407 MHz, clock lock not recorded · 335\.4 cycles = 139\.4 ns/)).toBeInTheDocument();
  });

  it('lists replaced runs as history, not as a warning', async () => {
    const { container } = render(<DeviceSection />);
    const l2 = (await screen.findByText('L2 latency')).closest('tr')!;
    expect(within(l2).getByText('history: 4 earlier runs replaced')).toBeInTheDocument();
    const first = within(l2).getAllByRole('listitem').find((li) => li.textContent!.includes('55945fd9cbef'))!;
    expect(first).toHaveTextContent('run 55945fd9cbef · 5509991 · 2026-10-14 05:35 UTC · replaced by fb77bc085d64 (36 rows)');
    expect(container.textContent).not.toContain('⚠');
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('shows a replaced source run as history, not as a warning', async () => {
    const model = structuredClone(archModel) as typeof archModel;
    Object.assign(model.copy_bw!.source, { status: 'replaced', replaced_rows: 6, replaced_by: ['newer01'] });
    responses.arch_model = model;
    const { container } = render(<DeviceSection />);
    expect(await screen.findByText('history: replaced by newer01 (6 rows)')).toBeInTheDocument();
    expect(container.textContent).not.toContain('⚠');
    expect(screen.queryByRole('status')).toBeNull();
    responses.arch_model = archModel;
  });
});

describe('RooflineSection', () => {
  it('lists every shape with its roof, CI and tie call', async () => {
    render(
      <ThemeProvider>
        <RooflineSection />
      </ThemeProvider>,
    );
    expect(await screen.findByText('Points')).toBeInTheDocument();
    const r = roofline as unknown as Roofline;
    const shapes = new Set(r.points.map((p) => p.shape_bucket));
    expect(shapes.size).toBe(14);
    const table = screen.getByText('Points').parentElement!.querySelector('table')!;
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(14);
    // Decode shapes are held to the read roof, the rest to the copy roof.
    for (const row of rows) {
      const shape = row.querySelector('td')!.textContent!;
      const m = Number(shape.split('x')[0]);
      expect(row.textContent).toContain(m <= 16 ? 'read (257.8 GB/s)' : 'copy (236.7 GB/s)');
    }
    const tied = rows.find((row) => row.textContent!.startsWith('16x4864x896'))!;
    expect(tied.textContent).toContain('tied vs mma_pipe_64x128x32_2x4_s4, runner-up/pick CI [0.992, 1.002]');
    expect(tied.textContent).toContain('99.2% of cublaslt_best, ratio CI [1.001, 1.004]: faster');
    expect(invoke).toHaveBeenCalledWith('roofline', { sm: 121 });
  });

  it('says "not measured" for an arch without an arch file', async () => {
    responses.roofline = null;
    render(
      <ThemeProvider>
        <RooflineSection />
      </ThemeProvider>,
    );
    expect(await screen.findByText('no arch file; roofs not measured')).toBeInTheDocument();
    responses.roofline = roofline;
  });
});

describe('Roofline data and hover', () => {
  it('matches the golden aegis-perf roofline listing point for point', () => {
    const r = roofline as unknown as Roofline;
    const got = r.points
      .map((p) => [p.label, p.roof.ai.toFixed(1), p.roof.tflops.toFixed(2), p.roof.pct_roof.toFixed(1), p.roof.roof].join(' '))
      .sort();
    const want = goldenRoofline
      .split('\n')
      .filter((l) => l.includes(' AI '))
      .map((l) => {
        const [label, rest] = l.split(' AI ');
        const t = rest.trim().split(/\s+/);
        return [label.trim(), t[0], t[1], t[3].replace('%', ''), t[6].slice(1)].join(' ');
      })
      .sort();
    expect(want).toHaveLength(28);
    expect(got).toEqual(want);
    expect(want.some((w) => w.startsWith('1x4864x896 ') && w.endsWith(' read'))).toBe(true);
  });

  it('hover: config, % of cublaslt_best with the paired CI, dispatch target', () => {
    const r = roofline as unknown as Roofline;
    const p = r.points.find((x) => x.label === '4096x4096x4096 mma_pipe_128x128x32_2x4_s3')!;
    render(<Hover active payload={[{ payload: { kind: 'point', x: p.roof.ai, y: p.roof.tflops, p } }]} />);
    expect(screen.getByText(/72\.2% of cublaslt_best, ratio CI \[0\.720, 0\.724\]: slower/)).toBeInTheDocument();
    expect(screen.getByText(/BM=128/)).toBeInTheDocument();
    expect(screen.getByText(/dispatch: cuBLASLt/)).toBeInTheDocument();
    expect(screen.getByText(/paired CI upper bound 0\.724 < 80% floor/)).toBeInTheDocument();
  });

  it('table: the dispatch target per shape', async () => {
    render(
      <ThemeProvider>
        <RooflineSection />
      </ThemeProvider>,
    );
    const table = (await screen.findByText('Points')).parentElement!.querySelector('table')!;
    const row = within(table).getAllByRole('row').find((x) => x.textContent!.startsWith('4096x4096x4096'))!;
    expect(row).toHaveTextContent('dispatch: cuBLASLt');
    const dec = within(table).getAllByRole('row').find((x) => x.textContent!.startsWith('1x4864x896'))!;
    expect(dec).toHaveTextContent('dispatch: AEGIS kernel');
  });
});

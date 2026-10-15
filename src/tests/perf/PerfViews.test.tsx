// Device and Roofline views over real command output: the fixtures are
// `cargo run --example dump` (custos-perf) against ~/custos-fixtures/aegis_perf.db.
import { render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import devices from './fixtures/devices.json';
import archModel from './fixtures/arch_model-121.json';
import roofline from './fixtures/roofline-121.json';
import { ThemeProvider } from '../../contexts/ThemeContext';
import { DeviceSection } from '../../components/sections/perf/DeviceSection';
import { RooflineSection } from '../../components/sections/perf/RooflineSection';
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
  it('shows manifest facts and the measured model with source runs', async () => {
    render(<DeviceSection />);
    expect(await screen.findByText('Measured hardware model, sm_121')).toBeInTheDocument();
    expect(screen.getByText('48')).toBeInTheDocument(); // SMs, from the manifest
    expect(screen.getByText('236.7 GB/s')).toBeInTheDocument(); // copy roof, arch file
    expect(screen.getByText('257.8 GB/s')).toBeInTheDocument(); // read roof
    expect(screen.getByText(/125\.6 TFLOPS/)).toBeInTheDocument();
    expect(screen.getAllByText('941ff9215564').length).toBe(2); // both bandwidths' source run
    // No power controls in the arch file: "not measured", not a number.
    const power = screen.getByText('Power controls').closest('tr')!;
    expect(within(power).getByText('not measured')).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith('arch_model', { sm: 121 });
  });

  it('shows latency in cycles and ns at the stated clock, with each run\'s clock and lock state', async () => {
    render(<DeviceSection />);
    expect(await screen.findByText('335.4 cycles · 139.4 ns at 2407 MHz')).toBeInTheDocument();
    expect(screen.getByText('956.6 cycles · 397.5 ns at 2407 MHz')).toBeInTheDocument();
    const l2 = screen.getByText('L2 latency').closest('tr')!;
    expect(within(l2).getByText(/SM 2407 MHz, clock lock not recorded · 335\.4 cycles = 139\.4 ns/)).toBeInTheDocument();
  });

  it('shows a replaced source run as history, not as a warning', async () => {
    const model = structuredClone(archModel) as typeof archModel;
    Object.assign(model.copy_bw!.source, { status: 'replaced', superseded_rows: 6, superseded_by: ['newer01'] });
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
    const tied = rows.find((row) => row.textContent!.startsWith('1x4864x896'))!;
    expect(tied.textContent).toContain('tied vs mma_pipe_64x128x32_2x4_s4, runner-up/pick CI [0.995, 1.002]');
    expect(tied.textContent).toContain('86.9% of cublaslt_best, ratio CI [0.872, 0.880]: slower');
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

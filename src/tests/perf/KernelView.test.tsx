// Kernel detail over real command output (`cargo run --example dump --
// kernel be0c6688d651513b 200` on tests/fixtures/; the SASS text is cut to its
// first 200 lines for the fixture, `lines` is the listing's full length).
import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import winners from './fixtures/winners-121.json';
import kernel from './fixtures/kernel-be0c6688d651513b.json';
import { KernelSection } from '../../components/sections/perf/KernelSection';
import type { KernelDetail } from '../../perf/types';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

const responses: Record<string, unknown> = {
  perf_sources: { db: '/f.db', core: '/c', measured_archs: [121] },
  winners,
  kernel_detail: kernel,
};

beforeEach(() => {
  invoke.mockReset();
  invoke.mockImplementation((cmd: string) => Promise.resolve(responses[cmd]));
});

describe('KernelSection', () => {
  it('config, registers, spills, shared memory', async () => {
    render(<KernelSection />);
    expect(await screen.findByRole('heading', { name: 'mma_pipe_64x64x32_2x2_s4' })).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith('kernel_detail', { kernelId: 'be0c6688d651513b' });
    const fact = (label: string) => screen.getByText(label).nextElementSibling!.textContent;
    expect(fact('Registers / thread')).toBe('74');
    expect(fact('Spills (local memory)')).toBe('0 B (no spills)');
    expect(fact('Shared memory / block')).toBe('32 KiB');
    expect(fact('STAGES')).toBe('4');
    expect(fact('smem')).toBe('xor');
    // The kernel picker lists each winner kernel once.
    const options = within(screen.getByLabelText('Kernel')).getAllByRole('option');
    expect(options.map((o) => o.textContent)).toContain('mma_pipe_64x64x32_2x2_s4 (10 shapes)');
  });

  it('instruction mix and the SASS listing of the row-major instantiation', async () => {
    render(<KernelSection />);
    const mix = await screen.findByRole('table', { name: 'Instruction mix' });
    const count = (op: string) => mix.querySelector(`[data-op="${op}"]`)!.textContent;
    expect([count('HMMA'), count('LDSM'), count('LDGSTS'), count('LDG'), count('STS')]).toEqual(['48', '24', '64', '558', '62']);
    expect(screen.getByText(/ptxas: 74 registers, 0 B local/)).toBeInTheDocument();
    expect(screen.getAllByText(/LayoutE0ELS5_0EEELi4EE/)[0]).toBeInTheDocument();
    const listing = screen.getByLabelText('SASS listing');
    expect(listing.textContent).toContain('Function : _ZN5aegis4gemm');
    expect(screen.getByText(/200 of 13,864 lines/)).toBeInTheDocument();
  });

  it('Nsight: "not profiled" when Core has no report', async () => {
    render(<KernelSection />);
    expect(await screen.findByText('not profiled')).toBeInTheDocument();
  });

  it('says why there is no SASS', async () => {
    const k = structuredClone(kernel) as unknown as KernelDetail;
    k.artifacts[0].sass = null;
    k.artifacts[0].instruction_mix = null;
    k.artifacts[0].sass_note = 'no SASS listing of the row-major instantiation in the dump';
    responses.kernel_detail = k;
    render(<KernelSection />);
    expect(await screen.findByText('no SASS: no SASS listing of the row-major instantiation in the dump')).toBeInTheDocument();
    responses.kernel_detail = kernel;
  });

  it('a listing longer than the preview can be shown in full', async () => {
    render(<KernelSection />);
    await screen.findByLabelText('SASS listing');
    // The fixture holds 200 lines, under the 400-line preview: no button.
    expect(screen.queryByRole('button', { name: 'show all' })).toBeNull();
    const k = structuredClone(kernel) as unknown as KernelDetail;
    k.artifacts[0].sass!.text = Array.from({ length: 500 }, (_, i) => `line ${i}`).join('\n');
    responses.kernel_detail = k;
    render(<KernelSection />);
    const button = await screen.findByRole('button', { name: 'show all' });
    fireEvent.click(button);
    expect(await screen.findByText(/500 of 13,864 lines/)).toBeInTheDocument();
    responses.kernel_detail = kernel;
  });
});

describe('KernelSection: SASS source', () => {
  const origin = async () => (await screen.findByRole('table', { name: 'Instruction mix' })) && document.querySelector('[data-col="sass-origin"]')!.textContent;

  it('the fixture listing: compiled from the tag by Custos', async () => {
    render(<KernelSection />);
    expect(await origin()).toBe('Source: compiled from tag aegis-perf-v0.3.0 (src/gemm/mma_pipe.cu) by Custos, not Core\'s dump');
  });

  it('a listing from Core\'s dump: Core artifact', async () => {
    const k = structuredClone(kernel) as unknown as KernelDetail;
    k.artifacts[0].sass!.origin = { kind: 'core_artifact' };
    responses.kernel_detail = k;
    render(<KernelSection />);
    expect(await origin()).toBe('Source: Core artifact (artifacts/sass, Core\'s dump)');
    responses.kernel_detail = kernel;
  });
});

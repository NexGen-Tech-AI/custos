// The win chain over real command output (`cargo run --example dump --
// win_chain 121 - 200` on tests/fixtures/; the SASS listing cut to 200 lines).
// Every value comes from the fixture DB, an artifact or a doc; each part says
// "not measured" when its source is missing.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import chain from './fixtures/win_chain-121.json';
import winners from './fixtures/winners-121.json';
import type { WinChain } from '../../perf/types';
import { ThemeProvider } from '../../contexts/ThemeContext';
import { WinChainPage } from '../../components/sections/perf/WinChain';
import { WinnersSection } from '../../components/sections/perf/WinnersSection';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

const c = chain as unknown as WinChain;

function page(x: WinChain) {
  render(
    <ThemeProvider>
      <WinChainPage c={x} />
    </ThemeProvider>,
  );
  return (id: string) => document.querySelector(`[data-section="${id}"]`) as HTMLElement;
}
const col = (el: ParentNode, name: string) => el.querySelector(`[data-col="${name}"]`)?.textContent ?? null;

describe('Win chain', () => {
  it('explains 16x896x896, the strongest decode win, and says its result is dirty', () => {
    page(c);
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('Win chain: 16x896x896');
    expect(col(document, 'chain-pick')).toBe(
      'Why this shape: no clean paired result: strongest unreproducible (dirty build) (paired_results #36, CI lower bound 113.5% of cublaslt_best)',
    );
    const order = Array.from(document.querySelectorAll('[data-section]')).map((s) => (s as HTMLElement).dataset.section);
    expect(order).toEqual(['roof', 'kernel', 'sass', 'paired', 'dispatch', 'docs']);
  });

  it('every value traces to the fixture, an artifact or a doc', () => {
    const s = page(c);
    // Roofline (the arch file and the DB's median).
    expect(col(s('roof'), 'chain-roof')).toBe(
      '2.69 TFLOPS at AI 15.4 FLOP/B · 67.6% of the read roof (257.8 GB/s, memory-bound) · 9.54 µs',
    );
    expect(col(s('roof'), 'chain-diagnosis')).toContain('below floor: launch-overhead bound');
    expect(col(s('roof'), 'chain-diagnosis')).toContain('docs/LOG.md:1977');
    // Kernel (perf DB) and instruction mix (the SASS artifact).
    expect(s('kernel')).toHaveTextContent('Registers / thread72');
    expect(s('kernel')).toHaveTextContent('Spills (local memory)0 B (no spills)');
    const op = (o: string) => s('kernel').querySelector(`[data-op="${o}"]`)!.textContent;
    expect(['HMMA', 'LDSM', 'LDGSTS', 'LDG', 'STS'].map(op)).toEqual(['24', '24', '72', '361', '69']);
    expect(col(s('kernel'), 'regs-mismatch')).toBe("⚠ the listing's build is not the measured one: ptxas 70 registers, the perf DB 72");
    // SASS with its provenance.
    expect(col(s('sass'), 'sass-origin')).toBe("Source: compiled from tag aegis-perf-v0.5.0 (src/gemm/gemv_tc.cu) by Custos, not Core's dump");
    expect(col(s('sass'), 'sass-note')).toContain('measured build 1084490 (REG 72 in the perf DB)');
    expect(within(s('sass')).getByLabelText('SASS listing').textContent).toContain('gemv_tc_kernel');
    // Paired CI (the tune's and paired-ab's).
    expect(col(s('paired'), 'chain-ci')).toBe('110.8% of cublaslt_best, ratio CI [1.109, 1.116]: faster');
    expect(col(s('paired'), 'chain-ab')).toContain('paired-ab: 114.8% [113.5, 115.3] of cublaslt_best (paired_results #36, 30 pairs)');
    expect(col(s('paired'), 'chain-ab')).toContain('win (unreproducible: dirty build)');
    // Dispatch: Core's rule, the header, aegis::matmul's paired-ab.
    expect(col(s('dispatch'), 'chain-dispatch')).toBe('dispatch: AEGIS kernel · paired CI upper bound 1.116 ≥ 80% floor');
    expect(s('dispatch')).toHaveTextContent('header: AEGIS kernel');
    expect(col(s('dispatch'), 'chain-dispatch-ab')).toContain('aegis::matmul: 115.0% [113.6, 115.4] of cublaslt_best (paired_results #38)');
    // Docs.
    const docs = within(s('docs')).getAllByRole('listitem').map((li) => li.textContent);
    expect(docs).toEqual([
      'docs/LOG.md:1898 § 2026-10-17 — Phase C step 2: GEMV tuning; % of the read-bandwidth floor (names gemv_tc_16x64x64_1x4_s4_k1)',
      'docs/LOG.md:1945 § 2026-10-17 — Phase C step 3: hardening of the decode family (names gemv_tc and 16x896x896)',
      'docs/LOG.md:1977 § 2026-10-17 — Phase C step 4: decode results, winners and dispatch (names gemv_tc_16x64x64_1x4_s4_k1)',
    ]);
  });

  it('each part renders "not measured" when its source is missing', () => {
    const x = structuredClone(c);
    x.roofline = null;
    x.winner.roof = null;
    x.kernel = null;
    x.winner.paired_ab = { kernel: null, dispatch: null };
    x.docs = [];
    const s = page(x);
    expect(s('roof')).toHaveTextContent('roofline position not measured (no arch file)');
    expect(s('kernel')).toHaveTextContent('kernel not in the perf DB');
    expect(s('sass')).toHaveTextContent('no SASS: not measured');
    expect(col(s('paired'), 'chain-ab')).toBe('no paired-ab result');
    expect(col(s('dispatch'), 'chain-dispatch-ab')).toBe('dispatch not measured');
    expect(s('docs')).toHaveTextContent('no Core doc names this kernel at this shape');
  });

  it('a kernel without its SASS artifact: listing and mix not measured', () => {
    const x = structuredClone(c);
    x.kernel!.artifacts = x.kernel!.artifacts.map((a) => ({
      ...a,
      sass: null,
      instruction_mix: null,
      resource_usage: null,
      sass_note: 'no SASS dump (artifacts/sass/sm_121 missing)',
    }));
    const s = page(x);
    expect(s('kernel')).toHaveTextContent('instruction mix not measured: no SASS dump (artifacts/sass/sm_121 missing)');
    expect(s('sass')).toHaveTextContent('no SASS: no SASS dump (artifacts/sass/sm_121 missing)');
  });
});

describe('Win chain from the Winners row', () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockImplementation((cmd: string) =>
      Promise.resolve(
        cmd === 'perf_sources' ? { db: '/f.db', core: '/c', measured_archs: [121] } : cmd === 'win_chain' ? chain : winners,
      ),
    );
  });

  it('only the chain\'s shape links to it, and the link opens the page', async () => {
    render(
      <ThemeProvider>
        <WinnersSection />
      </ThemeProvider>,
    );
    const table = (await screen.findByText('Winning config')).closest('table')!;
    const links = within(table).getAllByRole('button', { name: 'win chain →' });
    expect(links).toHaveLength(1);
    expect(links[0].closest('tr')!.dataset.shape).toBe('16x896x896');
    fireEvent.click(links[0]);
    expect(await screen.findByText('16x896x896', { selector: 'h2 span' })).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith('win_chain', { sm: 121, shape: '16x896x896' });
    fireEvent.click(screen.getByRole('button', { name: '← Winners' }));
    expect(await screen.findByText('Winning config')).toBeInTheDocument();
  });
});

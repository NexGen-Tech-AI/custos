// The regression view over real command output (`cargo run --example dump --
// regression 121` on tests/fixtures/): fixture nightly rows for watch,
// disturbed, and (on a doctored copy of the output, as custos-perf's tests do
// on the DB) regression; the nightly fuzz panel with case 24632.
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import regression from './fixtures/regression-121.json';
import type { Regression } from '../../perf/types';
import { RegressionView } from '../../components/sections/perf/RegressionSection';

const r = regression as unknown as Regression;
const runRow = (id: string) => document.querySelector(`tr[data-run="${id}"]`) as HTMLElement | null;
const col = (el: ParentNode, name: string) => el.querySelector(`[data-col="${name}"]`)?.textContent ?? null;

describe('Regression view', () => {
  it('build over build: one watch per clean nightly, by SHA', () => {
    render(<RegressionView r={r} />);
    for (const [run, shape, shift] of [
      ['b34425e97d6d', '16x4864x896', '99.4% (run 41cc8ffb03fd) → 96.1%'],
      ['eb5bcee294d4', '1x4864x896', '98.1% (run b34425e97d6d) → 94.0%'],
    ]) {
      const row = runRow(run)!;
      expect(row).toHaveTextContent('9157a34');
      const watches = Array.from(row.querySelectorAll('[data-status="watch"]'));
      expect(watches).toHaveLength(1);
      expect(watches[0].textContent).toBe('▲ watch');
      const li = row.querySelector(`li[data-shape="${shape}"]`)!;
      expect(li).toHaveTextContent(shift);
      expect(row.querySelector('[data-status="regression"]')).toBeNull();
      expect(col(row, 'header')).toContain("tests/fixtures/winners/9157a34/sm_121.h");
      expect(col(row, 'header')).toContain("the build's own header, provisional");
    }
  });

  it('disturbed runs are greyed out and hidden by default', () => {
    render(<RegressionView r={r} />);
    expect(runRow('d1504a45376d')).toBeNull();
    expect(runRow('60959720261a')).toBeNull();
    fireEvent.click(screen.getByLabelText(/show disturbed and allow_busy runs \(2\)/));
    const d = runRow('d1504a45376d')!;
    expect(d.dataset.excluded).toBe('true');
    expect(d.className).toContain('opacity-50');
    expect(col(d, 'run-state')).toContain('disturbed: excluded');
    expect(col(d, 'run-state')).toContain('1 of 41 2 s windows over 2%');
    expect(col(d, 'calls')).toContain('not classified');
  });

  it('a regression looks different from a watch, with its paired-ab confirmation', () => {
    const x = structuredClone(r);
    const run = x.runs.find((y) => y.run_id === 'b34425e97d6d')!;
    const c = run.checks.find((y) => y.shape === '16x4864x896')!;
    c.status = 'regression';
    c.why = 'confirmed by paired-ab';
    c.paired = {
      source: 'paired_results #45',
      id: 45,
      ratio: 1.04,
      ci_lo: 1.02,
      ci_hi: 1.06,
      sha_a: '9157a34',
      sha_b: '9157a34',
      provenance: 'clean',
      provenance_label: null,
    };
    render(<RegressionView r={x} />);
    const row = runRow('b34425e97d6d')!;
    const reg = row.querySelector('[data-status="regression"]')!;
    expect(reg.textContent).toBe('■ REGRESSION (confirmed by paired-ab)');
    expect(reg.className).toContain('bg-red-100');
    expect(runRow('eb5bcee294d4')!.querySelector('[data-status="watch"]')!.className).toContain('bg-amber-100');
    expect(col(row, 'confirmation')).toBe('paired-ab #45: B/A 1.040 [1.020, 1.060] · clean build');
  });

  it('nightly fuzz: counts, failures, and case 24632 adjudicated by FP64', () => {
    render(<RegressionView r={r} />);
    expect(col(document, 'fuzz-total')).toBe('4 nights, 200,000 cases, 1 failures');
    const night = document.querySelector('tr[data-night="20261014-201534"]')!;
    expect(col(night, 'failures')).toBe('1');
    const c = night.querySelector('li[data-case="24632"]')!;
    expect(col(c, 'adjudication')).toContain('FP64 adjudication: cuBLASLt 2.57 ulp vs AEGIS 0.43 ulp: a reference bug');
    expect(col(c, 'adjudication')).toContain('docs/LOG.md:1393 § 2026-10-15 — Fuzz case 24632: a cuBLASLt reference error, not ours');
    expect(col(document.querySelector('tr[data-night="20261017-030050"]')!, 'failures')).toBe('0');
  });

  it('says "not measured" without fuzz output or a Core adjudication', () => {
    const x = structuredClone(r);
    x.fuzz[0].cases_reported[0].adjudication = null;
    const { unmount } = render(<RegressionView r={x} />);
    expect(screen.getByText("no FP64 adjudication in Core's LOG")).toBeInTheDocument();
    unmount();
    render(<RegressionView r={{ ...r, fuzz: [] }} />);
    expect(screen.getByText('nightly fuzz: not measured (no results/nightly/fuzz-*.txt)')).toBeInTheDocument();
  });
});

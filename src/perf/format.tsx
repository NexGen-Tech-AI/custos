// Formatting for perf views. A null value renders as "not measured", never a
// placeholder number (project rules 9 and 16).
import type { Ci, Dispatch, LtAlgo, VsBaseline, Tie } from './types';

export const NOT_MEASURED = 'not measured';

export function NotMeasured({ label = NOT_MEASURED }: { label?: string }) {
  return <span className="italic text-gray-400 dark:text-gray-500">{label}</span>;
}

export function num(v: number | null | undefined, digits = 1, unit = ''): string | null {
  if (v === null || v === undefined || !Number.isFinite(v)) return null;
  return `${v.toFixed(digits)}${unit ? ` ${unit}` : ''}`;
}

/** A value or "not measured". */
export function V({ v }: { v: string | null }) {
  return v === null ? <NotMeasured /> : <>{v}</>;
}

/** CUDA versions are stored as 1000 * major + 10 * minor (13000 -> 13.0). */
export function cudaVersion(v: number | null): string | null {
  if (v === null) return null;
  return `${Math.floor(v / 1000)}.${Math.floor((v % 1000) / 10)}`;
}

export function bytes(v: number | null): string | null {
  if (v === null) return null;
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let x = v;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  return `${Number.isInteger(x) ? x : x.toFixed(1)} ${units[i]}`;
}

export function date(iso: string | null): string | null {
  if (!iso) return null;
  return iso.replace('T', ' ').slice(0, 16) + ' UTC';
}

/** "[0.924, 0.932]" with three decimals: the CI as Core records it. */
export function ci(c: Ci | null): string | null {
  return c ? `[${c.lo.toFixed(3)}, ${c.hi.toFixed(3)}]` : null;
}

/** % of cublaslt_best with its paired 95% CI (rule 6: never a bare median). */
export function vsBaseline(v: VsBaseline | null): string {
  if (!v || v.pct_of_cublaslt_best === null) return NOT_MEASURED;
  const pct = `${v.pct_of_cublaslt_best.toFixed(1)}% of cublaslt_best`;
  if (!v.ci) return `${pct} (no paired test)`;
  const verdict = v.verdict === 'tie' ? 'tie' : v.verdict === 'faster' ? 'faster' : 'slower';
  return `${pct}, ratio CI ${ci(v.ci)}: ${verdict}`;
}

/** "paired and unpaired disagree: median 82.2%, paired CI [78.5, 79.0]". */
export function disagreeText(v: VsBaseline | null): string | null {
  const d = v?.disagreement;
  if (!d) return null;
  return `paired and unpaired disagree: median ${d.median_pct.toFixed(1)}%, paired CI [${d.ci_lo_pct.toFixed(1)}, ${d.ci_hi_pct.toFixed(1)}]`;
}

/** The warning on a row whose median % lies outside its paired CI. */
export function DisagreeWarning({ v }: { v: VsBaseline | null }) {
  const text = disagreeText(v);
  if (!text) return null;
  const d = v!.disagreement!;
  return (
    <div role="note" data-col="disagree" className="mt-1 text-xs text-amber-700 dark:text-amber-400">
      <div className="font-medium">⚠ {text}</div>
      <div className="text-gray-500 dark:text-gray-400">
        the paired CI is the number of record; the median is secondary (&gt; {d.threshold_pts} points apart
        {d.provisional ? ', provisional threshold' : ''})
      </div>
    </div>
  );
}

export function tieText(t: Tie | null): string {
  if (!t) return NOT_MEASURED;
  if (t.method === 'band') return t.tied ? 'tied (p10-p90 band, no paired test)' : 'not tied (p10-p90 band, no paired test)';
  if (!t.ci) return t.tied ? 'tied' : 'single config, no runner-up';
  const who = t.contender ? ` vs ${t.contender}` : '';
  return `${t.tied ? 'tied' : 'not tied'}${who}, runner-up/pick CI ${ci(t.ci)}`;
}

export function pct(v: number | null | undefined, digits = 1): string | null {
  const s = num(v, digits);
  return s === null ? null : `${s}%`;
}

/** "dispatch: cuBLASLt" / "dispatch: AEGIS kernel". */
export function dispatchTarget(d: Dispatch | null): string {
  if (!d) return NOT_MEASURED;
  const t = d.target === 'cublaslt' ? 'cuBLASLt' : 'AEGIS kernel';
  return `dispatch: ${t}`;
}

/** Why: "paired CI upper bound 0.708 < 80% floor". */
export function dispatchWhy(d: Dispatch | null): string | null {
  if (!d || d.decided_on === null) return null;
  const rel = d.target === 'cublaslt' ? '<' : '≥';
  const what = d.basis === 'paired' ? 'paired CI upper bound' : 'unpaired median ratio';
  return `${what} ${d.decided_on.toFixed(3)} ${rel} ${(d.floor * 100).toFixed(0)}% floor`;
}

/** Dispatch %: what is dispatched, never AEGIS's kernel % for a cuBLASLt route. */
export function dispatchPct(d: Dispatch | null): string {
  if (!d) return NOT_MEASURED;
  if (d.target === 'cublaslt') return 'cuBLASLt path: not measured';
  return d.pct_of_cublaslt_best === null ? NOT_MEASURED : `${d.pct_of_cublaslt_best.toFixed(1)}%`;
}

/** "algo 67 · tile 412 · stages 35 · custom 31" (+ split-K, reduction,
 *  swizzle, inner/cluster shape when not the default). */
export function ltAlgoText(a: LtAlgo | null): string {
  if (!a) return 'not stored';
  const parts = [`algo ${a.algo_id}`, `tile ${a.tile_id}`, `stages ${a.stages_id}`];
  if (a.splitk !== 1) parts.push(`split-K ${a.splitk}`);
  if (a.reduction !== 0) parts.push(`reduction ${a.reduction}`);
  if (a.swizzle !== 0) parts.push(`swizzle ${a.swizzle}`);
  parts.push(`custom ${a.custom}`);
  if (a.inner_shape !== 0) parts.push(`inner shape ${a.inner_shape}`);
  if (a.cluster_shape !== 0) parts.push(`cluster shape ${a.cluster_shape}`);
  return parts.join(' · ');
}

/** "header: cuBLASLt": the dispatch Core stored in the winners header. */
export function storedDispatchText(d: Dispatch | null): string {
  if (!d || d.stored === null) return 'stored dispatch: no winners header row';
  return `header: ${d.stored === 'cublaslt' ? 'cuBLASLt' : 'AEGIS kernel'}`;
}

/** The warning on a shape whose stored dispatch disagrees with Core's rule
 *  applied to its paired CI (never hidden; docs/core-requests.md #4). */
export function DispatchMismatch({ d }: { d: Dispatch | null }) {
  if (!d || !d.mismatch) return null;
  const name = (t: string | null) => (t === 'cublaslt' ? 'cuBLASLt' : 'AEGIS kernel');
  return (
    <div role="note" data-col="dispatch-mismatch" className="mt-1 text-xs text-amber-700 dark:text-amber-400">
      <div className="font-medium">
        ⚠ stored dispatch disagrees with the rule: header {name(d.stored)}, rule on the paired CI {name(d.target)}
      </div>
      <div className="text-gray-500 dark:text-gray-400">filed in docs/core-requests.md #4</div>
    </div>
  );
}

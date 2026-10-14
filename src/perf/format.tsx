// Formatting for perf views. A null value renders as "not measured", never a
// placeholder number (CLAUDE.md rules 9 and 13).
import type { Ci, VsBaseline, Tie } from './types';

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

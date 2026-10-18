// Decode spotlight (Winners and Roofline): every decode shape (M <= 16) with
// its % of the read-bandwidth roof, the AEGIS kernel's paired ratio against
// cublaslt_best (the tune's CI, and the stored paired-ab result with its build
// provenance: a win is confirmed only from a clean build), the dispatch target
// and the impl family with its split-K. A diagnosis appears only where Core's
// docs state one, with its source; otherwise the number stands alone.
import type { DecodeSpotlight, Dispatch, PairedAb, Roofline, VsBaseline, Winner } from '../../../perf/types';
import { DocCite, NotMeasured, abText, dispatchTarget, pct, vsBaseline } from '../../../perf/format';

export interface SpotRow {
  shape: string;
  impl: string;
  vs: VsBaseline | null;
  dispatch: Dispatch | null;
  ab: PairedAb | null;
  spot: DecodeSpotlight;
}

export function spotRowsFromWinners(ws: Winner[]): SpotRow[] {
  return ws
    .filter((w) => w.decode_spotlight)
    .map((w) => ({ shape: w.shape_bucket, impl: w.impl, vs: w.vs_cublaslt_best, dispatch: w.dispatch, ab: w.paired_ab, spot: w.decode_spotlight! }));
}

export function spotRowsFromRoofline(r: Roofline): SpotRow[] {
  return r.points
    .filter((p) => p.series === 'winner' && p.hover.decode_spotlight)
    .map((p) => ({
      shape: p.shape_bucket,
      impl: p.impl,
      vs: p.hover.vs_cublaslt_best,
      dispatch: p.hover.dispatch,
      ab: p.hover.paired_ab,
      spot: p.hover.decode_spotlight!,
    }));
}

/** "gemv_tc (tensor_core) · split-K S = 3 (requested)". */
export function familyText(s: DecodeSpotlight): string {
  const path = s.path ? ` (${s.path})` : '';
  const split = s.split_k === null ? 'no split-K' : s.split_k === 0 ? 'split-K auto (one wave)' : `split-K S = ${s.split_k} (requested)`;
  return `${s.family}${path} · ${split}`;
}

const th = 'text-left font-medium text-gray-500 dark:text-gray-400 py-2 pr-4 whitespace-nowrap align-bottom';
const td = 'py-2 pr-4 align-top text-xs';
const muted = 'text-xs text-gray-500 dark:text-gray-400';

function Row({ r, onChain }: { r: SpotRow; onChain?: (shape: string) => void }) {
  const s = r.spot;
  const k = r.ab?.kernel ?? null;
  const d = r.ab?.dispatch ?? null;
  return (
    <tr className="border-b border-gray-100 dark:border-gray-700/50" data-shape={r.shape}>
      <td className={`${td} font-mono whitespace-nowrap`}>
        {r.shape}
        {onChain && (
          <div>
            <button type="button" className="text-blue-700 dark:text-blue-300 underline" onClick={() => onChain(r.shape)}>
              win chain
            </button>
          </div>
        )}
      </td>
      <td className={td} data-col="spot-roof">
        <span className="text-sm">{pct(s.pct_of_read_roof) ?? <NotMeasured />}</span>
        <div className={muted}>of the read roof{s.read_bw_gbps !== null ? ` (${s.read_bw_gbps.toFixed(1)} GB/s)` : ''}</div>
        {s.diagnosis && (
          <div className="mt-1" data-col="spot-diagnosis">
            <div className="text-amber-700 dark:text-amber-400">{s.diagnosis.label}</div>
            <div className={muted}>
              Core: <DocCite d={s.diagnosis.source} />
            </div>
          </div>
        )}
      </td>
      <td className={td} data-col="spot-kernel">
        <div>{vsBaseline(r.vs)}</div>
        <div className={muted}>tune paired test</div>
        <div className="mt-1" data-col="spot-ab">
          {k ? (
            <>
              <div>{abText(k)}</div>
              <div className={k.confirmed ? 'text-green-700 dark:text-green-400' : 'text-amber-700 dark:text-amber-400'} data-col="spot-call">
                {k.label}
              </div>
              <div className={muted}>
                paired-ab {k.source.replace('paired_results ', '')}, {k.pairs} pairs, {k.sha_b ?? 'build not recorded'}
              </div>
            </>
          ) : (
            <NotMeasured label="no paired-ab result" />
          )}
        </div>
      </td>
      <td className={td} data-col="spot-dispatch">
        <div>{dispatchTarget(r.dispatch)}</div>
        {d ? (
          <div className={muted} data-col="spot-dispatch-ab">
            aegis::matmul {abText(d)} · {d.label}
          </div>
        ) : (
          <div className={muted}>
            <NotMeasured label="dispatch not measured" />
          </div>
        )}
      </td>
      <td className={`${td} font-mono`} data-col="spot-family">
        {r.impl}
        <div className={`${muted} font-sans`}>{familyText(s)}</div>
      </td>
    </tr>
  );
}

export function DecodeSpotlightPanel({ rows, onChain }: { rows: SpotRow[]; onChain?: (shape: string) => void }) {
  if (rows.length === 0) return null;
  return (
    <div data-panel="decode-spotlight">
      <h3 className="text-lg font-semibold mb-2">Decode spotlight (M ≤ 16)</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700">
              <th className={th}>Shape</th>
              <th className={th}>% of read roof</th>
              <th className={th}>AEGIS kernel vs cublaslt_best</th>
              <th className={th}>Dispatch</th>
              <th className={th}>Impl family</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <Row key={r.shape} r={r} onChain={onChain} />
            ))}
          </tbody>
        </table>
      </div>
      <p className={`${muted} mt-2`}>
        % of the read roof: compulsory traffic at the arch file&apos;s read bandwidth, as aegis-perf report prints it (Core&apos;s
        LOG &quot;floor&quot; counts B&apos;s bytes only). Paired-ab: a stored paired_results row against cublaslt_best; a call is
        confirmed only when both builds are clean and tied to a run. Split-K is the config&apos;s requested count; the
        effective count per call is Core&apos;s. A diagnosis is shown only where Core&apos;s docs state it.
      </p>
    </div>
  );
}

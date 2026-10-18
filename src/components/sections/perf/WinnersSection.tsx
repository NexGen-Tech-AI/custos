// Winners view: one row per shape. The winning config, AEGIS's kernel % of
// cublaslt_best (rule 5) and, separately, where aegis::matmul dispatches the
// shape and what that path achieves (rule 10); the paired ratio and its 95%
// CI (rule 6); the tie call and the runner-up gap; the production bars.
// Dispatch is Core's own rule (aegis-perf tune::dispatch). The production
// bars are provisional: aegis-perf v0.5.0 has no bar constants, so
// custos-perf applies Core's documented bars (core_fallbacks.rs).
import { useEffect, useState } from 'react';
import { perfApi } from '../../../perf/api';
import type { Bars, Winner } from '../../../perf/types';
import {
  DisagreeWarning,
  DispatchMismatch,
  NotMeasured,
  ci,
  dispatchPct,
  dispatchTarget,
  dispatchWhy,
  ltAlgoText,
  pct,
  storedDispatchText,
} from '../../../perf/format';

const panel = 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5';
const th = 'text-left font-medium text-gray-500 dark:text-gray-400 py-2 pr-4 whitespace-nowrap align-bottom';
const td = 'py-2 pr-4 align-top';
const muted = 'text-xs text-gray-500 dark:text-gray-400';

const CLASS_LABEL: Record<Bars['class'], string> = { decode: 'decode', large: 'large', other: 'other' };

/** "fail · decode bar 100% · clear" (+ "below 80% floor"). */
export function barsText(b: Bars): string {
  if (b.verdict === null) return 'not measured';
  const bar = `${CLASS_LABEL[b.class]} bar ${(b.bar * 100).toFixed(0)}%`;
  const floor = b.below_floor ? `; below ${(b.floor * 100).toFixed(0)}% floor` : '';
  return `${b.verdict} · ${bar} · ${b.margin}${floor}`;
}

function pairedRatio(w: Winner): string | null {
  const c = w.vs_cublaslt_best.ci;
  if (!c) return null;
  const med = c.ratio_median === null ? '' : `${c.ratio_median.toFixed(3)} `;
  return `${med}${ci(c)}`;
}

function tied(w: Winner): string {
  const t = w.tie;
  if (t.method === 'band') return t.tied ? 'tied (p10-p90 band)' : 'no (p10-p90 band)';
  if (!t.ci) return t.tied ? 'tied' : 'no runner-up test';
  return `${t.tied ? 'tied' : 'no'} · ${ci(t.ci)}${t.contender ? ` vs ${t.contender}` : ''}`;
}

function gap(w: Winner): string | null {
  const g = w.tie.runner_up_gap_pct;
  return g === null ? null : `${g >= 0 ? '+' : ''}${g.toFixed(2)}%`;
}

function Row({ w }: { w: Winner }) {
  const routed = w.dispatch.target === 'cublaslt';
  const disagree = w.vs_cublaslt_best.disagreement !== null;
  return (
    <tr className="border-b border-gray-100 dark:border-gray-700/50" data-shape={w.shape_bucket}>
      <td className={`${td} font-mono whitespace-nowrap`}>
        {w.shape_bucket}
        <div className={muted}>
          {w.decode ? 'decode' : 'non-decode'} · {w.roof ? `${w.roof.roof} roof` : <NotMeasured label="roof not measured" />}
        </div>
      </td>
      <td className={`${td} font-mono text-xs`}>
        {w.impl}
        <div className={muted}>
          run {w.run_id}
          {w.git_sha && <> · {w.git_sha}</>}
        </div>
      </td>
      <td className={`${td} whitespace-nowrap`}>
        <span data-col="kernel-pct" className={disagree ? 'text-gray-500 dark:text-gray-400' : ''}>
          {pct(w.vs_cublaslt_best.pct_of_cublaslt_best) ?? <NotMeasured />}
        </span>
        {disagree && <div className={muted}>unpaired median (secondary)</div>}
      </td>
      <td className={`${td} text-xs`} data-col="dispatch">
        <span className={routed ? 'font-medium' : ''}>{dispatchTarget(w.dispatch)}</span>
        {dispatchWhy(w.dispatch) && <div className={muted}>{dispatchWhy(w.dispatch)}</div>}
        <div className={muted} data-col="stored-dispatch">
          {storedDispatchText(w.dispatch)}
        </div>
        <DispatchMismatch d={w.dispatch} />
        {routed && (
          <div className="font-mono" data-col="dispatch-algo">
            {w.lt_algo ? `runs cuBLASLt ${ltAlgoText(w.lt_algo)}` : <NotMeasured label="cuBLASLt algorithm not stored" />}
          </div>
        )}
      </td>
      <td className={`${td} text-xs whitespace-nowrap`} data-col="dispatch-pct">
        {routed ? <NotMeasured label={dispatchPct(w.dispatch)} /> : dispatchPct(w.dispatch)}
      </td>
      <td className={`${td} text-xs font-mono`} data-col="baseline-algo">
        {w.lt_algo ? ltAlgoText(w.lt_algo) : <NotMeasured label="not stored" />}
      </td>
      <td className={`${td} text-xs whitespace-nowrap`} data-col="paired">
        <span className={disagree ? 'font-medium' : ''}>{pairedRatio(w) ?? <NotMeasured label="no paired test" />}</span>
        <DisagreeWarning v={w.vs_cublaslt_best} />
      </td>
      <td className={`${td} text-xs`} data-col="tied">
        {tied(w)}
      </td>
      <td className={`${td} text-xs whitespace-nowrap`} data-col="gap">
        {gap(w) ?? <NotMeasured label={w.tie.method === 'paired_swap' ? 'runner-up faster (paired_swap)' : 'not measured'} />}
      </td>
      <td className={`${td} text-xs`} data-col="bars">
        <span className={w.bars.verdict === 'pass' ? 'text-green-700 dark:text-green-400' : 'text-red-700 dark:text-red-400'}>
          {barsText(w.bars)}
        </span>
        {w.bars.provisional && <div className={muted}>provisional</div>}
      </td>
    </tr>
  );
}

export function WinnersSection() {
  const [archs, setArchs] = useState<number[] | null>(null);
  const [sm, setSm] = useState<number | null>(null);
  const [rows, setRows] = useState<Winner[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    perfApi
      .sources()
      .then((s) => {
        setArchs(s.measured_archs);
        setSm(s.measured_archs[0] ?? null);
      })
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (sm === null) return;
    setRows(null);
    perfApi.winners(sm).then(setRows, (e) => setError(String(e)));
  }, [sm]);

  if (error) return <div className={`${panel} text-red-700 dark:text-red-300`}>Perf DB: {error}</div>;
  if (archs === null) return <div className={panel}>Loading…</div>;
  if (archs.length === 0) return <div className={panel}><NotMeasured label="no arch files in Core" /></div>;

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold">Winners</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            The tuned config per shape against cublaslt_best · protocol v2, cold cache, idle GPU.
          </p>
        </div>
        <label className="text-sm">
          <span className="mr-2 text-gray-500 dark:text-gray-400">Arch</span>
          <select
            className="rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-2 py-1"
            value={sm ?? ''}
            onChange={(e) => setSm(Number(e.target.value))}
          >
            {archs.map((a) => (
              <option key={a} value={a}>
                sm_{a}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className={panel}>
        {rows === null ? (
          'Loading winners…'
        ) : rows.length === 0 ? (
          <>sm_{sm}: no winners yet (run aegis-perf tune in Core).</>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className={th}>Shape (M×N×K)</th>
                    <th className={th}>Winning config</th>
                    <th className={th}>AEGIS kernel %</th>
                    <th className={th}>Dispatch</th>
                    <th className={th}>Dispatch %</th>
                    <th className={th}>cublaslt_best algorithm</th>
                    <th className={th}>Paired ratio vs cublaslt_best [95% CI]</th>
                    <th className={th}>Tied</th>
                    <th className={th}>Runner-up gap</th>
                    <th className={th}>Production bar</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((w) => (
                    <Row key={`${w.op}-${w.dtype}-${w.shape_bucket}`} w={w} />
                  ))}
                </tbody>
              </table>
            </div>
            <p className={`${muted} mt-3`}>
              Kernel %: cublaslt_best median / kernel median (Core&apos;s report). Paired ratio: cublaslt_best / kernel time, 30
              alternating windows, 95% bootstrap CI; tied means the runner-up CI contains 1.0. Dispatch: Core&apos;s rule and 80% floor (aegis-perf). Production
              bars are provisional: aegis-perf v0.5.0 has no bar constants, so Custos applies Core&apos;s documented bars
              (large: every dim ≥ 1024, ≥ 90%; decode M ≤ 16, ≥ 100%; floor 80%, Core&apos;s), a shape failing a bar when
              its CI lies entirely below it.
              A cuBLASLt route&apos;s dispatch % is not measured: no row times aegis::matmul&apos;s cuBLASLt path yet.
              A warning marks a shape whose kernel % (unpaired medians) lies more than 2 points outside its paired CI
              (provisional threshold); the paired CI is the number of record.
              cublaslt_best algorithm: the cuBLASLt algorithm Core stored for the shape (perf DB schema v4); a shape
              dispatched to cuBLASLt runs that algorithm.
              Header: the dispatch Core stored in the winners header; a warning marks any shape where it disagrees with
              the rule applied to the paired CI.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

// Regression view: Core's nightly regression check, build over build by SHA.
// Each regression sweep is classified by aegis-perf's own regress (a > 3% drop
// is a "watch"; a "regression" only when two consecutive nightlies or a
// paired-ab confirm it); Custos shows the call and the evidence, with each
// paired-ab confirmation's build provenance. Disturbed and allow_busy runs are
// greyed out and hidden by default. Below: the nightly fuzz, with Core's FP64
// adjudication of reported cases.
import { useEffect, useState } from 'react';
import { perfApi } from '../../../perf/api';
import type { FuzzNight, Regression, RegressionCheck, RegressionRun } from '../../../perf/types';
import { DocCite, NotMeasured, date, pct } from '../../../perf/format';

const panel = 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5';
const th = 'text-left font-medium text-gray-500 dark:text-gray-400 py-2 pr-4 whitespace-nowrap align-bottom';
const td = 'py-2 pr-4 align-top';
const muted = 'text-xs text-gray-500 dark:text-gray-400';

/** Watch and regression look different by color and by mark. */
export function StatusBadge({ c }: { c: RegressionCheck }) {
  if (c.status === 'regression')
    return (
      <span data-status="regression" className="inline-block rounded px-1.5 py-0.5 text-xs font-semibold bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300">
        ■ REGRESSION{c.why ? ` (${c.why})` : ''}
      </span>
    );
  if (c.status === 'watch')
    return (
      <span data-status="watch" className="inline-block rounded px-1.5 py-0.5 text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300">
        ▲ watch
      </span>
    );
  return null;
}

function shift(c: RegressionCheck): string {
  const now = pct(c.pct) ?? 'not measured';
  if (c.before_pct === null) return `${now} (no earlier run)`;
  return `${pct(c.before_pct)} (run ${c.before_run}) → ${now}`;
}

function Confirmation({ c }: { c: RegressionCheck }) {
  const p = c.paired;
  if (!p) return null;
  return (
    <div className={muted} data-col="confirmation">
      paired-ab {p.source.replace('paired_results ', '')}: B/A {p.ratio.toFixed(3)} [{p.ci_lo.toFixed(3)}, {p.ci_hi.toFixed(3)}]
      {p.provenance_label ? ` · ${p.provenance_label}` : ' · clean build'}
    </div>
  );
}

function RunRow({ r }: { r: RegressionRun }) {
  const flagged = r.checks.filter((c) => c.status === 'watch' || c.status === 'regression');
  return (
    <tr
      className={`border-b border-gray-100 dark:border-gray-700/50 ${r.excluded ? 'opacity-50' : ''}`}
      data-run={r.run_id}
      data-excluded={r.excluded ? 'true' : 'false'}
    >
      <td className={`${td} whitespace-nowrap text-xs`}>{date(r.started_at)}</td>
      <td className={`${td} font-mono text-xs`}>
        {r.git_sha ?? <NotMeasured label="build not recorded" />}
        <div className={muted}>run {r.run_id}</div>
      </td>
      <td className={`${td} text-xs`} data-col="run-state">
        {r.excluded ? (
          <>
            <div className="font-medium">{r.disturbed ? 'disturbed' : 'allow_busy'}: excluded</div>
            {r.disturbed_detail && <div className={muted}>{r.disturbed_detail}</div>}
            <div className={muted}>kind {r.kind}: a disturbed run&apos;s paired tests are hidden</div>
          </>
        ) : (
          <>
            {r.measured}/{r.checks.length} shapes measured
            <div className={muted}>regression sweep</div>
          </>
        )}
      </td>
      <td className={`${td} text-xs`} data-col="calls">
        {flagged.length === 0 ? (
          <span className={muted}>{r.excluded ? 'not classified' : 'no watch, no regression'}</span>
        ) : (
          <ul className="space-y-1">
            {flagged.map((c) => (
              <li key={c.shape} data-shape={c.shape}>
                <StatusBadge c={c} /> <span className="font-mono">{c.shape}</span> {c.impl}
                <div className={muted}>{shift(c)}</div>
                <Confirmation c={c} />
              </li>
            ))}
          </ul>
        )}
        <details className="mt-1">
          <summary className={`${muted} cursor-pointer`}>all {r.checks.length} shapes</summary>
          <table className="text-xs mt-1">
            <tbody>
              {r.checks.map((c) => (
                <tr key={c.shape}>
                  <td className="pr-3 font-mono">{c.shape}</td>
                  <td className="pr-3">{shift(c)}</td>
                  <td className="pr-3">{c.status}</td>
                  <td>dispatch {c.dispatch}: {pct(c.dispatch_pct) ?? 'not measured'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      </td>
      <td className={`${td} text-xs break-all`} data-col="header">
        {r.header ? (
          <>
            <span className="font-mono">{r.header.path}</span>
            <div className={muted}>
              {r.header.own_build ? "the build's own header" : 'current header (the build’s own not available)'}
              {r.header.provisional ? ', provisional' : ''}
            </div>
          </>
        ) : (
          <NotMeasured label="no winners header" />
        )}
      </td>
    </tr>
  );
}

export function FuzzPanel({ nights }: { nights: FuzzNight[] }) {
  if (nights.length === 0) return <NotMeasured label="nightly fuzz: not measured (no results/nightly/fuzz-*.txt)" />;
  const total = (f: (n: FuzzNight) => number | null) => nights.reduce((s, n) => s + (f(n) ?? 0), 0);
  return (
    <div data-panel="fuzz">
      <p className="text-sm mb-2" data-col="fuzz-total">
        {nights.length} nights, {total((n) => n.cases).toLocaleString()} cases, {total((n) => n.failures)} failures
      </p>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200 dark:border-gray-700">
            <th className={th}>Night</th>
            <th className={th}>Cases</th>
            <th className={th}>Failures</th>
            <th className={th}>Reference: FP64 / cuBLASLt</th>
            <th className={th}>Overruled by FP64</th>
            <th className={th}>Cases reported</th>
          </tr>
        </thead>
        <tbody>
          {nights.map((n) => (
            <tr key={n.stamp} className="border-b border-gray-100 dark:border-gray-700/50" data-night={n.stamp}>
              <td className={`${td} font-mono text-xs`}>
                {n.stamp}
                <div className={muted}>seed {n.seed ?? 'not recorded'}</div>
              </td>
              <td className={td}>{n.cases?.toLocaleString() ?? <NotMeasured />}</td>
              <td className={td} data-col="failures">
                {n.failures ?? <NotMeasured />}
              </td>
              <td className={`${td} text-xs`}>
                {n.fp64_reference ?? '?'} / {n.cublaslt_reference ?? '?'}
              </td>
              <td className={`${td} text-xs`}>{n.overruled_by_fp64 ?? 0}</td>
              <td className={`${td} text-xs`}>
                {n.cases_reported.length === 0 ? (
                  <span className={muted}>none</span>
                ) : (
                  <ul className="space-y-1">
                    {n.cases_reported.map((c) => (
                      <li key={c.case} data-case={c.case}>
                        <span className="font-medium">
                          case {c.case} ({c.kind})
                        </span>
                        {c.detail && <div className={`${muted} font-mono`}>{c.detail}</div>}
                        {c.adjudication ? (
                          <div data-col="adjudication">
                            FP64 adjudication: cuBLASLt {c.adjudication.cublaslt_ulp.toFixed(2)} ulp vs AEGIS{' '}
                            {c.adjudication.ours_ulp.toFixed(2)} ulp: {c.adjudication.verdict}
                            <div className={muted}>
                              Core: <DocCite d={c.adjudication.source} />
                            </div>
                          </div>
                        ) : (
                          <NotMeasured label="no FP64 adjudication in Core's LOG" />
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className={`${muted} mt-2`}>
        From aegis_fuzz&apos;s nightly output (results/nightly/fuzz-*.txt; not in the perf DB, docs/core-requests.md #10). ulp:
        FP16 ulp at the FP64 reference, as Core&apos;s LOG reports it.
      </p>
    </div>
  );
}

export function RegressionView({ r }: { r: Regression }) {
  const [showExcluded, setShowExcluded] = useState(false);
  const hidden = r.runs.filter((x) => x.excluded).length;
  const runs = r.runs.filter((x) => showExcluded || !x.excluded);
  return (
    <div className="space-y-6">
      <div className={panel}>
        <div className="flex items-end justify-between gap-4 mb-3">
          <h3 className="text-lg font-semibold">Nightly regression check, build over build</h3>
          <label className="text-sm">
            <input type="checkbox" className="mr-2" checked={showExcluded} onChange={(e) => setShowExcluded(e.target.checked)} />
            show disturbed and allow_busy runs ({hidden})
          </label>
        </div>
        {runs.length === 0 ? (
          <NotMeasured label="no regression sweeps yet (Core's nightly)" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className={th}>Started</th>
                  <th className={th}>Build</th>
                  <th className={th}>State</th>
                  <th className={th}>Watch / regression</th>
                  <th className={th}>Checked against</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((x) => (
                  <RunRow key={x.run_id} r={x} />
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className={`${muted} mt-3`}>
          aegis-perf regress: each shape&apos;s % of cublaslt_best against the newest earlier clean run. A drop over{' '}
          {r.threshold_pct}% is a watch (one unpaired drop); a regression only when two consecutive nightlies or a paired-ab
          confirm it. The header is the winners header the run&apos;s build dispatched (provisional: Core does not record it,
          docs/core-requests.md #11).
        </p>
      </div>
      <div className={panel}>
        <h3 className="text-lg font-semibold mb-3">Nightly fuzz</h3>
        <FuzzPanel nights={r.fuzz} />
      </div>
    </div>
  );
}

export function RegressionSection() {
  const [archs, setArchs] = useState<number[] | null>(null);
  const [sm, setSm] = useState<number | null>(null);
  const [data, setData] = useState<Regression | null>(null);
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
    setData(null);
    perfApi.regression(sm).then(setData, (e) => setError(String(e)));
  }, [sm]);

  if (error) return <div className={`${panel} text-red-700 dark:text-red-300`}>Perf DB: {error}</div>;
  if (archs === null) return <div className={panel}>Loading…</div>;
  if (archs.length === 0) return <div className={panel}><NotMeasured label="no arch files in Core" /></div>;
  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold">Regressions</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">Core&apos;s nightly: regression sweeps by build, and the fuzz.</p>
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
      {data === null ? <div className={panel}>Loading regressions…</div> : <RegressionView r={data} />}
    </div>
  );
}

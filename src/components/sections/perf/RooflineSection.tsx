// Roofline view: the points `aegis-perf roofline` plots (winners and
// cublaslt_best), against the measured roofs of the arch file. Decode shapes
// (M <= 16) are held to the read roof, the rest to the copy roof (rule 4);
// every point and table row names its roof. Roof metrics are computed by
// custos-perf on each call, never stored (rule 3). The hover and the table
// give the config, % of cublaslt_best with its paired CI, and the dispatch
// target (Core's rule and 80% floor, aegis-perf tune::dispatch).
import { useEffect, useMemo, useState } from 'react';
import { DecodeSpotlightPanel, spotRowsFromRoofline } from './DecodeSpotlight';
import {
  CartesianGrid,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from 'recharts';
import { perfApi } from '../../../perf/api';
import type { ArchRoofs, Roofline, RooflinePoint } from '../../../perf/types';
import {
  DisagreeWarning,
  DispatchMismatch,
  NotMeasured,
  dispatchTarget,
  dispatchWhy,
  num,
  pct,
  storedDispatchText,
  tieText,
  vsBaseline,
} from '../../../perf/format';
import { useTheme } from '../../../contexts/ThemeContext';

const panel = 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5';
const th = 'text-left font-medium text-gray-500 dark:text-gray-400 py-2 pr-4 whitespace-nowrap';
const td = 'py-2 pr-4 align-top whitespace-nowrap';

// Categorical slots 1-2, validated (dataviz validate_palette.js) against the
// light (#ffffff) and dark (gray-800 #1f2937) panel surfaces.
const SERIES = {
  light: { winner: '#2a78d6', baseline: '#eb6834', roof: '#374151', roofRead: '#6b7280', grid: '#e5e7eb', ink: '#4b5563' },
  dark: { winner: '#3987e5', baseline: '#d95926', roof: '#d1d5db', roofRead: '#9ca3af', grid: '#374151', ink: '#9ca3af' },
};

export type Datum =
  | { kind: 'point'; x: number; y: number; p: RooflinePoint }
  | { kind: 'roof'; x: number; y: number };

function decades(lo: number, hi: number): number[] {
  const out: number[] = [];
  for (let e = Math.ceil(Math.log10(lo)); e <= Math.floor(Math.log10(hi)); e++) out.push(10 ** e);
  return out;
}

/** The roof as a polyline: bw x AI below the ridge, the mma peak above it. */
function roofLine(r: ArchRoofs, bw: number, x0: number, x1: number): Datum[] {
  const ridge = (r.peak_tflops * 1e3) / bw;
  const xs = [x0, Math.min(Math.max(ridge, x0), x1), x1];
  return xs.map((x) => ({ kind: 'roof', x, y: Math.min((bw * x) / 1e3, r.peak_tflops) }));
}

export function Hover({ active, payload }: { active?: boolean; payload?: { payload: Datum }[] }) {
  const d = payload?.[0]?.payload;
  if (!active || !d || d.kind !== 'point') return null;
  const p = d.p;
  const cfg = p.hover.config;
  return (
    <div className="rounded-md border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-900 p-3 text-xs shadow-lg max-w-sm">
      <div className="font-semibold text-sm mb-1">
        {p.shape_bucket} · {p.impl}
      </div>
      <div className="text-gray-600 dark:text-gray-300 space-y-0.5">
        <div>
          {p.roof.tflops.toFixed(2)} TFLOPS at AI {p.roof.ai.toFixed(1)} FLOP/B · {p.median_us.toFixed(2)} µs
        </div>
        <div>
          {p.roof.pct_roof.toFixed(1)}% of roof ({p.roof.roof} {p.roof.roof_gbps.toFixed(1)} GB/s, {p.roof.bound}-bound)
        </div>
        {p.series === 'winner' ? (
          <>
            <div>{vsBaseline(p.hover.vs_cublaslt_best)}</div>
            <DisagreeWarning v={p.hover.vs_cublaslt_best} />
            {p.hover.vs_cublaslt_best?.tested_impl && p.hover.vs_cublaslt_best.tested_impl !== p.impl && (
              <div>paired test ran {p.hover.vs_cublaslt_best.tested_impl} (tied with the pick)</div>
            )}
            <div>Tie: {tieText(p.hover.tie)}</div>
            {p.hover.tie?.pick_reason && <div>Pick: {p.hover.tie.pick_reason}</div>}
            {cfg && (
              <div className="font-mono text-[11px] mt-1 break-all">
                {Object.entries(cfg)
                  .map(([k, v]) => `${k}=${String(v)}`)
                  .join(' ')}
              </div>
            )}
          </>
        ) : (
          <div>Baseline for this shape (cuBLASLt heuristic, fastest passing of top 8).</div>
        )}
        <div className="mt-1">
          {dispatchTarget(p.hover.dispatch)}
          {dispatchWhy(p.hover.dispatch) && <span className="text-gray-500 dark:text-gray-400"> · {dispatchWhy(p.hover.dispatch)}</span>}
        </div>
        <DispatchMismatch d={p.hover.dispatch} />
      </div>
    </div>
  );
}

/** The roofline chart; `focus` (a shape) plots only that shape's points, on the same axes. */
export function Chart({ r, focus }: { r: Roofline; focus?: string }) {
  const { resolvedTheme } = useTheme();
  const c = SERIES[resolvedTheme];
  const { winners, baselines, xDomain, yDomain } = useMemo(() => {
    const pts = r.points.map<Datum>((p) => ({ kind: 'point', x: p.roof.ai, y: p.roof.tflops, p }));
    const ais = r.points.map((p) => p.roof.ai);
    const tf = r.points.map((p) => p.roof.tflops);
    const x0 = 10 ** Math.floor(Math.log10(Math.min(...ais) / 2));
    const x1 = 10 ** Math.ceil(Math.log10(Math.max(r.roofs.ridge_copy, r.roofs.ridge_read, ...ais) * 2));
    const y0 = 10 ** Math.floor(Math.log10(Math.min(...tf) / 2));
    const y1 = r.roofs.peak_tflops * 2;
    const shown = pts.filter((d) => d.kind === 'point' && (!focus || d.p.shape_bucket === focus));
    return {
      winners: shown.filter((d) => d.kind === 'point' && d.p.series === 'winner'),
      baselines: shown.filter((d) => d.kind === 'point' && d.p.series === 'cublaslt_best'),
      xDomain: [x0, x1] as [number, number],
      yDomain: [y0, y1] as [number, number],
    };
  }, [r, focus]);
  const copy = roofLine(r.roofs, r.roofs.copy_bw_gbps, ...xDomain);
  const read = roofLine(r.roofs, r.roofs.read_bw_gbps, ...xDomain);
  const tick = { fill: c.ink, fontSize: 12 };
  const noDot = () => <g />;

  return (
    <div>
      <ul className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-gray-600 dark:text-gray-300 mb-2" aria-label="Legend">
        <li className="flex items-center gap-2">
          <svg width="12" height="12" aria-hidden><circle cx="6" cy="6" r="5" fill={c.winner} /></svg>
          AEGIS winner
        </li>
        <li className="flex items-center gap-2">
          <svg width="12" height="12" aria-hidden><path d="M6 1V11M1 6H11" stroke={c.baseline} strokeWidth="3" /></svg>
          cublaslt_best
        </li>
        <li className="flex items-center gap-2">
          <svg width="20" height="4" aria-hidden><line x1="0" y1="2" x2="20" y2="2" stroke={c.roof} strokeWidth="2" /></svg>
          copy roof {r.roofs.copy_bw_gbps.toFixed(1)} GB/s (M &gt; {r.roofs.decode_max_m})
        </li>
        <li className="flex items-center gap-2">
          <svg width="20" height="4" aria-hidden><line x1="0" y1="2" x2="20" y2="2" stroke={c.roofRead} strokeWidth="2" strokeDasharray="4 3" /></svg>
          read roof {r.roofs.read_bw_gbps.toFixed(1)} GB/s (M ≤ {r.roofs.decode_max_m})
        </li>
        <li>compute roof {r.roofs.peak_tflops.toFixed(1)} TFLOPS (mma.sync)</li>
      </ul>
      <div className="h-[480px]" role="img" aria-label={`Roofline for sm_${r.sm}; the table below lists every point`}>
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 8, right: 16, bottom: 32, left: 16 }}>
            <CartesianGrid stroke={c.grid} strokeDasharray="0" />
            <XAxis
              type="number"
              dataKey="x"
              scale="log"
              domain={xDomain}
              ticks={decades(...xDomain)}
              allowDataOverflow
              tick={tick}
              stroke={c.grid}
              label={{ value: 'arithmetic intensity (FLOP/byte, compulsory traffic)', position: 'bottom', offset: 12, fill: c.ink, fontSize: 12 }}
            />
            <YAxis
              type="number"
              dataKey="y"
              scale="log"
              domain={yDomain}
              ticks={decades(...yDomain)}
              allowDataOverflow
              tick={tick}
              stroke={c.grid}
              label={{ value: 'TFLOPS', angle: -90, position: 'insideLeft', fill: c.ink, fontSize: 12 }}
            />
            <ZAxis range={[90, 90]} />
            <Tooltip content={<Hover />} cursor={false} isAnimationActive={false} />
            <Scatter data={copy} line={{ stroke: c.roof, strokeWidth: 2 }} shape={noDot} isAnimationActive={false} legendType="none" />
            <Scatter
              data={read}
              line={{ stroke: c.roofRead, strokeWidth: 2, strokeDasharray: '6 4' }}
              shape={noDot}
              isAnimationActive={false}
              legendType="none"
            />
            <Scatter name="cublaslt_best" data={baselines} fill={c.baseline} shape="cross" isAnimationActive={false} />
            <Scatter name="AEGIS winner" data={winners} fill={c.winner} shape="circle" isAnimationActive={false} />
          </ScatterChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function PointTable({ r }: { r: Roofline }) {
  const shapes = [...new Map(r.points.map((p) => [p.shape_bucket, [p.m, p.n, p.k]])).entries()]
    .sort(([, a], [, b]) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2])
    .map(([s]) => s);
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200 dark:border-gray-700">
            <th className={th}>Shape (M×N×K)</th>
            <th className={th}>Roof</th>
            <th className={th}>AI</th>
            <th className={th}>Winner</th>
            <th className={th}>TFLOPS</th>
            <th className={th}>% roof</th>
            <th className={th}>cublaslt_best TFLOPS</th>
            <th className={th}>% roof</th>
            <th className={th}>vs cublaslt_best (paired 95% CI)</th>
            <th className={th}>Tie</th>
            <th className={th}>Dispatch</th>
          </tr>
        </thead>
        <tbody>
          {shapes.map((s) => {
            const w = r.points.find((p) => p.shape_bucket === s && p.series === 'winner');
            const b = r.points.find((p) => p.shape_bucket === s && p.series === 'cublaslt_best');
            const any = (w ?? b)!;
            return (
              <tr key={s} data-shape={s} className="border-b border-gray-100 dark:border-gray-700/50">
                <td className={`${td} font-mono`}>{s}</td>
                <td className={td}>
                  {any.roof.roof} ({any.roof.roof_gbps.toFixed(1)} GB/s)
                </td>
                <td className={td}>{any.roof.ai.toFixed(1)}</td>
                <td className={`${td} font-mono text-xs`}>{w?.impl ?? <NotMeasured />}</td>
                <td className={td}>{num(w?.roof.tflops, 2) ?? <NotMeasured />}</td>
                <td className={td}>{pct(w?.roof.pct_roof) ?? <NotMeasured />}</td>
                <td className={td}>{num(b?.roof.tflops, 2) ?? <NotMeasured />}</td>
                <td className={td}>{pct(b?.roof.pct_roof) ?? <NotMeasured />}</td>
                <td className="py-2 pr-4 align-top text-xs min-w-[14rem]" data-col="vs-baseline">
                  {vsBaseline(w?.hover.vs_cublaslt_best ?? null)}
                  <DisagreeWarning v={w?.hover.vs_cublaslt_best ?? null} />
                </td>
                <td className="py-2 pr-4 align-top text-xs min-w-[14rem] break-all">{tieText(w?.hover.tie ?? null)}</td>
                <td className="py-2 pr-4 align-top text-xs min-w-[12rem]">
                  {dispatchTarget(any.hover.dispatch)}
                  {dispatchWhy(any.hover.dispatch) && <div className="text-gray-500 dark:text-gray-400">{dispatchWhy(any.hover.dispatch)}</div>}
                  <div className="text-gray-500 dark:text-gray-400" data-col="stored-dispatch">{storedDispatchText(any.hover.dispatch)}</div>
                  <DispatchMismatch d={any.hover.dispatch} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function RooflineSection() {
  const [archs, setArchs] = useState<number[] | null>(null);
  const [sm, setSm] = useState<number | null>(null);
  const [data, setData] = useState<Roofline | null | undefined>(undefined);
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
    setData(undefined);
    perfApi
      .roofline(sm)
      .then(setData)
      .catch((e) => setError(String(e)));
  }, [sm]);

  if (error) return <div className={`${panel} text-red-700 dark:text-red-300`}>Perf DB: {error}</div>;
  if (archs === null) return <div className={panel}>Loading…</div>;
  if (archs.length === 0) return <div className={panel}><NotMeasured label="no arch files in Core: roofs not measured" /></div>;

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold">Roofline</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Winners and cublaslt_best against measured roofs · protocol v2, cold cache, idle GPU.
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
      {data === undefined ? (
        <div className={panel}>Loading roofline…</div>
      ) : data === null ? (
        <div className={panel}>
          sm_{sm}: <NotMeasured label="no arch file; roofs not measured" />
        </div>
      ) : data.points.length === 0 ? (
        <div className={panel}>sm_{sm}: no winners yet (run aegis-perf tune in Core).</div>
      ) : (
        <>
          <div className={panel}>
            <Chart r={data} />
            <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
              Roofs from <span className="font-mono">{data.roofs.arch_file}</span>; ridge {data.roofs.ridge_read.toFixed(0)}{' '}
              (read) / {data.roofs.ridge_copy.toFixed(0)} (copy) FLOP/B. Same points as{' '}
              <span className="font-mono">aegis-perf roofline --arch {data.sm}</span>.
            </p>
          </div>
          <div className={panel}>
            <h3 className="text-lg font-semibold mb-3">Points</h3>
            <PointTable r={data} />
          </div>
          {spotRowsFromRoofline(data).length > 0 && (
            <div className={panel}>
              <DecodeSpotlightPanel rows={spotRowsFromRoofline(data)} />
            </div>
          )}
        </>
      )}
    </div>
  );
}

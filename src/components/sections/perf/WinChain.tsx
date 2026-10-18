// The win chain: one decode win on one page, in order: roofline position;
// kernel config, registers, spills and instruction mix; the SASS listing with
// its provenance; the paired CI against cublaslt_best; the dispatch decision;
// Core's docs that discuss the kernel at the shape. Built from the existing
// views' components and data (Roofline, Kernel, Winners); every value comes
// from the fixture or Core's DB, an artifact or a doc, and a missing source
// renders "not measured".
import { useEffect, useState } from 'react';
import { perfApi } from '../../../perf/api';
import type { WinChain } from '../../../perf/types';
import {
  DispatchMismatch,
  DocCite,
  NotMeasured,
  abText,
  dispatchTarget,
  dispatchWhy,
  pct,
  storedDispatchText,
  vsBaseline,
} from '../../../perf/format';
import { Chart } from './RooflineSection';
import { InstructionMix, KernelFacts, SassListing } from './KernelSection';
import { familyText } from './DecodeSpotlight';

const panel = 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5';
const muted = 'text-xs text-gray-500 dark:text-gray-400';

function Step({ n, title, id, children }: { n: number; title: string; id: string; children: React.ReactNode }) {
  return (
    <section className={panel} data-section={id} aria-label={title}>
      <h3 className="text-lg font-semibold mb-3">
        {n}. {title}
      </h3>
      {children}
    </section>
  );
}

export function WinChainPage({ c }: { c: WinChain }) {
  const w = c.winner;
  const spot = w.decode_spotlight;
  const k = c.kernel;
  const art = k?.artifacts.find((a) => a.sm === c.sm) ?? k?.artifacts[0] ?? null;
  const ab = w.paired_ab.kernel;
  const dab = w.paired_ab.dispatch;
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">
          Win chain: <span className="font-mono">{c.shape_bucket}</span>
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          <span className="font-mono">{w.impl}</span> on sm_{c.sm}
          {spot && <> · {familyText(spot)}</>}
        </p>
        {c.pick && (
          <p className={`text-sm mt-1 ${c.pick.clean ? '' : 'text-amber-700 dark:text-amber-400'}`} data-col="chain-pick">
            Why this shape: {c.pick.basis} ({c.pick.source}, CI lower bound {c.pick.ci_lo_pct.toFixed(1)}% of cublaslt_best)
          </p>
        )}
      </div>

      <Step n={1} title="Roofline position" id="roof">
        {c.roofline && w.roof ? (
          <>
            <Chart r={c.roofline} focus={c.shape_bucket} />
            <p className="text-sm mt-2" data-col="chain-roof">
              {w.roof.tflops.toFixed(2)} TFLOPS at AI {w.roof.ai.toFixed(1)} FLOP/B · {w.roof.pct_roof.toFixed(1)}% of the{' '}
              {w.roof.roof} roof ({w.roof.roof_gbps.toFixed(1)} GB/s, {w.roof.bound}-bound) · {w.median_us.toFixed(2)} µs
            </p>
            {spot?.diagnosis && (
              <p className="text-sm text-amber-700 dark:text-amber-400" data-col="chain-diagnosis">
                {spot.diagnosis.label} <span className={muted}>(Core: </span>
                <DocCite d={spot.diagnosis.source} />
                <span className={muted}>)</span>
              </p>
            )}
            <p className={muted}>Roofs from {c.roofline.roofs.arch_file}; the Roofline view&apos;s points for this shape.</p>
          </>
        ) : (
          <NotMeasured label="roofline position not measured (no arch file)" />
        )}
      </Step>

      <Step n={2} title="Kernel: config, registers, spills, instruction mix" id="kernel">
        {k ? (
          <>
            <KernelFacts k={k} />
            <h4 className="text-sm font-semibold mt-5 mb-2">Instruction mix</h4>
            {art ? <InstructionMix k={k} a={art} /> : <NotMeasured label="instruction mix not measured" />}
          </>
        ) : (
          <NotMeasured label="kernel not in the perf DB" />
        )}
      </Step>

      <Step n={3} title="SASS listing" id="sass">
        {art ? <SassListing a={art} /> : <NotMeasured label="no SASS: not measured" />}
      </Step>

      <Step n={4} title="Paired CI vs cublaslt_best" id="paired">
        <p className="text-sm" data-col="chain-ci">
          {vsBaseline(w.vs_cublaslt_best)}
        </p>
        <p className={muted}>tune paired test, run {w.run_id}{w.git_sha ? ` (build ${w.git_sha})` : ''}</p>
        <div className="mt-2" data-col="chain-ab">
          {ab ? (
            <>
              <p className="text-sm">
                paired-ab: {abText(ab)} ({ab.source}, {ab.pairs} pairs)
              </p>
              <p className={`text-sm ${ab.confirmed ? 'text-green-700 dark:text-green-400' : 'text-amber-700 dark:text-amber-400'}`}>
                {ab.label}
              </p>
              <p className={muted}>
                builds {ab.sha_a ?? 'not recorded'} vs {ab.sha_b ?? 'not recorded'}
              </p>
            </>
          ) : (
            <NotMeasured label="no paired-ab result" />
          )}
        </div>
      </Step>

      <Step n={5} title="Dispatch decision" id="dispatch">
        <p className="text-sm" data-col="chain-dispatch">
          {dispatchTarget(w.dispatch)}
          {dispatchWhy(w.dispatch) && <span className={muted}> · {dispatchWhy(w.dispatch)}</span>}
        </p>
        <p className={muted}>{storedDispatchText(w.dispatch)}</p>
        <DispatchMismatch d={w.dispatch} />
        <p className="text-sm mt-1" data-col="chain-dispatch-ab">
          {dab ? (
            <>
              aegis::matmul: {abText(dab)} ({dab.source}) · {dab.label}
            </>
          ) : (
            <NotMeasured label="dispatch not measured" />
          )}
        </p>
        {w.dispatch.target === 'aegis' && <p className={muted}>Kernel % = dispatch %: {pct(w.vs_cublaslt_best.pct_of_cublaslt_best) ?? 'not measured'}</p>}
      </Step>

      <Step n={6} title="Core's docs on this kernel" id="docs">
        {c.docs.length > 0 ? (
          <ul className="space-y-1 text-sm" data-col="chain-docs">
            {c.docs.map((d) => (
              <li key={`${d.doc}:${d.line}`}>
                <DocCite d={d} /> {d.why && <span className={muted}>({d.why})</span>}
              </li>
            ))}
          </ul>
        ) : (
          <NotMeasured label="no Core doc names this kernel at this shape" />
        )}
      </Step>
    </div>
  );
}

/** The chain for `shape`, loaded from the win_chain command. */
export function WinChainView({ sm, shape, onBack }: { sm: number; shape: string; onBack: () => void }) {
  const [c, setC] = useState<WinChain | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setC(undefined);
    perfApi.winChain(sm, shape).then(setC, (e) => setError(String(e)));
  }, [sm, shape]);
  return (
    <div className="space-y-4">
      <button type="button" className="text-sm text-blue-700 dark:text-blue-300 underline" onClick={onBack}>
        ← Winners
      </button>
      {error ? (
        <div className={`${panel} text-red-700 dark:text-red-300`}>Perf DB: {error}</div>
      ) : c === undefined ? (
        <div className={panel}>Loading win chain…</div>
      ) : c === null ? (
        <div className={panel}>
          <NotMeasured label={`no winner at ${shape}`} />
        </div>
      ) : (
        <WinChainPage c={c} />
      )}
    </div>
  );
}

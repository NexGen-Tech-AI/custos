// Device view: the devices in the perf DB and the measured hardware model of
// their arch (include/aegis/arch/sm_<arch>.json), each value linked to the run
// that measured it. Only valid microbench rows feed the model; runs a newer
// run replaced are listed as history, never as a warning (contract rule 7).
import { useEffect, useState } from 'react';
import { perfApi } from '../../../perf/api';
import type { ArchModel, Device, HistoryRun, Latency, SourceRun } from '../../../perf/types';
import { NotMeasured, V, bytes, cudaVersion, date, num } from '../../../perf/format';

const panel = 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5';
const th = 'text-left font-medium text-gray-500 dark:text-gray-400 py-2 pr-4';
const td = 'py-2 pr-4 align-top';
const muted = 'text-xs text-gray-500 dark:text-gray-400';

type Src = { run: SourceRun; extra?: string };

export function clockLock(locked: boolean | null): string {
  return locked === null ? 'clock lock not recorded' : locked ? 'clocks locked' : 'clocks not locked';
}

function toolchain(r: SourceRun): string | null {
  if (r.cuda_ver === null && r.driver_ver === null) return null;
  return `CUDA ${cudaVersion(r.cuda_ver) ?? 'not recorded'}, driver API ${cudaVersion(r.driver_ver) ?? 'not recorded'}`;
}

function Sources({ runs }: { runs: Src[] }) {
  return (
    <ul className="space-y-1">
      {runs.map(({ run: r, extra }) => (
        <li key={`${r.run_id}-${r.detail ?? ''}`} className="text-xs text-gray-600 dark:text-gray-400">
          <span className="font-mono" title={`run ${r.run_id} (${r.probe})`}>
            run {r.run_id}
          </span>
          {r.detail && <span> · {r.detail}</span>}
          {r.git_sha && <span> · <span className="font-mono">{r.git_sha}</span></span>}
          {r.started_at && <span> · {date(r.started_at)}</span>}
          {extra && <span> · {extra}</span>}
          {r.disturbed && <span> · disturbed run</span>}
          {r.status === 'replaced' && (
            // History: a later run re-measured this probe. Not an error.
            <span className="block text-gray-500 dark:text-gray-500">
              history: replaced by {r.replaced_by.join(', ')} ({r.replaced_rows} rows)
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

/** Earlier runs of the value's probe that a newer run replaced (history). */
function History({ runs }: { runs: HistoryRun[] }) {
  if (runs.length === 0) return null;
  return (
    <details className="mt-1">
      <summary className={`${muted} cursor-pointer`}>
        history: {runs.length} earlier run{runs.length === 1 ? '' : 's'} replaced
      </summary>
      <ul className="mt-1 space-y-0.5">
        {runs.map((h) => (
          <li key={h.run_id} className="text-xs text-gray-500 dark:text-gray-500">
            run <span className="font-mono">{h.run_id}</span>
            {h.git_sha && <> · <span className="font-mono">{h.git_sha}</span></>}
            {h.started_at && <> · {date(h.started_at)}</>} · replaced by {h.replaced_by.join(', ')} ({h.replaced_rows} rows)
          </li>
        ))}
      </ul>
    </details>
  );
}

/** "335.4 cycles = 139.4 ns at 2407 MHz (clocks not locked)": what is stored
 *  (cycles), the derived ns, and the clock and lock state it holds at. */
export function latencyText(l: Latency | null): string | null {
  if (!l) return null;
  return `${l.cycles.toFixed(1)} cycles = ${l.ns_at_ref.toFixed(1)} ns at ${l.ref_clock_mhz.toFixed(0)} MHz (${clockLock(l.clocks_locked)})`;
}

function latencyHow(l: Latency | null): string | null {
  if (!l) return null;
  const spread = l.clock_spread_pct === null ? '' : `; run clocks spread ${l.clock_spread_pct.toFixed(1)}%`;
  const ref = l.ref_clock_rule ? ` Reference clock: ${l.ref_clock_rule}.` : '';
  return `${l.working_sets ?? ''}, ${l.points ?? '?'} points${spread}. ${l.combine ?? ''}.${ref} ${l.method ?? ''}`;
}

function latencySources(l: Latency | null): Src[] {
  return (l?.runs ?? []).map((r) => ({
    run: r.source,
    extra:
      `SM ${r.sm_clock_mhz === null ? 'clock not measured' : `${r.sm_clock_mhz.toFixed(0)} MHz`}, ${clockLock(r.clocks_locked)}` +
      (r.cycles !== null && r.ns !== null ? ` · ${r.cycles.toFixed(1)} cycles = ${r.ns.toFixed(1)} ns` : ''),
  }));
}

function Fact({ label, value }: { label: string; value: string | null }) {
  return (
    <div>
      <dt className="text-xs text-gray-500 dark:text-gray-400">{label}</dt>
      <dd className="text-sm font-medium">
        <V v={value} />
      </dd>
    </div>
  );
}

function DeviceFacts({ d }: { d: Device }) {
  const m = d.manifest;
  return (
    <div className={panel}>
      <div className="flex items-baseline justify-between mb-4">
        <h3 className="text-lg font-semibold">
          {d.gpu_name ?? d.device_id} <span className="text-gray-500 dark:text-gray-400 font-normal">sm_{d.sm_arch}</span>
        </h3>
        <span className="text-xs text-gray-500 dark:text-gray-400">
          {d.device_id} · {d.runs} runs · last {date(d.last_run)}
        </span>
      </div>
      <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Fact label="SMs" value={m?.sm_count?.toString() ?? null} />
        <Fact label="Memory" value={bytes(m?.global_mem_bytes ?? null)} />
        <Fact label="Unified (integrated)" value={m?.integrated == null ? null : m.integrated ? 'yes' : 'no'} />
        <Fact label="L2" value={bytes(m?.l2_bytes ?? null)} />
        <Fact label="Shared memory / SM" value={bytes(m?.smem_per_sm_bytes ?? null)} />
        <Fact label="Shared memory / block (opt-in)" value={bytes(m?.smem_per_block_optin_bytes ?? null)} />
        <Fact label="Registers / SM" value={m?.regs_per_sm?.toLocaleString() ?? null} />
        <Fact label="Threads / SM" value={m?.max_threads_per_sm?.toLocaleString() ?? null} />
        <Fact label="CUDA runtime" value={cudaVersion(m?.cuda_runtime ?? d.cuda_ver)} />
        <Fact label="CUDA driver" value={cudaVersion(m?.cuda_driver ?? d.driver_ver)} />
        <Fact
          label="aegis_manifest D2D copy (not a roof)"
          value={num(m?.measured_d2d_bw_gbps ?? null, 1, 'GB/s')}
        />
      </dl>
      <p className="mt-3 text-xs text-gray-500 dark:text-gray-400">
        {m ? <>Manifest: <span className="font-mono">{m.path}</span></> : <NotMeasured label="no manifest for this device" />}
      </p>
    </div>
  );
}

type Row = { q: string; v: string | null; how: string | null; src: Src[]; cite?: string; history?: HistoryRun[] };

function HardwareModel({ a }: { a: ArchModel }) {
  const r = a.roofs;
  const sources = [a.copy_bw?.source, a.read_bw?.source, a.mma_peak?.source, ...(a.l2_latency?.runs ?? []).map((x) => x.source)]
    .filter((s): s is SourceRun => !!s);
  const toolchains = [...new Set(sources.map(toolchain).filter((t): t is string => t !== null))];
  const powerModes = [...new Set(sources.map((s) => s.power_mode).filter((p): p is string => p !== null))];
  const rows: Row[] = [
    { q: 'SMs', v: a.sm_count?.toString() ?? null, how: null, src: [], cite: 'arch file' },
    { q: 'Memory', v: bytes(a.global_mem_bytes), how: null, src: [], cite: a.manifest ? `manifest ${a.manifest}` : undefined },
    { q: 'L2', v: bytes(a.l2_bytes), how: null, src: [], cite: 'arch file' },
    {
      q: 'Copy bandwidth (roof, M > 16)',
      v: num(a.copy_bw?.gbps, 1, 'GB/s'),
      how: a.copy_bw?.method ?? null,
      src: a.copy_bw ? [{ run: a.copy_bw.source }] : [],
      history: a.copy_bw?.history,
    },
    {
      q: 'Read bandwidth (roof, M ≤ 16)',
      v: num(a.read_bw?.gbps, 1, 'GB/s'),
      how: a.read_bw?.method ?? null,
      src: a.read_bw ? [{ run: a.read_bw.source }] : [],
      history: a.read_bw?.history,
    },
    {
      q: 'mma.sync peak (compute roof)',
      v: a.mma_peak
        ? `${a.mma_peak.tflops.toFixed(1)} TFLOPS` +
          (a.mma_peak.hmma_per_clk_per_sm !== null ? ` · ${a.mma_peak.hmma_per_clk_per_sm.toFixed(3)} HMMA/clk/SM` : '')
        : null,
      how: a.mma_peak?.instruction ?? null,
      src: a.mma_peak ? [{ run: a.mma_peak.source }] : [],
      history: a.mma_peak?.history,
    },
    { q: 'L2 latency', v: latencyText(a.l2_latency), how: latencyHow(a.l2_latency), src: latencySources(a.l2_latency), history: a.l2_latency?.history },
    { q: 'DRAM latency', v: latencyText(a.dram_latency), how: latencyHow(a.dram_latency), src: latencySources(a.dram_latency), history: a.dram_latency?.history },
    {
      q: 'Power controls',
      v: a.power ? JSON.stringify(a.power) : powerModes.length ? powerModes.join(', ') : null,
      how: a.power ? null : 'Not in the arch file; no source run recorded a power mode.',
      src: [],
    },
    {
      q: 'Toolchain',
      v: toolchains.length ? toolchains.join('; ') : null,
      how: a.generated_by,
      src: [],
      cite: 'the source runs above (runs table)',
    },
  ];
  return (
    <div className={panel}>
      <h3 className="text-lg font-semibold mb-1">Measured hardware model, sm_{a.sm}</h3>
      <p className={`${muted} mb-4`}>
        <span className="font-mono">{a.arch_file}</span>
        {a.generated_by && <> · {a.generated_by}</>}
      </p>
      <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-5">
        <Fact label="Ridge, read roof" value={num(r.ridge_read, 0, 'FLOP/B')} />
        <Fact label="Ridge, copy roof" value={num(r.ridge_copy, 0, 'FLOP/B')} />
        <Fact label="Decode shapes" value={`M ≤ ${r.decode_max_m} use the read roof`} />
        <Fact label="Device (arch file)" value={a.device} />
      </dl>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700">
              <th className={th}>Quantity</th>
              <th className={th}>Measured</th>
              <th className={th}>Method</th>
              <th className={th}>Measured by</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.q} className="border-b border-gray-100 dark:border-gray-700/50">
                <td className={`${td} font-medium`}>{row.q}</td>
                <td className={`${td} whitespace-nowrap`}>
                  <V v={row.v} />
                </td>
                <td className={`${td} text-xs text-gray-600 dark:text-gray-400 max-w-md`}>{row.how ?? ''}</td>
                <td className={td}>
                  {row.src.length ? <Sources runs={row.src} /> : row.cite ? <span className={muted}>{row.cite}</span> : null}
                  {row.history && <History runs={row.history} />}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h4 className="text-sm font-semibold mt-5 mb-2">Microbench probes</h4>
      <p className={`${muted} mb-2`}>
        Valid rows feed the model; replaced rows are history. Invalidated rows (known bad) are not shown.
      </p>
      <div className="flex flex-wrap gap-2">
        {a.probes.map((p) => (
          <span key={p.probe} className="text-xs rounded border border-gray-200 dark:border-gray-700 px-2 py-1">
            <span className="font-mono">{p.probe}</span> · {p.rows} valid rows · {p.runs.length} run{p.runs.length === 1 ? '' : 's'}
            {p.replaced_rows > 0 && <> · {p.replaced_rows} replaced (history)</>} · {p.units.join(', ')}
          </span>
        ))}
      </div>
    </div>
  );
}

export function DeviceSection() {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [models, setModels] = useState<Record<number, ArchModel | null>>({});
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const ds = await perfApi.devices();
        setDevices(ds);
        const archs = [...new Set(ds.map((d) => d.sm_arch))];
        const entries = await Promise.all(archs.map(async (sm) => [sm, await perfApi.archModel(sm)] as const));
        setModels(Object.fromEntries(entries));
      } catch (e) {
        setError(String(e));
      }
    })();
  }, []);

  if (error) return <div className={`${panel} text-red-700 dark:text-red-300`}>Perf DB: {error}</div>;
  if (!devices) return <div className={panel}>Loading devices…</div>;
  if (devices.length === 0) return <div className={panel}>No runs in the perf DB.</div>;

  const archs = [...new Set(devices.map((d) => d.sm_arch))];
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Devices</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">Devices with runs in the AEGIS perf DB and their measured roofs.</p>
      </div>
      {devices.map((d) => (
        <DeviceFacts key={`${d.device_id}-${d.sm_arch}`} d={d} />
      ))}
      {archs.map((sm) =>
        models[sm] ? (
          <HardwareModel key={sm} a={models[sm]!} />
        ) : sm in models ? (
          <div key={sm} className={panel}>
            sm_{sm}: <NotMeasured label="no arch file in Core; hardware model not measured" />
          </div>
        ) : null,
      )}
    </div>
  );
}

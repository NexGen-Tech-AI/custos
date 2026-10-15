// Device view: the devices in the perf DB and the measured hardware model of
// their arch (include/aegis/arch/sm_<arch>.json), each value linked to the runs
// that measured it. Superseded probe rows are excluded (rule 7).
import { useEffect, useState } from 'react';
import { perfApi } from '../../../perf/api';
import type { ArchModel, Device, Latency, SourceRun } from '../../../perf/types';
import { NotMeasured, V, bytes, cudaVersion, date, num } from '../../../perf/format';

const panel = 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5';
const th = 'text-left font-medium text-gray-500 dark:text-gray-400 py-2 pr-4';
const td = 'py-2 pr-4 align-top';

type Src = { run: SourceRun; extra?: string };

export function clockLock(locked: boolean | null): string {
  return locked === null ? 'clock lock not recorded' : locked ? 'clocks locked' : 'clocks not locked';
}

function Sources({ runs }: { runs: Src[] }) {
  return (
    <ul className="space-y-1">
      {runs.map(({ run: r, extra }) => (
        <li key={`${r.run_id}-${r.detail ?? ''}`} className="text-xs text-gray-600 dark:text-gray-400">
          <span className="font-mono">{r.run_id}</span>
          {r.detail && <span> · {r.detail}</span>}
          {r.git_sha && <span> · <span className="font-mono">{r.git_sha}</span></span>}
          {r.started_at && <span> · {date(r.started_at)}</span>}
          {extra && <span> · {extra}</span>}
          {r.status === 'replaced' && (
            // History: a later run re-measured this probe. Not an error.
            <span className="block text-gray-500 dark:text-gray-500">
              history: replaced by {r.superseded_by.join(', ')} ({r.superseded_rows} rows)
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

/** "335.4 cycles · 139.4 ns at 2407 MHz": cycles first, ns at the stated clock. */
export function latencyText(l: Latency | null): string | null {
  if (!l) return null;
  return `${l.cycles.toFixed(1)} cycles · ${l.ns_at_ref.toFixed(1)} ns at ${l.ref_clock_mhz.toFixed(0)} MHz`;
}

function latencyHow(l: Latency | null): string | null {
  if (!l) return null;
  const spread = l.clock_spread_pct === null ? '' : `; run clocks spread ${l.clock_spread_pct.toFixed(1)}%`;
  return `${l.working_sets ?? ''}, ${l.points ?? '?'} points${spread}. ${l.combine ?? ''}. ${l.method ?? ''}`;
}

function latencySources(l: Latency | null): Src[] {
  return (l?.runs ?? []).map((r) => ({
    run: r.source,
    extra:
      `SM ${r.sm_clock_mhz === null ? 'clock not measured' : `${r.sm_clock_mhz.toFixed(0)} MHz`}, ${clockLock(r.source.clocks_locked)}` +
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

function HardwareModel({ a }: { a: ArchModel }) {
  const r = a.roofs;
  const rows: { q: string; v: string | null; how: string | null; src: Src[] }[] = [
    { q: 'Copy bandwidth (roof, M > 16)', v: num(a.copy_bw?.gbps, 1, 'GB/s'), how: a.copy_bw?.method ?? null, src: a.copy_bw ? [{ run: a.copy_bw.source }] : [] },
    { q: 'Read bandwidth (roof, M ≤ 16)', v: num(a.read_bw?.gbps, 1, 'GB/s'), how: a.read_bw?.method ?? null, src: a.read_bw ? [{ run: a.read_bw.source }] : [] },
    {
      q: 'mma.sync peak (compute roof)',
      v: a.mma_peak
        ? `${a.mma_peak.tflops.toFixed(1)} TFLOPS` +
          (a.mma_peak.hmma_per_clk_per_sm !== null ? ` · ${a.mma_peak.hmma_per_clk_per_sm.toFixed(3)} HMMA/clk/SM` : '')
        : null,
      how: a.mma_peak?.instruction ?? null,
      src: a.mma_peak ? [{ run: a.mma_peak.source }] : [],
    },
    { q: 'L2 latency', v: latencyText(a.l2_latency), how: latencyHow(a.l2_latency), src: latencySources(a.l2_latency) },
    { q: 'DRAM latency', v: latencyText(a.dram_latency), how: latencyHow(a.dram_latency), src: latencySources(a.dram_latency) },
    { q: 'Power controls', v: a.power ? JSON.stringify(a.power) : null, how: null, src: [] },
  ];
  return (
    <div className={panel}>
      <h3 className="text-lg font-semibold mb-1">Measured hardware model, sm_{a.sm}</h3>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
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
              <th className={th}>Source runs</th>
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
                <td className={td}>{row.src.length ? <Sources runs={row.src} /> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h4 className="text-sm font-semibold mt-5 mb-2">Current microbench probes</h4>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">Rows a later run re-measured (superseded) are excluded.</p>
      <div className="flex flex-wrap gap-2">
        {a.probes.map((p) => (
          <span key={p.probe} className="text-xs rounded border border-gray-200 dark:border-gray-700 px-2 py-1">
            <span className="font-mono">{p.probe}</span> · {p.rows} rows · {p.runs.length} run{p.runs.length === 1 ? '' : 's'} ·{' '}
            {p.units.join(', ')}
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

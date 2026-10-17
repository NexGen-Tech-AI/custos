// Kernel detail: one tuned kernel's config, registers, spills and shared
// memory (perf DB), its SASS listing and instruction mix (counted in the
// listing, as Core's tools/sass_dump.sh counts), ptxas resource usage, and
// Nsight data where Core profiled it ("not profiled" otherwise, rule 9).
import { useEffect, useMemo, useState } from 'react';
import { perfApi } from '../../../perf/api';
import type { KernelDetail, Winner } from '../../../perf/types';
import { NotMeasured, V, bytes } from '../../../perf/format';

const panel = 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5';
const muted = 'text-xs text-gray-500 dark:text-gray-400';
const PREVIEW_LINES = 400;

function Fact({ label, value }: { label: string; value: string | null }) {
  return (
    <div>
      <dt className={muted}>{label}</dt>
      <dd className="text-sm font-medium">
        <V v={value} />
      </dd>
    </div>
  );
}

function spills(local: number | null): string | null {
  if (local === null) return null;
  return local === 0 ? '0 B (no spills)' : `${bytes(local)} local per thread (spills)`;
}

function Listing({ text, lines }: { text: string; lines: number }) {
  const [all, setAll] = useState(false);
  const shown = useMemo(() => (all ? text : text.split('\n').slice(0, PREVIEW_LINES).join('\n')), [all, text]);
  const available = text.split('\n').length;
  return (
    <div>
      <pre
        aria-label="SASS listing"
        className="max-h-[32rem] overflow-auto text-[11px] leading-tight font-mono bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded p-3"
      >
        {shown}
      </pre>
      <p className={`${muted} mt-1`}>
        {all ? available : Math.min(PREVIEW_LINES, available)} of {lines.toLocaleString()} lines
        {!all && available > PREVIEW_LINES && (
          <button type="button" className="ml-2 underline" onClick={() => setAll(true)}>
            show all
          </button>
        )}
      </p>
    </div>
  );
}

function Detail({ k }: { k: KernelDetail }) {
  const cfg = typeof k.config === 'string' ? { config: k.config } : k.config;
  return (
    <div className="space-y-6">
      <div className={panel}>
        <h3 className="text-lg font-semibold font-mono">{k.impl}</h3>
        <p className={`${muted} mb-4`}>
          kernel {k.kernel_id} · {k.op}
          {k.winner_of.length > 0 && <> · winner of {k.winner_of.length} shapes: {k.winner_of.join(', ')}</>}
        </p>
        <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Fact label="Registers / thread" value={k.regs?.toString() ?? null} />
          <Fact label="Spills (local memory)" value={spills(k.local_bytes)} />
          <Fact label="Shared memory / block" value={bytes(k.smem_bytes)} />
          <Fact label="Baseline" value={k.baseline ? 'yes (cuBLAS)' : 'no'} />
        </dl>
        <h4 className="text-sm font-semibold mt-5 mb-2">Config</h4>
        <dl className="grid grid-cols-3 md:grid-cols-7 gap-3">
          {Object.entries(cfg).map(([key, v]) => (
            <Fact key={key} label={key} value={String(v)} />
          ))}
        </dl>
      </div>

      {k.artifacts.map((a) => (
        <div key={a.sm} className={panel}>
          <h3 className="text-lg font-semibold mb-1">SASS, sm_{a.sm}</h3>
          {a.sass ? (
            <>
              <p className={`${muted} mb-3 break-all`}>
                <span className="font-mono">{a.sass.path}</span>
                <br />
                <span className="font-mono">{a.sass.symbol}</span>
              </p>
              <h4 className="text-sm font-semibold mb-2">Instruction mix</h4>
              <table className="text-sm mb-1" aria-label="Instruction mix">
                <thead>
                  <tr>
                    {Object.keys(a.instruction_mix ?? {}).map((op) => (
                      <th key={op} className="text-left font-medium text-gray-500 dark:text-gray-400 pr-6 font-mono">
                        {op}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    {Object.entries(a.instruction_mix ?? {}).map(([op, n]) => (
                      <td key={op} className="pr-6" data-op={op}>
                        {n}
                      </td>
                    ))}
                  </tr>
                </tbody>
              </table>
              <p className={`${muted} mb-4`}>
                Lines of the listing with each opcode (static counts, as tools/sass_dump.sh counts them).
                {a.resource_usage && (
                  <>
                    {' '}
                    ptxas: {a.resource_usage.regs ?? '?'} registers, {a.resource_usage.local ?? '?'} B local,{' '}
                    {a.resource_usage.stack ?? '?'} B stack, {a.resource_usage.shared ?? '?'} B static shared.
                  </>
                )}
              </p>
              <Listing text={a.sass.text} lines={a.sass.lines} />
            </>
          ) : (
            <p className="text-sm">
              <NotMeasured label={`no SASS: ${a.sass_note ?? 'not dumped'}`} />
            </p>
          )}
        </div>
      ))}

      <div className={panel}>
        <h3 className="text-lg font-semibold mb-2">Nsight Compute</h3>
        {k.nsight_reports.length === 0 ? (
          <NotMeasured label="not profiled" />
        ) : (
          <>
            <ul className="text-sm space-y-1">
              {k.nsight_reports.map((r) => (
                <li key={r.path}>
                  <span className="font-mono">{r.shape}</span> · <span className="font-mono text-xs">{r.path}</span>
                </li>
              ))}
            </ul>
            <p className={`${muted} mt-2`}>
              {k.nsight_stalls ? null : (
                <NotMeasured label="stall breakdown not extracted: open the report in Nsight Compute (docs/core-requests.md #6)" />
              )}
            </p>
          </>
        )}
      </div>
    </div>
  );
}

export function KernelSection() {
  const [kernels, setKernels] = useState<{ id: string; impl: string; shapes: string[] }[] | null>(null);
  const [id, setId] = useState<string | null>(null);
  const [detail, setDetail] = useState<KernelDetail | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const s = await perfApi.sources();
        const all: Winner[] = (await Promise.all(s.measured_archs.map((sm) => perfApi.winners(sm)))).flat();
        const byId = new Map<string, { id: string; impl: string; shapes: string[] }>();
        for (const w of all) {
          const e = byId.get(w.kernel_id) ?? { id: w.kernel_id, impl: w.impl, shapes: [] };
          e.shapes.push(`sm_${w.sm_arch} ${w.shape_bucket}`);
          byId.set(w.kernel_id, e);
        }
        const list = [...byId.values()];
        setKernels(list);
        setId(list[0]?.id ?? null);
      } catch (e) {
        setError(String(e));
      }
    })();
  }, []);

  useEffect(() => {
    if (id === null) return;
    setDetail(undefined);
    perfApi.kernelDetail(id).then(setDetail, (e) => setError(String(e)));
  }, [id]);

  if (error) return <div className={`${panel} text-red-700 dark:text-red-300`}>Perf DB: {error}</div>;
  if (kernels === null) return <div className={panel}>Loading…</div>;
  if (kernels.length === 0) return <div className={panel}>No winners yet (run aegis-perf tune in Core).</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold">Kernel detail</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">A tuned kernel: config, resources, SASS and profiles.</p>
        </div>
        <label className="text-sm">
          <span className="mr-2 text-gray-500 dark:text-gray-400">Kernel</span>
          <select
            aria-label="Kernel"
            className="rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-2 py-1 font-mono"
            value={id ?? ''}
            onChange={(e) => setId(e.target.value)}
          >
            {kernels.map((k) => (
              <option key={k.id} value={k.id}>
                {k.impl} ({k.shapes.length} shape{k.shapes.length === 1 ? '' : 's'})
              </option>
            ))}
          </select>
        </label>
      </div>
      {detail === undefined ? (
        <div className={panel}>Loading kernel…</div>
      ) : detail === null ? (
        <div className={panel}>
          <NotMeasured label="kernel not in the perf DB" />
        </div>
      ) : (
        <Detail k={detail} />
      )}
    </div>
  );
}

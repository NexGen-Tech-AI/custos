// The aegis-hw slot (Device view): where Core's hardware discovery JSON will
// show (GPU, CPU, memory, thermal, video engines). Prepared only: Core has no
// discovery API or schema yet (LOG 2026-10-17 "Paused here" plans one, item
// 1), so nothing is queried and every category reads "not available".
//
// TODO(docs/core-requests.md #12): once Core publishes the discovery schema,
// define the types from it (not before), add a custos-perf reader and a perf
// command, and show each row with its profile (measured | unmeasured) and its
// throttle state. Until then the only shape fixed here is that per-row state.
import { NotMeasured } from '../../../perf/format';

/** Every discovered row will say whether a measured profile backs it. */
export type HwProfile = 'measured' | 'unmeasured';

/** Planned per-row state (not queried yet; core-requests #12). */
export interface HwRowState {
  profile: HwProfile;
  /** Core's throttle state for the row; null: not reported. */
  throttle: string | null;
}

export const HW_CATEGORIES = ['GPU', 'CPU', 'Memory', 'Thermal', 'Video engines'] as const;

const panel = 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5';
const muted = 'text-xs text-gray-500 dark:text-gray-400';

export function HwDiscoverySlot() {
  return (
    <div className={panel} data-panel="aegis-hw">
      <h3 className="text-lg font-semibold mb-1">Hardware discovery (aegis-hw)</h3>
      <p className="text-sm mb-3" data-col="hw-state">
        <NotMeasured label="aegis-hw discovery not available" />
      </p>
      <dl className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {HW_CATEGORIES.map((c) => (
          <div key={c} data-hw={c}>
            <dt className={muted}>{c}</dt>
            <dd className="text-sm">
              <NotMeasured label="not available" />
            </dd>
          </div>
        ))}
      </dl>
      <p className={`${muted} mt-3`}>
        Core plans a discovery API (C ABI, exposed as JSON) but has published no schema yet. Each row will show its
        profile (measured or unmeasured) and its throttle state. docs/core-requests.md #12.
      </p>
    </div>
  );
}

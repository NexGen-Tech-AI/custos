// Every AEGIS view sits behind the perf DB check (perf_status). When the DB
// is missing, or its schema is outside what this build reads, the view shows
// only that state ("Incompatible perf DB: DB schema vN, Custos supports vA"),
// never a half-loaded view or a raw error. The supported range comes from
// aegis-perf.
import { useEffect, useState, type ReactNode } from 'react';
import { perfApi } from '../../../perf/api';
import type { DbStatus } from '../../../perf/types';

const panel = 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5';

export function PerfGate({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<DbStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    perfApi.status().then(setStatus, (e) => setError(String(e)));
  }, []);

  if (status?.state === 'ok') return <>{children}</>;
  if (!status && !error) return <div className={panel}>Checking the perf DB…</div>;
  return (
    <div
      role="alert"
      className="p-4 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-300 dark:border-yellow-700 rounded-lg"
    >
      <p className="font-medium text-yellow-800 dark:text-yellow-200">{error ?? status?.message}</p>
      {status && (
        <>
          <p className="text-xs text-yellow-700 dark:text-yellow-300 mt-1 font-mono break-all">{status.db}</p>
          <p className="text-sm text-yellow-800 dark:text-yellow-200 mt-3">
            The AEGIS views need a perf DB this build reads (schema{' '}
            {status.supported[0] === status.supported[1]
              ? `v${status.supported[0]}`
              : `v${status.supported[0]}–v${status.supported[1]}`}
            ). Point AEGIS_PERFDB at one, or update Custos to an aegis-perf that reads
            {status.db_schema === null ? ' this DB' : ` schema v${status.db_schema}`}.
          </p>
        </>
      )}
    </div>
  );
}

// The perf DB state at startup (perf_status): when the DB is missing, or its
// schema is outside what this build reads, say so plainly instead of showing
// views that would fail. The supported range comes from aegis-perf.
import { useEffect, useState } from 'react';
import { perfApi } from '../../../perf/api';
import type { DbStatus } from '../../../perf/types';

export function PerfStatusBanner() {
  const [status, setStatus] = useState<DbStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    perfApi.status().then(setStatus, (e) => setError(String(e)));
  }, []);

  const message = error ?? (status && status.state !== 'ok' ? status.message : null);
  if (!message) return null;
  return (
    <div
      role="alert"
      className="mb-6 p-4 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-300 dark:border-yellow-700 rounded-lg"
    >
      <p className="font-medium text-yellow-800 dark:text-yellow-200">{message}</p>
      {status && <p className="text-xs text-yellow-700 dark:text-yellow-300 mt-1 font-mono">{status.db}</p>}
    </div>
  );
}

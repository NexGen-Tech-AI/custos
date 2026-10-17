// The AEGIS build flag and the perf DB state banner.
import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import enabled from '../../aegis/enabled';
import disabled from '../../aegis/disabled';
import { Sidebar } from '../../components/Sidebar';
import { PerfGate } from '../../components/sections/perf/PerfGate';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

beforeEach(() => {
  invoke.mockReset();
});

function nav(registry: typeof enabled) {
  render(<Sidebar isCollapsed={false} onToggle={() => {}} activeSection="monitoring" onSectionChange={() => {}} extraItems={registry.sections} />);
}

describe('AEGIS build flag', () => {
  it('adds the AEGIS views to the nav by default', () => {
    nav(enabled);
    expect(screen.getByText('Device (AEGIS)')).toBeInTheDocument();
    expect(screen.getByText('Roofline (AEGIS)')).toBeInTheDocument();
    expect(screen.getByText('Winners (AEGIS)')).toBeInTheDocument();
    expect(screen.getByText('Kernel (AEGIS)')).toBeInTheDocument();
    expect(screen.getByText('System Monitoring')).toBeInTheDocument();
  });

  it('VITE_AEGIS=0: the original system monitor, no AEGIS entries', () => {
    nav(disabled);
    expect(screen.queryByText(/\(AEGIS\)/)).toBeNull();
    expect(screen.getByText('System Monitoring')).toBeInTheDocument();
  });
});

describe('PerfGate', () => {
  // perf_status as custos-perf answered it for a sqlite3 .backup of the live
  // perf DB on 2026-10-17 (schema v4) with aegis-perf v0.3.0.
  const v4 = {
    state: 'incompatible',
    db: '/perf/live-v4/aegis_perf.db',
    db_schema: 4,
    supported: [3, 3],
    message: 'Incompatible perf DB: DB schema v4, Custos supports v3',
  };

  it('an incompatible DB shows only its state, never the view', async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === 'perf_status' ? Promise.resolve(v4) : Promise.reject(new Error(`must not be called: ${cmd}`)),
    );
    const view = vi.fn(() => <p>the view</p>);
    const View = view;
    render(
      <PerfGate>
        <View />
      </PerfGate>,
    );
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Incompatible perf DB: DB schema v4, Custos supports v3');
    expect(alert).toHaveTextContent('The AEGIS views need a perf DB this build reads (schema v3)');
    expect(alert).toHaveTextContent('reads schema v4');
    expect(view).not.toHaveBeenCalled();
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it('a usable DB shows the view', async () => {
    invoke.mockResolvedValue({ state: 'ok', db: '/f.db', db_schema: 3, supported: [3, 3], message: null });
    render(
      <PerfGate>
        <p>the view</p>
      </PerfGate>,
    );
    expect(await screen.findByText('the view')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).toBeNull();
  });
});

// The AEGIS build flag and the perf DB state banner.
import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import enabled from '../../aegis/enabled';
import disabled from '../../aegis/disabled';
import { Sidebar } from '../../components/Sidebar';
import { PerfStatusBanner } from '../../components/sections/perf/PerfStatusBanner';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

beforeEach(() => invoke.mockReset());

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

describe('PerfStatusBanner', () => {
  it('shows an incompatible DB plainly', async () => {
    invoke.mockResolvedValue({
      state: 'incompatible',
      db: '/perf/aegis_perf.db',
      db_schema: 4,
      supported: [3, 3],
      message: 'Incompatible perf DB: DB schema v4, Custos supports v3',
    });
    render(<PerfStatusBanner />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Incompatible perf DB: DB schema v4, Custos supports v3');
    expect(invoke).toHaveBeenCalledWith('perf_status');
  });

  it('stays out of the way when the DB is usable', async () => {
    invoke.mockResolvedValue({ state: 'ok', db: '/f.db', db_schema: 3, supported: [3, 3], message: null });
    const { container } = render(<PerfStatusBanner />);
    await Promise.resolve();
    expect(container).toBeEmptyDOMElement();
  });
});

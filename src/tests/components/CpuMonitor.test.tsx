import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { CpuMonitor } from '../../components/monitors/CpuMonitor';
import { CpuMetrics } from '../../types';

// Mock the hooks
vi.mock('../../hooks/useMetricsHistory', () => ({
  useMetricsHistory: () => [
    { time: '00:00', value: 40 },
    { time: '00:01', value: 45 },
    { time: '00:02', value: 50 },
  ],
}));

// Mock recharts to avoid canvas errors
vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: any) => <div>{children}</div>,
  AreaChart: ({ children }: any) => <div>{children}</div>,
  Area: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
  LineChart: ({ children }: any) => <div>{children}</div>,
  Line: () => null,
}));

const mockCpuMetrics: CpuMetrics = {
  usage_percent: 45.5,
  frequency_mhz: 3200,
  temperature_celsius: 65,
  load_average: [1.5, 1.2, 0.9],
  per_core_usage: [40, 50, 45, 55],
  processes_running: 5,
  processes_total: 250,
  context_switches: 1000,
  interrupts: 5000,
};

describe('CpuMonitor', () => {
  it('renders CPU usage information', () => {
    render(<CpuMonitor metrics={mockCpuMetrics} />);
    
    expect(screen.getByText('CPU Usage')).toBeInTheDocument();
    expect(screen.getByText('45.5%')).toBeInTheDocument();
    expect(screen.getByText('3.20 GHz')).toBeInTheDocument();
  });

  it('displays load average', () => {
    render(<CpuMonitor metrics={mockCpuMetrics} />);
    
    expect(screen.getByText('Load Average (1min, 5min, 15min)')).toBeInTheDocument();
    expect(screen.getByText('1.50, 1.20, 0.90')).toBeInTheDocument();
  });

  it('shows process counts', () => {
    render(<CpuMonitor metrics={mockCpuMetrics} />);
    
    expect(screen.getByText('Processes')).toBeInTheDocument();
    expect(screen.getByText('5 / 250')).toBeInTheDocument();
  });

  it('renders per-thread usage', () => {
    render(<CpuMonitor metrics={mockCpuMetrics} />);
    
    expect(screen.getByText('Per Thread Usage (4 threads)')).toBeInTheDocument();
    expect(screen.getByText('T1')).toBeInTheDocument();
    expect(screen.getByText('T2')).toBeInTheDocument();
    expect(screen.getByText('T3')).toBeInTheDocument();
    expect(screen.getByText('T4')).toBeInTheDocument();
  });
});
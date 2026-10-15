import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { Dashboard } from '../../components/Dashboard';
import { SystemInfo, SystemMetrics } from '../../types';

const mockSystemInfo: SystemInfo = {
  hostname: 'test-host',
  os_name: 'Linux',
  os_version: '5.0',
  kernel_version: '5.0.0',
  architecture: 'x86_64',
  cpu_brand: 'Intel Core i7',
  cpu_cores: 4,
  cpu_threads: 8,
  total_memory: 16 * 1024 * 1024 * 1024,
  boot_time: Math.floor(Date.now() / 1000),
};

const mockMetrics: SystemMetrics = {
  timestamp: Math.floor(Date.now() / 1000).toString(),
  system_info: mockSystemInfo,
  cpu: {
    usage_percent: 45.5,
    frequency_mhz: 3200,
    temperature_celsius: 65,
    load_average: [1.5, 1.2, 0.9],
    per_core_usage: [40, 50, 45, 55],
    processes_running: 5,
    processes_total: 250,
    context_switches: 1000,
    interrupts: 5000,
  },
  memory: {
    total_bytes: 16 * 1024 * 1024 * 1024,
    used_bytes: 8 * 1024 * 1024 * 1024,
    available_bytes: 8 * 1024 * 1024 * 1024,
    cached_bytes: 2 * 1024 * 1024 * 1024,
    swap_total_bytes: 8 * 1024 * 1024 * 1024,
    swap_used_bytes: 1 * 1024 * 1024 * 1024,
    usage_percent: 50,
    swap_usage_percent: 12.5,
  },
  gpus: [],
  disks: [
    {
      mount_point: '/',
      device_name: '/dev/sda1',
      fs_type: 'ext4',
      total_bytes: 500 * 1024 * 1024 * 1024,
      used_bytes: 250 * 1024 * 1024 * 1024,
      available_bytes: 250 * 1024 * 1024 * 1024,
      usage_percent: 50,
      read_bytes_per_sec: 1024 * 1024,
      write_bytes_per_sec: 512 * 1024,
      io_operations_per_sec: 100,
    },
  ],
  networks: [
    {
      interface_name: 'eth0',
      is_up: true,
      mac_address: '00:00:00:00:00:00',
      ip_addresses: ['192.168.1.100'],
      bytes_sent: 1024 * 1024 * 1024,
      bytes_received: 2 * 1024 * 1024 * 1024,
      packets_sent: 1000000,
      packets_received: 2000000,
      errors_sent: 0,
      errors_received: 0,
      speed_mbps: 1000,
      bytes_sent_rate: 1024 * 1024,
      bytes_received_rate: 2 * 1024 * 1024,
    },
  ],
  top_processes: [
    {
      pid: 1234,
      name: 'firefox',
      cpu_usage_percent: 15.5,
      memory_bytes: 512 * 1024 * 1024,
      memory_percent: 3.125,
      disk_read_bytes: 0,
      disk_write_bytes: 0,
      status: 'Running',
      threads: 10,
      start_time: Math.floor(Date.now() / 1000).toString(),
    },
  ],
  dpus: [],
  npus: [],
  external_ddr: [],
  fpgas: [],
  asics: [],
  quantum_processors: [],
};

describe('Dashboard', () => {
  it('renders loading state when no data is provided', () => {
    render(<Dashboard systemInfo={null} metrics={null} />);
    expect(screen.getByText('Initializing system monitoring...')).toBeInTheDocument();
  });

  it('renders all monitoring components when data is provided', () => {
    render(<Dashboard systemInfo={mockSystemInfo} metrics={mockMetrics} />);
    
    // Check that main components are rendered
    expect(screen.getByText('CPU Usage')).toBeInTheDocument();
    expect(screen.getByText('Memory Usage')).toBeInTheDocument();
    expect(screen.getByText('Disk Usage')).toBeInTheDocument();
    expect(screen.getByText('Network Interfaces')).toBeInTheDocument();
    expect(screen.getByText('Top Processes')).toBeInTheDocument();
  });

  it('displays system overview information', () => {
    render(<Dashboard systemInfo={mockSystemInfo} metrics={mockMetrics} />);
    
    expect(screen.getByText('test-host')).toBeInTheDocument();
    expect(screen.getByText(/Linux/)).toBeInTheDocument();
    expect(screen.getByText(/Intel Core i7/)).toBeInTheDocument();
  });

  it('shows CPU metrics correctly', () => {
    render(<Dashboard systemInfo={mockSystemInfo} metrics={mockMetrics} />);
    
    expect(screen.getByText('45.5%')).toBeInTheDocument();
    expect(screen.getByText('3.20 GHz')).toBeInTheDocument();
  });
});
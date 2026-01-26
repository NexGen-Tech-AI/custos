export interface SystemInfo {
  hostname: string;
  os_name: string;
  os_version: string;
  kernel_version: string;
  architecture: string;
  cpu_brand: string;
  cpu_cores: number;
  cpu_threads: number;
  total_memory: number;
  boot_time: number;
}

export interface CpuMetrics {
  usage_percent: number;
  frequency_mhz: number;
  temperature_celsius?: number;
  load_average: [number, number, number];
  per_core_usage: number[];
  processes_running: number;
  processes_total: number;
  context_switches: number;
  interrupts: number;
}

export interface MemoryMetrics {
  total_bytes: number;
  used_bytes: number;
  available_bytes: number;
  cached_bytes: number;
  swap_total_bytes: number;
  swap_used_bytes: number;
  usage_percent: number;
  swap_usage_percent: number;
}

export interface GpuMetrics {
  name: string;
  driver_version: string;
  temperature_celsius: number;
  usage_percent: number;
  memory_total_bytes: number;
  memory_used_bytes: number;
  memory_usage_percent: number;
  power_watts: number;
  fan_speed_percent?: number;
  clock_mhz: number;
  memory_clock_mhz: number;
}

export interface DiskMetrics {
  mount_point: string;
  device_name: string;
  fs_type: string;
  total_bytes: number;
  used_bytes: number;
  available_bytes: number;
  usage_percent: number;
  read_bytes_per_sec: number;
  write_bytes_per_sec: number;
  io_operations_per_sec: number;
}

export interface NetworkMetrics {
  interface_name: string;
  is_up: boolean;
  mac_address: string;
  ip_addresses: string[];
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
  errors_sent: number;
  errors_received: number;
  speed_mbps?: number;
  bytes_sent_rate: number;
  bytes_received_rate: number;
}

export interface ProcessMetrics {
  pid: number;
  name: string;
  cpu_usage_percent: number;
  memory_bytes: number;
  memory_percent: number;
  disk_read_bytes: number;
  disk_write_bytes: number;
  status: string;
  threads: number;
  start_time: string;
}

export interface SystemMetrics {
  timestamp: string;
  system_info: SystemInfo;
  cpu: CpuMetrics;
  memory: MemoryMetrics;
  gpus: GpuMetrics[];
  disks: DiskMetrics[];
  networks: NetworkMetrics[];
  top_processes: ProcessMetrics[];
  // Specialized hardware accelerators (only populated if detected)
  dpus: DpuMetrics[];
  npus: NpuMetrics[];
  external_ddr: ExternalDdrMetrics[];
  fpgas: FpgaMetrics[];
  asics: AsicMetrics[];
  quantum_processors: QuantumProcessorMetrics[];
}

// High-Performance Metrics Types (for ultra-low-latency monitoring)
export interface HighPerfCpuMetrics {
  global_usage: number;
  per_core_usage: number[];
  frequency_mhz: number[];
  temperature?: number;
  load_average: [number, number, number];
  context_switches: number;
  interrupts: number;
  cache_misses: number;
  cache_hits: number;
}

export interface HighPerfMemoryMetrics {
  total_bytes: number;
  used_bytes: number;
  available_bytes: number;
  cached_bytes: number;
  buffer_bytes: number;
  swap_total_bytes: number;
  swap_used_bytes: number;
  page_faults: number;
  page_ins: number;
  page_outs: number;
}

export interface HighPerfGpuMetrics {
  name: string;
  usage_percent: number;
  memory_used_bytes: number;
  memory_total_bytes: number;
  temperature_celsius: number;
  power_watts: number;
  fan_speed_percent?: number;
  clock_mhz: number;
  memory_clock_mhz: number;
}

export interface HighPerfDiskMetrics {
  device_name: string;
  mount_point: string;
  total_bytes: number;
  used_bytes: number;
  read_bytes_per_sec: number;
  write_bytes_per_sec: number;
  io_operations_per_sec: number;
  read_latency_ms: number;
  write_latency_ms: number;
}

export interface HighPerfNetworkMetrics {
  interface_name: string;
  bytes_sent_per_sec: number;
  bytes_received_per_sec: number;
  packets_sent_per_sec: number;
  packets_received_per_sec: number;
  errors_per_sec: number;
  latency_ms: number;
}

export interface HighPerfProcessMetrics {
  pid: number;
  name: string;
  cpu_usage_percent: number;
  memory_bytes: number;
  memory_percent: number;
  disk_read_bytes_per_sec: number;
  disk_write_bytes_per_sec: number;
  network_bytes_per_sec: number;
  threads: number;
  priority: number;
}

// Specialized hardware accelerator types
export interface DpuMetrics {
  name: string;
  vendor: string;
  model: string;
  usage_percent: number;
  memory_used_bytes: number;
  memory_total_bytes: number;
  temperature_celsius: number;
  power_watts: number;
  clock_mhz: number;
  throughput_gbps: number;
  packet_processing_rate: number;
  active_flows: number;
  driver_version: string;
}

export interface NpuMetrics {
  name: string;
  vendor: string;
  model: string;
  usage_percent: number;
  memory_used_bytes: number;
  memory_total_bytes: number;
  temperature_celsius: number;
  power_watts: number;
  clock_mhz: number;
  inference_rate: number;
  model_accuracy: number;
  active_models: number;
  driver_version: string;
}

export interface ExternalDdrMetrics {
  name: string;
  vendor: string;
  capacity_bytes: number;
  used_bytes: number;
  bandwidth_gbps: number;
  latency_ns: number;
  temperature_celsius: number;
  power_watts: number;
  error_rate: number;
  refresh_rate_hz: number;
}

export interface FpgaMetrics {
  name: string;
  vendor: string;
  model: string;
  usage_percent: number;
  temperature_celsius: number;
  power_watts: number;
  clock_mhz: number;
  logic_utilization: number;
  memory_utilization: number;
  dsp_utilization: number;
  bitstream_version: string;
}

export interface AsicMetrics {
  name: string;
  vendor: string;
  model: string;
  usage_percent: number;
  temperature_celsius: number;
  power_watts: number;
  clock_mhz: number;
  throughput_gbps: number;
  packet_processing_rate: number;
  active_channels: number;
}

export interface QuantumProcessorMetrics {
  name: string;
  vendor: string;
  qubits: number;
  coherence_time_ms: number;
  gate_fidelity: number;
  temperature_mk: number; // millikelvin
  power_watts: number;
  active_qubits: number;
  error_rate: number;
}

export interface HighPerfMetrics {
  timestamp_nanos: number;
  cpu: HighPerfCpuMetrics;
  memory: HighPerfMemoryMetrics;
  gpus: HighPerfGpuMetrics[];
  disks: HighPerfDiskMetrics[];
  networks: HighPerfNetworkMetrics[];
  processes: HighPerfProcessMetrics[];
  // Specialized hardware accelerators (only populated if detected)
  dpus: DpuMetrics[];
  npus: NpuMetrics[];
  external_ddr: ExternalDdrMetrics[];
  fpgas: FpgaMetrics[];
  asics: AsicMetrics[];
  quantum_processors: QuantumProcessorMetrics[];
}

// Threat Detection Types
export type ThreatSeverity = 'Critical' | 'High' | 'Medium' | 'Low';
export type ThreatCategory = 'Malware' | 'SuspiciousActivity' | 'PolicyViolation' | 'NetworkThreat' | 'Vulnerability' | 'Other';

export interface ThreatEvent {
  id: string;
  timestamp: string;
  severity: ThreatSeverity;
  category: ThreatCategory;
  title: string;
  description: string;
  confidence: number;
  process_name?: string;
  process_path?: string;
  process_id?: number;
  user?: string;
  file_path?: string;
  file_hash?: string;
  network_source?: string;
  network_destination?: string;
  network_port?: number;
  mitre_tactics: string[];
  mitre_techniques: string[];
  recommended_actions: string[];
  ai_analysis?: string;
  threat_intel?: ThreatIntelligence;
}

export interface ThreatIntelligence {
  virustotal_score?: number;
  virustotal_link?: string;
  abuseipdb_score?: number;
  alienvault_pulses?: number;
}

export interface Alert {
  id: string;
  threat_event: ThreatEvent;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
  notes: AlertNote[];
  created_at: string;
}

export interface AlertNote {
  id: string;
  user: string;
  content: string;
  created_at: string;
}

export interface ThreatStats {
  total_threats: number;
  by_severity: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
  };
  by_category: {
    Malware: number;
    SuspiciousActivity: number;
    PolicyViolation: number;
    NetworkThreat: number;
    Vulnerability: number;
    Other: number;
  };
  last_updated: string;
}

// ========================================
// Network Security Types
// ========================================

export interface NetworkConnectionRecord {
  id: string;
  timestamp: string;
  process_id?: number;
  process_name?: string;
  local_ip?: string;
  local_port?: number;
  remote_ip: string;
  remote_port: number;
  protocol: string;
  direction: string;
  bytes_sent?: number;
  bytes_received?: number;
  duration_seconds?: number;
  state?: string;
}

export interface TopTalker {
  process_name: string;
  process_id?: number;
  connection_count: number;
  total_bytes_sent: number;
  total_bytes_received: number;
  unique_destinations: number;
  suspicious_connections: number;
}

export interface ConnectionStats {
  total_connections: number;
  unique_processes: number;
  unique_destinations: number;
  suspicious_connections: number;
  top_ports: [number, number][];
  top_protocols: [string, number][];
}

export interface DNSQuery {
  id: string;
  timestamp: string;
  process_pid?: number;
  process_name: string;
  query: string;
  query_type: string;
  response_code?: string;
  is_suspicious: boolean;
  suspicion_reasons: string[];
  entropy: number;
  subdomain_count: number;
}

export type NetworkSegment = 'LAN' | 'Guest' | 'IoT' | 'Work' | 'Servers' | 'Internet' | 'Unknown';

export interface SegmentPolicy {
  segment: NetworkSegment;
  blocked_asns: number[];
  blocked_countries: string[];
  allowed_ports?: number[];
  blocked_ports: number[];
  restrict_lateral: boolean;
  block_internet: boolean;
}

export interface GeoIPInfo {
  ip: string;
  country_code?: string;
  country_name?: string;
  city?: string;
  asn?: number;
  asn_org?: string;
  is_known_vpn: boolean;
  is_tor: boolean;
  is_hosting: boolean;
  is_proxy: boolean;
}

export type IsolationAction =
  | { TemporaryIsolate: { hostname: string; duration_minutes: number } }
  | { BlockDestination: { ip: string; duration_minutes?: number } }
  | { BlockASN: { asn: number; duration_minutes?: number } }
  | { BlockPort: { port: number; protocol: string } }
  | { BlockDomain: { domain: string; duration_minutes?: number } };

export interface ActionPreview {
  action: IsolationAction;
  affected_connections: number;
  affected_processes: string[];
  will_break: string[];
  reversible: boolean;
  recommended: boolean;
}

export interface ActionResult {
  action_id: string;
  action: IsolationAction;
  executed_at: string;
  executed_by: string;
  success: boolean;
  rollback_info?: RollbackInfo;
  error?: string;
}

export interface RollbackInfo {
  action_id: string;
  original_rules: string[];
  expires_at?: string;
}

export interface IsolationRecord {
  id: string;
  action: IsolationAction;
  executed_at: string;
  executed_by: string;
  expires_at?: string;
  rolled_back_at?: string;
  status: 'Active' | 'Expired' | 'RolledBack';
}

// ========================================
// Vulnerability Scanning Types
// ========================================

export type CVESeverity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

export interface CVE {
  id: string;
  description: string;
  cvss_score?: number;
  cvss_vector?: string;
  severity: CVESeverity;
  published_date: string;
  modified_date: string;
  affected_packages: AffectedPackage[];
  references: string[];
  cisa_kev: boolean;
  has_exploit: boolean;
  epss_score?: number;
}

export interface AffectedPackage {
  package_name: string;
  ecosystem: string;
  affected_versions: VersionRange[];
  fixed_version?: string;
}

export interface VersionRange {
  introduced?: string;
  fixed?: string;
}

export interface Package {
  name: string;
  version: string;
  architecture?: string;
  source: string;
}

export type FindingStatus = 'New' | 'Acknowledged' | 'InRemediation' | 'Resolved' | 'Accepted';

export type RemediationAction =
  | { Upgrade: { to_version: string; package_manager_command: string } }
  | { Patch: { description: string } }
  | { Mitigate: { steps: string[] } }
  | 'NoFixAvailable';

export interface VulnerabilityFinding {
  id: string;
  cve: CVE;
  affected_package: Package;
  risk_score: number;
  exploitable: boolean;
  exposed: boolean;
  fix_available: boolean;
  recommended_action: RemediationAction;
  discovered_at: string;
  status: FindingStatus;
}

export interface ScanStatistics {
  total_vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  exploitable: number;
  fix_available: number;
  last_scan?: string;
}

export type PriorityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export interface PrioritizedFinding {
  finding: VulnerabilityFinding;
  priority_score: number;
  priority_level: PriorityLevel;
  rationale: string[];
}

export interface PackageVulnerabilityGroup {
  package_name: string;
  vulnerability_count: number;
  highest_priority: number;
  findings: PrioritizedFinding[];
}

export type MisconfigCategory =
  | 'Firewall'
  | 'Encryption'
  | 'Authentication'
  | 'Services'
  | 'Permissions'
  | 'Auditing'
  | 'Updates'
  | 'Network';

export type MisconfigSeverity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';

export type MisconfigStatus = 'New' | 'Acknowledged' | 'InRemediation' | 'Resolved' | 'Accepted';

export interface Misconfiguration {
  id: string;
  category: MisconfigCategory;
  title: string;
  description: string;
  severity: MisconfigSeverity;
  affected_component: string;
  discovered_at: string;
  remediation_steps: string[];
  status: MisconfigStatus;
  cis_benchmark_ref?: string;
}
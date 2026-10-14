// Types of the AEGIS Custos perf commands (src-tauri/src/perf.rs, custos-perf).
// Missing data is null and renders as "not measured" (CLAUDE.md rule 13).

export interface PerfSources {
  db: string;
  core: string;
  measured_archs: number[];
}

export interface Manifest {
  path: string;
  gpu_name: string | null;
  sm_arch: number | null;
  sm_count: number | null;
  integrated: boolean | null;
  global_mem_bytes: number | null;
  l2_bytes: number | null;
  smem_per_block_optin_bytes: number | null;
  smem_per_sm_bytes: number | null;
  regs_per_sm: number | null;
  max_threads_per_sm: number | null;
  measured_d2d_bw_gbps: number | null;
  cuda_runtime: number | null;
  cuda_driver: number | null;
}

export interface Device {
  device_id: string;
  sm_arch: number;
  gpu_name: string | null;
  cuda_ver: number | null;
  driver_ver: number | null;
  runs: number;
  first_run: string;
  last_run: string;
  manifest: Manifest | null;
  arch_file: string | null;
}

export interface SourceRun {
  run_id: string;
  probe: string;
  detail: string | null;
  device_id: string | null;
  git_sha: string | null;
  started_at: string | null;
  superseded_rows: number;
  superseded_by: string[];
}

export interface Bandwidth {
  gbps: number;
  reps: number[];
  method: string | null;
  source: SourceRun;
}

export interface MmaPeak {
  tflops: number;
  hmma_per_clk_per_sm: number | null;
  instruction: string | null;
  at: unknown;
  source: SourceRun;
}

export interface Latency {
  ns: number;
  cycles: number | null;
  ns_min: number | null;
  ns_max: number | null;
  points: number | null;
  working_sets: string | null;
  method: string | null;
  sources: SourceRun[];
}

export interface ArchRoofs {
  sm: number;
  arch_file: string;
  copy_bw_gbps: number;
  read_bw_gbps: number;
  peak_tflops: number;
  ridge_read: number;
  ridge_copy: number;
  decode_max_m: number;
}

export interface ProbeSummary {
  probe: string;
  rows: number;
  runs: string[];
  units: string[];
}

export interface ArchModel {
  sm: number;
  arch_file: string;
  device: string | null;
  sm_count: number | null;
  l2_bytes: number | null;
  generated_by: string | null;
  roof_rule: string | null;
  roofs: ArchRoofs;
  copy_bw: Bandwidth | null;
  read_bw: Bandwidth | null;
  mma_peak: MmaPeak | null;
  l2_latency: Latency | null;
  dram_latency: Latency | null;
  sm_clock_mhz: [string, number | null][];
  power: unknown | null;
  probes: ProbeSummary[];
}

export type RoofKind = 'read' | 'copy';

export interface RoofMetrics {
  ai: number;
  tflops: number;
  gbps: number;
  roof: RoofKind;
  roof_gbps: number;
  pct_peak: number;
  pct_bw: number;
  pct_roof: number;
  bound: 'memory' | 'compute';
}

export interface Ci {
  ratio_median: number | null;
  lo: number;
  hi: number;
  pairs: number | null;
  contains_one: boolean;
}

export interface VsBaseline {
  pct_of_cublaslt_best: number | null;
  ci: Ci | null;
  verdict: 'tie' | 'faster' | 'slower' | null;
  tested_impl: string | null;
}

export interface Tie {
  method: string | null;
  tied: boolean;
  tie_set: string[];
  contender: string | null;
  ci: Ci | null;
  runner_up_gap_pct: number | null;
  pick_reason: string | null;
}

export interface RooflinePoint {
  label: string;
  shape_bucket: string;
  m: number;
  n: number;
  k: number;
  impl: string;
  series: 'winner' | 'cublaslt_best';
  median_us: number;
  roof: RoofMetrics;
  hover: {
    kernel_id: string | null;
    config: Record<string, unknown> | null;
    vs_cublaslt_best: VsBaseline | null;
    tie: Tie | null;
  };
}

export interface Roofline {
  sm: number;
  roofs: ArchRoofs;
  points: RooflinePoint[];
}

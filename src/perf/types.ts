// Types of the AEGIS Custos perf commands (src-tauri/src/perf.rs, custos-perf).
// Missing data is null and renders as "not measured" (project rule 16).

export interface PerfSources {
  db: string;
  core: string;
  measured_archs: number[];
}

/** perf_status: can this build read the perf DB? (custos-perf status.rs) */
export interface DbStatus {
  state: 'ok' | 'missing' | 'incompatible' | 'unreadable';
  db: string;
  db_schema: number | null;
  /** Oldest and newest schema this build reads, from aegis-perf. */
  supported: [number, number];
  message: string | null;
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
  /** null: the run did not record whether its clocks were locked. */
  clocks_locked: boolean | null;
  /** The run's rows of this probe: "valid" (current) or "replaced" (a newer run
   *  re-measured the probe: history, not an error). */
  /** The run's toolchain and power mode; null: not recorded. */
  cuda_ver: number | null;
  driver_ver: number | null;
  power_mode: string | null;
  /** The idle guard during the run; null: not watched. */
  disturbed: boolean | null;
  status: 'valid' | 'replaced';
  replaced_rows: number;
  replaced_by: string[];
}

/** An earlier run of a value's probe, replaced by a newer one (history). */
export interface HistoryRun {
  run_id: string;
  git_sha: string | null;
  started_at: string | null;
  replaced_rows: number;
  replaced_by: string[];
}

export interface Bandwidth {
  gbps: number;
  reps: number[];
  method: string | null;
  source: SourceRun;
  history: HistoryRun[];
}

export interface MmaPeak {
  tflops: number;
  hmma_per_clk_per_sm: number | null;
  instruction: string | null;
  at: unknown;
  source: SourceRun;
  history: HistoryRun[];
}

/** Cycles are stored; ns is derived by aegis-perf at the reference clock. */
export interface Latency {
  cycles: number;
  cycles_min: number | null;
  cycles_max: number | null;
  ref_clock_mhz: number;
  ref_clock_rule: string | null;
  /** Every source run measured at locked clocks. */
  clocks_locked: boolean;
  ns_at_ref: number;
  clock_spread_pct: number | null;
  combine: string | null;
  points: number | null;
  working_sets: string | null;
  method: string | null;
  runs: LatencyRun[];
  history: HistoryRun[];
}

export interface LatencyRun {
  source: SourceRun;
  sm_clock_mhz: number | null;
  /** null: the run did not record whether its clocks were locked. */
  clocks_locked: boolean | null;
  clock_lock: string | null;
  cycles: number | null;
  /** cycles at this run's own clock, derived. */
  ns: number | null;
  points: number | null;
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
  /** Valid rows (the hardware model's). */
  rows: number;
  /** Replaced rows (history). */
  replaced_rows: number;
  runs: string[];
  units: string[];
}

export interface ArchModel {
  sm: number;
  arch_file: string;
  device: string | null;
  /** From the arch file. */
  sm_count: number | null;
  l2_bytes: number | null;
  /** From the arch's device manifest (path in `manifest`). */
  global_mem_bytes: number | null;
  manifest: string | null;
  generated_by: string | null;
  roof_rule: string | null;
  roofs: ArchRoofs;
  copy_bw: Bandwidth | null;
  read_bw: Bandwidth | null;
  mma_peak: MmaPeak | null;
  l2_latency: Latency | null;
  dram_latency: Latency | null;
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

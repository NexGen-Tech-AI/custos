//! The internal model: devices, runs, kernels, launches, counters, timelines
//! and measurements, each with its [`Provenance`]. Adapters produce a
//! [`Capture`]; views and the diagnosis engine read only the model.
//!
//! Two kinds of time are kept apart by type:
//! - [`Measurement`]: a performance result, from the source's own timing
//!   protocol (AEGIS: protocol v2, cold, paired). Only these back a claim.
//! - [`ProfilerTiming`] on a [`Launch`] or timeline event: what a profiler
//!   observed while instrumenting. It explains; it is never a result.
use serde::{Deserialize, Serialize};

use crate::provenance::Provenance;

/// A value that may be missing. Never estimated (rules 9 and 16): a value the
/// source did not measure is `NotMeasured`; one the device or tool cannot
/// report is `NotAvailable` with the reason ("not available on this device").
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum Value<T> {
    Present(T),
    NotMeasured,
    NotAvailable(String),
}

impl<T> Value<T> {
    pub fn present(&self) -> Option<&T> {
        match self {
            Value::Present(v) => Some(v),
            _ => None,
        }
    }
    pub fn from_option(v: Option<T>) -> Value<T> {
        v.map_or(Value::NotMeasured, Value::Present)
    }
}

/// A number with its unit as the source states it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Quantity {
    pub value: Value<f64>,
    pub unit: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Device {
    /// Stable within a capture (e.g. "gpu0", AEGIS's device_id).
    pub id: String,
    pub name: Value<String>,
    pub sm_arch: Value<i64>,
    pub sm_count: Value<i64>,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Run {
    pub id: String,
    /// The source's own kind: "tune" | "sweep" | "nightly" | "paired-ab" |
    /// "ncu-session" | "nsys-capture" | "telemetry" ...; "not readable" when unknown.
    pub kind: String,
    pub device: Option<String>,
    pub provenance: Provenance,
}

/// A kernel: one compiled function (and, for AEGIS, its impl and config).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Kernel {
    /// Stable key: the AEGIS kernel_id, or the demangled name for profiler-only kernels.
    pub id: String,
    /// Demangled name with template arguments, as the source gives it.
    pub name: String,
    pub mangled: Option<String>,
    /// AEGIS impl name (e.g. "gemv_tc_16x64x64_1x4_s6_ksm"), when known.
    pub impl_: Option<String>,
    pub registers_per_thread: Value<i64>,
    pub static_smem_bytes: Value<i64>,
    pub local_bytes_per_thread: Value<i64>,
    pub provenance: Provenance,
}

/// A profiler's view of time. Explanation only (rule: profiler timings are
/// never presented as performance results).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProfilerTiming {
    pub start_ns: i64,
    pub end_ns: i64,
}

impl ProfilerTiming {
    pub fn duration_ns(&self) -> i64 {
        self.end_ns - self.start_ns
    }
}

/// One kernel launch seen by a profiler.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Launch {
    pub id: String,
    pub run: String,
    pub kernel: String,
    pub device: Option<String>,
    pub grid: [i64; 3],
    pub block: [i64; 3],
    pub dynamic_smem_bytes: Value<i64>,
    pub stream: Option<i64>,
    pub correlation_id: Option<i64>,
    pub timing: Option<ProfilerTiming>,
    pub provenance: Provenance,
}

impl Launch {
    pub fn blocks(&self) -> i64 {
        self.grid.iter().product()
    }
    pub fn threads_per_block(&self) -> i64 {
        self.block.iter().product()
    }
}

/// A profiled hardware counter or metric (Nsight Compute), or a telemetry
/// sample (NVML / sysfs). The two never share a series (rule 8): `provenance.source` says which.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Counter {
    /// The launch it was collected on (ncu), or None for device telemetry.
    pub launch: Option<String>,
    pub device: Option<String>,
    /// The source's metric id (e.g. "dram__throughput.avg.pct_of_peak_sustained_elapsed").
    pub metric: String,
    /// The source's section (ncu "Memory Workload Analysis"), if any.
    pub section: Option<String>,
    /// The source's display label ("Memory Throughput"), if any.
    pub label: Option<String>,
    pub quantity: Quantity,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Kernel,
    Memcpy,
    Memset,
    /// A CUDA runtime or driver API call on a CPU thread.
    CudaApi,
    /// An OS runtime call (OSRT) on a CPU thread.
    OsRuntime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub kind: EventKind,
    pub name: String,
    pub timing: ProfilerTiming,
    /// CPU thread (process-local tid) for API / OS events.
    pub thread: Option<i64>,
    pub stream: Option<i64>,
    pub correlation_id: Option<i64>,
    /// Memcpy / memset bytes.
    pub bytes: Option<i64>,
    /// The launch this kernel event is (Launch.id).
    pub launch: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Timeline {
    pub run: String,
    /// Sorted by start.
    pub events: Vec<TimelineEvent>,
    pub provenance: Provenance,
}

/// A performance result from the source's own protocol.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Measurement {
    pub run: String,
    pub kernel: String,
    pub impl_: String,
    pub shape: (i64, i64, i64),
    pub dtype: String,
    pub median_us: f64,
    pub p10_us: Value<f64>,
    pub p90_us: Value<f64>,
    /// Shown in default views (rule 2), or excluded with the reason shown on request.
    pub exclusion: Option<String>,
    pub provenance: Provenance,
}

/// What `aegis::matmul` runs for a shape (rule 10: a separate column).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DispatchState {
    /// "aegis" | "cublaslt".
    pub target: String,
    /// % of the baseline of what is dispatched; NotMeasured when no row times it.
    pub pct: Value<f64>,
    /// What the source stored, when it stores one, and whether it differs from its rule.
    pub stored: Option<String>,
    pub mismatch: bool,
}

/// A kernel against a baseline: the number of record is the paired figure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Comparison {
    /// Measurement.kernel of the subject.
    pub kernel: String,
    pub shape: (i64, i64, i64),
    pub run: String,
    /// Must be "cublaslt_best" for a headline (rule 5).
    pub baseline: String,
    /// Kernel % of the baseline: paired median when paired (stats in provenance), else unpaired.
    pub kernel_pct: Value<f64>,
    /// The unpaired median %, labelled, when the source also gives one.
    pub unpaired_pct: Value<f64>,
    /// "win" | "tie" | "loss" from the CI; None without one.
    pub verdict: Option<String>,
    pub dispatch: Option<DispatchState>,
    /// The production bar the source judged it against, if any ("decode", "large", "floor").
    pub bar: Option<String>,
    pub bar_verdict: Option<String>,
    pub provenance: Provenance,
}

/// A build-over-build regression check of one shape (AEGIS regress).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegressionCheck {
    pub run: String,
    pub shape: (i64, i64, i64),
    pub impl_: String,
    pub pct: Value<f64>,
    pub before_run: Option<String>,
    pub before_pct: Value<f64>,
    /// "regression" | "watch" | "ok" | "not measured", as the source classifies it.
    pub status: String,
    pub why: Option<String>,
    /// A paired confirmation (its own provenance: build, CI).
    pub confirmation: Option<Box<Comparison>>,
    pub dispatch: Option<DispatchState>,
    pub exclusion: Option<String>,
    pub provenance: Provenance,
}

/// A value computed at view time from a roof (rules 3 and 4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Derived {
    /// What it is derived from (a Measurement.kernel or Launch.id).
    pub of: String,
    pub shape: Option<(i64, i64, i64)>,
    /// "pct_of_roof" | "pct_of_bw" | "pct_of_peak" | "gbps" | "tflops" | "latency_ns" ...
    pub name: String,
    pub quantity: Quantity,
    pub provenance: Provenance,
}

/// Everything one adapter read from one source.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Capture {
    pub devices: Vec<Device>,
    pub runs: Vec<Run>,
    pub kernels: Vec<Kernel>,
    pub launches: Vec<Launch>,
    pub counters: Vec<Counter>,
    pub timelines: Vec<Timeline>,
    pub measurements: Vec<Measurement>,
    pub comparisons: Vec<Comparison>,
    pub regressions: Vec<RegressionCheck>,
    pub derived: Vec<Derived>,
    /// What the adapter could not read, and why (shown, never hidden).
    pub notes: Vec<String>,
}

impl Capture {
    pub fn kernel(&self, id: &str) -> Option<&Kernel> {
        self.kernels.iter().find(|k| k.id == id)
    }
    pub fn counters_of<'a>(&'a self, launch: &'a str) -> impl Iterator<Item = &'a Counter> + 'a {
        self.counters.iter().filter(move |c| c.launch.as_deref() == Some(launch))
    }
}

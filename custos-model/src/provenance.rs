//! Where every value comes from. Each entity in the model carries one
//! [`Provenance`]: the source and tool, when it was captured, the build that
//! produced it, the clock-control state, and the source-specific state that
//! the data contract (CLAUDE.md rules 1-12) needs to judge it.
use serde::{Deserialize, Serialize};

/// The system a value came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The AEGIS Core perf DB (aegis-perf): measurements, winners, microbench.
    Aegis,
    /// Nsight Compute: profiled kernel metrics.
    Ncu,
    /// Nsight Systems: timelines.
    Nsys,
    /// NVML: continuous telemetry.
    Nvml,
    /// Linux sysfs / tegrastats (Jetson telemetry).
    Sysfs,
    /// cuobjdump / nvdisasm: SASS listings and resource usage.
    Sass,
}

impl Source {
    /// Continuous telemetry (rule 8): never mixed with profiled metrics.
    pub fn is_telemetry(self) -> bool {
        matches!(self, Source::Nvml | Source::Sysfs)
    }
    /// A profiler: its timings explain, they are never performance results.
    pub fn is_profiler(self) -> bool {
        matches!(self, Source::Ncu | Source::Nsys)
    }
}

/// A fact that may be missing from the source; why it is missing is kept.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum Known<T> {
    Known(T),
    /// Not recorded by the source (the reason, e.g. "the CSV export has no version").
    Unknown(String),
}

impl<T> Known<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            Known::Known(t) => Some(t),
            Known::Unknown(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    /// "aegis-perf", "ncu", "nsys", "nvml", "cuobjdump", ...
    pub name: String,
    pub version: Known<String>,
}

/// A build's identity. `sha` is a full 40-hex-digit commit; a source that
/// records less keeps it in `label` and `sha` stays None (never padded or guessed).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Build {
    pub sha: Option<String>,
    /// None: the source does not say whether the tree was dirty.
    pub dirty: Option<bool>,
    /// The identity as the source stored it (e.g. "0bd0f22a35a6-dirty", "1084490").
    pub label: Option<String>,
}

impl Build {
    pub fn full(sha: &str, dirty: bool) -> Option<Build> {
        (sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| Build { sha: Some(sha.to_ascii_lowercase()), dirty: Some(dirty), label: None })
    }
    /// A stored label such as "9157a34" or "0bd0f22a35a6-dirty": dirty when it says so.
    pub fn from_label(label: &str) -> Build {
        let dirty = label.ends_with("-dirty");
        Build { sha: None, dirty: dirty.then_some(true), label: Some(label.to_string()) }
    }
    /// Reproducible from a commit: a full SHA, known clean.
    pub fn reproducible(&self) -> bool {
        self.sha.is_some() && self.dirty == Some(false)
    }
}

/// How the GPU clocks were controlled while the value was measured.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockControl {
    /// Locked to a fixed clock (nvidia-smi -lgc, or the probe's own lock).
    Locked,
    /// Nsight Compute's --clock-control base: clocks locked to base for profiling.
    Base,
    /// Not controlled: the clock the GPU chose.
    Uncontrolled,
    /// The source does not say.
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Clocks {
    pub control: ClockControl,
    /// How `control` is known (e.g. "runs.clocks_locked = 0", "--clock-control
    /// not on the recorded command line: ncu's default, base").
    pub basis: String,
    /// The SM clock the value was measured at (MHz), when recorded.
    pub sm_mhz: Option<f64>,
}

impl Clocks {
    pub fn unknown(why: &str) -> Clocks {
        Clocks { control: ClockControl::Unknown, basis: why.to_string(), sm_mhz: None }
    }
}

/// AEGIS row state the default filters and exclusions read (rules 2 and 7).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AegisState {
    /// Microbench rows: "valid" | "replaced" | "invalidated"; other rows: None.
    pub status: Option<String>,
    pub replaced_by: Option<String>,
    /// The in-run idle watch: Some(true) disturbed, Some(false) clean, None not watched.
    pub disturbed: Option<bool>,
    pub allow_busy: bool,
    /// Timing protocol (1 or 2).
    pub protocol: i64,
    /// "cold" | "warm" (v2); None for v1 rows.
    pub cache_mode: Option<String>,
}

impl AegisState {
    /// What every view shows by default (rule 2): protocol v2, cold, not
    /// disturbed, not allow_busy; and for microbench rows, valid (rule 7).
    pub fn default_view(&self) -> bool {
        self.protocol == 2
            && self.cache_mode.as_deref() == Some("cold")
            && self.disturbed != Some(true)
            && !self.allow_busy
            && self.status.as_deref().is_none_or(|s| s == "valid")
    }
}

/// A 95% confidence interval.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ci {
    pub lo: f64,
    pub hi: f64,
}

impl Ci {
    pub fn contains_one(&self) -> bool {
        self.lo <= 1.0 && self.hi >= 1.0
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Pairing {
    /// Alternating paired windows against `against`, in one process (aegis_tune)
    /// or across two builds (paired-ab).
    Paired { against: String, pairs: Option<i64>, across_builds: bool },
    /// Independent medians: secondary, never a claim on its own (rule 6).
    Unpaired,
}

/// Statistics of a measurement or comparison.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Stats {
    pub ci: Option<Ci>,
    pub pairing: Pairing,
}

/// Where a roof came from (rule 3 and the diagnosis engine).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RoofOrigin {
    /// AEGIS's measured roofs (include/aegis/arch/sm_<arch>.json), from valid microbench rows.
    Measured { arch_file: String, microbench_status: String },
    /// A device peak from a datasheet or vendor table: always labelled "datasheet-derived".
    Datasheet { label: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoofUsed {
    /// "read" | "copy" (memory) or "compute".
    pub kind: String,
    pub value: f64,
    pub unit: String,
    pub origin: RoofOrigin,
}

/// Where a value comes from, in full.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub source: Source,
    pub tool: Tool,
    /// When the source captured it (ISO 8601), if it says.
    pub captured_at: Option<String>,
    pub build: Option<Build>,
    pub clocks: Clocks,
    /// AEGIS rows only.
    pub aegis: Option<AegisState>,
    /// Measurements and comparisons: CI and pairing, where present.
    pub stats: Option<Stats>,
    /// Derived values: the roof used.
    pub roof: Option<RoofUsed>,
    /// The record it came from: a run id, a report file name (no path), a table row.
    pub origin: String,
    /// A hand-built fixture, not a capture (tests/fixtures, labelled "synthetic").
    pub synthetic: bool,
    /// Derived from a Custos fallback constant (rule 12), with the core-request it cites.
    pub provisional: Option<String>,
}

impl Provenance {
    /// A minimal provenance for a source; callers fill in what they know.
    pub fn new(source: Source, tool: &str, version: Known<String>, origin: &str) -> Provenance {
        Provenance {
            source,
            tool: Tool { name: tool.to_string(), version },
            captured_at: None,
            build: None,
            clocks: Clocks::unknown("not recorded by the source"),
            aegis: None,
            stats: None,
            roof: None,
            origin: origin.to_string(),
            synthetic: false,
            provisional: None,
        }
    }
}

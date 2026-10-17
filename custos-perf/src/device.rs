//! Device view: devices seen in the perf DB with their manifests, and the
//! measured hardware model of an arch (the arch file, each value linked to
//! the runs that measured it. Only valid microbench rows feed the model;
//! replaced rows are history (contract rule 7).
use std::collections::{BTreeMap, HashMap};

use aegis_perf::rusqlite::Connection;
use aegis_perf::view::{self, MicrobenchStatus};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use aegis_perf::params;

use crate::roof::{self, ArchRoofs};
use crate::Sources;

/// Device facts from `aegis_manifest` (results/manifest-<device>.json).
#[derive(Clone, Debug, Serialize)]
pub struct Manifest {
    pub path: String,
    pub gpu_name: Option<String>,
    pub sm_arch: Option<i64>,
    pub sm_count: Option<i64>,
    pub integrated: Option<bool>,
    pub global_mem_bytes: Option<i64>,
    pub l2_bytes: Option<i64>,
    pub smem_per_block_optin_bytes: Option<i64>,
    pub smem_per_sm_bytes: Option<i64>,
    pub regs_per_sm: Option<i64>,
    pub max_threads_per_sm: Option<i64>,
    /// aegis_manifest's quick D2D copy measurement. The roofs come from the arch file.
    pub measured_d2d_bw_gbps: Option<f64>,
    pub cuda_runtime: Option<i64>,
    pub cuda_driver: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Device {
    pub device_id: String,
    pub sm_arch: i64,
    pub gpu_name: Option<String>,
    pub cuda_ver: Option<i64>,
    pub driver_ver: Option<i64>,
    pub runs: usize,
    pub first_run: String,
    pub last_run: String,
    pub manifest: Option<Manifest>,
    /// The arch file path when Core has measured this arch.
    pub arch_file: Option<String>,
}

fn manifest(src: &Sources, device_id: &str) -> Result<Option<Manifest>> {
    let path = src.manifest_dir.join(format!("manifest-{device_id}.json"));
    if !path.exists() {
        return Ok(None);
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path)?).with_context(|| format!("parse {}", path.display()))?;
    let i = |k: &str| v.get(k).and_then(Value::as_i64);
    Ok(Some(Manifest {
        path: path.display().to_string(),
        gpu_name: v.get("gpu_name").and_then(Value::as_str).map(str::to_string),
        sm_arch: i("sm_arch"),
        sm_count: i("sm_count"),
        integrated: v.get("integrated").and_then(Value::as_bool),
        global_mem_bytes: i("global_mem_bytes"),
        l2_bytes: i("l2_bytes"),
        smem_per_block_optin_bytes: i("smem_per_block_optin_bytes"),
        smem_per_sm_bytes: i("smem_per_sm_bytes"),
        regs_per_sm: i("regs_per_sm"),
        max_threads_per_sm: i("max_threads_per_sm"),
        measured_d2d_bw_gbps: v.get("measured_d2d_bw_gbps").and_then(Value::as_f64),
        cuda_runtime: i("cuda_runtime"),
        cuda_driver: i("cuda_driver"),
    }))
}

/// Every (device, arch) with runs in the perf DB, most recent first.
pub fn devices(src: &Sources, con: &Connection) -> Result<Vec<Device>> {
    let mut by: BTreeMap<(String, i64), Vec<view::Run>> = BTreeMap::new();
    for r in view::runs(con)? {
        by.entry((r.device_id.clone(), r.sm_arch)).or_default().push(r);
    }
    let mut out = Vec::new();
    for ((device_id, sm_arch), runs) in by {
        // runs are oldest first; the latest run's toolchain describes the device now.
        let last = runs.last().context("empty group")?;
        let arch_file = src.arch_file(sm_arch);
        out.push(Device {
            manifest: manifest(src, &device_id)?,
            gpu_name: last.gpu_name.clone(),
            cuda_ver: last.cuda_ver,
            driver_ver: last.driver_ver,
            runs: runs.len(),
            first_run: runs[0].started_at.clone(),
            last_run: last.started_at.clone(),
            arch_file: arch_file.exists().then(|| arch_file.display().to_string()),
            device_id,
            sm_arch,
        });
    }
    out.sort_by(|a, b| b.last_run.cmp(&a.last_run));
    Ok(out)
}

/// A run a hardware-model value came from.
#[derive(Clone, Debug, Serialize)]
pub struct SourceRun {
    pub run_id: String,
    pub probe: String,
    /// Stream or pointer-chase layout, when the arch file names one.
    pub detail: Option<String>,
    pub device_id: Option<String>,
    pub git_sha: Option<String>,
    pub started_at: Option<String>,
    /// Whether the run's clocks were locked (runs.clocks_locked); None when the
    /// run did not record it.
    pub clocks_locked: Option<bool>,
    /// The run's toolchain and power mode (runs table); None: not recorded.
    pub cuda_ver: Option<i64>,
    pub driver_ver: Option<i64>,
    pub power_mode: Option<String>,
    /// The idle guard during the run (None: not watched).
    pub disturbed: Option<bool>,
    /// The run's microbench rows of this probe: "valid" (current) or
    /// "replaced" (a newer run re-measured the probe: history, not an error).
    pub status: &'static str,
    /// Rows of this probe in this run marked replaced, and by which runs.
    pub replaced_rows: usize,
    pub replaced_by: Vec<String>,
}

/// An earlier run of a model value's probe, replaced by a newer one: history
/// (contract rule 7), shown labeled, never in the model.
#[derive(Clone, Debug, Serialize)]
pub struct HistoryRun {
    pub run_id: String,
    pub git_sha: Option<String>,
    pub started_at: Option<String>,
    pub replaced_rows: usize,
    pub replaced_by: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Bandwidth {
    pub gbps: f64,
    pub reps: Vec<f64>,
    pub method: Option<String>,
    pub source: SourceRun,
    pub history: Vec<HistoryRun>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MmaPeak {
    pub tflops: f64,
    pub hmma_per_clk_per_sm: Option<f64>,
    pub instruction: Option<String>,
    pub at: Value,
    pub source: SourceRun,
    pub history: Vec<HistoryRun>,
}

/// A pointer-chase latency (arch schema 2 and later). Cycles are what Core
/// stores; ns is derived here through aegis-perf (`params::Latency::ns`) at the
/// arch file's reference clock, and per source run at that run's own clock.
#[derive(Clone, Debug, Serialize)]
pub struct Latency {
    pub cycles: f64,
    pub cycles_min: Option<f64>,
    pub cycles_max: Option<f64>,
    pub ref_clock_mhz: f64,
    /// How Core chose the reference clock (`ref_clock_rule`).
    pub ref_clock_rule: Option<String>,
    /// Every source run measured at locked clocks.
    pub clocks_locked: bool,
    /// cycles at ref_clock_mhz, derived (never stored).
    pub ns_at_ref: f64,
    pub clock_spread_pct: Option<f64>,
    /// How Core combined the runs (e.g. "clocks within 2%: ...").
    pub combine: Option<String>,
    pub points: Option<i64>,
    pub working_sets: Option<String>,
    pub method: Option<String>,
    pub runs: Vec<LatencyRun>,
    pub history: Vec<HistoryRun>,
}

/// One source run of a latency: its own cycles, SM clock and lock state.
#[derive(Clone, Debug, Serialize)]
pub struct LatencyRun {
    pub source: SourceRun,
    pub sm_clock_mhz: Option<f64>,
    /// None: the run did not record it (rows from before the clock-locking probes).
    pub clocks_locked: Option<bool>,
    /// What the probe requested and saw, e.g. "locked externally at 2418 MHz ...".
    pub clock_lock: Option<String>,
    pub cycles: Option<f64>,
    /// cycles at this run's own sm_clock_mhz, derived (never stored).
    pub ns: Option<f64>,
    pub points: Option<i64>,
}

/// Microbench rows per probe: valid rows (the hardware model's) and replaced
/// rows (history). aegis-perf never returns invalidated rows.
#[derive(Clone, Debug, Serialize)]
pub struct ProbeSummary {
    pub probe: String,
    /// Valid rows.
    pub rows: usize,
    pub replaced_rows: usize,
    pub runs: Vec<String>,
    pub units: Vec<String>,
}

/// The measured hardware model of one arch. A missing value is None and
/// renders as "not measured" (contract rule 9).
#[derive(Clone, Debug, Serialize)]
pub struct ArchModel {
    pub sm: i64,
    pub arch_file: String,
    pub device: Option<String>,
    /// SM count and L2 size: from the arch file (emit-arch copies them from
    /// aegis_manifest); the source is the arch file itself.
    pub sm_count: Option<i64>,
    pub l2_bytes: Option<i64>,
    /// Device memory: not in the arch file; from the manifest of the arch's
    /// device (`aegis_manifest`), with its path as the source.
    pub global_mem_bytes: Option<i64>,
    pub manifest: Option<String>,
    pub generated_by: Option<String>,
    pub roof_rule: Option<String>,
    pub roofs: ArchRoofs,
    pub copy_bw: Option<Bandwidth>,
    pub read_bw: Option<Bandwidth>,
    pub mma_peak: Option<MmaPeak>,
    pub l2_latency: Option<Latency>,
    pub dram_latency: Option<Latency>,
    /// Power controls, when the arch file carries them (not yet).
    pub power: Option<Value>,
    pub probes: Vec<ProbeSummary>,
}

struct Ctx<'a> {
    runs: HashMap<String, view::Run>,
    micro_all: &'a [view::Microbench],
}

impl Ctx<'_> {
    fn source(&self, run_id: &str, probe: &str, detail: Option<String>) -> SourceRun {
        let run = self.runs.get(run_id);
        let replaced: Vec<&view::Microbench> = self
            .micro_all
            .iter()
            .filter(|m| m.run_id == run_id && m.probe == probe && m.status == MicrobenchStatus::Replaced)
            .collect();
        let mut by: Vec<String> = replaced.iter().filter_map(|m| m.replaced_by.clone()).collect();
        by.sort();
        by.dedup();
        SourceRun {
            run_id: run_id.to_string(),
            probe: probe.to_string(),
            detail,
            device_id: run.map(|r| r.device_id.clone()),
            git_sha: run.and_then(|r| r.git_sha.clone()),
            started_at: run.map(|r| r.started_at.clone()),
            clocks_locked: run.and_then(|r| r.clocks_locked).map(|v| v != 0),
            cuda_ver: run.and_then(|r| r.cuda_ver),
            driver_ver: run.and_then(|r| r.driver_ver),
            power_mode: run.and_then(|r| r.power_mode.clone()),
            disturbed: run.and_then(|r| r.disturbed),
            status: if replaced.is_empty() { "valid" } else { "replaced" },
            replaced_rows: replaced.len(),
            replaced_by: by,
        }
    }

    /// Every run of `probe` with replaced rows, oldest first (`except`: the
    /// value's own source runs, which carry their status themselves).
    fn history(&self, probe: &str, except: &[&str]) -> Vec<HistoryRun> {
        let mut out: Vec<HistoryRun> = Vec::new();
        for m in self.micro_all.iter().filter(|m| m.probe == probe && m.status == MicrobenchStatus::Replaced) {
            if except.contains(&m.run_id.as_str()) {
                continue;
            }
            let h = match out.iter_mut().find(|h| h.run_id == m.run_id) {
                Some(h) => h,
                None => {
                    let run = self.runs.get(&m.run_id);
                    out.push(HistoryRun {
                        run_id: m.run_id.clone(),
                        git_sha: run.and_then(|r| r.git_sha.clone()),
                        started_at: run.map(|r| r.started_at.clone()),
                        replaced_rows: 0,
                        replaced_by: Vec::new(),
                    });
                    out.last_mut().expect("just pushed")
                }
            };
            h.replaced_rows += 1;
            if let Some(by) = &m.replaced_by {
                if !h.replaced_by.contains(by) {
                    h.replaced_by.push(by.clone());
                }
            }
        }
        out
    }

    fn bandwidth(&self, v: &Value) -> Option<Bandwidth> {
        let src = v.get("source")?;
        let (run_id, probe) = (src.get("run_id")?.as_str()?, src.get("probe")?.as_str()?);
        Some(Bandwidth {
            gbps: v.get("value")?.as_f64()?,
            reps: v.get("reps").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_f64).collect()).unwrap_or_default(),
            method: s(v.get("method")),
            source: self.source(run_id, probe, s(src.get("stream"))),
            history: self.history(probe, &[run_id]),
        })
    }

    /// `typed` is Core's own reading of the entry (aegis_perf::params): the
    /// headline numbers come from it, so a schema change breaks here at
    /// compile time; per-run detail comes from the same JSON entry.
    fn latency(&self, typed: Option<params::Latency>, v: Option<&Value>) -> Option<Latency> {
        let t = typed?;
        let v = v?;
        let f = |k: &str| v.get(k).and_then(Value::as_f64);
        let probe = v.get("probe").and_then(Value::as_str).unwrap_or("ptr_chase_latency");
        let runs: Vec<LatencyRun> = v
            .get("runs")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|r| {
                        let g = |k: &str| r.get(k).and_then(Value::as_f64);
                        let clocks_locked = r.get("clocks_locked").and_then(Value::as_bool);
                        let ns = match (g("cycles"), g("sm_clock_mhz")) {
                            (Some(cycles), Some(mhz)) if mhz > 0.0 => {
                                let at_run = params::Latency { cycles, ref_clock_mhz: mhz, clocks_locked: clocks_locked == Some(true) };
                                Some(at_run.ns())
                            }
                            _ => None,
                        };
                        Some(LatencyRun {
                            source: self.source(r.get("run_id")?.as_str()?, probe, s(r.get("layout"))),
                            sm_clock_mhz: g("sm_clock_mhz"),
                            clocks_locked,
                            clock_lock: s(r.get("clock_lock")),
                            cycles: g("cycles"),
                            ns,
                            points: r.get("points").and_then(Value::as_i64),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Latency {
            cycles: t.cycles,
            cycles_min: f("cycles_min"),
            cycles_max: f("cycles_max"),
            ref_clock_mhz: t.ref_clock_mhz,
            ref_clock_rule: s(v.get("ref_clock_rule")),
            clocks_locked: t.clocks_locked,
            ns_at_ref: t.ns(),
            clock_spread_pct: f("clock_spread_pct"),
            combine: s(v.get("combine")),
            points: v.get("points").and_then(Value::as_i64),
            working_sets: s(v.get("working_sets")),
            method: s(v.get("method")),
            history: self.history(probe, &runs.iter().map(|r| r.source.run_id.as_str()).collect::<Vec<_>>()),
            runs,
        })
    }
}

fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_string)
}

/// The arch file of `sm` with its source runs, or None when Core has not
/// measured that arch.
pub fn arch_model(src: &Sources, con: &Connection, sm: i64) -> Result<Option<ArchModel>> {
    let Some(params) = roof::load(src, sm)? else { return Ok(None) };
    let path = src.arch_file(sm);
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path)?).with_context(|| format!("parse {}", path.display()))?;
    let micro_all = view::microbench(con, sm)?;
    let ctx = Ctx { runs: view::runs(con)?.into_iter().map(|r| (r.run_id.clone(), r)).collect(), micro_all: &micro_all };

    let mma_peak = doc.get("mma_peak").and_then(|v| {
        let src = v.get("source")?;
        let (run_id, probe) = (src.get("run_id")?.as_str()?, src.get("probe")?.as_str()?);
        Some(MmaPeak {
            tflops: v.get("tflops")?.as_f64()?,
            hmma_per_clk_per_sm: v.get("hmma_per_clk_per_sm").and_then(Value::as_f64),
            instruction: s(v.get("instruction")),
            at: v.get("at").cloned().unwrap_or(Value::Null),
            source: ctx.source(run_id, probe, None),
            history: ctx.history(probe, &[run_id]),
        })
    });
    // Device memory is not in the arch file: the manifest of the arch's device.
    let manifest = devices(src, con)?.into_iter().filter(|d| d.sm_arch == sm).find_map(|d| d.manifest);
    // Valid rows feed the model; replaced rows are counted as history (rule 7).
    let mut probes: BTreeMap<String, ProbeSummary> = BTreeMap::new();
    for m in &micro_all {
        let p = probes.entry(m.probe.clone()).or_insert_with(|| ProbeSummary {
            probe: m.probe.clone(),
            rows: 0,
            replaced_rows: 0,
            runs: Vec::new(),
            units: Vec::new(),
        });
        if m.status == MicrobenchStatus::Replaced {
            p.replaced_rows += 1;
            continue;
        }
        p.rows += 1;
        if !p.runs.contains(&m.run_id) {
            p.runs.push(m.run_id.clone());
        }
        if !p.units.contains(&m.unit) {
            p.units.push(m.unit.clone());
        }
    }

    Ok(Some(ArchModel {
        sm,
        arch_file: path.display().to_string(),
        device: s(doc.get("device")),
        sm_count: doc.get("sm_count").and_then(Value::as_i64),
        l2_bytes: doc.get("l2_bytes").and_then(Value::as_i64),
        global_mem_bytes: manifest.as_ref().and_then(|m| m.global_mem_bytes),
        manifest: manifest.map(|m| m.path),
        generated_by: s(doc.get("generated_by")),
        roof_rule: s(doc.get("roof_rule")),
        roofs: ArchRoofs::new(sm, &params),
        copy_bw: doc.get("copy_bw_gbps").and_then(|v| ctx.bandwidth(v)),
        read_bw: doc.get("read_bw_gbps").and_then(|v| ctx.bandwidth(v)),
        mma_peak,
        l2_latency: ctx.latency(params.l2_latency, doc.get("l2_latency")),
        dram_latency: ctx.latency(params.dram_latency, doc.get("dram_latency")),
        power: doc.get("power").cloned(),
        probes: probes.into_values().collect(),
    }))
}

/// Archs Core has an arch file for (include/aegis/arch/sm_*.json).
pub fn measured_archs(src: &Sources) -> Vec<i64> {
    let mut v: Vec<i64> = std::fs::read_dir(&src.arch_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.strip_prefix("sm_")?.strip_suffix(".json")?.parse().ok()
        })
        .collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mb(run: &str, replaced_by: Option<&str>) -> view::Microbench {
        view::Microbench {
            run_id: run.into(),
            probe: "ptr_chase_latency".into(),
            param_json: "{}".into(),
            value: Some(1.0),
            unit: "cycles".into(),
            status: if replaced_by.is_some() { MicrobenchStatus::Replaced } else { MicrobenchStatus::Valid },
            replaced_by: replaced_by.map(str::to_string),
            sm_clock_mhz: None,
            clocks_locked: None,
            clock_lock: None,
        }
    }

    /// A cited run whose rows a later run re-measured is "replaced" (history),
    /// with the replacing run named; an untouched one is "valid".
    #[test]
    fn replaced_runs_are_history() {
        let micro = [mb("old", Some("new")), mb("old", Some("new")), mb("new", None)];
        let ctx = Ctx { runs: HashMap::new(), micro_all: &micro };
        let old = ctx.source("old", "ptr_chase_latency", None);
        assert_eq!((old.status, old.replaced_rows, old.replaced_by.clone()), ("replaced", 2, vec!["new".to_string()]));
        let new = ctx.source("new", "ptr_chase_latency", None);
        assert_eq!((new.status, new.replaced_rows), ("valid", 0));
        assert_eq!(new.clocks_locked, None);
    }
}

//! Device view: devices seen in the perf DB with their manifests, and the
//! measured hardware model of an arch (the arch file, each value linked to
//! the runs that measured it; superseded microbench rows excluded, rule 7).
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use aegis_perf::rusqlite::Connection;
use aegis_perf::view;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

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
    let name = format!("manifest-{device_id}.json");
    let mut candidates = vec![src.core_path("results").join(&name)];
    if let Some(dir) = src.db.parent() {
        candidates.push(dir.join(&name));
    }
    let Some(path) = candidates.into_iter().find(|p| p.exists()) else { return Ok(None) };
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
    /// "current", or "replaced": a later run re-measured this probe (Core
    /// marks every older row superseded on ingest). History, not an error.
    pub status: &'static str,
    /// Rows of this probe in this run marked superseded, and by which runs.
    pub superseded_rows: usize,
    pub superseded_by: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Bandwidth {
    pub gbps: f64,
    pub reps: Vec<f64>,
    pub method: Option<String>,
    pub source: SourceRun,
}

#[derive(Clone, Debug, Serialize)]
pub struct MmaPeak {
    pub tflops: f64,
    pub hmma_per_clk_per_sm: Option<f64>,
    pub instruction: Option<String>,
    pub at: Value,
    pub source: SourceRun,
}

/// A pointer-chase latency (arch schema 2). Cycles are primary: they do not
/// depend on the clock. ns is stated at a reference clock (the highest
/// source-run clock), and each source run keeps its own clock and ns.
#[derive(Clone, Debug, Serialize)]
pub struct Latency {
    pub cycles: f64,
    pub cycles_min: Option<f64>,
    pub cycles_max: Option<f64>,
    pub ref_clock_mhz: f64,
    pub ns_at_ref: f64,
    /// Measured ns across runs; None when the runs' clocks differ by > 2%
    /// (Core does not average ns measured at different clocks).
    pub ns_measured: Option<NsMeasured>,
    pub clock_spread_pct: Option<f64>,
    /// How Core combined the runs (e.g. "clocks within 2%: ...").
    pub combine: Option<String>,
    pub points: Option<i64>,
    pub working_sets: Option<String>,
    pub method: Option<String>,
    pub runs: Vec<LatencyRun>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NsMeasured {
    pub median: f64,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

/// One source run of a latency: its own cycles, ns and SM clock.
#[derive(Clone, Debug, Serialize)]
pub struct LatencyRun {
    pub source: SourceRun,
    pub sm_clock_mhz: Option<f64>,
    pub cycles: Option<f64>,
    pub ns: Option<f64>,
    pub points: Option<i64>,
}

/// Current (non-superseded) rows per microbench probe.
#[derive(Clone, Debug, Serialize)]
pub struct ProbeSummary {
    pub probe: String,
    pub rows: usize,
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
    pub sm_count: Option<i64>,
    pub l2_bytes: Option<i64>,
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
        let sup: Vec<&view::Microbench> =
            self.micro_all.iter().filter(|m| m.run_id == run_id && m.probe == probe && m.superseded).collect();
        let mut by: Vec<String> = sup.iter().filter_map(|m| m.superseded_by.clone()).collect();
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
            status: if sup.is_empty() { "current" } else { "replaced" },
            superseded_rows: sup.len(),
            superseded_by: by,
        }
    }

    fn bandwidth(&self, v: &Value) -> Option<Bandwidth> {
        let src = v.get("source")?;
        Some(Bandwidth {
            gbps: v.get("value")?.as_f64()?,
            reps: v.get("reps").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_f64).collect()).unwrap_or_default(),
            method: s(v.get("method")),
            source: self.source(src.get("run_id")?.as_str()?, src.get("probe")?.as_str()?, s(src.get("stream"))),
        })
    }

    /// `typed` is Core's own reading of the entry (aegis_perf::params): the
    /// headline numbers come from it, so a schema change breaks here at
    /// compile time; per-run detail comes from the same JSON entry.
    fn latency(&self, typed: Option<aegis_perf::params::Latency>, v: Option<&Value>) -> Option<Latency> {
        let t = typed?;
        let v = v?;
        let f = |k: &str| v.get(k).and_then(Value::as_f64);
        let probe = v.get("probe").and_then(Value::as_str).unwrap_or("ptr_chase_latency");
        let runs = v
            .get("runs")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|r| {
                        let g = |k: &str| r.get(k).and_then(Value::as_f64);
                        Some(LatencyRun {
                            source: self.source(r.get("run_id")?.as_str()?, probe, s(r.get("layout"))),
                            sm_clock_mhz: g("sm_clock_mhz"),
                            cycles: g("cycles"),
                            ns: g("ns"),
                            points: r.get("points").and_then(Value::as_i64),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let ns_measured = v.get("ns_measured").and_then(|n| {
            Some(NsMeasured {
                median: n.get("median")?.as_f64()?,
                min: n.get("min").and_then(Value::as_f64),
                max: n.get("max").and_then(Value::as_f64),
            })
        });
        Some(Latency {
            cycles: t.cycles,
            cycles_min: f("cycles_min"),
            cycles_max: f("cycles_max"),
            ref_clock_mhz: t.ref_clock_mhz,
            ns_at_ref: t.ns_at_ref,
            ns_measured,
            clock_spread_pct: f("clock_spread_pct"),
            combine: s(v.get("combine")),
            points: v.get("points").and_then(Value::as_i64),
            working_sets: s(v.get("working_sets")),
            method: s(v.get("method")),
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
    let micro_all = view::microbench(con, sm, true)?;
    let ctx = Ctx { runs: view::runs(con)?.into_iter().map(|r| (r.run_id.clone(), r)).collect(), micro_all: &micro_all };

    let mma_peak = doc.get("mma_peak").and_then(|v| {
        let src = v.get("source")?;
        Some(MmaPeak {
            tflops: v.get("tflops")?.as_f64()?,
            hmma_per_clk_per_sm: v.get("hmma_per_clk_per_sm").and_then(Value::as_f64),
            instruction: s(v.get("instruction")),
            at: v.get("at").cloned().unwrap_or(Value::Null),
            source: ctx.source(src.get("run_id")?.as_str()?, src.get("probe")?.as_str()?, None),
        })
    });
    // Current probes only (rule 7).
    let mut probes: BTreeMap<String, ProbeSummary> = BTreeMap::new();
    for m in micro_all.iter().filter(|m| !m.superseded) {
        let p = probes.entry(m.probe.clone()).or_insert_with(|| ProbeSummary {
            probe: m.probe.clone(),
            rows: 0,
            runs: Vec::new(),
            units: Vec::new(),
        });
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
    let dir: PathBuf = src.core_path("include/aegis/arch");
    let mut v: Vec<i64> = std::fs::read_dir(dir)
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

    fn mb(run: &str, superseded_by: Option<&str>) -> view::Microbench {
        view::Microbench {
            run_id: run.into(),
            probe: "ptr_chase_latency".into(),
            param_json: "{}".into(),
            value: Some(1.0),
            unit: "cycles".into(),
            superseded: superseded_by.is_some(),
            superseded_by: superseded_by.map(str::to_string),
        }
    }

    /// A cited run whose rows a later run re-measured is "replaced" (history),
    /// with the replacing run named; an untouched one is "current".
    #[test]
    fn replaced_runs_are_history() {
        let micro = [mb("old", Some("new")), mb("old", Some("new")), mb("new", None)];
        let ctx = Ctx { runs: HashMap::new(), micro_all: &micro };
        let old = ctx.source("old", "ptr_chase_latency", None);
        assert_eq!((old.status, old.superseded_rows, old.superseded_by.clone()), ("replaced", 2, vec!["new".to_string()]));
        let new = ctx.source("new", "ptr_chase_latency", None);
        assert_eq!((new.status, new.superseded_rows), ("current", 0));
        assert_eq!(new.clocks_locked, None);
    }
}

//! Roof metrics, computed at view time from the arch file (contract rules 3
//! and 4). Nothing here is stored or cached between calls: a re-measured roof
//! updates every number the next time a view renders.
use std::collections::HashMap;

use aegis_perf::params::{self, ArchParams, BwKind};
use anyhow::Result;
use serde::Serialize;

use crate::Sources;

/// One arch's measured roofs (from `include/aegis/arch/sm_<arch>.json`).
#[derive(Clone, Debug, Serialize)]
pub struct ArchRoofs {
    pub sm: i64,
    pub arch_file: String,
    pub copy_bw_gbps: f64,
    pub read_bw_gbps: f64,
    pub peak_tflops: f64,
    pub ridge_read: f64,
    pub ridge_copy: f64,
    /// Shapes with M <= this are held to the read roof; the rest to the copy roof.
    pub decode_max_m: f64,
}

impl ArchRoofs {
    pub fn new(sm: i64, p: &ArchParams) -> Self {
        ArchRoofs {
            sm,
            arch_file: p.path.display().to_string(),
            copy_bw_gbps: p.copy_bw_gbps,
            read_bw_gbps: p.read_bw_gbps,
            peak_tflops: p.peak_tflops,
            ridge_read: p.ridge(BwKind::Read),
            ridge_copy: p.ridge(BwKind::Copy),
            decode_max_m: params::DECODE_MAX_M,
        }
    }
}

/// Roof position of one GEMM measurement (compulsory traffic, FP16).
#[derive(Clone, Debug, Serialize)]
pub struct RoofMetrics {
    pub ai: f64,
    pub tflops: f64,
    pub gbps: f64,
    /// Which memory roof the shape is held to: "read" (M <= 16) or "copy".
    pub roof: &'static str,
    pub roof_gbps: f64,
    pub pct_peak: f64,
    pub pct_bw: f64,
    pub pct_roof: f64,
    /// "memory" or "compute": which side of the ridge the shape's AI falls on.
    pub bound: &'static str,
}

pub fn metrics(p: &ArchParams, m: i64, n: i64, k: i64, median_us: f64) -> RoofMetrics {
    let r = p.roof(m as f64, n as f64, k as f64, median_us);
    RoofMetrics {
        ai: r.ai,
        tflops: r.tflops,
        gbps: r.gbps,
        roof: r.bw.name(),
        roof_gbps: p.bw(r.bw),
        pct_peak: r.pct_peak,
        pct_bw: r.pct_bw,
        pct_roof: r.pct_roof,
        bound: if r.memory_bound { "memory" } else { "compute" },
    }
}

/// The arch file of `sm`, or None when Core has not measured that arch (its
/// roof metrics then read "not measured").
pub fn load(src: &Sources, sm: i64) -> Result<Option<ArchParams>> {
    let path = src.arch_file(sm);
    if !path.exists() {
        return Ok(None);
    }
    params::load(&path).map(Some)
}

/// Arch files loaded once per view call (never across calls).
pub struct PerCall<'a> {
    src: &'a Sources,
    loaded: HashMap<i64, Option<ArchParams>>,
}

impl<'a> PerCall<'a> {
    pub fn new(src: &'a Sources) -> Self {
        PerCall { src, loaded: HashMap::new() }
    }

    pub fn get(&mut self, sm: i64) -> Result<Option<&ArchParams>> {
        if !self.loaded.contains_key(&sm) {
            let p = load(self.src, sm)?;
            self.loaded.insert(sm, p);
        }
        Ok(self.loaded[&sm].as_ref())
    }

    pub fn metrics(&mut self, sm: i64, m: i64, n: i64, k: i64, median_us: f64) -> Result<Option<RoofMetrics>> {
        Ok(self.get(sm)?.map(|p| metrics(p, m, n, k, median_us)))
    }
}

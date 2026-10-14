//! Roofline view: exactly the points `aegis-perf roofline` plots (one source,
//! `aegis_perf::roofline::points`), plus the hover data the SVG cannot carry:
//! config, % of cublaslt_best with its CI, and the tie call.
use aegis_perf::rusqlite::Connection;
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::roof::{self, ArchRoofs, RoofMetrics};
use crate::winners::{self, Tie, VsBaseline};
use crate::Sources;

#[derive(Clone, Debug, Serialize)]
pub struct Hover {
    pub kernel_id: Option<String>,
    pub config: Option<Value>,
    pub vs_cublaslt_best: Option<VsBaseline>,
    pub tie: Option<Tie>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Point {
    /// "<shape> <impl>", as `aegis-perf roofline` prints it.
    pub label: String,
    pub shape_bucket: String,
    pub m: i64,
    pub n: i64,
    pub k: i64,
    #[serde(rename = "impl")]
    pub impl_: String,
    /// "winner" or "cublaslt_best".
    pub series: &'static str,
    pub median_us: f64,
    pub roof: RoofMetrics,
    /// The shape's winner details (both series share them).
    pub hover: Hover,
}

#[derive(Clone, Debug, Serialize)]
pub struct Roofline {
    pub sm: i64,
    pub roofs: ArchRoofs,
    pub points: Vec<Point>,
}

/// The roofline of arch `sm`, or None when Core has no arch file for it.
pub fn roofline(src: &Sources, con: &Connection, sm: i64) -> Result<Option<Roofline>> {
    let Some(params) = roof::load(src, sm)? else { return Ok(None) };
    let winners = winners::winners(src, con, sm)?;
    let points = aegis_perf::roofline::points(con, sm, &params)?
        .into_iter()
        .map(|p| {
            let w = winners.iter().find(|w| w.op == "gemm" && w.shape_bucket == p.shape_bucket);
            Point {
                series: if p.baseline { "cublaslt_best" } else { "winner" },
                roof: roof::metrics(&params, p.m, p.n, p.k, p.median_us),
                hover: Hover {
                    kernel_id: w.map(|w| w.kernel_id.clone()),
                    config: w.map(|w| w.config.clone()),
                    vs_cublaslt_best: w.map(|w| w.vs_cublaslt_best.clone()),
                    tie: w.map(|w| w.tie.clone()),
                },
                label: p.label,
                shape_bucket: p.shape_bucket,
                m: p.m,
                n: p.n,
                k: p.k,
                impl_: p.impl_,
                median_us: p.median_us,
            }
        })
        .collect();
    Ok(Some(Roofline { sm, roofs: roof::ArchRoofs::new(sm, &params), points }))
}

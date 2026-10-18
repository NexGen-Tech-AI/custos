//! The win chain: one decode shape's win explained on one page, from what
//! the other views already compute: its roofline position, the kernel (config,
//! registers, spills, instruction mix, SASS with its provenance), the paired
//! CI against cublaslt_best, the dispatch decision, and the sections of Core's
//! docs that discuss the kernel at that shape. Nothing is computed here that a
//! view does not already show; a missing source is None ("not measured").
use aegis_perf::rusqlite::Connection;
use anyhow::Result;
use serde::Serialize;

use crate::docs::{self, DocRef};
use crate::kernel::{self, KernelDetail};
use crate::roofline::{self, Roofline};
use crate::winners::{self, ChainPick, Winner};
use crate::Sources;

#[derive(Clone, Debug, Serialize)]
pub struct WinChain {
    pub sm: i64,
    pub shape_bucket: String,
    /// Why this shape (set when it is the chain's pick).
    pub pick: Option<ChainPick>,
    /// The Winners row: CI, dispatch, paired-ab results, decode spotlight.
    pub winner: Winner,
    /// The Roofline view's data (None: no arch file).
    pub roofline: Option<Roofline>,
    /// The Kernel view's data for the winner's kernel.
    pub kernel: Option<KernelDetail>,
    /// Sections of Core's docs that name the kernel, or its family and the shape.
    pub docs: Vec<DocRef>,
}

/// The chain for `shape` on arch `sm`, or for the picked shape when `shape` is
/// None. None: no such winner (or nothing to pick).
pub fn win_chain(src: &Sources, con: &Connection, sm: i64, shape: Option<&str>) -> Result<Option<WinChain>> {
    let ws = winners::winners(src, con, sm)?;
    let w = match shape {
        Some(s) => ws.into_iter().find(|w| w.op == "gemm" && w.shape_bucket == s),
        None => ws.into_iter().find(|w| w.win_chain.is_some()),
    };
    let Some(w) = w else { return Ok(None) };
    Ok(Some(WinChain {
        sm,
        shape_bucket: w.shape_bucket.clone(),
        pick: w.win_chain.clone(),
        roofline: roofline::roofline(src, con, sm)?,
        kernel: kernel::kernel_detail(src, con, &w.kernel_id)?,
        docs: docs::about(src, &w.impl_, &winners::family(&w.impl_), &w.shape_bucket),
        winner: w,
    }))
}

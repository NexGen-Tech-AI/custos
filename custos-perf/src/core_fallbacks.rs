//! What Custos needs from AEGIS Core but aegis-perf (the pinned tag) does not
//! provide yet (contract rule 12). Each item cites its docs/core-requests.md
//! entry and goes away when Core ships it (then a pin bump, rule 23). The UI
//! labels every value derived from a constant here "provisional".
use std::path::Path;

use aegis_perf::rusqlite::{Connection, OpenFlags};
use anyhow::{Context, Result};

/// The schema version of a perf DB that `aegis_perf::db::connect_ro` refused,
/// so the UI can say which way it is off. aegis-perf only returns the refusal
/// as text ("DB schema vN, binary expects vM"); this opens the file read-only
/// (never a write, never a migration) and asks aegis-perf's own
/// `db::schema_version`. A DB without the table is v1, as Core counts it.
/// docs/core-requests.md #3 (a typed schema check).
pub fn db_schema_version(db: &Path) -> Result<i64> {
    let con = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .with_context(|| format!("open {} read-only", db.display()))?;
    Ok(aegis_perf::db::schema_version(&con)?.unwrap_or(1))
}

/// Production bar 3 (Core CLAUDE.md, "Production bar"): shapes >= 1024 in
/// every dimension are "large". Not in aegis-perf. docs/core-requests.md #4.
pub const LARGE_SHAPE_MIN_DIM: i64 = 1024;
/// Large shapes: >= 90% of cublaslt_best. docs/core-requests.md #4.
pub const LARGE_BAR: f64 = 0.90;
/// Decode shapes (M <= aegis_perf::params::DECODE_MAX_M, which is Core's):
/// >= 100% of cublaslt_best, "a tie or a win". docs/core-requests.md #4.
pub const DECODE_BAR: f64 = 1.00;
// Every shape: not below the floor, aegis_perf::tune::DISPATCH_FLOOR (Core's).

/// A winner's unpaired median % of cublaslt_best (Core's report and header)
/// and its paired CI disagree when the median lies more than this many points
/// outside the CI. Core has no such rule. docs/core-requests.md #4.
pub const DISAGREE_PTS: f64 = 2.0;

/// The cuBLASLt algorithm cublaslt_best picked at a shape (schema v4
/// `winners.lt_algo`), as aegis-perf renders it: an
/// `aegis::detail::LtAlgoConfig` (`tune::lt_config`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct LtAlgo {
    pub algo_id: i64,
    pub tile_id: i64,
    pub stages_id: i64,
    pub splitk: i64,
    pub reduction: i64,
    pub swizzle: i64,
    pub custom: i64,
    pub inner_shape: i64,
    pub cluster_shape: i64,
}

/// Each winner shape's stored cuBLASLt algorithm. aegis-perf (v0.4.0, v0.5.0) stores it
/// but `view::Winner` does not return it; the one library path is
/// `tune::header_text`, which reads it with Core's own query and writes it as
/// the last field of each winners-header row (`{id, tile, stages, splitk,
/// reduction, swizzle, custom, inner_shape, cluster_shape}`, `{}` when none).
/// Reads only. docs/core-requests.md #7.
pub fn stored_lt_algos(con: &Connection, arch: i64) -> Result<std::collections::HashMap<(i64, i64, i64), LtAlgo>> {
    let (text, _) = aegis_perf::tune::header_text(con, arch, "custos")?;
    let mut out = std::collections::HashMap::new();
    for line in text.lines().map(str::trim).filter(|l| l.starts_with('{')) {
        let code = line.split("//").next().unwrap_or("");
        let dims: Vec<i64> = code.trim_start_matches('{').split(',').take(3).filter_map(|d| d.trim().parse().ok()).collect();
        let [m, n, k] = dims[..] else { continue };
        let Some(open) = code.rfind('{') else { continue };
        let fields: Vec<i64> = code[open + 1..].split('}').next().unwrap_or("").split(',').filter_map(|f| f.trim().parse().ok()).collect();
        if let [algo_id, tile_id, stages_id, splitk, reduction, swizzle, custom, inner_shape, cluster_shape] = fields[..] {
            out.insert((m, n, k), LtAlgo { algo_id, tile_id, stages_id, splitk, reduction, swizzle, custom, inner_shape, cluster_shape });
        }
    }
    Ok(out)
}

/// A diagnosis Core states in prose in its docs, which Custos shows on the
/// shapes it names. Core has no machine-readable diagnosis per shape
/// (docs/core-requests.md #9), so each entry here names the doc section
/// and the sentences that state it; Custos shows the label only while that
/// section still states them (`docs::stated`), and links it. Never a Custos
/// judgement: an entry is added only for a statement Core made.
pub struct StatedDiagnosis {
    pub shapes: &'static [&'static str],
    pub label: &'static str,
    /// Under Core's docs/: "LOG.md" or "analysis/<name>.md".
    pub doc: &'static str,
    pub heading: &'static str,
    /// Each must appear verbatim in the section.
    pub quotes: &'static [&'static str],
}

pub const STATED_DIAGNOSES: &[StatedDiagnosis] = &[StatedDiagnosis {
    shapes: &["1x896x896", "16x896x896"],
    label: "below floor: launch-overhead bound",
    doc: "LOG.md",
    heading: "2026-10-17 — Phase C step 4: decode results, winners and dispatch",
    quotes: &["**The 896x896 shapes** run at ~65-70% of the floor", "They are bound by launch overhead"],
}];

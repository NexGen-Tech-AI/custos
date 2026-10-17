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

/// Production bar 3: `aegis::matmul` never runs a kernel below 80% of
/// cublaslt_best; such shapes dispatch to cuBLASLt. Core has this as
/// `tune::DISPATCH_FLOOR` and `tune::dispatch` since d80d03f, after
/// aegis-perf-v0.3.0, and records the result only in the winners header, not
/// in the perf DB. docs/core-requests.md #4.
pub const DISPATCH_FLOOR: f64 = 0.80;

/// Where `aegis::matmul` sends a winner's shape. Core's rule (`tune::dispatch`,
/// d80d03f), restated: cuBLASLt when the paired CI of cublaslt_best / winner
/// time lies entirely below the floor (upper bound below it); without a paired
/// CI, when the unpaired median ratio is below it; neither known: the kernel.
/// Returns (cuBLASLt?, the ratio the decision used, its basis: "paired",
/// "unpaired" or "none").
pub fn dispatch_to_cublaslt(lt_ci: Option<(f64, f64)>, pct_of_cublaslt_best: Option<f64>) -> (bool, Option<f64>, &'static str) {
    match (lt_ci, pct_of_cublaslt_best) {
        (Some((_, hi)), _) => (hi < DISPATCH_FLOOR, Some(hi), "paired"),
        (None, Some(p)) => (p / 100.0 < DISPATCH_FLOOR, Some(p / 100.0), "unpaired"),
        (None, None) => (false, None, "none"),
    }
}

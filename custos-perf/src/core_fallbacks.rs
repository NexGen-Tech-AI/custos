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

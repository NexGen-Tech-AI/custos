//! Startup check: can Custos read this perf DB? The supported schema range
//! comes from aegis-perf (contract rule 12): `connect_ro` accepts exactly
//! `db::SCHEMA_VERSION`. A DB outside it, in either direction, is a state the
//! UI shows ("Incompatible perf DB: ..."), never a crash.
use serde::Serialize;

use crate::{core_fallbacks, Sources};

/// Oldest and newest perf DB schema this build reads (from aegis-perf).
pub const SUPPORTED_SCHEMA: (i64, i64) = (aegis_perf::db::SCHEMA_VERSION, aegis_perf::db::SCHEMA_VERSION);

#[derive(Clone, Debug, Serialize)]
pub struct DbStatus {
    /// "ok", "missing", "incompatible" (schema outside the supported range,
    /// or a column aegis-perf needs is missing) or "unreadable".
    pub state: &'static str,
    pub db: String,
    /// The DB's schema version, when it could be read.
    pub db_schema: Option<i64>,
    pub supported: (i64, i64),
    /// What to show: None when the DB is usable.
    pub message: Option<String>,
}

fn range((a, b): (i64, i64)) -> String {
    if a == b { format!("v{a}") } else { format!("v{a}–v{b}") }
}

pub fn db_status(src: &Sources) -> DbStatus {
    let supported = SUPPORTED_SCHEMA;
    let status = |state, db_schema, message: Option<String>| DbStatus {
        state,
        db: src.db.display().to_string(),
        db_schema,
        supported,
        message,
    };
    if !src.db.exists() {
        return status("missing", None, Some(format!("No perf DB at {}", src.db.display())));
    }
    let refused = match src.open() {
        Ok(con) => return status("ok", aegis_perf::db::schema_version(&con).ok().flatten(), None),
        Err(e) => format!("{e:#}"),
    };
    match core_fallbacks::db_schema_version(&src.db) {
        Ok(v) if v < supported.0 || v > supported.1 => status(
            "incompatible",
            Some(v),
            Some(format!("Incompatible perf DB: DB schema v{v}, Custos supports {}", range(supported))),
        ),
        // In range, yet refused (e.g. a column aegis-perf reads is missing): Core's reason.
        Ok(v) => status("incompatible", Some(v), Some(format!("Incompatible perf DB: {refused}"))),
        Err(e) => status("unreadable", None, Some(format!("Unreadable perf DB: {refused} ({e:#})"))),
    }
}

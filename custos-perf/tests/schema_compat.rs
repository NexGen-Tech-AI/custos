//! The startup schema check on doctored copies of the committed fixture: a DB
//! one schema version behind and one ahead are each a clear "incompatible"
//! state, never a crash, and every perf view returns an error instead of data.
use std::path::PathBuf;

use aegis_perf::db::SCHEMA_VERSION;
use custos_perf::{status::SUPPORTED_SCHEMA, Sources};

/// A copy of the committed fixture (a file no process writes, so a plain
/// copy is a consistent one) with its schema_version set to `v`.
fn doctored(name: &str, v: i64) -> Sources {
    let mut s = Sources::repo_fixtures();
    let dir = std::env::temp_dir().join(format!("custos-schema-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db: PathBuf = dir.join("aegis_perf.db");
    std::fs::copy(&s.db, &db).unwrap();
    let con = aegis_perf::rusqlite::Connection::open(&db).unwrap();
    con.execute("UPDATE schema_version SET version = ?1 WHERE id = 1", [v]).unwrap();
    s.db = db;
    s
}

#[test]
fn supported_range_comes_from_aegis_perf() {
    assert_eq!(SUPPORTED_SCHEMA, (SCHEMA_VERSION, SCHEMA_VERSION));
    let s = Sources::repo_fixtures();
    let st = custos_perf::db_status(&s);
    assert_eq!((st.state, st.db_schema, st.message), ("ok", Some(SCHEMA_VERSION), None));
}

#[test]
fn older_db_is_incompatible_not_a_crash() {
    let s = doctored("older", SCHEMA_VERSION - 1);
    let st = custos_perf::db_status(&s);
    assert_eq!(st.state, "incompatible");
    assert_eq!(st.db_schema, Some(SCHEMA_VERSION - 1));
    assert_eq!(
        st.message.as_deref(),
        Some(format!("Incompatible perf DB: DB schema v{}, Custos supports v{SCHEMA_VERSION}", SCHEMA_VERSION - 1).as_str())
    );
    assert!(s.open().is_err(), "every view call fails with Core's reason instead of reading");
    std::fs::remove_dir_all(s.db.parent().unwrap()).ok();
}

#[test]
fn newer_db_is_incompatible_not_a_crash() {
    let s = doctored("newer", SCHEMA_VERSION + 1);
    let st = custos_perf::db_status(&s);
    assert_eq!(st.state, "incompatible");
    assert_eq!(st.db_schema, Some(SCHEMA_VERSION + 1));
    assert_eq!(
        st.message.as_deref(),
        Some(format!("Incompatible perf DB: DB schema v{}, Custos supports v{SCHEMA_VERSION}", SCHEMA_VERSION + 1).as_str())
    );
    let err = format!("{:#}", s.open().unwrap_err());
    assert!(err.contains(&format!("binary expects v{SCHEMA_VERSION}")), "{err}");
    std::fs::remove_dir_all(s.db.parent().unwrap()).ok();
}

#[test]
fn missing_db_is_a_state() {
    let mut s = Sources::repo_fixtures();
    s.db = std::env::temp_dir().join("custos-no-such-perf.db");
    let st = custos_perf::db_status(&s);
    assert_eq!(st.state, "missing");
    assert!(!s.db.exists(), "the check never creates a DB");
}

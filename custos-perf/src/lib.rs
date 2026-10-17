//! AEGIS Custos data layer: read-only views over the AEGIS Core perf DB.
//!
//! Every query goes through `aegis_perf` (project rule 17), every DB handle
//! is read-only (contract rule 1), and roof-derived metrics are computed here
//! at view time from the arch file (contract rule 3), never stored.
use std::path::{Path, PathBuf};

pub use aegis_perf::rusqlite::Connection;
use anyhow::Result;

/// Where Custos reads Core's data from.
#[derive(Clone, Debug)]
pub struct Sources {
    /// The perf DB (opened read-only).
    pub db: PathBuf,
    /// The AEGIS Core repo root: arch files, manifests, artifacts, docs.
    pub core: PathBuf,
}

impl Sources {
    /// `AEGIS_PERFDB` (default `~/custos-fixtures/aegis_perf.db`) and
    /// `AEGIS_CORE` (default `~/Documents/projects/aegis`).
    pub fn from_env() -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        let var = |k: &str, default: PathBuf| std::env::var_os(k).map(PathBuf::from).unwrap_or(default);
        Sources {
            db: var("AEGIS_PERFDB", home.join("custos-fixtures/aegis_perf.db")),
            core: var("AEGIS_CORE", home.join("Documents/projects/aegis")),
        }
    }

    pub fn open(&self) -> Result<Connection> {
        aegis_perf::db::connect_ro(&self.db)
    }

    pub fn arch_file(&self, sm: i64) -> PathBuf {
        self.core.join(aegis_perf::params::arch_file(sm))
    }

    pub fn core_path(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.core.join(rel)
    }
}

pub mod device;
pub mod kernel;
pub mod measure;
pub mod roof;
pub mod roofline;
pub mod winners;

pub use device::{arch_model, devices, measured_archs};
pub use kernel::kernel_detail;
pub use measure::{compare, measurements, Filter};
pub use roofline::roofline;
pub use winners::winners;

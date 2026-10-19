//! AEGIS Custos data layer: read-only views over the AEGIS Core perf DB.
//!
//! Every query goes through `aegis_perf` (project rule 17), every DB handle
//! is read-only (contract rule 1), and roof-derived metrics are computed here
//! at view time from the arch file (contract rule 3), never stored.
use std::path::{Path, PathBuf};

pub use aegis_perf::rusqlite::Connection;
use anyhow::Result;

/// Where Custos reads Core's data from: the perf DB and the files Core
/// generates (arch files, manifests, SASS and Nsight artifacts).
#[derive(Clone, Debug)]
pub struct Sources {
    /// The perf DB (opened read-only).
    pub db: PathBuf,
    /// Describes the source on screen: the Core repo root, or the fixture dir.
    pub root: PathBuf,
    /// `sm_<arch>.json` arch files.
    pub arch_dir: PathBuf,
    /// `manifest-<device>.json` (aegis_manifest).
    pub manifest_dir: PathBuf,
    /// `sm_<arch>/` SASS directories.
    pub sass_dir: PathBuf,
    /// Nsight Compute reports (`*.ncu-rep`).
    pub ncu_dir: PathBuf,
    /// Winners headers: `sm_<arch>.h` (what aegis::matmul dispatches), and
    /// `<build>/sm_<arch>.h`, the header a past build ran (core_fallbacks::build_header).
    pub winners_dir: PathBuf,
    /// Core's docs: `LOG.md` and `analysis/*.md`.
    pub docs_dir: PathBuf,
    /// The nightly job's outputs (`fuzz-<stamp>.txt`).
    pub nightly_dir: PathBuf,
}

impl Sources {
    /// A Core checkout: `include/aegis/arch`, `results/`, `artifacts/`.
    pub fn core(core: impl Into<PathBuf>, db: impl Into<PathBuf>) -> Self {
        let core = core.into();
        Sources {
            db: db.into(),
            arch_dir: core.join("include/aegis/arch"),
            manifest_dir: core.join("results"),
            sass_dir: core.join("artifacts/sass"),
            ncu_dir: core.join("artifacts/ncu"),
            winners_dir: core.join("include/aegis/winners"),
            docs_dir: core.join("docs"),
            nightly_dir: core.join("results/nightly"),
            root: core,
        }
    }

    /// The committed fixtures (tests/fixtures/, flat; see its README).
    pub fn fixtures(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Sources {
            db: dir.join("aegis_perf.db"),
            arch_dir: dir.clone(),
            manifest_dir: dir.clone(),
            sass_dir: dir.join("sass"),
            ncu_dir: dir.join("ncu"),
            winners_dir: dir.join("winners"),
            docs_dir: dir.join("docs"),
            nightly_dir: dir.join("nightly"),
            root: dir,
        }
    }

    /// This repo's tests/fixtures/ (resolved at compile time).
    pub fn repo_fixtures() -> Self {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures");
        Self::fixtures(dir.canonicalize().unwrap_or(dir))
    }

    /// `AEGIS_CORE` (a Core checkout) with `AEGIS_PERFDB` (default: its
    /// `results/aegis_perf.db`). Without `AEGIS_CORE`, the repo fixtures
    /// (`AEGIS_PERFDB` still overrides the DB).
    pub fn from_env() -> Self {
        let db = std::env::var_os("AEGIS_PERFDB").map(PathBuf::from);
        match std::env::var_os("AEGIS_CORE").map(PathBuf::from) {
            Some(core) => {
                let db = db.unwrap_or_else(|| core.join("results/aegis_perf.db"));
                Self::core(core, db)
            }
            None => {
                let mut s = Self::repo_fixtures();
                if let Some(db) = db {
                    s.db = db;
                }
                s
            }
        }
    }

    pub fn open(&self) -> Result<Connection> {
        aegis_perf::db::connect_ro(&self.db)
    }

    /// The winners header aegis::matmul dispatches from (`sm_<arch>.h`).
    pub fn winners_header(&self, sm: i64) -> PathBuf {
        self.winners_dir.join(format!("sm_{sm}.h"))
    }

    pub fn arch_file(&self, sm: i64) -> PathBuf {
        let name = aegis_perf::params::arch_file(sm);
        self.arch_dir.join(name.file_name().expect("arch_file names a file"))
    }
}

pub mod aegis_adapter;
pub mod core_fallbacks;
pub mod device;
pub mod docs;
pub mod kernel;
pub mod measure;
pub mod regression;
pub mod roof;
pub mod roofline;
pub mod status;
pub mod win_chain;
pub mod winners;

pub use device::{arch_model, devices, measured_archs};
pub use kernel::kernel_detail;
pub use measure::{compare, measurements, Filter};
pub use regression::regression;
pub use roofline::roofline;
pub use status::{db_status, DbStatus};
pub use win_chain::win_chain;
pub use winners::winners;

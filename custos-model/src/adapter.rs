//! The adapter interface. Each source (AEGIS, Nsight Systems, Nsight Compute,
//! NVML, sysfs, SASS) has an adapter that reports whether its tool is usable
//! here and turns the source's recorded output into a [`Capture`].
//!
//! Reading a recorded output (an nsys SQLite export, ncu CSV pages, a perf DB)
//! needs no NVIDIA tool. Producing one (`nsys export`, `ncu --import --csv`)
//! does; without the tool the adapter says "unavailable" with the reason,
//! never an error from a missing binary.
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::model::Capture;
use crate::provenance::{Known, Source};

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Availability {
    Available { tool: String, version: Known<String> },
    Unavailable { reason: String },
}

pub trait Adapter {
    fn source(&self) -> Source;
    /// Whether the tool that produces this source's records is usable here.
    fn availability(&self) -> Availability;
}

/// What an adapter ingests: a recorded output, never a live profile.
pub trait Ingest: Adapter {
    type Input: ?Sized;
    fn ingest(&self, input: &Self::Input) -> anyhow::Result<Capture>;
}

/// Where NVIDIA's tools are installed when they are not on PATH.
pub const TOOL_DIRS: &[&str] = &["/usr/local/cuda/bin"];

/// `name` on PATH, else in `dirs`.
pub fn find_tool(name: &str, path: Option<&std::ffi::OsStr>, dirs: &[&str]) -> Option<PathBuf> {
    let from_path = path.map(|p| std::env::split_paths(p).map(|d| d.join(name)).collect::<Vec<_>>()).unwrap_or_default();
    from_path
        .into_iter()
        .chain(dirs.iter().map(|d| Path::new(d).join(name)))
        .find(|p| p.is_file())
}

/// The first line of `tool --version` that contains a version number.
pub fn tool_version(tool: &Path) -> Known<String> {
    match Command::new(tool).arg("--version").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .rev()
            .find(|l| l.chars().any(|c| c.is_ascii_digit()) && l.to_lowercase().contains("version"))
            .map_or(Known::Unknown("--version printed no version".into()), |l| Known::Known(l.trim().to_string())),
        Ok(o) => Known::Unknown(format!("--version exited {}", o.status)),
        Err(e) => Known::Unknown(format!("--version failed: {e}")),
    }
}

/// Availability of a command-line tool, searched on `path` (the process PATH by default) and TOOL_DIRS.
pub fn command_availability(name: &str, path: Option<&std::ffi::OsStr>, dirs: &[&str]) -> Availability {
    match find_tool(name, path, dirs) {
        Some(p) => Availability::Available { tool: name.to_string(), version: tool_version(&p) },
        None => Availability::Unavailable { reason: format!("{name} is not installed (not on PATH, not in {})", dirs.join(", ")) },
    }
}

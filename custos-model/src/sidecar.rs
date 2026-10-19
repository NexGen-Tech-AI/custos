//! The sidecar `tools/capture_fixtures.sh` writes beside each recorded output
//! (`<stem>.meta.json`): what the output itself does not record. An nsys
//! export records only its schema; an ncu report does not record its clock
//! control, and neither records the profiled build.
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::Value;
use crate::provenance::Build;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Sidecar {
    /// "nsys" | "ncu".
    #[serde(default)]
    pub tool: Option<String>,
    /// `nsys --version` / `ncu --version`, last line.
    #[serde(default)]
    pub tool_version: Option<String>,
    /// The profiled build (`bench_gemm --build-info`): 40 hex digits and dirty.
    #[serde(default)]
    pub build_sha: Option<String>,
    #[serde(default)]
    pub build_dirty: Option<bool>,
    /// NVIDIA driver (`nvidia-smi --query-gpu=driver_version`).
    #[serde(default)]
    pub driver_version: Option<String>,
    /// The CUDA version the driver supports (`nvidia-smi`'s header).
    #[serde(default)]
    pub cuda_driver_version: Option<String>,
    /// The CUDA toolkit (`nvcc --version`).
    #[serde(default)]
    pub cuda_toolkit_version: Option<String>,
    /// ncu's `--clock-control`, as passed (the script always passes it).
    #[serde(default)]
    pub clock_control: Option<String>,
    /// The exact command lines, one argv each, with the Core checkout and the
    /// output directory written `<core>` and `<out>` (rule 28).
    #[serde(default)]
    pub commands: Vec<Vec<String>>,
    /// A hand-built fixture.
    #[serde(default)]
    pub synthetic: bool,
}

impl Sidecar {
    /// `<dir>/<stem>.meta.json`, if present.
    pub fn load(dir: &Path, stem: &str) -> Result<Option<Sidecar>> {
        let p = dir.join(format!("{stem}.meta.json"));
        if !p.exists() {
            return Ok(None);
        }
        let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
        Ok(Some(serde_json::from_str(&s).with_context(|| format!("parse {}", p.display()))?))
    }

    /// The sidecar of an export file (`decode-1x896x896.sqlite` -> `decode-1x896x896.meta.json`).
    pub fn for_file(file: &Path) -> Result<Option<Sidecar>> {
        let dir = file.parent().unwrap_or(Path::new("."));
        let stem = file.file_stem().map_or_else(String::new, |s| s.to_string_lossy().into_owned());
        Sidecar::load(dir, &stem)
    }

    pub fn build(&self) -> Option<Build> {
        match (&self.build_sha, self.build_dirty) {
            (Some(s), Some(d)) => Build::full(s, d),
            _ => None,
        }
    }

    fn field(v: &Option<String>) -> Value<String> {
        v.clone().map_or(Value::NotAvailable("not recorded (no capture sidecar)".into()), Value::Present)
    }
    pub fn driver(&self) -> Value<String> {
        Self::field(&self.driver_version)
    }
    pub fn cuda_driver(&self) -> Value<String> {
        Self::field(&self.cuda_driver_version)
    }
    pub fn cuda_toolkit(&self) -> Value<String> {
        Self::field(&self.cuda_toolkit_version)
    }
}

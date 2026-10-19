//! Jetson telemetry, where NVML does not exist: Linux sysfs and tegrastats
//! output (CLAUDE.md rule 8: continuous telemetry, never hardware counters).
//! The GPU load files are AEGIS Core's (its idle guard, src/bench/harness.cu):
//! per mille, the first that exists of [`LOAD_PATHS`]; tegrastats GR3D_FREQ as
//! Core parses it.
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::model::{Capture, Counter, Quantity, Value};
use crate::provenance::{Clocks, Known, Provenance, Source};
use crate::telemetry::{spec, Read, TelemetryBackend};

/// The Tegra GPU load file (per mille), in Core's order.
pub const LOAD_PATHS: &[&str] = &[
    "sys/devices/platform/gpu.0/load",
    "sys/devices/gpu.0/load",
    "sys/devices/platform/17000000.gpu/load",
    "sys/devices/platform/bus@0/17000000.gpu/load",
];

/// Jetson sysfs under `root` ("/" on the device; a recorded tree in tests).
#[derive(Clone, Debug)]
pub struct Sysfs {
    pub root: PathBuf,
    /// A hand-built tree (the tests'): its records are synthetic.
    pub synthetic: bool,
}

fn read_trim(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim_matches(|c: char| c.is_whitespace() || c == '\0').to_string())
}

impl Sysfs {
    pub fn new(root: impl Into<PathBuf>) -> Sysfs {
        Sysfs { root: root.into(), synthetic: false }
    }
    fn load_file(&self) -> Option<PathBuf> {
        LOAD_PATHS.iter().map(|p| self.root.join(p)).find(|p| p.exists())
    }
    /// The GPU's devfreq node (its name names the GPU).
    fn devfreq(&self) -> Option<PathBuf> {
        let rd = std::fs::read_dir(self.root.join("sys/class/devfreq")).ok()?;
        let mut v: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().is_some_and(|n| {
                let n = n.to_string_lossy();
                n.contains("gpu") || n.contains("ga10b") || n.contains("gv11b") || n.contains("gp10b")
            }))
            .collect();
        v.sort();
        v.into_iter().next()
    }
    /// The GPU thermal zone (type "GPU-therm" / "gpu-thermal").
    fn thermal_zone(&self) -> Option<PathBuf> {
        let rd = std::fs::read_dir(self.root.join("sys/class/thermal")).ok()?;
        let mut v: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("thermal_zone")))
            .filter(|p| read_trim(&p.join("type")).is_some_and(|t| t.eq_ignore_ascii_case("gpu-therm") || t.eq_ignore_ascii_case("gpu-thermal")))
            .collect();
        v.sort();
        v.into_iter().next()
    }
    fn number(p: Option<PathBuf>, scale: f64) -> Read<f64> {
        let Some(p) = p else { return Read::NotSupported };
        match read_trim(&p).map(|s| s.parse::<f64>()) {
            Some(Ok(v)) => Read::Ok(v * scale),
            Some(Err(e)) => Read::Err(format!("{}: {e}", p.file_name().unwrap_or_default().to_string_lossy())),
            None => Read::Err("cannot read".into()),
        }
    }
}

impl TelemetryBackend for Sysfs {
    fn source(&self) -> Source {
        Source::Sysfs
    }
    fn tool(&self) -> (String, Known<String>) {
        let kernel = read_trim(&self.root.join("proc/sys/kernel/osrelease"));
        ("sysfs".into(), kernel.map_or(Known::Unknown("kernel release not readable".into()), |k| Known::Known(format!("Linux {k}"))))
    }
    /// L4T release (/etc/nv_tegra_release), the Jetson driver stack.
    fn driver_version(&self) -> Read<String> {
        match read_trim(&self.root.join("etc/nv_tegra_release")) {
            Some(s) => Read::Ok(s.lines().next().unwrap_or("").trim_start_matches("# ").to_string()),
            None => Read::NotSupported,
        }
    }
    fn cuda_driver_version(&self) -> Read<String> {
        Read::NotRead("not in sysfs".into())
    }
    fn device_count(&self) -> Result<u32> {
        Ok(u32::from(self.load_file().is_some() || self.devfreq().is_some()))
    }
    fn name(&self, _: u32) -> Read<String> {
        read_trim(&self.root.join("proc/device-tree/model")).map_or(Read::NotSupported, Read::Ok)
    }
    fn compute_capability(&self, _: u32) -> Read<(i64, i64)> {
        Read::NotRead("not in sysfs".into())
    }
    fn read(&self, _: u32, field: &str) -> Read<f64> {
        match field {
            "utilization.gpu" => Self::number(self.load_file(), 0.1),
            "clocks.graphics" => Self::number(self.devfreq().map(|d| d.join("cur_freq")), 1e-6),
            "temperature.gpu" => Self::number(self.thermal_zone().map(|z| z.join("temp")), 1e-3),
            f if f.starts_with("power.") || f == "energy.total" => {
                Read::NotRead("not read from sysfs (the INA3221 rails vary by board; tegrastats reports VDD_GPU_SOC)".into())
            }
            _ => Read::NotRead("not read from sysfs".into()),
        }
    }
    fn synthetic(&self) -> bool {
        self.synthetic
    }
}

/// One tegrastats line's GPU fields: GR3D_FREQ load (and its frequency), the
/// GPU temperature, the VDD_GPU_SOC rail (current reading; the GPU and SoC
/// together). An optional leading "MM-DD-YYYY HH:MM:SS" is the sample time.
pub fn parse_tegrastats_line(line: &str) -> (Option<String>, Vec<(&'static str, f64)>) {
    let mut out = Vec::new();
    let words: Vec<&str> = line.split_whitespace().collect();
    let at = match (words.first(), words.get(1)) {
        (Some(d), Some(t)) if d.len() == 10 && d.as_bytes()[2] == b'-' && t.len() == 8 && t.as_bytes()[2] == b':' => {
            Some(format!("{}-{}-{}T{t}", &d[6..10], &d[0..2], &d[3..5]))
        }
        _ => None,
    };
    let num = |s: &str| s.trim_end_matches(|c: char| !c.is_ascii_digit() && c != '.').parse::<f64>().ok();
    for (i, w) in words.iter().enumerate() {
        if *w == "GR3D_FREQ" {
            if let Some(v) = words.get(i + 1) {
                let (pct, freq) = v.split_once('@').unwrap_or((v, ""));
                if let Some(p) = pct.strip_suffix('%').and_then(|p| p.parse::<f64>().ok()) {
                    out.push(("utilization.gpu", p));
                }
                if let Some(f) = freq.trim_start_matches('[').split(',').next().and_then(num) {
                    out.push(("clocks.graphics", f));
                }
            }
        } else if let Some(t) = w.strip_prefix("gpu@").or_else(|| w.strip_prefix("GPU@")) {
            if let Some(c) = t.strip_suffix('C').and_then(|c| c.parse::<f64>().ok()) {
                out.push(("temperature.gpu", c));
            }
        } else if *w == "VDD_GPU_SOC" {
            if let Some(mw) = words.get(i + 1).and_then(|v| v.split('/').next()).and_then(|v| v.strip_suffix("mW")).and_then(|v| v.parse::<f64>().ok()) {
                out.push(("power.usage", mw));
            }
        }
    }
    (at, out)
}

/// Recorded tegrastats output as telemetry counters for `device`.
pub fn ingest_tegrastats(text: &str, device: &str, origin: &str, synthetic: bool) -> Capture {
    let mut c = Capture::default();
    for line in text.lines() {
        let (at, fields) = parse_tegrastats_line(line);
        for (field, v) in fields {
            let mut p = Provenance::new(Source::Sysfs, "tegrastats", Known::Unknown("tegrastats prints no version".into()), origin);
            p.captured_at = at.clone();
            p.clocks = Clocks::unknown("telemetry: the clocks are read, their lock state is not");
            p.synthetic = synthetic;
            let s = spec(field).expect("a known field");
            c.counters.push(Counter {
                launch: None,
                device: Some(device.to_string()),
                metric: field.to_string(),
                section: Some("telemetry".into()),
                label: Some(if field == "power.usage" { "VDD_GPU_SOC rail (GPU and SoC)".into() } else { s.label.to_string() }),
                quantity: Quantity { value: Value::Present(v), unit: s.unit.to_string() },
                provenance: p,
            });
        }
    }
    c
}

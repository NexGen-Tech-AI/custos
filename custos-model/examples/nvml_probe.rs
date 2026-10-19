//! One-shot, read-only telemetry capability probe: which fields each device
//! reports, and how often power and energy update and by how much. Reads only
//! (no load, no profiling, no GPU lock needed); about `--window-ms` of
//! repeated reads per power / energy field.
//!
//!   cargo run --release --manifest-path custos-model/Cargo.toml --features nvml --example nvml_probe
//!       [-- --window-ms 2000] [--record FILE]
//!   ... --example nvml_probe -- --sysfs /           (Jetson sysfs; no feature needed)
//!   ... --example nvml_probe -- --replay FILE       (a recorded probe, e.g. the tests' NVML mock)
//!
//! `--record FILE` writes the probe as a recorded probe (custos_model::nvml::Recorded:
//! no UUID, serial, PCI id or host name), to be committed as a real fixture.
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use custos_model::model::{Support, Value};
use custos_model::nvml::{FieldRecord, Nvml, Recorded, RecordedDevice};
use custos_model::telemetry::{self, granularity, Read, TelemetryBackend, FIELDS};

/// Fields whose update rate and step matter for energy / power work.
const TIMED: &[&str] = &["power.usage", "power.instant", "power.average", "energy.total"];

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn backend(args: &[String]) -> Result<(Box<dyn TelemetryBackend>, Option<Recorded>), String> {
    if let Some(f) = arg(args, "--replay") {
        let r = Recorded::load(std::path::Path::new(&f)).map_err(|e| format!("{e:#}"))?;
        return Ok((Box::new(r.clone()), Some(r)));
    }
    if let Some(root) = arg(args, "--sysfs") {
        return Ok((Box::new(custos_model::jetson::Sysfs::new(root)), None));
    }
    open_nvml()
}

#[cfg(feature = "nvml")]
fn open_nvml() -> Result<(Box<dyn TelemetryBackend>, Option<Recorded>), String> {
    Nvml::default().open().map(|l| (Box::new(l) as Box<dyn TelemetryBackend>, None)).map_err(|e| format!("{e:#}"))
}
#[cfg(not(feature = "nvml"))]
fn open_nvml() -> Result<(Box<dyn TelemetryBackend>, Option<Recorded>), String> {
    let e = Nvml::default().open().err().map(|e| format!("{e:#}")).unwrap_or_default();
    Err(format!("{e}: rerun with --features nvml (or use --sysfs ROOT / --replay FILE)"))
}

fn show<T: std::fmt::Display>(v: &Value<T>) -> String {
    match v {
        Value::Present(x) => x.to_string(),
        Value::NotMeasured => "not measured".into(),
        Value::NotAvailable(why) => why.clone(),
    }
}

/// Repeated reads of one field for `window`, 1 ms apart: (ms, value).
fn series(b: &dyn TelemetryBackend, dev: u32, field: &str, window: Duration) -> Vec<(f64, f64)> {
    let t0 = Instant::now();
    let mut out = Vec::new();
    while t0.elapsed() < window {
        if let Read::Ok(v) = b.read(dev, field) {
            out.push((t0.elapsed().as_secs_f64() * 1e3, v));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    out
}

/// The change points of a series (and its last read): what `granularity` needs.
fn changes_only(s: &[(f64, f64)]) -> Vec<(f64, f64)> {
    let mut out: Vec<(f64, f64)> = Vec::new();
    for &(t, v) in s {
        if out.last().is_none_or(|l| l.1 != v) {
            out.push((t, v));
        }
    }
    if let (Some(&l), Some(o)) = (s.last(), out.last()) {
        if o.0 != l.0 {
            out.push(l);
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let window = Duration::from_millis(arg(&args, "--window-ms").and_then(|w| w.parse().ok()).unwrap_or(2000));
    let (b, replay) = match backend(&args) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let at = telemetry::utc_now();
    let c = match telemetry::probe(b.as_ref(), &at) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("probe failed: {e:#}");
            std::process::exit(1);
        }
    };
    let (tool, version) = b.tool();
    let run = &c.runs[0];
    println!("{tool} {}  driver {}  CUDA (driver) {}  probed {at}{}", version.known().cloned().unwrap_or_else(|| "version unknown".into()),
        show(&run.driver), show(&run.cuda_driver), if b.synthetic() { "  [SYNTHETIC]" } else { "" });
    if c.devices.is_empty() {
        println!("no devices");
    }
    let mut rec = Recorded {
        synthetic: b.synthetic(),
        note: Some(format!("Recorded by examples/nvml_probe at {at} (read-only probe, {} ms windows)", window.as_millis())),
        nvml_version: version.known().cloned(),
        driver_version: run.driver.present().cloned(),
        cuda_driver_version: run.cuda_driver.present().cloned(),
        devices: Vec::new(),
    };
    for (i, d) in c.devices.iter().enumerate() {
        let sm = d.sm_arch.present().map_or_else(|| show(&d.sm_arch), |a| format!("sm_{a}"));
        println!("\n{}: {}  ({sm})", d.id, show(&d.name));
        println!("  {:<22} {:<15} {:>14} {:<8} granularity (observed)", "field", "support", "value", "unit");
        let mut rd = RecordedDevice {
            name: d.name.present().cloned(),
            compute_capability: b.compute_capability(i as u32).ok(),
            fields: BTreeMap::new(),
            series: BTreeMap::new(),
            granularity: BTreeMap::new(),
        };
        for f in FIELDS {
            let cap = d.capability(f.field).unwrap();
            let now = b.read(i as u32, f.field);
            let now_copy = now.clone();
            let (support, value) = match (&cap.support, &now) {
                (Support::Supported, Read::Ok(v)) => ("supported".to_string(), format!("{v}")),
                (Support::NotSupported, _) => ("NOT SUPPORTED".to_string(), "-".to_string()),
                (Support::NotRead(w), _) => ("not read".to_string(), w.clone()),
                (Support::Error(e), _) | (_, Read::Err(e)) => ("error".to_string(), e.clone()),
                _ => ("?".to_string(), "-".to_string()),
            };
            rd.fields.insert(
                f.field.to_string(),
                match now {
                    Read::Ok(v) => FieldRecord::Value { value: v },
                    Read::NotSupported => FieldRecord::Status("not_supported".into()),
                    Read::NotRead(_) => FieldRecord::Status("not_read".into()),
                    Read::Err(e) => FieldRecord::Error { error: e },
                },
            );
            let mut gran = String::new();
            if let (Read::Ok(bits), "clocks_event_reasons") = (&now_copy, f.field) {
                gran = telemetry::clock_event_reasons(*bits as u64).join(", ");
            }
            if TIMED.contains(&f.field) && cap.support == Support::Supported {
                let s = match &replay {
                    Some(r) => r.devices[i].series.get(f.field).cloned().unwrap_or_default(),
                    None => series(b.as_ref(), i as u32, f.field, window),
                };
                if !s.is_empty() {
                    gran = granularity(&s).describe(f.unit);
                    rd.granularity.insert(f.field.to_string(), gran.clone());
                    rd.series.insert(f.field.to_string(), changes_only(&s));
                }
            }
            println!("  {:<22} {:<15} {:>14} {:<8} {gran}", f.field, support, value, f.unit);
        }
        rec.devices.push(rd);
        let has = |f: &str| d.capability(f).is_some_and(|c| c.support == Support::Supported);
        println!(
            "\n  power: {}; total energy counter: {}",
            if TIMED[..3].iter().any(|f| has(f)) {
                format!("reported ({})", TIMED[..3].iter().filter(|f| has(f)).copied().collect::<Vec<_>>().join(", "))
            } else {
                "NOT reported".into()
            },
            if has("energy.total") { "reported (mJ since driver load)" } else { "NOT reported" }
        );
    }
    if let Some(path) = arg(&args, "--record") {
        let json = serde_json::to_string_pretty(&rec).unwrap();
        if let Err(e) = std::fs::write(&path, json + "\n") {
            eprintln!("cannot write {path}: {e}");
            std::process::exit(1);
        }
        eprintln!("recorded to {path}");
    }
}

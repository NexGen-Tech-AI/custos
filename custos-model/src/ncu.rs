//! Nsight Compute: a report's CSV pages, `ncu --import <report> --csv
//! --print-units base --page details | raw | session` ([`export`]), read into
//! the model. Base units matter: without them ncu scales and rounds the raw page
//! (56.848 Kbyte/block), and byte fields are then "not available", never rounded.
//!
//! - details: per launch, per section, the metrics ncu shows (SOL, memory and
//!   compute workload, scheduler and warp state, launch statistics,
//!   occupancy). Rule rows are kept as notes by name only: their "Estimated
//!   Speedup" is ncu's estimate, never a value here (CLAUDE.md rule 9).
//! - raw: every metric id of every launch (stall reasons, pipe utilization,
//!   throughput, bank conflicts, registers, shared memory, waves), with units.
//! - session: the ncu version, when the report was created, the CUDA and
//!   driver versions, device attributes, and the clock-control mode.
//!
//! Dropped on ingest (rule 28): host name, process id and name, target IP
//! addresses, process paths, and the profiler command line, of which only
//! `--clock-control` is read. ncu does not export the mode itself: when the
//! recorded command line has no `--clock-control`, the mode is ncu's documented
//! default, `base`, and the provenance says that is how it is known.
//!
//! Every value is a profiled metric (rule 8: never mixed with telemetry), and
//! durations are profiler timings (rule 25), collected under replay.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::adapter::{command_availability, Adapter, Availability, Ingest, TOOL_DIRS};
use crate::model::{Capture, Counter, Device, Kernel, Launch, Quantity, Run, Value};
use crate::provenance::{ClockControl, Clocks, Known, Provenance, Source};

/// A report's CSV pages (any may be missing but details).
#[derive(Clone, Debug, Default)]
pub struct NcuCsv {
    /// The report's file name (no directory), for provenance.
    pub report: String,
    pub details: String,
    pub raw: Option<String>,
    pub session: Option<String>,
    /// A hand-built fixture.
    pub synthetic: bool,
}

impl NcuCsv {
    /// `<dir>/<stem>.details.csv` (+ `.raw.csv`, `.session.csv`, and a `.synthetic` marker file).
    pub fn load(dir: &Path, stem: &str) -> Result<NcuCsv> {
        let read = |p: &str| std::fs::read_to_string(dir.join(format!("{stem}.{p}.csv")));
        Ok(NcuCsv {
            report: format!("{stem}.ncu-rep"),
            details: read("details").with_context(|| format!("read {stem}.details.csv in {}", dir.display()))?,
            raw: read("raw").ok(),
            session: read("session").ok(),
            synthetic: dir.join(format!("{stem}.synthetic")).exists(),
        })
    }
}

pub struct Ncu {
    pub path: Option<std::ffi::OsString>,
}

impl Adapter for Ncu {
    fn source(&self) -> Source {
        Source::Ncu
    }
    fn availability(&self) -> Availability {
        let path = self.path.clone().or_else(|| std::env::var_os("PATH"));
        command_availability("ncu", path.as_deref(), TOOL_DIRS)
    }
}

impl Ingest for Ncu {
    type Input = NcuCsv;
    fn ingest(&self, csv: &NcuCsv) -> Result<Capture> {
        ingest(csv)
    }
}

/// ncu prints numbers with thousands separators ("113,767"); anything else is text.
fn number(s: &str) -> Option<f64> {
    let t = s.trim().replace(',', "");
    if t.is_empty() {
        return None;
    }
    t.parse().ok()
}

/// "(7, 1, 4)" -> [7, 1, 4].
fn dims(s: &str) -> Option<[i64; 3]> {
    let v: Vec<i64> = s.trim_matches(|c| c == '(' || c == ')').split(',').map(|x| x.trim().parse().ok()).collect::<Option<_>>()?;
    v.try_into().ok()
}

fn reader(text: &str) -> csv::Reader<&[u8]> {
    csv::ReaderBuilder::new().flexible(true).has_headers(true).from_reader(text.as_bytes())
}

/// The session page: "Title" lines, each followed by a two-column CSV table.
fn session_tables(text: &str) -> BTreeMap<String, Vec<(String, String)>> {
    let mut out: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut title = String::new();
    let mut header = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with('"') {
            title = line.trim().to_string();
            header = true;
            continue;
        }
        let mut r = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(line.as_bytes());
        let Some(Ok(rec)) = r.records().next() else { continue };
        if header {
            header = false; // the table's own column names
            continue;
        }
        if rec.len() >= 2 {
            out.entry(title.clone()).or_default().push((rec[0].to_string(), rec[1].to_string()));
        }
    }
    out
}

fn get<'a>(t: &'a BTreeMap<String, Vec<(String, String)>>, table: &str, key: &str) -> Option<&'a str> {
    t.get(table)?.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// The clock-control mode and how it is known, from the recorded command line.
fn clock_control(cmdline: Option<&str>) -> Clocks {
    let Some(cmd) = cmdline else {
        return Clocks::unknown("no session page: the profiler command line was not exported");
    };
    let mut words = cmd.split_whitespace();
    let mut mode = None;
    while let Some(w) = words.next() {
        if let Some(v) = w.strip_prefix("--clock-control=") {
            mode = Some(v.to_string());
        } else if w == "--clock-control" {
            mode = words.next().map(str::to_string);
        }
    }
    match mode.as_deref() {
        Some("base") => Clocks { control: ClockControl::Base, basis: "--clock-control base on the recorded command line".into(), sm_mhz: None },
        Some("none") => Clocks { control: ClockControl::Uncontrolled, basis: "--clock-control none on the recorded command line".into(), sm_mhz: None },
        Some(other) => Clocks { control: ClockControl::Unknown, basis: format!("--clock-control {other}: not a mode Custos knows"), sm_mhz: None },
        None => Clocks {
            control: ClockControl::Base,
            basis: "--clock-control not on the recorded command line: ncu's documented default, base".into(),
            sm_mhz: None,
        },
    }
}

/// Identity columns of the details and raw pages that are never kept.
const DROPPED: &[&str] = &["Process ID", "Process Name", "Host Name"];

pub fn ingest(csv: &NcuCsv) -> Result<Capture> {
    let mut c = Capture::default();
    let session = csv.session.as_deref().map(session_tables).unwrap_or_default();
    let version = get(&session, "Session Info", "Nsight Compute Target")
        .map(|v| Known::Known(v.to_string()))
        .unwrap_or_else(|| Known::Unknown("no session page exported (ncu --page session)".into()));
    let mut prov = Provenance::new(Source::Ncu, "ncu", version, &csv.report);
    prov.synthetic = csv.synthetic;
    prov.captured_at = get(&session, "Session Info", "Created").map(str::to_string);
    prov.clocks = clock_control(get(&session, "Launch Settings", "Profiler Command Line"));
    let run_id = format!("ncu:{}", csv.report.trim_end_matches(".ncu-rep"));
    if !session.is_empty() {
        let attr = |k: &str| get(&session, "Device Attributes", k);
        let cc = match (attr("compute_capability_major").and_then(number), attr("compute_capability_minor").and_then(number)) {
            (Some(a), Some(b)) => Value::Present(a as i64 * 10 + b as i64),
            _ => Value::NotMeasured,
        };
        c.devices.push(Device {
            id: "gpu0".into(),
            name: Value::from_option(attr("display_name").map(str::to_string)),
            sm_arch: cc,
            sm_count: Value::from_option(attr("multiprocessor_count").and_then(number).map(|n| n as i64)),
            provenance: prov.clone(),
        });
        for (k, label) in [("CUDA Version", "CUDA"), ("Display Driver Version", "driver")] {
            if let Some(v) = get(&session, "Session Info", k) {
                c.notes.push(format!("{label} {v}"));
            }
        }
    }
    c.runs.push(Run { id: run_id.clone(), kind: "ncu-session".into(), device: c.devices.first().map(|d| d.id.clone()), provenance: prov.clone() });

    // details: one row per (launch, section, metric) or (launch, section, rule).
    let mut rd = reader(&csv.details);
    let h = rd.headers()?.clone();
    let col = |name: &str| h.iter().position(|x| x == name);
    let need = ["ID", "Kernel Name", "Block Size", "Grid Size", "Section Name", "Metric Name", "Metric Unit", "Metric Value"];
    for n in need {
        if col(n).is_none() {
            bail!("ncu details CSV without the \"{n}\" column; not an `ncu --csv --page details` export");
        }
    }
    let at = |rec: &csv::StringRecord, n: &str| col(n).and_then(|i| rec.get(i)).unwrap_or("").to_string();
    let mut text_values = 0;
    let mut rules: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rec in rd.records() {
        let rec = rec?;
        let id = at(&rec, "ID");
        let launch_id = format!("{run_id}:{id}");
        if !c.launches.iter().any(|l| l.id == launch_id) {
            let name = at(&rec, "Kernel Name");
            let (grid, block) = match (dims(&at(&rec, "Grid Size")), dims(&at(&rec, "Block Size"))) {
                (Some(g), Some(b)) => (g, b),
                _ => bail!("ncu details: launch {id} without a parsable grid / block size"),
            };
            if c.kernel(&name).is_none() {
                c.kernels.push(Kernel {
                    id: name.clone(),
                    name: name.clone(),
                    mangled: None,
                    impl_: None,
                    registers_per_thread: Value::NotMeasured,
                    static_smem_bytes: Value::NotMeasured,
                    local_bytes_per_thread: Value::NotMeasured,
                    provenance: prov.clone(),
                });
            }
            c.launches.push(Launch {
                id: launch_id.clone(),
                run: run_id.clone(),
                kernel: name,
                device: Some("gpu0".into()),
                grid,
                block,
                dynamic_smem_bytes: Value::NotMeasured,
                stream: at(&rec, "Stream").parse().ok(),
                correlation_id: None,
                timing: None,
                provenance: prov.clone(),
            });
        }
        let metric = at(&rec, "Metric Name");
        if metric.is_empty() {
            let rule = at(&rec, "Rule Name");
            if !rule.is_empty() {
                rules.entry(launch_id).or_default().push(format!("{rule} ({})", at(&rec, "Rule Type")));
            }
            continue;
        }
        let section = at(&rec, "Section Name");
        let Some(v) = number(&at(&rec, "Metric Value")) else {
            text_values += 1;
            continue;
        };
        c.counters.push(Counter {
            launch: Some(launch_id),
            device: Some("gpu0".into()),
            metric: format!("details:{section}/{metric}"),
            section: Some(section),
            label: Some(metric),
            quantity: Quantity { value: Value::Present(v), unit: at(&rec, "Metric Unit") },
            provenance: prov.clone(),
        });
    }
    for (launch, r) in rules {
        c.notes.push(format!("ncu rules on {launch}: {} (estimated speedups not kept)", r.join(", ")));
    }
    if text_values > 0 {
        c.notes.push(format!("{text_values} text-valued details metrics not kept as counters"));
    }

    // raw: header, units row, one row per launch.
    if let Some(raw) = &csv.raw {
        let mut rr = reader(raw);
        let h = rr.headers()?.clone();
        let mut recs = rr.records();
        let units = recs.next().context("ncu raw CSV without its units row")??;
        let id_col = h.iter().position(|x| x == "ID").context("ncu raw CSV without an ID column")?;
        let first_metric = h.iter().position(|x| x == "CC").map_or(0, |i| i + 1);
        for rec in recs {
            let rec = rec?;
            let launch_id = format!("{run_id}:{}", &rec[id_col]);
            for i in first_metric..h.len() {
                let name = &h[i];
                if DROPPED.contains(&name) {
                    continue;
                }
                let Some(v) = rec.get(i).and_then(number) else { continue };
                c.counters.push(Counter {
                    launch: Some(launch_id.clone()),
                    device: Some("gpu0".into()),
                    metric: name.to_string(),
                    section: None,
                    label: None,
                    quantity: Quantity { value: Value::Present(v), unit: units.get(i).unwrap_or("").to_string() },
                    provenance: prov.clone(),
                });
            }
        }
    }

    // Per launch: registers, shared memory and the SM clock, from its own metrics.
    let value_of = |c: &Capture, launch: &str, metric: &str| {
        c.counters_of(launch).find(|k| k.metric == metric).and_then(|k| k.quantity.value.present().copied())
    };
    // Bytes only from a byte unit: an auto-scaled export ("Kbyte", rounded) is not exact.
    let bytes_of = |c: &Capture, launch: &str, metric: &str| -> Value<i64> {
        match c.counters_of(launch).find(|k| k.metric == metric) {
            None => Value::NotMeasured,
            Some(k) if k.quantity.unit.starts_with("byte") => Value::from_option(k.quantity.value.present().map(|b| *b as i64)),
            Some(k) => Value::NotAvailable(format!(
                "{metric} exported in {} (scaled and rounded); re-export the raw page with --print-units base",
                k.quantity.unit
            )),
        }
    };
    for i in 0..c.launches.len() {
        let id = c.launches[i].id.clone();
        let ghz = value_of(&c, &id, "details:GPU Speed Of Light Throughput/SM Frequency");
        let dyn_smem = bytes_of(&c, &id, "launch__shared_mem_per_block_dynamic");
        let regs = value_of(&c, &id, "launch__registers_per_thread")
            .or_else(|| value_of(&c, &id, "details:Launch Statistics/Registers Per Thread"));
        let static_smem = bytes_of(&c, &id, "launch__shared_mem_per_block_static");
        let l = &mut c.launches[i];
        l.provenance.clocks.sm_mhz = ghz.map(|g| g * 1000.0);
        l.dynamic_smem_bytes = dyn_smem;
        let kname = l.kernel.clone();
        if let Some(k) = c.kernels.iter_mut().find(|k| k.id == kname) {
            if let Some(r) = regs {
                k.registers_per_thread = Value::Present(r as i64);
            }
            if !matches!(static_smem, Value::NotMeasured) {
                k.static_smem_bytes = static_smem;
            }
        }
    }
    Ok(c)
}

/// `ncu --import <report> --csv --print-units base --page <page>` for details,
/// raw and session (needs ncu; never run by the tests). Reading a report profiles nothing.
pub fn export(ncu: &Path, report: &Path) -> Result<NcuCsv> {
    let page = |p: &str| -> Result<String> {
        let o = std::process::Command::new(ncu)
            .arg("--import")
            .arg(report)
            .args(["--csv", "--print-units", "base", "--page", p])
            .output()
            .with_context(|| format!("run {} --import", ncu.display()))?;
        if !o.status.success() {
            bail!("ncu --import --page {p} failed ({}): {}", o.status, String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or(""));
        }
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    };
    Ok(NcuCsv {
        report: report.file_name().map_or_else(String::new, |f| f.to_string_lossy().into_owned()),
        details: page("details")?,
        raw: Some(page("raw")?),
        session: Some(page("session")?),
        synthetic: false,
    })
}

//! Continuous device telemetry (NVML; sysfs and tegrastats on Jetson) in the
//! model: a capability probe (which fields each device reports, stored on the
//! [`Device`]) and samples ([`Counter`]s without a launch: rule 8 keeps them
//! apart from profiled metrics). A field a device does not report has no
//! value at all; views show it "not available on this device"
//! ([`Device::telemetry`]).
//!
//! Backends ([`TelemetryBackend`]): the NVML library (`nvml` feature), a
//! recorded probe (the tests' NVML mock, [`crate::nvml::Recorded`]), Jetson
//! sysfs ([`crate::jetson::Sysfs`]).
use anyhow::Result;

use crate::model::{Capability, Capture, Counter, Device, Quantity, Run, Support, Value};
use crate::provenance::{Clocks, Known, Provenance, Source};

pub struct FieldSpec {
    pub field: &'static str,
    pub unit: &'static str,
    pub label: &'static str,
}

/// The telemetry fields, in display order.
pub const FIELDS: &[FieldSpec] = &[
    FieldSpec { field: "clocks.graphics", unit: "MHz", label: "graphics clock" },
    FieldSpec { field: "clocks.sm", unit: "MHz", label: "SM clock" },
    FieldSpec { field: "clocks.memory", unit: "MHz", label: "memory clock" },
    FieldSpec { field: "temperature.gpu", unit: "C", label: "GPU temperature" },
    FieldSpec { field: "power.usage", unit: "mW", label: "power draw (NVML power usage)" },
    FieldSpec { field: "power.instant", unit: "mW", label: "instantaneous power (NVML field 186)" },
    FieldSpec { field: "power.average", unit: "mW", label: "averaged power (NVML field 185)" },
    FieldSpec { field: "power.limit", unit: "mW", label: "enforced power limit" },
    FieldSpec { field: "energy.total", unit: "mJ", label: "total energy since driver load" },
    FieldSpec { field: "utilization.gpu", unit: "%", label: "GPU utilization (time a kernel ran)" },
    FieldSpec { field: "utilization.memory", unit: "%", label: "memory utilization (time memory was read or written)" },
    FieldSpec { field: "clocks_event_reasons", unit: "bitmask", label: "throttle / clock event reasons" },
    FieldSpec { field: "memory.used", unit: "B", label: "device memory used" },
    FieldSpec { field: "memory.total", unit: "B", label: "device memory total" },
];

pub fn spec(field: &str) -> Option<&'static FieldSpec> {
    FIELDS.iter().find(|f| f.field == field)
}

/// One read of a backend.
#[derive(Clone, Debug, PartialEq)]
pub enum Read<T> {
    Ok(T),
    /// The device does not report it (NVML_ERROR_NOT_SUPPORTED; no such sysfs node).
    NotSupported,
    /// This backend does not read the field (it says nothing about the device).
    NotRead(String),
    /// Any other failure.
    Err(String),
}

impl<T> Read<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Read<U> {
        match self {
            Read::Ok(v) => Read::Ok(f(v)),
            Read::NotSupported => Read::NotSupported,
            Read::NotRead(w) => Read::NotRead(w),
            Read::Err(e) => Read::Err(e),
        }
    }
    pub fn ok(self) -> Option<T> {
        match self {
            Read::Ok(v) => Some(v),
            _ => None,
        }
    }
    fn support(&self) -> Support {
        match self {
            Read::Ok(_) => Support::Supported,
            Read::NotSupported => Support::NotSupported,
            Read::NotRead(why) => Support::NotRead(why.clone()),
            Read::Err(e) => Support::Error(e.clone()),
        }
    }
    fn value(self, what: &str) -> Value<T> {
        match self {
            Read::Ok(v) => Value::Present(v),
            Read::NotSupported => Value::NotAvailable(crate::model::NOT_ON_DEVICE.into()),
            Read::NotRead(why) => Value::NotAvailable(why),
            Read::Err(e) => Value::NotAvailable(format!("{what}: {e}")),
        }
    }
}

pub trait TelemetryBackend {
    fn source(&self) -> Source;
    /// The tool and its version ("NVML", "12.580.142").
    fn tool(&self) -> (String, Known<String>);
    fn driver_version(&self) -> Read<String>;
    /// The CUDA version the driver supports.
    fn cuda_driver_version(&self) -> Read<String>;
    fn device_count(&self) -> Result<u32>;
    fn name(&self, device: u32) -> Read<String>;
    fn compute_capability(&self, device: u32) -> Read<(i64, i64)>;
    fn sm_count(&self, _device: u32) -> Read<i64> {
        Read::NotRead("not reported by this telemetry source".into())
    }
    /// One field ([`FIELDS`]), in its unit.
    fn read(&self, device: u32, field: &str) -> Read<f64>;
    /// A recorded or hand-built backend (the tests' mock): its records are synthetic when it says so.
    fn synthetic(&self) -> bool {
        false
    }
}

fn provenance(b: &dyn TelemetryBackend, at: &str, origin: &str) -> Provenance {
    let (tool, version) = b.tool();
    let mut p = Provenance::new(b.source(), &tool, version, origin);
    p.captured_at = Some(at.to_string());
    p.clocks = Clocks::unknown("telemetry: the clocks are read, their lock state is not");
    p.synthetic = b.synthetic();
    p
}

/// The capability probe: every device, every field read once (read-only, no
/// load), its support stored on the device. `at` is the probe time (RFC 3339).
pub fn probe(b: &dyn TelemetryBackend, at: &str) -> Result<Capture> {
    let mut c = Capture::default();
    let (tool, _) = b.tool();
    let prov = provenance(b, at, &format!("{tool} capability probe"));
    for i in 0..b.device_count()? {
        let mut d = Device::new(
            &format!("gpu{i}"),
            b.name(i).value("name"),
            b.compute_capability(i).map(|(maj, min)| maj * 10 + min).value("compute capability"),
            b.sm_count(i).value("SM count"),
            prov.clone(),
        );
        d.capabilities = FIELDS
            .iter()
            .map(|f| Capability { field: f.field.to_string(), support: b.read(i, f.field).support(), detail: None })
            .collect();
        c.devices.push(d);
    }
    let mut run = Run::new(&format!("{}:probe:{at}", b.source().as_str()), "telemetry-probe", c.devices.first().map(|d| d.id.clone()), prov);
    run.driver = b.driver_version().value("driver version");
    run.cuda_driver = b.cuda_driver_version().value("CUDA version");
    run.cuda_toolkit = Value::NotAvailable(format!("{tool} does not report the CUDA toolkit"));
    c.runs.push(run);
    Ok(c)
}

/// One sample of every field the probe found supported, as telemetry counters
/// (no launch). Unsupported fields produce no counter: they have no value.
pub fn sample(b: &dyn TelemetryBackend, devices: &[Device], at: &str) -> Vec<Counter> {
    let (tool, _) = b.tool();
    let prov = provenance(b, at, &format!("{tool} sample"));
    let mut out = Vec::new();
    for (i, d) in devices.iter().enumerate() {
        for cap in d.capabilities.iter().filter(|c| c.support == Support::Supported) {
            let Some(f) = spec(&cap.field) else { continue };
            let read = b.read(i as u32, f.field);
            let label = match (&read, f.field) {
                (Read::Ok(bits), "clocks_event_reasons") => format!("{}: {}", f.label, clock_event_reasons(*bits as u64).join(", ")),
                _ => f.label.to_string(),
            };
            out.push(Counter {
                launch: None,
                device: Some(d.id.clone()),
                metric: f.field.to_string(),
                section: Some("telemetry".into()),
                label: Some(label),
                quantity: Quantity { value: read.value(f.field), unit: f.unit.to_string() },
                provenance: prov.clone(),
            });
        }
    }
    out
}

/// NVML clock event (throttle) reason bits, by name (nvml.h, nvmlClocksEventReason*).
pub fn clock_event_reasons(bits: u64) -> Vec<&'static str> {
    const NAMES: &[(u64, &str)] = &[
        (0x1, "GPU idle"),
        (0x2, "applications clocks setting"),
        (0x4, "software power cap"),
        (0x8, "hardware slowdown"),
        (0x10, "sync boost"),
        (0x20, "software thermal slowdown"),
        (0x40, "hardware thermal slowdown"),
        (0x80, "hardware power brake slowdown"),
        (0x100, "display clock setting"),
    ];
    if bits == 0 {
        return vec!["none"];
    }
    let mut v: Vec<&str> = NAMES.iter().filter(|(b, _)| bits & b != 0).map(|(_, n)| *n).collect();
    if bits & !0x1ff != 0 {
        v.push("other (unknown bits)");
    }
    v
}

/// What repeated reads of one field show about its granularity: how often the
/// value changes and by how little. Observed, not documented: a probe reports
/// it as such.
#[derive(Clone, Debug, PartialEq)]
pub struct Granularity {
    pub samples: usize,
    pub window_ms: f64,
    /// Number of reads whose value differed from the previous read.
    pub changes: usize,
    /// The smallest non-zero difference between consecutive distinct values.
    pub min_step: Option<f64>,
    /// The median time between changes (needs 2+ changes).
    pub median_interval_ms: Option<f64>,
}

/// `series`: (time in ms, value) in read order.
pub fn granularity(series: &[(f64, f64)]) -> Granularity {
    let window_ms = match (series.first(), series.last()) {
        (Some(a), Some(b)) => b.0 - a.0,
        _ => 0.0,
    };
    let mut change_times = Vec::new();
    let mut min_step: Option<f64> = None;
    for w in series.windows(2) {
        let d = (w[1].1 - w[0].1).abs();
        if d > 0.0 {
            change_times.push(w[1].0);
            min_step = Some(min_step.map_or(d, |m| m.min(d)));
        }
    }
    let mut gaps: Vec<f64> = change_times.windows(2).map(|w| w[1] - w[0]).collect();
    gaps.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median_interval_ms = (!gaps.is_empty()).then(|| {
        let n = gaps.len();
        if n % 2 == 1 { gaps[n / 2] } else { (gaps[n / 2 - 1] + gaps[n / 2]) / 2.0 }
    });
    Granularity { samples: series.len(), window_ms, changes: change_times.len(), min_step, median_interval_ms }
}

impl Granularity {
    pub fn describe(&self, unit: &str) -> String {
        let reads = format!("{} reads over {:.0} ms", self.samples, self.window_ms);
        match (self.changes, self.median_interval_ms, self.min_step) {
            (0, _, _) => format!("{reads}: the value never changed (updates slower than the window, or constant)"),
            (_, Some(iv), Some(step)) => {
                format!("{reads}: changed {} times, every {iv:.1} ms (median), smallest step {step} {unit}", self.changes)
            }
            (_, None, Some(step)) => format!("{reads}: changed once, step {step} {unit} (window too short for an interval)"),
            _ => reads,
        }
    }
}

/// Now, as RFC 3339 UTC (millisecond precision).
pub fn utc_now() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    rfc3339(d.as_secs() as i64, d.subsec_millis())
}

/// Unix seconds as RFC 3339 UTC (civil-from-days, H. Hinnant).
pub fn rfc3339(secs: i64, millis: u32) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z", tod / 3600, tod % 3600 / 60, tod % 60)
}

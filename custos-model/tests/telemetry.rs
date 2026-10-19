//! Telemetry: the NVML capability probe and samples on the NVML mock
//! (tests/fixtures/nvml/, synthetic: one device with full support, one
//! GB10-like device with gaps), the granularity analysis, and the Jetson
//! fallback on a synthetic sysfs tree and tegrastats lines. No NVML, no GPU.
use std::path::{Path, PathBuf};

use custos_model::adapter::{Adapter, Availability};
use custos_model::contract::violations;
use custos_model::jetson::{self, Sysfs};
use custos_model::model::{Support, Value, NOT_ON_DEVICE};
use custos_model::nvml::{check_recorded, Nvml, Recorded};
use custos_model::provenance::Source;
use custos_model::telemetry::{self, clock_event_reasons, granularity, rfc3339, FIELDS};

fn fixture(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(p)
}
fn mock(name: &str) -> Recorded {
    let r = Recorded::load(&fixture(&format!("nvml/{name}"))).unwrap();
    check_recorded(&r).unwrap();
    r
}
const AT: &str = "2026-10-19T00:00:00.000Z";

#[test]
fn full_support_device_reports_every_field() {
    let b = mock("full-synthetic.json");
    let c = telemetry::probe(&b, AT).unwrap();
    let d = &c.devices[0];
    assert_eq!((d.id.as_str(), &d.sm_arch), ("gpu0", &Value::Present(89)));
    assert_eq!(d.capabilities.len(), FIELDS.len());
    assert!(d.capabilities.iter().all(|c| c.support == Support::Supported), "{:?}", d.capabilities);
    assert_eq!(d.sm_count, Value::NotAvailable("not reported by this telemetry source".into()), "NVML has no SM count");
    let p = &d.provenance;
    assert_eq!((p.source, p.tool.name.as_str(), p.synthetic, p.captured_at.as_deref()), (Source::Nvml, "NVML", true, Some(AT)));
    let r = &c.runs[0];
    assert_eq!((r.kind.as_str(), &r.driver), ("telemetry-probe", &Value::Present("000.00 (synthetic)".into())));
    assert!(matches!(&r.cuda_toolkit, Value::NotAvailable(_)));

    let s = telemetry::sample(&b, &c.devices, AT);
    assert_eq!(s.len(), FIELDS.len());
    assert!(s.iter().all(|k| k.launch.is_none() && k.provenance.source.is_telemetry()), "rule 8: telemetry has no launch");
    let power = s.iter().find(|k| k.metric == "power.usage").unwrap();
    assert_eq!((power.quantity.value.present(), power.quantity.unit.as_str()), (Some(&31250.0), "mW"));
    let ev = s.iter().find(|k| k.metric == "clocks_event_reasons").unwrap();
    assert!(ev.label.as_deref().unwrap().ends_with(": GPU idle"), "{:?}", ev.label);
    let mut all = c.clone();
    all.counters = s;
    assert!(violations(&all).is_empty(), "{:?}", violations(&all));
}

/// The GB10-like device: unsupported fields are recorded as such on the
/// device, sampled not at all, and shown "not available on this device".
#[test]
fn gb10_like_device_records_its_gaps() {
    let b = mock("gb10-like-synthetic.json");
    let c = telemetry::probe(&b, AT).unwrap();
    let d = &c.devices[0];
    assert_eq!(d.sm_arch, Value::Present(121));
    let unsupported: Vec<&str> =
        d.capabilities.iter().filter(|c| c.support == Support::NotSupported).map(|c| c.field.as_str()).collect();
    assert_eq!(
        unsupported,
        ["clocks.memory", "power.instant", "power.limit", "energy.total", "utilization.memory", "memory.used", "memory.total"]
    );
    assert_eq!(d.telemetry::<f64>("memory.used", None), Value::NotAvailable(NOT_ON_DEVICE.into()));
    assert_eq!(d.telemetry("memory.used", Some(&1.0)), Value::NotAvailable(NOT_ON_DEVICE.into()), "never a value for an unsupported field");
    assert_eq!(d.telemetry::<f64>("power.usage", None), Value::NotMeasured, "supported, not sampled yet");
    assert_eq!(d.telemetry("power.usage", Some(&4120.0)), Value::Present(4120.0));

    let mut cap = c.clone();
    cap.counters = telemetry::sample(&b, &c.devices, AT);
    assert_eq!(cap.counters.len(), FIELDS.len() - unsupported.len());
    assert!(cap.counters.iter().all(|k| !unsupported.contains(&k.metric.as_str())));
    assert!(violations(&cap).is_empty());

    // A value for a field the device does not report can only be made up (rule 9).
    let mut bad = cap.clone();
    let mut k = bad.counters[0].clone();
    k.metric = "memory.used".into();
    bad.counters.push(k);
    assert_eq!(violations(&bad).iter().map(|v| v.rule).collect::<Vec<_>>(), ["9"]);
    // Telemetry on a profiled launch is rule 8.
    let mut bad = cap.clone();
    bad.counters[0].launch = Some("ncu:x:0".into());
    assert_eq!(violations(&bad).iter().map(|v| v.rule).collect::<Vec<_>>(), ["8"]);
}

#[test]
fn granularity_from_repeated_reads() {
    let full = mock("full-synthetic.json");
    let g = granularity(&full.devices[0].series["power.usage"]);
    assert_eq!((g.samples, g.changes, g.min_step, g.median_interval_ms), (51, 10, Some(7.0), Some(100.0)));
    assert_eq!(g.describe("mW"), "51 reads over 1000 ms: changed 10 times, every 100.0 ms (median), smallest step 7 mW");
    let e = granularity(&full.devices[0].series["energy.total"]);
    assert_eq!((e.min_step, e.median_interval_ms), (Some(3.0), Some(20.0)));
    let gb = mock("gb10-like-synthetic.json");
    let g = granularity(&gb.devices[0].series["power.usage"]);
    assert_eq!((g.changes, g.min_step, g.median_interval_ms), (5, Some(5.0), Some(200.0)));
    let flat = granularity(&[(0.0, 1.0), (10.0, 1.0)]);
    assert!(flat.describe("mW").contains("never changed"));
}

#[test]
fn clock_event_reasons_by_name() {
    assert_eq!(clock_event_reasons(0), ["none"]);
    assert_eq!(clock_event_reasons(0x1), ["GPU idle"]);
    assert_eq!(clock_event_reasons(0x44), ["software power cap", "hardware thermal slowdown"]);
    assert_eq!(clock_event_reasons(0x1000), ["other (unknown bits)"]);
}

#[test]
fn rfc3339_utc() {
    assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
    assert_eq!(rfc3339(1_760_745_600, 5), "2025-10-18T00:00:00.005Z");
    assert_eq!(rfc3339(951_782_400 + 3_723, 0), "2000-02-29T01:02:03.000Z");
}

/// No NVML here (or in CI): the adapter says so, never errors.
#[test]
fn nvml_unavailable_is_reported_cleanly() {
    let a = Nvml { lib_path: Some(PathBuf::from("/nonexistent/libnvidia-ml.so.1")) };
    assert_eq!(a.source(), Source::Nvml);
    match a.availability() {
        Availability::Unavailable { reason } => {
            #[cfg(not(feature = "nvml"))]
            assert!(reason.contains("built without the \"nvml\" feature"), "{reason}");
            #[cfg(feature = "nvml")]
            assert!(reason.contains("could not be loaded"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn jetson_sysfs_mirrors_cores_load_file() {
    let s = Sysfs { root: fixture("jetson/sysfs-orin-synthetic"), synthetic: true };
    let c = telemetry::probe(&s, AT).unwrap();
    let d = &c.devices[0];
    assert_eq!(d.name, Value::Present("Synthetic Jetson AGX Orin".into()));
    assert_eq!(d.provenance.source, Source::Sysfs);
    assert_eq!(d.provenance.tool.version.known().map(String::as_str), Some("Linux 5.15.0-synthetic-tegra"));
    assert!(c.runs[0].driver.present().unwrap().starts_with("R36 (release)"));
    let sup = |f: &str| d.capability(f).unwrap().support.clone();
    assert_eq!((sup("utilization.gpu"), sup("clocks.graphics"), sup("temperature.gpu")), (Support::Supported, Support::Supported, Support::Supported));
    // Not read from sysfs says nothing about the device: never "not available on this device".
    assert!(matches!(sup("power.usage"), Support::NotRead(_)));
    assert!(matches!(d.telemetry::<f64>("power.usage", None), Value::NotAvailable(w) if w.contains("tegrastats")));

    let k = telemetry::sample(&s, &c.devices, AT);
    let v = |m: &str| *k.iter().find(|x| x.metric == m).unwrap().quantity.value.present().unwrap();
    assert!((v("utilization.gpu") - 12.3).abs() < 1e-9, "per mille / 10");
    assert!((v("clocks.graphics") - 918.0).abs() < 1e-9);
    assert!((v("temperature.gpu") - 45.5).abs() < 1e-9, "the gpu-thermal zone, not cpu-thermal");

    let none = Sysfs::new(fixture("jetson/no-such-root"));
    assert_eq!(telemetry::probe(&none, AT).unwrap().devices.len(), 0);
}

#[test]
fn tegrastats_lines() {
    let text = std::fs::read_to_string(fixture("jetson/tegrastats-synthetic.txt")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let (at, f) = jetson::parse_tegrastats_line(lines[1]);
    assert_eq!(at.as_deref(), Some("2026-10-18T12:00:01"));
    assert_eq!(f, [("utilization.gpu", 12.0), ("clocks.graphics", 918.0), ("temperature.gpu", 45.75), ("power.usage", 2810.0)]);
    let (at, f) = jetson::parse_tegrastats_line(lines[2]);
    assert_eq!(at, None);
    assert_eq!(f, [("utilization.gpu", 7.0), ("clocks.graphics", 921.0), ("temperature.gpu", 38.5)]);

    let c = jetson::ingest_tegrastats(&text, "gpu0", "tegrastats-synthetic.txt", true);
    assert_eq!(c.counters.len(), 4 + 4 + 3);
    assert!(c.counters.iter().all(|k| k.provenance.source == Source::Sysfs && k.provenance.synthetic && k.launch.is_none()));
    assert!(c.counters.iter().any(|k| k.label.as_deref() == Some("VDD_GPU_SOC rail (GPU and SoC)")));
    assert!(violations(&c).is_empty());
}

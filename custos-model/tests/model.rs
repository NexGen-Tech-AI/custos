//! The model's own guarantees, with no AEGIS and no NVIDIA tool installed.
use custos_model::adapter::{command_availability, Availability};
use custos_model::contract::violations;
use custos_model::model::{Capture, Counter, Quantity, Value};
use custos_model::provenance::{Build, Known, Provenance, Source};

#[test]
fn a_build_is_full_or_only_a_label() {
    assert!(Build::full("0123456789abcdef0123456789abcdef01234567", false).unwrap().reproducible());
    assert_eq!(Build::full("9157a34", false), None, "7 digits are never a SHA");
    let b = Build::from_label("0bd0f22a35a6-dirty");
    assert_eq!((b.sha.as_deref(), b.dirty, b.reproducible()), (None, Some(true), false));
    assert_eq!(Build::from_label("1084490").dirty, None, "no marker: the source does not say");
}

/// With an empty PATH and no tool directory, every tool reports "unavailable", never an error.
#[test]
fn missing_tools_are_unavailable_not_errors() {
    for t in ["nsys", "ncu", "cuobjdump", "nvdisasm"] {
        match command_availability(t, Some(std::ffi::OsStr::new("")), &[]) {
            Availability::Unavailable { reason } => assert!(reason.contains("not installed"), "{reason}"),
            a => panic!("{t}: {a:?}"),
        }
    }
}

fn counter(source: Source, launch: Option<&str>) -> Counter {
    Counter {
        launch: launch.map(str::to_string),
        device: Some("gpu0".into()),
        metric: "x".into(),
        section: None,
        label: None,
        quantity: Quantity { value: Value::Present(1.0), unit: "%".into() },
        provenance: Provenance::new(source, "t", Known::Unknown("synthetic".into()), "test"),
    }
}

/// Rule 8: a telemetry sample is never attached to a profiled launch, and a
/// profiled metric always is.
#[test]
fn telemetry_and_profiled_metrics_stay_apart() {
    let ok = Capture { counters: vec![counter(Source::Nvml, None), counter(Source::Ncu, Some("l0"))], ..Default::default() };
    assert!(violations(&ok).is_empty());
    for bad in [counter(Source::Nvml, Some("l0")), counter(Source::Ncu, None)] {
        let c = Capture { counters: vec![bad], ..Default::default() };
        assert_eq!(violations(&c)[0].rule, "8");
    }
}

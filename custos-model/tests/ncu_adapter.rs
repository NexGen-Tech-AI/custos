//! The Nsight Compute adapter on the synthetic CSV pages (tests/fixtures/ncu/,
//! in the exact format of `ncu --import --csv --print-units base`, 2025.3.1).
use std::path::Path;

use custos_model::adapter::{Adapter, Availability};
use custos_model::contract::violations;
use custos_model::model::Value;
use custos_model::ncu::{self, Ncu, NcuCsv};
use custos_model::provenance::{ClockControl, Source};
use custos_model::sidecar::Sidecar;

fn fixture() -> NcuCsv {
    NcuCsv::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ncu"), "decode-synthetic").unwrap()
}

fn metric(c: &custos_model::Capture, launch: &str, m: &str) -> (f64, String) {
    let k = c.counters_of(launch).find(|k| k.metric == m).unwrap_or_else(|| panic!("{m}"));
    (*k.quantity.value.present().unwrap(), k.quantity.unit.clone())
}

#[test]
fn normalizes_launches_counters_and_provenance() {
    let c = ncu::ingest(&fixture()).unwrap();
    assert!(violations(&c).is_empty(), "{:?}", violations(&c));
    let d = &c.devices[0];
    assert_eq!((&d.sm_arch, &d.sm_count), (&Value::Present(121), &Value::Present(48)));
    let p = &c.runs[0].provenance;
    assert_eq!((p.source, p.synthetic), (Source::Ncu, true));
    assert_eq!(p.tool.version.known().map(String::as_str), Some("2025.3.1.0 (build 36398880) (public-release)"));
    assert_eq!(p.captured_at.as_deref(), Some("2026-Oct-18 00:00:00"));
    assert_eq!(p.clocks.control, ClockControl::Base);
    assert!(p.clocks.basis.contains("ncu's documented default, base"), "{}", p.clocks.basis);

    assert_eq!(c.launches.len(), 2);
    let l0 = &c.launches[0];
    assert_eq!((l0.grid, l0.block, l0.blocks()), ([14, 1, 1], [128, 1, 1], 14));
    assert_eq!(l0.dynamic_smem_bytes, Value::Present(49152));
    assert_eq!(l0.provenance.clocks.sm_mhz, Some(2140.0), "the launch's own SM Frequency");
    assert_eq!(l0.timing, None, "ncu replays a kernel; it has no timeline");
    let k0 = c.kernel(&l0.kernel).unwrap();
    assert_eq!((&k0.registers_per_thread, &k0.static_smem_bytes), (&Value::Present(70), &Value::Present(0)));

    // details and raw metrics, with ncu's units; thousands separators parsed.
    assert_eq!(metric(&c, &l0.id, "details:GPU Speed Of Light Throughput/Elapsed Cycles"), (19260.0, "cycle".into()));
    assert_eq!(metric(&c, &l0.id, "launch__waves_per_multiprocessor"), (0.29, "".into()));
    assert_eq!(metric(&c, &l0.id, "smsp__average_warps_issue_stalled_long_scoreboard_per_issue_active.ratio"), (9.1, "inst".into()));
    assert_eq!(metric(&c, &l0.id, "l1tex__m_xbar2l1tex_read_bytes.sum"), (1605632.0, "byte".into()));
    assert_eq!(metric(&c, &c.launches[1].id, "l1tex__data_bank_conflicts_pipe_lsu_mem_shared.sum"), (1024.0, "".into()));
    assert!(c.counters.iter().all(|k| k.provenance.source == Source::Ncu && k.launch.is_some()));
    // Rules by name only; ncu's estimated speedups are never kept.
    assert!(c.notes.iter().any(|n| n.contains("SOLBottleneck (OPT)") && n.contains("estimated speedups not kept")));
    let all = serde_json::to_string(&c).unwrap();
    assert!(!all.contains("12.5") && !all.contains("40.0\""), "no estimated speedup value");
}

/// Host name, target IPs, process ids and names, and the command line never reach the model.
#[test]
fn identity_fields_are_dropped() {
    let all = serde_json::to_string(&ncu::ingest(&fixture()).unwrap()).unwrap();
    for leak in ["synthetic-host", "192.0.2.10", "4096", "./bench_gemm", "--impl", "Profiler Command Line", "Process"] {
        assert!(!all.contains(leak), "{leak} leaked into the model");
    }
}

#[test]
fn clock_control_comes_from_the_command_line_or_is_unknown() {
    let mut f = fixture();
    let s = f.session.clone().unwrap();
    f.session = Some(s.replace("ncu --set full", "ncu --clock-control none --set full"));
    let c = ncu::ingest(&f).unwrap();
    assert_eq!(c.runs[0].provenance.clocks.control, ClockControl::Uncontrolled);
    f.session = None;
    let c = ncu::ingest(&f).unwrap();
    let p = &c.runs[0].provenance;
    assert_eq!(p.clocks.control, ClockControl::Unknown);
    assert!(p.tool.version.known().is_none() && c.devices.is_empty());
}

/// The capture script's sidecar: the clock control it passed, checked against
/// the command line; the build; the driver and CUDA (the report's own record first).
#[test]
fn the_capture_sidecar_names_clock_control_build_and_software() {
    let mut f = fixture();
    let sha = "0123456789abcdef0123456789abcdef01234567";
    f.sidecar = Some(Sidecar {
        tool: Some("ncu".into()),
        build_sha: Some(sha.into()),
        build_dirty: Some(false),
        driver_version: Some("000.00 (synthetic)".into()),
        cuda_toolkit_version: Some("0.0 (synthetic)".into()),
        clock_control: Some("base".into()),
        commands: vec![vec!["ncu".into(), "--clock-control".into(), "base".into()]],
        synthetic: true,
        ..Default::default()
    });
    let c = ncu::ingest(&f).unwrap();
    let r = &c.runs[0];
    assert_eq!(r.provenance.clocks.control, ClockControl::Base);
    assert_eq!(r.provenance.clocks.basis, "--clock-control base, passed explicitly (capture sidecar)");
    assert_eq!(r.provenance.build.as_ref().and_then(|b| b.sha.as_deref()), Some(sha));
    // The session page records driver and CUDA itself; the toolkit only the sidecar does.
    assert_eq!((&r.driver, &r.cuda_driver), (&Value::Present("580.142".into()), &Value::Present("13.0".into())));
    assert_eq!(r.cuda_toolkit, Value::Present("0.0 (synthetic)".into()));
    assert_eq!(r.commands[0], ["ncu", "--clock-control", "base"]);

    // Passed one mode, recorded another: unknown, saying both.
    let s = f.session.clone().unwrap();
    f.session = Some(s.replace("ncu --set full", "ncu --clock-control none --set full"));
    let p = ncu::ingest(&f).unwrap().runs[0].provenance.clone();
    assert_eq!(p.clocks.control, ClockControl::Unknown);
    assert!(p.clocks.basis.contains("sidecar says --clock-control base") && p.clocks.basis.contains("says none"), "{}", p.clocks.basis);
}

/// An auto-scaled raw export: byte fields are "not available", never rounded into bytes.
#[test]
fn scaled_units_are_not_bytes() {
    let mut f = fixture();
    let raw = f.raw.clone().unwrap();
    let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
    lines[1] = lines[1].replacen("\"byte/block\",\"byte/block\"", "\"byte/block\",\"Kbyte/block\"", 1);
    lines[2] = lines[2].replacen("\"49,152\"", "\"49.152000\"", 1);
    f.raw = Some(lines.join("\n"));
    let c = ncu::ingest(&f).unwrap();
    match &c.launches[0].dynamic_smem_bytes {
        Value::NotAvailable(why) => assert!(why.contains("Kbyte/block") && why.contains("--print-units base"), "{why}"),
        v => panic!("{v:?}"),
    }
}

#[test]
fn a_page_that_is_not_ncu_details_fails_clearly() {
    let f = NcuCsv { report: "x.ncu-rep".into(), details: "\"a\",\"b\"\n\"1\",\"2\"\n".into(), ..Default::default() };
    let e = ncu::ingest(&f).unwrap_err().to_string();
    assert!(e.contains("without the \"ID\" column"), "{e}");
}

#[test]
fn ncu_missing_is_unavailable() {
    match (Ncu { path: Some("".into()) }).availability() {
        Availability::Unavailable { reason } => assert!(reason.contains("ncu is not installed")),
        Availability::Available { tool, .. } => assert_eq!(tool, "ncu"),
    }
}

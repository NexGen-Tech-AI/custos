//! A Winners row and a regression row, ported through the internal model
//! (custos-model) by the AEGIS adapter, keep every data-contract field, and
//! the model's contract check passes them as shown and catches each rule when
//! a field is broken.
use custos_model::contract::violations;
use custos_model::model::Value;
use custos_model::provenance::{ClockControl, Pairing, RoofOrigin, Source};
use custos_perf::aegis_adapter::{self, AEGIS_PERF_TAG};
use custos_perf::Sources;

fn rules(c: &custos_model::Capture) -> Vec<&'static str> {
    let mut r: Vec<&'static str> = violations(c).iter().map(|v| v.rule).collect();
    r.dedup();
    r
}

#[test]
fn the_pin_is_the_tag_in_cargo_toml() {
    let toml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    assert!(toml.contains(&format!("tag = \"{AEGIS_PERF_TAG}\"")), "AEGIS_PERF_TAG must match the aegis-perf pin");
}

/// 512x4864x896: the paired CI puts the kernel below the 80% floor, so it
/// dispatches to cuBLASLt; every field the Winners view shows survives.
#[test]
fn a_winners_row_keeps_every_contract_field() {
    let s = Sources::repo_fixtures();
    let con = s.open().unwrap();
    let ws = custos_perf::winners(&s, &con, 121).unwrap();
    let w = ws.iter().find(|w| w.shape_bucket == "512x4864x896").unwrap();
    let c = aegis_adapter::winner(&s, &con, w).unwrap();
    assert!(violations(&c).is_empty(), "{:?}", violations(&c));

    // The measurement: the source's own protocol, rule-2 state, build as stored.
    let m = &c.measurements[0];
    assert_eq!((m.impl_.as_str(), m.shape, m.median_us), (w.impl_.as_str(), (512, 4864, 896), w.median_us));
    let p = &m.provenance;
    assert_eq!((p.source, p.tool.name.as_str(), p.tool.version.known().map(String::as_str)), (Source::Aegis, "aegis-perf", Some(AEGIS_PERF_TAG)));
    let a = p.aegis.as_ref().unwrap();
    assert_eq!((a.protocol, a.cache_mode.as_deref(), a.allow_busy), (2, Some("cold"), false));
    assert_ne!(a.disturbed, Some(true));
    let run = aegis_perf::view::run(&con, &w.run_id).unwrap().unwrap();
    assert_eq!(p.captured_at.as_deref(), Some(run.started_at.as_str()));
    let b = p.build.as_ref().unwrap();
    assert_eq!((b.label.as_deref(), b.sha.as_deref()), (w.git_sha.as_deref(), None), "a 7-digit label is never padded into a SHA");
    assert!(!b.reproducible());
    // Tune runs leave runs.clocks_locked NULL: the lock state is unknown, and says why.
    assert_eq!((p.clocks.control.clone(), p.clocks.basis.as_str()), (ClockControl::Unknown, "runs.clocks_locked is NULL (not recorded for this run)"));

    // The comparison: baseline, paired CI, kernel % and dispatch apart, bars provisional.
    let k = &c.comparisons[0];
    let vs = &w.vs_cublaslt_best;
    assert_eq!(k.baseline, "cublaslt_best");
    assert_eq!(k.unpaired_pct, Value::from_option(vs.pct_of_cublaslt_best));
    let ci = vs.ci.as_ref().unwrap();
    let st = k.provenance.stats.as_ref().unwrap();
    assert_eq!(st.ci.map(|c| (c.lo, c.hi)), Some((ci.lo, ci.hi)));
    assert_eq!(st.pairing, Pairing::Paired { against: "cublaslt_best".into(), pairs: ci.pairs, across_builds: false });
    assert_eq!(k.verdict.as_deref(), Some("loss"));
    let d = k.dispatch.as_ref().unwrap();
    assert_eq!((d.target.as_str(), &d.pct), ("cublaslt", &Value::NotMeasured), "the kernel's % is never the dispatch's");
    assert_eq!((d.stored.clone(), d.mismatch), (w.dispatch.stored.clone(), w.dispatch.mismatch));
    assert_eq!((k.bar.as_deref(), k.bar_verdict.as_deref()), (Some(w.bars.class), w.bars.verdict));
    assert!(k.provenance.provisional.as_deref().unwrap().contains("#4"));

    // Derived values name their roof: the copy roof (M = 512), from the measured arch file.
    let r = w.roof.as_ref().unwrap();
    let pct = c.derived.iter().find(|d| d.name == "pct_of_roof").unwrap();
    assert_eq!(pct.quantity.value, Value::Present(r.pct_roof));
    let roof = pct.provenance.roof.as_ref().unwrap();
    assert_eq!((roof.kind.as_str(), roof.value), ("copy", r.roof_gbps));
    assert!(matches!(&roof.origin, RoofOrigin::Measured { arch_file, microbench_status } if arch_file == "sm_121.json" && microbench_status == "valid"));

    // Each rule is caught when its field is broken.
    let mut x = c.clone();
    x.comparisons[0].provenance.stats.as_mut().unwrap().ci = None;
    assert_eq!(rules(&x), ["6"]);
    let mut x = c.clone();
    x.comparisons[0].baseline = "cublas".into();
    assert_eq!(rules(&x), ["5"]);
    let mut x = c.clone();
    x.comparisons[0].dispatch.as_mut().unwrap().pct = x.comparisons[0].kernel_pct.clone();
    assert_eq!(rules(&x), ["10"]);
    let mut x = c.clone();
    x.measurements[0].provenance.aegis.as_mut().unwrap().cache_mode = Some("warm".into());
    assert_eq!(rules(&x), ["2"]);
    x.measurements[0].exclusion = Some("warm cache (shown on request)".into());
    assert!(rules(&x).is_empty(), "an excluded row shown with its reason is fine");
    let mut x = c.clone();
    x.derived[0].provenance.roof.as_mut().unwrap().kind = "read".into();
    assert_eq!(rules(&x), ["4"]);
    let mut x = c.clone();
    x.derived[0].provenance.roof = None;
    assert_eq!(rules(&x), ["3"]);
    let mut x = c.clone();
    x.derived[0].provenance.roof.as_mut().unwrap().origin =
        RoofOrigin::Measured { arch_file: "sm_121.json".into(), microbench_status: "replaced".into() };
    assert_eq!(rules(&x), ["7"]);
    let mut x = c.clone();
    x.derived[0].provenance.roof.as_mut().unwrap().origin = RoofOrigin::Datasheet { label: "GB10 spec".into() };
    assert_eq!(rules(&x), ["9"]);
    let mut x = c.clone();
    x.measurements[0].provenance.source = Source::Nsys;
    assert!(rules(&x).contains(&"P"), "a profiler timing is never a measurement");
}

/// The 16x4864x896 watch of nightly b34425e97d6d, and the disturbed nightly's
/// exclusion, keep status, before / after, threshold, header and row state.
#[test]
fn a_regression_row_keeps_every_contract_field() {
    let s = Sources::repo_fixtures();
    let con = s.open().unwrap();
    let reg = custos_perf::regression(&s, &con, 121).unwrap();
    let r = reg.runs.iter().find(|r| r.run_id == "b34425e97d6d").unwrap();
    let c = aegis_adapter::regression_run(&con, &reg, r).unwrap();
    assert!(violations(&c).is_empty(), "{:?}", violations(&c));
    let src = r.checks.iter().find(|c| c.shape == "16x4864x896").unwrap();
    let x = c.regressions.iter().find(|x| x.shape == (16, 4864, 896)).unwrap();
    assert_eq!((x.status.as_str(), x.impl_.as_str()), ("watch", src.impl_.as_str()));
    assert_eq!((x.pct.clone(), x.before_pct.clone()), (Value::from_option(src.pct), Value::from_option(src.before_pct)));
    assert_eq!(x.before_run.as_deref(), Some("41cc8ffb03fd"));
    assert_eq!(x.exclusion, None);
    let d = x.dispatch.as_ref().unwrap();
    assert_eq!((d.target.as_str(), &d.pct), (src.dispatch.as_str(), &Value::from_option(src.dispatch_pct)));
    let p = &x.provenance;
    assert!(p.origin.contains("regress threshold 3%"));
    assert_eq!(p.build.as_ref().unwrap().label.as_deref(), r.git_sha.as_deref());
    let a = p.aegis.as_ref().unwrap();
    assert_eq!((a.disturbed, a.allow_busy), (r.disturbed, r.allow_busy));
    assert_eq!(p.provisional.is_some(), r.header.as_ref().unwrap().provisional);

    // The disturbed nightly: listed, excluded with its reason, never shown by default.
    let dr = reg.runs.iter().find(|r| r.run_id == "d1504a45376d").unwrap();
    let dc = aegis_adapter::regression_run(&con, &reg, dr).unwrap();
    assert!(violations(&dc).is_empty());
    let e = dc.regressions[0].exclusion.as_deref().unwrap();
    assert!(e.starts_with("disturbed: 1 of 41 2 s windows over 2%"), "{e}");
    let mut x = dc.clone();
    x.regressions[0].exclusion = None;
    assert_eq!(rules(&x), ["2"], "a disturbed run's rows cannot be shown by default");
    // A regression must say what confirmed it.
    let mut x = c.clone();
    x.regressions[0].status = "regression".into();
    x.regressions[0].why = None;
    assert_eq!(rules(&x), ["6"]);
}

#[test]
fn profiles_are_reported_missing() {
    assert!(aegis_adapter::profiles_note().contains("no profiles table"));
}

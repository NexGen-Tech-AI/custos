//! The regression view on the committed fixtures: each nightly sweep checked
//! by aegis-perf's own regress (watch vs regression), against the header its
//! build ran; disturbed runs listed and excluded; paired-ab confirmations with
//! their provenance; the nightly fuzz panel.
use aegis_perf::ab::{self, NewPairedResult};
use custos_perf::regression::Regression;
use custos_perf::Sources;

fn regression(s: &Sources) -> Regression {
    custos_perf::regression(s, &s.open().unwrap(), 121).unwrap()
}

/// Per shape, what `aegis-perf regress` printed for the run (golden, the
/// tag's CLI on this fixture with the same header): (shape, "96.1%" or "-",
/// "watch" / "REGRESSION" / "").
fn golden(run: &str) -> Vec<(String, String, String)> {
    let path = format!("{}/../tests/fixtures/golden/regress-{run}.txt", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("  "))
        .map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let flag = if l.contains("REGRESSION") { "REGRESSION" } else if l.contains("  watch") { "watch" } else { "" };
            (t[0].to_string(), t[3].to_string(), flag.to_string())
        })
        .collect()
}

/// Every check equals the tag's CLI on the same run and header: the rule is
/// aegis-perf's, Custos only calls it.
#[test]
fn classifications_are_cores() {
    let r = regression(&Sources::repo_fixtures());
    assert_eq!(r.threshold_pct, 3.0);
    for run in ["d1504a45376d", "b34425e97d6d", "eb5bcee294d4"] {
        let x = r.runs.iter().find(|x| x.run_id == run).unwrap_or_else(|| panic!("{run}"));
        let got: Vec<(String, String, String)> = x
            .checks
            .iter()
            .map(|c| {
                let pct = c.pct.map_or("-".to_string(), |p| format!("{p:.1}%"));
                let flag = match c.status {
                    "regression" => "REGRESSION",
                    "watch" => "watch",
                    _ => "",
                };
                (c.shape.clone(), pct, flag.to_string())
            })
            .collect();
        assert_eq!(got, golden(run), "{run}");
        let h = x.header.as_ref().unwrap();
        assert!(h.own_build && h.path.ends_with("tests/fixtures/winners/9157a34/sm_121.h"));
    }
}

/// Build over build: two clean nightlies, one watch each, no regression.
#[test]
fn nightly_watches() {
    let r = regression(&Sources::repo_fixtures());
    let clean: Vec<&str> = r.runs.iter().filter(|x| !x.excluded).map(|x| x.run_id.as_str()).collect();
    assert_eq!(clean, ["b34425e97d6d", "eb5bcee294d4"]);
    let watch = |run: &str| {
        let x = r.runs.iter().find(|x| x.run_id == run).unwrap();
        assert_eq!((x.kind, x.measured, x.regressions), ("sweep", 14, 0));
        let w: Vec<_> = x.checks.iter().filter(|c| c.status == "watch").collect();
        assert_eq!(w.len(), 1);
        (w[0].shape.clone(), (w[0].before_pct.unwrap() * 10.0).round() / 10.0, (w[0].pct.unwrap() * 10.0).round() / 10.0, w[0].before_run.clone().unwrap())
    };
    assert_eq!(watch("b34425e97d6d"), ("16x4864x896".into(), 99.4, 96.1, "41cc8ffb03fd".into()));
    assert_eq!(watch("eb5bcee294d4"), ("1x4864x896".into(), 98.1, 94.0, "b34425e97d6d".into()));
}

/// Disturbed runs (the in-run watch) are listed, excluded, never classified.
#[test]
fn disturbed_runs_are_excluded() {
    let r = regression(&Sources::repo_fixtures());
    let excluded: Vec<&str> = r.runs.iter().filter(|x| x.excluded).map(|x| x.run_id.as_str()).collect();
    assert_eq!(excluded, ["d1504a45376d", "60959720261a"]);
    let d = r.runs.iter().find(|x| x.run_id == "d1504a45376d").unwrap();
    assert_eq!((d.disturbed, d.kind, d.measured), (Some(true), "not readable", 0));
    assert!(d.disturbed_detail.as_deref().unwrap().starts_with("1 of 41 2 s windows over 2%"));
    assert!(d.checks.iter().all(|c| c.status == "not measured" && c.pct.is_none()));
}

fn confirm(sha: &str) -> NewPairedResult {
    NewPairedResult {
        sha_a: Some(sha.into()),
        sha_b: Some(sha.into()),
        shape: (16, 4864, 896),
        impl_a: "mma_pipe_64x64x32_2x2_s4".into(),
        impl_b: "mma_pipe_64x64x32_2x2_s4".into(),
        ratio: 1.04,
        ci_lo: 1.02,
        ci_hi: 1.06,
        n: 30,
        protocol_version: 2,
        cache_mode: "cold".into(),
        idle_reading: Some(0.2),
        clocks_locked: false,
        started_at: "2026-10-16T12:00:00+00:00".into(),
        finished_at: "2026-10-16T12:02:00+00:00".into(),
        disturbed: Some(false),
        disturbed_detail: None,
    }
}

fn doctored(name: &str, r: &NewPairedResult) -> (Sources, std::path::PathBuf) {
    let mut s = Sources::repo_fixtures();
    let dir = std::env::temp_dir().join(format!("custos-regress-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("aegis_perf.db");
    std::fs::copy(&s.db, &db).unwrap();
    ab::store(&aegis_perf::db::connect(&db).unwrap(), r).unwrap();
    s.db = db;
    (s, dir)
}

/// No confirmed regression exists in the live DB. A doctored copy with a
/// paired-ab (same impl, two builds, CI above 1.0) after the watch's earlier
/// run makes it one, by Core's rule; its provenance is shown with it.
#[test]
fn a_paired_ab_confirms_a_regression() {
    let (s, dir) = doctored("clean", &confirm("9157a34"));
    let r = regression(&s);
    let x = r.runs.iter().find(|x| x.run_id == "b34425e97d6d").unwrap();
    let c = x.checks.iter().find(|c| c.shape == "16x4864x896").unwrap();
    assert_eq!((c.status, c.why), ("regression", Some("confirmed by paired-ab")));
    let p = c.paired.as_ref().unwrap();
    assert_eq!((p.ratio, p.ci_lo, p.ci_hi, p.provenance), (1.04, 1.02, 1.06, "clean"));
    assert_eq!((x.watches, x.regressions), (0, 1));
    // The next night 16x4864x896 is back (99.3%): nothing, confirmation or not.
    let y = r.runs.iter().find(|x| x.run_id == "eb5bcee294d4").unwrap();
    assert_eq!(y.checks.iter().find(|c| c.shape == "16x4864x896").unwrap().status, "ok");
    std::fs::remove_dir_all(dir).ok();

    // Core's rule does not look at the build; Custos labels a dirty one.
    let (s, dir) = doctored("dirty", &confirm("9157a34d24b5-dirty"));
    let r = regression(&s);
    let x = r.runs.iter().find(|x| x.run_id == "b34425e97d6d").unwrap();
    let c = x.checks.iter().find(|c| c.shape == "16x4864x896").unwrap();
    assert_eq!(c.status, "regression");
    assert_eq!(c.paired.as_ref().unwrap().provenance_label, Some("unreproducible (dirty build)"));
    std::fs::remove_dir_all(dir).ok();
}

/// Without the build's own header, the current one is used, and said so.
#[test]
fn current_header_when_the_build_header_is_missing() {
    let mut s = Sources::repo_fixtures();
    let dir = std::env::temp_dir().join(format!("custos-regress-hdr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(s.winners_header(121), dir.join("sm_121.h")).unwrap();
    s.winners_dir = dir.clone();
    let r = regression(&s);
    let x = r.runs.iter().find(|x| x.run_id == "b34425e97d6d").unwrap();
    let h = x.header.as_ref().unwrap();
    assert!(!h.own_build && h.provisional);
    // The v0.5.0 header's decode and TMA winners were never in a 9157a34 nightly.
    assert_eq!(x.checks.iter().find(|c| c.shape == "1x896x896").unwrap().status, "not measured");
    std::fs::remove_dir_all(dir).ok();
}

/// The nightly fuzz: four nights of 50,000 cases; the first night's one
/// failure, case 24632, with Core's FP64 adjudication from its LOG.
#[test]
fn nightly_fuzz_panel() {
    let mut s = Sources::repo_fixtures();
    let r = regression(&s);
    let nights: Vec<(&str, Option<i64>, Option<i64>)> = r.fuzz.iter().map(|n| (n.stamp.as_str(), n.cases, n.failures)).collect();
    assert_eq!(
        nights,
        [
            ("20261014-201534", Some(50000), Some(1)),
            ("20261015-030050", Some(50000), Some(0)),
            ("20261016-030050", Some(50000), Some(0)),
            ("20261017-030050", Some(50000), Some(0)),
        ]
    );
    let first = &r.fuzz[0];
    assert_eq!((first.seed, first.fp64_reference, first.cublaslt_reference, first.seconds), (Some(20261014), Some(37333), Some(12667), Some(1003.0)));
    let c = &first.cases_reported[0];
    assert_eq!((c.kind.as_str(), c.case), ("FAIL", 24632));
    assert!(c.detail.as_deref().unwrap().contains("got 1.00684, ref 1.00977"));
    let a = c.adjudication.as_ref().unwrap();
    assert_eq!((a.cublaslt_ulp, a.ours_ulp, a.verdict.as_str()), (2.57, 0.43, "a reference bug"));
    assert_eq!((a.source.line, a.source.heading.as_str()), (1393, "2026-10-15 — Fuzz case 24632: a cuBLASLt reference error, not ours"));

    s.docs_dir = std::env::temp_dir().join("custos-no-docs");
    assert!(regression(&s).fuzz[0].cases_reported[0].adjudication.is_none());
    s.nightly_dir = std::env::temp_dir().join("custos-no-nightly");
    assert!(regression(&s).fuzz.is_empty());
}

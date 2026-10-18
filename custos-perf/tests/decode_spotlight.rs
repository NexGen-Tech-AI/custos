//! The decode spotlight (M <= 16) on the committed fixtures: % of the read
//! roof as `aegis-perf report` prints it, the kernel's paired results against
//! cublaslt_best with their build provenance, the dispatch target, the impl
//! family and split-K, and a diagnosis only where Core's LOG states one.
use aegis_perf::ab::{self, NewPairedResult};
use custos_perf::winners::Winner;
use custos_perf::Sources;

fn winners(s: &Sources) -> Vec<Winner> {
    custos_perf::winners(s, &s.open().unwrap(), 121).unwrap()
}

fn decode(w: &[Winner]) -> Vec<&Winner> {
    w.iter().filter(|x| x.decode).collect()
}

/// `aegis-perf report`'s roof table: (M, N, K, impl) -> %roof and roof name,
/// from the golden output of the pinned tag's CLI on the fixture.
/// ((M, N, K, impl), (%roof, roof)).
type RoofRow = ((i64, i64, i64, String), (String, String));

fn report_roof() -> Vec<RoofRow> {
    let text = include_str!("../../tests/fixtures/golden/report-121.txt");
    let table = text.split("%roof\n").nth(1).unwrap();
    table
        .lines()
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let dims = (t[0].parse().unwrap(), t[1].parse().unwrap(), t[2].parse().unwrap());
            ((dims.0, dims.1, dims.2, t[3].to_string()), (t[t.len() - 1].to_string(), t[t.len() - 4].to_string()))
        })
        .collect()
}

/// Every decode value against the report: % of the read roof (the roof
/// table's %roof on the winner's row, roof "read") and the kernel % (the
/// report cell, checked in winners_view.rs); the dispatch target; the family
/// and requested split-K from the config.
#[test]
fn decode_values_match_the_report() {
    let s = Sources::repo_fixtures();
    let w = winners(&s);
    let d = decode(&w);
    assert_eq!(d.len(), 6);
    let report = report_roof();
    for x in &d {
        let sp = x.decode_spotlight.as_ref().unwrap();
        let ((_, _, _, _), (pct_roof, roof)) =
            report.iter().find(|((m, n, k, i), _)| (*m, *n, *k) == (x.m, x.n, x.k) && i == &x.impl_).unwrap_or_else(|| panic!("{}", x.shape_bucket));
        assert_eq!(roof, "read", "{}", x.shape_bucket);
        assert_eq!(&format!("{:.1}%", sp.pct_of_read_roof.unwrap()), pct_roof, "{}", x.shape_bucket);
        assert!((sp.read_bw_gbps.unwrap() - 257.841).abs() < 1e-9);
        assert_eq!(x.dispatch.target, "aegis", "{}: every decode shape runs the kernel", x.shape_bucket);
        assert_eq!((sp.family.as_str(), sp.path.as_deref()), ("gemv_tc", Some("tensor_core")));
        assert!(x.impl_.ends_with(&format!("_k{}", sp.split_k.unwrap())), "{}", x.impl_);
    }
    let k = |b: &str| d.iter().find(|x| x.shape_bucket == b).unwrap().decode_spotlight.as_ref().unwrap().split_k;
    assert_eq!((k("1x896x4864"), k("16x896x4864"), k("1x896x896")), (Some(3), Some(3), Some(1)));
    assert!(w.iter().filter(|x| !x.decode).all(|x| x.decode_spotlight.is_none()));
}

/// The paired-ab results (Phase C step 4, ids 26-44) are all from build
/// 0bd0f22a35a6-dirty: every decode call is labeled unreproducible, none is
/// confirmed. The values are LOG's (2026-10-17, Phase C step 4) table.
#[test]
fn decode_paired_results_are_unreproducible() {
    let s = Sources::repo_fixtures();
    let w = winners(&s);
    let want = [
        ("1x896x896", 27, 106.2, (105.2, 106.7), "win"),
        ("1x4864x896", 30, 100.2, (97.7, 101.2), "tie"),
        ("1x896x4864", 33, 105.3, (104.0, 105.7), "win"),
        ("16x896x896", 36, 114.8, (113.5, 115.3), "win"),
        ("16x4864x896", 40, 101.1, (100.6, 102.3), "win"),
        ("16x896x4864", 43, 100.3, (97.3, 100.8), "tie"),
    ];
    for (shape, id, pct, (lo, hi), verdict) in want {
        let x = w.iter().find(|x| x.shape_bucket == shape).unwrap();
        let a = x.paired_ab.kernel.as_ref().unwrap_or_else(|| panic!("{shape}"));
        assert_eq!((a.id, a.impl_.as_str(), a.verdict), (id, x.impl_.as_str(), verdict), "{shape}");
        let r1 = |v: f64| (v * 10.0).round() / 10.0;
        assert_eq!((r1(a.pct_of_cublaslt_best), r1(a.ci_lo_pct), r1(a.ci_hi_pct)), (pct, lo, hi), "{shape}");
        assert_eq!(a.sha_b.as_deref(), Some("0bd0f22a35a6-dirty"));
        assert!(!a.confirmed && a.provenance == "dirty");
        assert_eq!(a.label, format!("{verdict} (unreproducible: dirty build)"));
        // The dispatch (aegis::matmul) against cublaslt_best: the kernel route.
        let d = x.paired_ab.dispatch.as_ref().unwrap();
        assert_eq!(d.impl_, "aegis_matmul");
        assert!(!d.confirmed);
    }
    // 16x896x896's dispatch result #37 was disturbed: left out, #38 is used.
    let x = w.iter().find(|x| x.shape_bucket == "16x896x896").unwrap();
    let d = x.paired_ab.dispatch.as_ref().unwrap();
    assert_eq!((d.id, d.excluded), (38, 1));
    assert!((d.pct_of_cublaslt_best - 115.0).abs() < 0.05, "{}", d.pct_of_cublaslt_best);
}

/// A doctored copy with a clean result from a build that has a runs row
/// (the decode tune's, 1084490): the win counts as confirmed.
#[test]
fn a_clean_build_confirms_a_decode_win() {
    let mut s = Sources::repo_fixtures();
    let dir = std::env::temp_dir().join(format!("custos-decode-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("aegis_perf.db");
    std::fs::copy(&s.db, &db).unwrap();
    {
        let con = aegis_perf::db::connect(&db).unwrap();
        ab::store(
            &con,
            &NewPairedResult {
                sha_a: Some("1084490".into()),
                sha_b: Some("1084490".into()),
                shape: (1, 896, 896),
                impl_a: "cublaslt_best".into(),
                impl_b: "gemv_tc_16x64x64_1x4_s4_k1".into(),
                ratio: 0.95,
                ci_lo: 0.94,
                ci_hi: 0.96,
                n: 30,
                protocol_version: 2,
                cache_mode: "cold".into(),
                idle_reading: Some(0.3),
                clocks_locked: false,
                started_at: "2026-10-18T09:00:00+00:00".into(),
                finished_at: "2026-10-18T09:02:00+00:00".into(),
                disturbed: Some(false),
                disturbed_detail: None,
            },
        )
        .unwrap();
    }
    s.db = db;
    let w = winners(&s);
    let a = w.iter().find(|x| x.shape_bucket == "1x896x896").unwrap().paired_ab.kernel.clone().unwrap();
    assert!(a.confirmed && a.provenance == "clean" && a.provenance_label.is_none());
    assert_eq!((a.verdict, a.label.as_str()), ("win", "win (confirmed)"));
    std::fs::remove_dir_all(&dir).ok();
}

/// "below floor: launch-overhead bound" only where Core's LOG says so (the
/// 896x896 shapes, Phase C step 4), with its source; without the doc, or
/// with a doc that no longer says it, the number stands alone.
#[test]
fn launch_overhead_diagnosis_only_where_core_states_it() {
    let mut s = Sources::repo_fixtures();
    let w = winners(&s);
    let diagnosed: Vec<&str> = decode(&w)
        .into_iter()
        .filter(|x| x.decode_spotlight.as_ref().unwrap().diagnosis.is_some())
        .map(|x| x.shape_bucket.as_str())
        .collect();
    assert_eq!(diagnosed, ["1x896x896", "16x896x896"]);
    let x = w.iter().find(|x| x.shape_bucket == "1x896x896").unwrap();
    let d = x.decode_spotlight.as_ref().unwrap().diagnosis.as_ref().unwrap();
    assert_eq!(d.label, "below floor: launch-overhead bound");
    assert_eq!((d.source.doc.as_str(), d.source.line), ("docs/LOG.md", 1977));
    assert_eq!(d.source.heading, "2026-10-17 — Phase C step 4: decode results, winners and dispatch");

    s.docs_dir = std::env::temp_dir().join("custos-no-docs");
    assert!(decode(&winners(&s)).iter().all(|x| x.decode_spotlight.as_ref().unwrap().diagnosis.is_none()));

    let dir = std::env::temp_dir().join(format!("custos-docs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = std::fs::read_to_string(Sources::repo_fixtures().docs_dir.join("LOG.md")).unwrap();
    std::fs::write(dir.join("LOG.md"), log.replace("They are bound by\nlaunch overhead", "They are limited by something")).unwrap();
    s.docs_dir = dir.clone();
    assert!(decode(&winners(&s)).iter().all(|x| x.decode_spotlight.as_ref().unwrap().diagnosis.is_none()));
    std::fs::remove_dir_all(&dir).ok();
}

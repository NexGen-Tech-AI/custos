//! The win chain on the committed fixtures: which decode shape it explains
//! and why, and that each part comes from its source (Roofline, Kernel,
//! Winners, Core's docs) or is None when that source is missing.
use aegis_perf::ab::{self, NewPairedResult};
use custos_perf::kernel::SassOrigin;
use custos_perf::Sources;

fn chain(s: &Sources) -> custos_perf::win_chain::WinChain {
    custos_perf::win_chain(s, &s.open().unwrap(), 121, None).unwrap().expect("a decode win to explain")
}

/// No decode result is clean, so the chain takes the strongest dirty one,
/// labeled: 16x896x896 (paired-ab #36, CI 113.5-115.3% of cublaslt_best).
#[test]
fn picks_the_strongest_decode_win_and_says_it_is_dirty() {
    let s = Sources::repo_fixtures();
    let c = chain(&s);
    assert_eq!(c.shape_bucket, "16x896x896");
    let p = c.pick.as_ref().unwrap();
    assert!(!p.clean);
    assert_eq!((p.source.as_str(), p.basis.as_str()), ("paired_results #36", "no clean paired result: strongest unreproducible (dirty build)"));
    assert!((p.ci_lo_pct - 113.54).abs() < 0.01);
    // Exactly one Winners row links to it.
    let ws = custos_perf::winners(&s, &s.open().unwrap(), 121).unwrap();
    let linked: Vec<&str> = ws.iter().filter(|w| w.win_chain.is_some()).map(|w| w.shape_bucket.as_str()).collect();
    assert_eq!(linked, ["16x896x896"]);
}

/// Each part of the page, from its source.
#[test]
fn every_part_comes_from_its_source() {
    let s = Sources::repo_fixtures();
    let c = chain(&s);
    let w = &c.winner;
    assert_eq!(w.impl_, "gemv_tc_16x64x64_1x4_s4_k1");
    // Roofline position: the Roofline view's own points for the shape.
    let r = c.roofline.as_ref().unwrap();
    let pts: Vec<_> = r.points.iter().filter(|p| p.shape_bucket == "16x896x896").collect();
    assert_eq!(pts.len(), 2);
    assert_eq!(pts.iter().find(|p| p.series == "winner").unwrap().impl_, w.impl_);
    assert!((w.roof.as_ref().unwrap().pct_roof - 67.64).abs() < 0.01);
    // Kernel: config, registers, spills, mix and SASS with its provenance.
    let k = c.kernel.as_ref().unwrap();
    assert_eq!((k.kernel_id.as_str(), k.regs, k.local_bytes), (w.kernel_id.as_str(), Some(72), Some(0)));
    let sass = k.artifacts[0].sass.as_ref().unwrap();
    assert!(matches!(&sass.origin, SassOrigin::CompiledFromTag { tag, .. } if tag == "aegis-perf-v0.5.0"));
    assert!(k.artifacts[0].instruction_mix.is_some());
    // Paired CI and dispatch: the Winners row's.
    assert!((w.vs_cublaslt_best.ci.as_ref().unwrap().lo - 1.10918).abs() < 1e-9);
    assert_eq!(w.paired_ab.kernel.as_ref().unwrap().id, 36);
    assert_eq!((w.dispatch.target, w.dispatch.stored.as_deref()), ("aegis", Some("aegis")));
    // Docs: the LOG sections that name the kernel, or gemv_tc and the shape.
    let docs: Vec<(usize, &str)> = c.docs.iter().map(|d| (d.line, d.why.as_deref().unwrap())).collect();
    assert_eq!(
        docs,
        [
            (1898, "names gemv_tc_16x64x64_1x4_s4_k1"),
            (1945, "names gemv_tc and 16x896x896"),
            (1977, "names gemv_tc_16x64x64_1x4_s4_k1"),
        ]
    );
    assert!(c.docs.iter().all(|d| d.doc == "docs/LOG.md"));
}

/// Each source removed: its part is None (shown "not measured"), the rest stays.
#[test]
fn a_missing_source_is_none() {
    let none = std::env::temp_dir().join("custos-chain-none");
    let mut s = Sources::repo_fixtures();
    s.arch_dir = none.clone();
    let c = chain(&s);
    assert!(c.roofline.is_none() && c.winner.roof.is_none());
    assert!(c.winner.decode_spotlight.as_ref().unwrap().pct_of_read_roof.is_none());
    assert!(c.kernel.is_some());

    let mut s = Sources::repo_fixtures();
    s.sass_dir = none.clone();
    let k = chain(&s).kernel.unwrap();
    assert!(k.artifacts.iter().all(|a| a.sass.is_none() && a.instruction_mix.is_none() && a.resource_usage.is_none()));

    let mut s = Sources::repo_fixtures();
    s.docs_dir = none;
    let c = chain(&s);
    assert!(c.docs.is_empty());
    assert!(c.winner.decode_spotlight.as_ref().unwrap().diagnosis.is_none());
}

/// A clean, linked paired result for another decode win makes that one the
/// chain's, and says so (doctored copy, written by aegis-perf).
#[test]
fn a_clean_result_wins_the_pick() {
    let mut s = Sources::repo_fixtures();
    let dir = std::env::temp_dir().join(format!("custos-chain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("aegis_perf.db");
    std::fs::copy(&s.db, &db).unwrap();
    {
        let con = aegis_perf::db::connect(&db).unwrap();
        let r = NewPairedResult {
            sha_a: Some("1084490".into()),
            sha_b: Some("1084490".into()),
            shape: (1, 896, 4864),
            impl_a: "cublaslt_best".into(),
            impl_b: "gemv_tc_16x64x64_1x4_s5_k3".into(),
            ratio: 0.96,
            ci_lo: 0.955,
            ci_hi: 0.965,
            n: 30,
            protocol_version: 2,
            cache_mode: "cold".into(),
            idle_reading: Some(0.2),
            clocks_locked: false,
            started_at: "2026-10-18T09:00:00+00:00".into(),
            finished_at: "2026-10-18T09:02:00+00:00".into(),
            disturbed: Some(false),
            disturbed_detail: None,
        };
        ab::store(&con, &r).unwrap();
    }
    s.db = db;
    let c = chain(&s);
    assert_eq!(c.shape_bucket, "1x896x4864");
    let p = c.pick.unwrap();
    assert!(p.clean && p.basis == "strongest clean paired result");
    std::fs::remove_dir_all(&dir).ok();
}

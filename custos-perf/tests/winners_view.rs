//! Winners view acceptance: one row per shape, matching the golden outputs of
//! the pinned tag's CLI on the same fixture DB (tests/fixtures/golden/):
//! `emit-header` (config, % of cuBLAS and of cublaslt_best, the runner-up
//! paired CI, ties) and `report` (% of cublaslt_best per impl and shape).
use std::collections::HashMap;

use custos_perf::winners::Winner;
use custos_perf::Sources;

fn winners() -> Vec<Winner> {
    let s = Sources::repo_fixtures();
    let con = s.open().unwrap();
    custos_perf::winners(&s, &con, 121).unwrap()
}

struct HeaderRow {
    bucket: String,
    impl_: String,
    pct_cublas: String,
    pct_lt: String,
    ci: Option<String>,
    tied_with: Option<String>,
}

/// `{M, N, K, "impl"},  // 103.1% of cuBLAS, 98.2% of cublaslt_best [paired CI 1.032-1.033]`
fn header_rows(text: &str) -> Vec<HeaderRow> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .map(|l| {
            let (code, comment) = l.split_once("//").unwrap();
            let f: Vec<&str> = code.trim_start_matches('{').split('}').next().unwrap().split(',').map(str::trim).collect();
            let pct = |what: &str| {
                let i = comment.find(what).unwrap();
                comment[..i].trim_end().rsplit(' ').next().unwrap().trim_end_matches('%').to_string()
            };
            let ci = comment.split_once("[paired CI ").map(|(_, r)| r.split(']').next().unwrap().to_string());
            let tied_with = comment.split_once("TIED with ").map(|(_, r)| r.split_whitespace().next().unwrap().to_string());
            HeaderRow {
                bucket: format!("{}x{}x{}", f[0], f[1], f[2]),
                impl_: f[3].trim_matches('"').to_string(),
                pct_cublas: pct("% of cuBLAS"),
                pct_lt: pct("% of cublaslt_best"),
                ci,
                tied_with,
            }
        })
        .collect()
}

#[test]
fn matches_the_golden_header() {
    let w = winners();
    let rows = header_rows(include_str!("../../tests/fixtures/golden/emit-header-sm_121.h"));
    assert_eq!(rows.len(), 14);
    assert_eq!(w.len(), rows.len(), "one Winners row per header row");
    for h in &rows {
        let x = w.iter().find(|x| x.shape_bucket == h.bucket).unwrap_or_else(|| panic!("{}", h.bucket));
        assert_eq!(x.impl_, h.impl_, "{}: winning config", h.bucket);
        assert_eq!(format!("{:.1}", x.pct_of_cublas.unwrap()), h.pct_cublas, "{}", h.bucket);
        assert_eq!(format!("{:.1}", x.vs_cublaslt_best.pct_of_cublaslt_best.unwrap()), h.pct_lt, "{}: kernel %", h.bucket);
        let ci = x.tie.ci.as_ref().map(|c| format!("{:.3}-{:.3}", c.lo, c.hi));
        assert_eq!(ci, h.ci, "{}: runner-up paired CI", h.bucket);
        assert_eq!(x.tie.tied, h.tied_with.is_some(), "{}: tied", h.bucket);
        if let Some(other) = &h.tied_with {
            assert_eq!(x.tie.contender.as_deref(), Some(other.as_str()), "{}", h.bucket);
        }
    }
}

/// The report's cell for the winner's impl (% of cublaslt_best, latest clean
/// v2 cold rows) equals the Winners view's kernel %.
#[test]
fn matches_the_golden_report() {
    let text = include_str!("../../tests/fixtures/golden/report-121.txt");
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
    let impls = &header[header.iter().position(|h| *h == "TFLOPS").unwrap() + 1..];
    let mut cells: HashMap<(String, String), String> = HashMap::new();
    for l in lines.skip(1).take_while(|l| !l.trim().is_empty()) {
        let t: Vec<&str> = l.split_whitespace().collect();
        let bucket = format!("{}x{}x{}", t[1], t[2], t[3]);
        assert_eq!(t.len(), 6 + impls.len(), "{l}");
        for (i, c) in impls.iter().zip(&t[6..]) {
            cells.insert((bucket.clone(), i.to_string()), c.to_string());
        }
    }
    let w = winners();
    for x in &w {
        let cell = &cells[&(x.shape_bucket.clone(), x.impl_.clone())];
        assert_eq!(*cell, format!("{:.1}%", x.vs_cublaslt_best.pct_of_cublaslt_best.unwrap()), "{}", x.shape_bucket);
    }
    assert!(text.contains("excluding --allow-busy and disturbed rows"), "the report's default filters are the view's");
}

/// Contract rule 10: a shape routed to cuBLASLt shows "dispatch: cuBLASLt"
/// and never AEGIS's kernel % as its dispatch %.
#[test]
fn cublaslt_dispatch_never_shows_the_kernel_pct() {
    let w = winners();
    let routed: Vec<&Winner> = w.iter().filter(|x| x.dispatch.target == "cublaslt").collect();
    assert_eq!(routed.len(), 4);
    for x in routed {
        let kernel = x.vs_cublaslt_best.pct_of_cublaslt_best;
        assert!(kernel.is_some(), "{}: the kernel's own % stays beside it", x.shape_bucket);
        assert_eq!(x.dispatch.pct_of_cublaslt_best, None, "{}", x.shape_bucket);
        assert_ne!(x.dispatch.pct_of_cublaslt_best, kernel);
        assert_eq!(x.bars.below_floor, Some(true), "{}", x.shape_bucket);
    }
    // A kernel route: the dispatch % is the kernel's own.
    for x in w.iter().filter(|x| x.dispatch.target == "aegis") {
        assert_eq!(x.dispatch.pct_of_cublaslt_best, x.vs_cublaslt_best.pct_of_cublaslt_best);
    }
}

/// Production bars (provisional): large >= 90%, decode >= 100% (a tie or a
/// win), 80% floor, judged on the paired CI's upper bound.
#[test]
fn production_bars() {
    let w = winners();
    let got: Vec<(&str, &str, &str, &str)> = w
        .iter()
        .map(|x| (x.shape_bucket.as_str(), x.bars.class, x.bars.verdict.unwrap(), x.bars.margin.unwrap()))
        .collect();
    assert_eq!(
        got,
        [
            ("256x256x256", "other", "pass", "clear"),
            ("512x512x512", "other", "pass", "clear"),
            ("1024x1024x1024", "large", "pass", "clear"),
            ("2048x2048x2048", "large", "fail", "clear"),
            ("4096x4096x4096", "large", "fail", "clear"),
            ("1x896x896", "decode", "fail", "clear"),
            ("1x4864x896", "decode", "fail", "clear"),
            ("1x896x4864", "decode", "fail", "clear"),
            ("16x896x896", "decode", "fail", "clear"),
            // CI [1.00121, 1.00384] vs cublaslt_best: a win, meets the decode bar.
            ("16x4864x896", "decode", "pass", "clear"),
            ("16x896x4864", "decode", "fail", "clear"),
            ("512x896x896", "other", "pass", "clear"),
            // CI [0.78509, 0.79031] entirely below the 80% floor.
            ("512x4864x896", "other", "fail", "clear"),
            ("512x896x4864", "other", "pass", "clear"),
        ]
    );
    assert!(w.iter().all(|x| x.bars.basis == "paired"));
    let decode = w.iter().find(|x| x.shape_bucket == "1x896x896").unwrap();
    assert_eq!((decode.bars.bar, decode.bars.floor), (1.0, 0.8));
}

/// The fixture's winners are the ones the pinned tag's own header was
/// generated from: the golden emit-header (the tag's CLI on the fixture) has
/// the same rows as tests/fixtures/winners/sm_121.h.
#[test]
fn matches_the_tags_header() {
    let golden = header_rows(include_str!("../../tests/fixtures/golden/emit-header-sm_121.h"));
    let tag = header_rows(include_str!("../../tests/fixtures/winners/sm_121.h"));
    assert_eq!(tag.len(), 14);
    for (g, t) in golden.iter().zip(&tag) {
        assert_eq!(
            (&g.bucket, &g.impl_, &g.pct_cublas, &g.pct_lt, &g.ci, &g.tied_with),
            (&t.bucket, &t.impl_, &t.pct_cublas, &t.pct_lt, &t.ci, &t.tied_with)
        );
    }
}

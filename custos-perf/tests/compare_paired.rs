//! compare() reads paired_results (contract rule 6): a median shift over
//! Core's 3% gate is "confirmed" or "not_confirmed" only when a stored
//! paired-ab result matches it (same shape, the same impl on both sides,
//! protocol, cache mode, the two builds in either order); otherwise
//! "unconfirmed". On the committed fixture, and on doctored copies of it
//! with paired results added through Core's own writer (aegis_perf::ab::store).
use aegis_perf::ab::{self, NewPairedResult};
use custos_perf::measure::{Compare, CompareRow, REGRESSION_PCT};
use custos_perf::{Filter, Sources};

// The fixture's two tune builds (runs.git_sha keeps 7 hex digits).
const A: &str = "7fe7a84";
const B: &str = "9157a34";
const BIG: (i64, i64, i64) = (4096, 4096, 4096);

fn row<'a>(c: &'a Compare, impl_: &str) -> &'a CompareRow {
    c.rows.iter().find(|r| r.impl_ == impl_ && (r.m, r.n, r.k) == BIG).unwrap_or_else(|| panic!("{impl_}"))
}

fn result(sha_a: &str, sha_b: &str, impl_: &str, (lo, hi): (f64, f64)) -> NewPairedResult {
    NewPairedResult {
        sha_a: Some(sha_a.into()),
        sha_b: Some(sha_b.into()),
        shape: BIG,
        impl_a: impl_.into(),
        impl_b: impl_.into(),
        ratio: (lo + hi) / 2.0,
        ci_lo: lo,
        ci_hi: hi,
        n: 30,
        protocol_version: 2,
        cache_mode: "cold".into(),
        idle_reading: Some(0.4),
        clocks_locked: false,
        started_at: "2026-10-17T23:00:00+00:00".into(),
        finished_at: "2026-10-17T23:02:00+00:00".into(),
        disturbed: Some(false),
        disturbed_detail: None,
    }
}

/// A copy of the committed fixture (no process writes it, so a plain copy is
/// consistent) with `extra` paired results stored by aegis-perf itself.
fn doctored(name: &str, extra: &[NewPairedResult]) -> Sources {
    let mut s = Sources::repo_fixtures();
    let dir = std::env::temp_dir().join(format!("custos-compare-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("aegis_perf.db");
    std::fs::copy(&s.db, &db).unwrap();
    {
        let con = aegis_perf::db::connect(&db).unwrap();
        for r in extra {
            ab::store(&con, r).unwrap();
        }
    }
    s.db = db;
    s
}

fn compare(s: &Sources, f: &Filter) -> Compare {
    custos_perf::compare(&s.open().unwrap(), A, B, f).unwrap()
}

#[test]
fn threshold_is_cores_regression_gate() {
    assert_eq!(REGRESSION_PCT, aegis_perf::regress::REGRESSION * 100.0);
    assert_eq!(compare(&Sources::repo_fixtures(), &Filter::default()).threshold_pct, 3.0);
}

/// The fixture as committed: its 10 paired results are other builds or
/// other impl pairs (cublaslt_best vs aegis_matmul), so no shift between
/// 7fe7a84 and 9157a34 is backed: every one is unconfirmed.
#[test]
fn fixture_shifts_are_unconfirmed() {
    let c = compare(&Sources::repo_fixtures(), &Filter::default());
    assert_eq!(c.rows.len(), 81);
    assert_eq!((c.confirmed_slower, c.not_confirmed_slower, c.unconfirmed_slower, c.faster, c.within), (0, 0, 11, 2, 68));
    for r in c.rows.iter().filter(|r| r.flag != "within") {
        assert_eq!(r.status, "unconfirmed", "{}", r.impl_);
        assert!(r.paired.is_none() && r.paired_excluded == 0);
    }
}

#[test]
fn matching_paired_results_confirm_or_not() {
    let s = doctored(
        "match",
        &[
            // +5.8% median shift; paired CI above 1: confirmed.
            result(A, "9157a34d24b5", "mma_pipe_64x64x32_2x2_s4", (1.050, 1.064)),
            // +4.5%; paired CI contains 1.0: not confirmed.
            result(A, "9157a34d24b5", "mma_pipe_128x64x32_2x2_s3", (0.995, 1.012)),
            // -15.7%, stored the other way round (B, A): inverted to b / a =
            // [1/1.19, 1/1.17], below 1: a confirmed speed-up.
            result("9157a34d24b5", A, "mma_pipe_128x256x32_2x4_s4", (1.17, 1.19)),
        ],
    );
    let c = compare(&s, &Filter::default());
    let r = row(&c, "mma_pipe_64x64x32_2x2_s4");
    assert!(r.change_pct > REGRESSION_PCT);
    assert_eq!((r.flag, r.status), ("slower", "confirmed"));
    let p = r.paired.as_ref().unwrap();
    assert!(p.source.starts_with("paired_results #") && !p.inverted && !p.dirty && p.linked);
    assert_eq!((p.provenance, p.provenance_label), ("clean", None));
    assert_eq!((p.ratio_ci_lo, p.ratio_ci_hi, p.pairs), (1.050, 1.064, Some(30)));

    let r = row(&c, "mma_pipe_128x64x32_2x2_s3");
    assert_eq!((r.flag, r.status), ("slower", "not_confirmed"));

    let r = row(&c, "mma_pipe_128x256x32_2x4_s4");
    assert_eq!((r.flag, r.status), ("faster", "confirmed"));
    let p = r.paired.as_ref().unwrap();
    assert!(p.inverted && p.usable());
    assert!((p.ratio_ci_lo - 1.0 / 1.19).abs() < 1e-12 && (p.ratio_ci_hi - 1.0 / 1.17).abs() < 1e-12);

    assert_eq!((c.confirmed_slower, c.not_confirmed_slower, c.unconfirmed_slower), (1, 1, 9));
    std::fs::remove_dir_all(s.db.parent().unwrap()).ok();
}

/// Only a result for the same shape, impl (both sides), protocol, cache
/// mode and builds counts; a disturbed or busy one only on request.
#[test]
fn non_matching_and_excluded_results_leave_it_unconfirmed() {
    let impl_ = "mma_pipe_64x128x32_2x4_s3"; // +10.8% median shift
    let base = || result(A, B, impl_, (1.08, 1.12));
    let other_impl = NewPairedResult { impl_b: "mma_pipe_64x128x32_2x4_s4".into(), ..base() };
    let warm = NewPairedResult { cache_mode: "warm".into(), ..base() };
    let v1 = NewPairedResult { protocol_version: 1, ..base() };
    let other_shape = NewPairedResult { shape: (2048, 2048, 2048), ..base() };
    let other_builds = result("b0bedd58fbf9", B, impl_, (1.08, 1.12));
    let disturbed = NewPairedResult { disturbed: Some(true), disturbed_detail: Some("firefox".into()), ..base() };
    let busy = NewPairedResult { idle_reading: Some(5.0), ..base() };
    let unread = NewPairedResult { idle_reading: None, ..base() };
    let s = doctored("nomatch", &[other_impl, warm, v1, other_shape, other_builds, disturbed, busy, unread]);

    let c = compare(&s, &Filter::default());
    let r = row(&c, impl_);
    assert_eq!((r.flag, r.status), ("slower", "unconfirmed"));
    assert!(r.paired.is_none());
    assert_eq!(r.paired_excluded, 3, "disturbed, busy and unread-idle results are left out, and counted");

    // On request (include_busy), the newest of the three backs it, labeled.
    let all = compare(&s, &Filter { include_busy: true, ..Default::default() });
    let r = row(&all, impl_);
    assert_eq!((r.flag, r.status), ("slower", "confirmed"));
    let p = r.paired.as_ref().unwrap();
    assert_eq!((p.older_matches, r.paired_excluded), (2, 0));
    std::fs::remove_dir_all(s.db.parent().unwrap()).ok();
}

/// Doctored copies: a paired result from a `-dirty` build, or with a short
/// SHA no runs row can be matched to, is attached to the shift, labeled, and
/// never confirms it (or rules it out).
#[test]
fn dirty_and_unlinked_results_never_confirm() {
    let up = "mma_pipe_64x64x32_2x2_s4"; // +5.8% median shift
    let up2 = "mma_pipe_64x128x32_2x4_s3"; // +10.8%
    let down = "mma_pipe_128x256x32_2x4_s4"; // -15.7%
    let s = doctored(
        "provenance",
        &[
            // CI above 1, but build b had uncommitted changes.
            result(A, "9157a34d24b5-dirty", up, (1.050, 1.064)),
            // CI above 1, but "7fe7a" (5 hex digits) is shorter than any
            // runs.git_sha: it cannot be tied to the measured run.
            result("7fe7a", B, up2, (1.08, 1.12)),
            // CI entirely below 1 (would confirm the speed-up), dirty build a.
            result("7fe7a84-dirty", B, down, (0.84, 0.86)),
        ],
    );
    let c = compare(&s, &Filter::default());

    let r = row(&c, up);
    assert_eq!((r.flag, r.status), ("slower", "unconfirmed"));
    let p = r.paired.as_ref().unwrap();
    assert!(p.dirty && !p.usable());
    assert_eq!((p.provenance, p.provenance_label), ("dirty", Some("unreproducible (dirty build)")));
    assert_eq!((p.ratio_ci_lo, p.ratio_ci_hi), (1.050, 1.064));

    let r = row(&c, up2);
    assert_eq!((r.flag, r.status), ("slower", "unconfirmed"));
    let p = r.paired.as_ref().unwrap();
    assert!(!p.dirty && !p.linked);
    assert_eq!((p.provenance, p.provenance_label), ("unlinked", Some("unlinked build")));

    let r = row(&c, down);
    assert_eq!((r.flag, r.status), ("faster", "unconfirmed"));
    assert_eq!(r.paired.as_ref().unwrap().provenance_label, Some("unreproducible (dirty build)"));

    assert_eq!((c.confirmed_slower, c.not_confirmed_slower, c.unconfirmed_slower), (0, 0, 11));
    std::fs::remove_dir_all(s.db.parent().unwrap()).ok();
}

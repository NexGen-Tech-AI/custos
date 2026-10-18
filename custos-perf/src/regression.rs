//! Regression view: Core's nightly regression check, build over build. Each
//! regression sweep (a run without paired tests: the nightly's) is checked by
//! aegis-perf itself (`regress::check`, `ShapeCheck::watch` / `regressed`:
//! a > 3% drop is a "watch", a "regression" only when two consecutive
//! nightlies or a paired-ab confirm it). Custos never restates the rule; it
//! only picks the winners header the run's build dispatched (a fallback,
//! core-requests #11) and labels the evidence. Disturbed and allow_busy runs
//! are listed, marked excluded (hidden by default in the UI). The nightly
//! fuzz panel is in `fuzz`.
use aegis_perf::regress::{self, ShapeCheck};
use aegis_perf::rusqlite::Connection;
use aegis_perf::view;
use anyhow::Result;
use serde::Serialize;

use crate::core_fallbacks::{self, FuzzNight};
use crate::measure::{run_shas, Provenance};
use crate::Sources;

/// A paired-ab result that confirms a slowdown (`ShapeCheck::paired`), with
/// its build provenance (Core's rule does not look at it; Custos labels it).
#[derive(Clone, Debug, Serialize)]
pub struct Confirmation {
    pub source: String,
    pub id: i64,
    /// B / A time, the same impl in two builds; CI entirely above 1.0.
    pub ratio: f64,
    pub ci_lo: f64,
    pub ci_hi: f64,
    pub sha_a: Option<String>,
    pub sha_b: Option<String>,
    pub provenance: &'static str,
    pub provenance_label: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub shape: String,
    #[serde(rename = "impl")]
    pub impl_: String,
    /// % of cublaslt_best in this run; None: not measured cleanly here.
    pub pct: Option<f64>,
    /// The newest earlier clean measurement of the pair: (run, %).
    pub before_run: Option<String>,
    pub before_pct: Option<f64>,
    /// "regression", "watch", "ok" (measured, no drop) or "not measured".
    pub status: &'static str,
    /// Why a regression is confirmed, as Core says it.
    pub why: Option<&'static str>,
    pub paired: Option<Confirmation>,
    pub dispatch: String,
    pub dispatch_pct: Option<f64>,
}

/// Which winners header a run was checked against.
#[derive(Clone, Debug, Serialize)]
pub struct HeaderUsed {
    pub path: String,
    /// The header of the run's own build (a fixture or recorded copy), or
    /// only the current one (labeled: the shapes and impls may differ).
    pub own_build: bool,
    pub provisional: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RegressionRun {
    pub run_id: String,
    pub git_sha: Option<String>,
    pub started_at: String,
    pub disturbed: Option<bool>,
    pub disturbed_detail: Option<String>,
    pub allow_busy: bool,
    /// Disturbed or allow_busy: not evidence; greyed out and hidden by default.
    pub excluded: bool,
    /// "sweep" (no paired tests: a regression sweep, the nightly's), or for an
    /// excluded run "not readable": `view::paired` hides a disturbed or busy
    /// run's paired tests, so a tune and a sweep look alike (core-requests #11).
    pub kind: &'static str,
    pub header: Option<HeaderUsed>,
    pub checks: Vec<Check>,
    pub measured: usize,
    pub watches: usize,
    pub regressions: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Regression {
    pub sm: i64,
    /// Core's threshold (`regress::REGRESSION`), in %.
    pub threshold_pct: f64,
    /// Oldest first.
    pub runs: Vec<RegressionRun>,
    pub fuzz: Vec<FuzzNight>,
}

fn status(c: &ShapeCheck) -> (&'static str, Option<&'static str>) {
    if c.regressed() {
        (
            "regression",
            Some(if c.two_consecutive() { "2 consecutive nightlies" } else { "confirmed by paired-ab" }),
        )
    } else if c.watch() {
        ("watch", None)
    } else if c.pct.is_some() {
        ("ok", None)
    } else {
        ("not measured", None)
    }
}

/// The run has v2 cold measurements (disturbed and busy rows included).
fn measured(con: &Connection, run: &view::Run) -> Result<bool> {
    let sel = aegis_perf::db::Selection { include_busy: true, ..aegis_perf::db::Selection::ranking() };
    Ok(!view::measurements(con, &view::MeasurementFilter { sel, run_id: Some(run.run_id.clone()), ..Default::default() })?.is_empty())
}

/// A regression sweep: measured, and no paired tests at the header's shapes
/// (a tune pairs every shape it tunes). Only for clean runs: the paired
/// tests of a disturbed or busy run are not readable.
fn is_sweep(con: &Connection, run: &view::Run, shapes: &[(i64, i64, i64)]) -> Result<bool> {
    if !measured(con, run)? {
        return Ok(false);
    }
    for &s in shapes {
        if !view::paired(con, &run.run_id, s)?.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn regression(src: &Sources, con: &Connection, sm: i64) -> Result<Regression> {
    let results = view::paired_results(con, &view::PairedResultFilter::default())?;
    let shas = run_shas(con)?;
    let mut runs = Vec::new();
    for r in view::runs(con)?.into_iter().filter(|r| r.sm_arch == sm) {
        let header = r.git_sha.as_deref().and_then(|sha| core_fallbacks::build_header(src, sm, sha));
        let (path, own) = match header {
            Some(p) => (p, true),
            None => (src.winners_header(sm), false),
        };
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let winners = regress::header_winners(&text);
        let dispatch = regress::header_dispatch(&text);
        let shapes: Vec<_> = winners.iter().map(|&(m, n, k, _)| (m, n, k)).collect();
        let excluded = r.disturbed == Some(true) || r.allow_busy;
        let kind = if excluded {
            if !measured(con, &r)? {
                continue;
            }
            "not readable"
        } else if is_sweep(con, &r, &shapes)? {
            "sweep"
        } else {
            continue;
        };
        let checks: Vec<Check> = regress::check(con, &r.run_id, &winners)?
            .into_iter()
            .map(|c| {
                let (st, why) = status(&c);
                let paired = c.paired.map(|(id, ratio, ci_lo, ci_hi)| {
                    let p = results.iter().find(|p| p.id == id);
                    let prov = p.map(|p| Provenance::of(p, &shas));
                    Confirmation {
                        source: format!("paired_results #{id}"),
                        id,
                        ratio,
                        ci_lo,
                        ci_hi,
                        sha_a: p.and_then(|p| p.sha_a.clone()),
                        sha_b: p.and_then(|p| p.sha_b.clone()),
                        provenance: prov.as_ref().map_or("unlinked", |p| p.provenance),
                        provenance_label: prov.as_ref().map_or(Some("unlinked build"), |p| p.provenance_label),
                    }
                });
                let (m, n, k) = c.shape;
                Check {
                    shape: format!("{m}x{n}x{k}"),
                    status: st,
                    why,
                    pct: c.pct,
                    before_run: c.before.as_ref().map(|(r, _)| r.clone()),
                    before_pct: c.before.as_ref().map(|(_, p)| *p),
                    paired,
                    // Core's cmd_regress fills the dispatch from the header.
                    dispatch: dispatch.iter().find(|(s, _)| *s == c.shape).map_or(c.dispatch.clone(), |(_, d)| d.clone()),
                    dispatch_pct: c.dispatch_pct,
                    impl_: c.impl_,
                }
            })
            .collect();
        let count = |s: &str| checks.iter().filter(|c| c.status == s).count();
        runs.push(RegressionRun {
            excluded,
            kind,
            header: Some(HeaderUsed { path: path.display().to_string(), own_build: own, provisional: true }),
            measured: checks.iter().filter(|c| c.pct.is_some()).count(),
            watches: count("watch"),
            regressions: count("regression"),
            checks,
            run_id: r.run_id,
            git_sha: r.git_sha,
            started_at: r.started_at,
            disturbed: r.disturbed,
            disturbed_detail: r.disturbed_detail,
            allow_busy: r.allow_busy,
        });
    }
    Ok(Regression {
        sm,
        threshold_pct: regress::REGRESSION * 100.0,
        runs,
        fuzz: core_fallbacks::nightly_fuzz(src),
    })
}

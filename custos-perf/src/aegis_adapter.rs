//! The AEGIS adapter: Custos's perf-DB views (built on aegis-perf, pinned to
//! [`AEGIS_PERF_TAG`]) expressed in the internal model (custos-model), with
//! every contract field in each value's provenance. A Winners row becomes a
//! [`Measurement`], a [`Comparison`] against cublaslt_best and its
//! roof-derived values; a regression row a [`RegressionCheck`].
//!
//! Nsight reports link to AEGIS measurements by run_id and build SHA through
//! a `profiles` table, which aegis-perf at this tag does not have:
//! [`profiles_note`] says so (docs/core-requests.md #13).
use aegis_perf::rusqlite::Connection;
use anyhow::Result;
use custos_model::model::{Capture, Comparison, Derived, DispatchState, Measurement, Quantity, RegressionCheck, Value};
use custos_model::provenance::{
    AegisState, Build, Ci as ModelCi, ClockControl, Clocks, Known, Pairing, Provenance, RoofOrigin, RoofUsed, Source,
    Stats,
};

use crate::regression::{Regression, RegressionRun};
use crate::winners::Winner;
use crate::Sources;

/// The aegis-perf release custos-perf is pinned to (custos-perf/Cargo.toml; a test checks they agree).
pub const AEGIS_PERF_TAG: &str = "aegis-perf-v0.5.0";

fn base(origin: &str) -> Provenance {
    Provenance::new(Source::Aegis, "aegis-perf", Known::Known(AEGIS_PERF_TAG.to_string()), origin)
}

/// The provenance every value of one AEGIS run shares: when, which build, clocks, row state.
fn run_provenance(con: &Connection, run_id: &str, protocol: i64, cache: Option<&str>) -> Result<Provenance> {
    let mut p = base(&format!("runs/{run_id}"));
    if let Some(r) = aegis_perf::view::run(con, run_id)? {
        p.captured_at = Some(r.started_at.clone());
        p.build = r.git_sha.as_deref().map(Build::from_label);
        p.clocks = match r.clocks_locked {
            Some(1) => Clocks { control: ClockControl::Locked, basis: "runs.clocks_locked = 1".into(), sm_mhz: None },
            Some(_) => Clocks { control: ClockControl::Uncontrolled, basis: "runs.clocks_locked = 0".into(), sm_mhz: None },
            None => Clocks::unknown("runs.clocks_locked is NULL (not recorded for this run)"),
        };
        p.aegis = Some(AegisState {
            status: None,
            replaced_by: None,
            disturbed: r.disturbed,
            allow_busy: r.allow_busy,
            protocol,
            cache_mode: cache.map(str::to_string),
        });
    }
    Ok(p)
}

fn verdict(v: &str) -> String {
    match v {
        "faster" => "win".into(),
        "slower" => "loss".into(),
        other => other.into(),
    }
}

/// One Winners row in the model.
pub fn winner(src: &Sources, con: &Connection, w: &Winner) -> Result<Capture> {
    let shape = (w.m, w.n, w.k);
    // Winners rank on protocol v2 cold rows only (Selection::ranking).
    let run = run_provenance(con, &w.run_id, w.protocol_version, Some("cold"))?;
    let mut c = Capture::default();
    c.measurements.push(Measurement {
        run: w.run_id.clone(),
        kernel: w.kernel_id.clone(),
        impl_: w.impl_.clone(),
        shape,
        dtype: w.dtype.clone(),
        median_us: w.median_us,
        p10_us: Value::NotMeasured,
        p90_us: Value::NotMeasured,
        exclusion: None,
        provenance: Provenance { stats: Some(Stats { ci: None, pairing: Pairing::Unpaired }), ..run.clone() },
    });
    let vs = &w.vs_cublaslt_best;
    let stats = Stats {
        ci: vs.ci.as_ref().map(|ci| ModelCi { lo: ci.lo, hi: ci.hi }),
        pairing: match &vs.ci {
            Some(ci) => Pairing::Paired { against: "cublaslt_best".into(), pairs: ci.pairs, across_builds: false },
            None => Pairing::Unpaired,
        },
    };
    let paired_pct = vs.ci.as_ref().and_then(|ci| ci.ratio_median).map(|r| r * 100.0);
    c.comparisons.push(Comparison {
        kernel: w.kernel_id.clone(),
        shape,
        run: w.run_id.clone(),
        baseline: "cublaslt_best".into(),
        kernel_pct: Value::from_option(paired_pct.or(vs.pct_of_cublaslt_best)),
        unpaired_pct: Value::from_option(vs.pct_of_cublaslt_best),
        verdict: vs.verdict.map(verdict),
        dispatch: Some(DispatchState {
            target: w.dispatch.target.to_string(),
            pct: Value::from_option(w.dispatch.pct_of_cublaslt_best),
            stored: w.dispatch.stored.clone(),
            mismatch: w.dispatch.mismatch,
        }),
        bar: Some(w.bars.class.to_string()),
        bar_verdict: w.bars.verdict.map(str::to_string),
        provenance: Provenance {
            stats: Some(stats),
            provisional: w.bars.provisional.then(|| "bars: core_fallbacks (docs/core-requests.md #4)".to_string()),
            ..run.clone()
        },
    });
    if let Some(r) = &w.roof {
        let roof = RoofUsed {
            kind: r.roof.to_string(),
            value: r.roof_gbps,
            unit: "GB/s".into(),
            origin: RoofOrigin::Measured {
                arch_file: src.arch_file(w.sm_arch).file_name().map_or_else(String::new, |f| f.to_string_lossy().into_owned()),
                // emit-arch builds the arch file from valid microbench rows only.
                microbench_status: "valid".into(),
            },
        };
        for (name, value, unit) in
            [("pct_of_roof", r.pct_roof, "%"), ("pct_of_bw", r.pct_bw, "%"), ("gbps", r.gbps, "GB/s"), ("tflops", r.tflops, "TFLOPS")]
        {
            c.derived.push(Derived {
                of: w.kernel_id.clone(),
                shape: Some(shape),
                name: name.into(),
                quantity: Quantity { value: Value::Present(value), unit: unit.into() },
                provenance: Provenance { roof: Some(roof.clone()), ..run.clone() },
            });
        }
    }
    Ok(c)
}

/// One regression run's checks in the model.
pub fn regression_run(con: &Connection, reg: &Regression, r: &RegressionRun) -> Result<Capture> {
    let mut c = Capture::default();
    // Regression sweeps are protocol v2, cold (aegis-perf sweep); the row state is the run's.
    let mut run = run_provenance(con, &r.run_id, 2, Some("cold"))?;
    run.provisional = r
        .header
        .as_ref()
        .filter(|h| h.provisional)
        .map(|h| format!("header {}: core_fallbacks::build_header (docs/core-requests.md #11)", h.path));
    let exclusion = r.excluded.then(|| match (r.disturbed, r.allow_busy) {
        (Some(true), _) => format!("disturbed: {}", r.disturbed_detail.clone().unwrap_or_default()),
        (_, true) => "allow_busy".to_string(),
        _ => "excluded".to_string(),
    });
    for ch in &r.checks {
        let dims: Vec<i64> = ch.shape.split('x').filter_map(|d| d.parse().ok()).collect();
        let shape = (dims[0], dims[1], dims[2]);
        let confirmation = ch.paired.as_ref().map(|p| {
            let mut prov = base(&p.source);
            prov.build = p.sha_b.as_deref().map(Build::from_label);
            prov.stats = Some(Stats {
                ci: Some(ModelCi { lo: p.ci_lo, hi: p.ci_hi }),
                pairing: Pairing::Paired { against: ch.impl_.clone(), pairs: None, across_builds: true },
            });
            Box::new(Comparison {
                kernel: ch.impl_.clone(),
                shape,
                run: r.run_id.clone(),
                baseline: "same impl, earlier build".into(),
                kernel_pct: Value::Present(p.ratio * 100.0),
                unpaired_pct: Value::NotMeasured,
                verdict: None,
                dispatch: None,
                bar: None,
                bar_verdict: p.provenance_label.map(str::to_string),
                provenance: prov,
            })
        });
        c.regressions.push(RegressionCheck {
            run: r.run_id.clone(),
            shape,
            impl_: ch.impl_.clone(),
            pct: Value::from_option(ch.pct),
            before_run: ch.before_run.clone(),
            before_pct: Value::from_option(ch.before_pct),
            status: ch.status.to_string(),
            why: ch.why.map(str::to_string),
            confirmation,
            dispatch: Some(DispatchState {
                target: ch.dispatch.clone(),
                pct: Value::from_option(ch.dispatch_pct),
                stored: None,
                mismatch: false,
            }),
            exclusion: exclusion.clone(),
            provenance: Provenance {
                stats: Some(Stats { ci: None, pairing: Pairing::Unpaired }),
                origin: format!("regress threshold {}%: runs/{}", reg.threshold_pct, r.run_id),
                ..run.clone()
            },
        });
    }
    Ok(c)
}

/// Linking Nsight reports to AEGIS measurements needs a profiles table
/// (run_id, build SHA, report file); aegis-perf at this tag has none.
pub fn profiles_note() -> String {
    format!(
        "Nsight reports cannot be linked to AEGIS measurements: {AEGIS_PERF_TAG} has no profiles table \
         (docs/core-requests.md #13). Reports are shown unlinked."
    )
}

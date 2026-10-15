//! Winners and ties: per shape, the dispatched config, % of cublaslt_best
//! (rule 5) with its paired 95% CI, and the statistical tie call (rule 6).
use aegis_perf::rusqlite::Connection;
use aegis_perf::view;
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::roof::{self, RoofMetrics};
use crate::Sources;

/// A paired ratio and its 95% bootstrap CI.
#[derive(Clone, Debug, Serialize)]
pub struct Ci {
    pub ratio_median: Option<f64>,
    pub lo: f64,
    pub hi: f64,
    pub pairs: Option<i64>,
    /// The CI contains 1.0: statistically indistinguishable.
    pub contains_one: bool,
}

impl Ci {
    fn new(ratio_median: Option<f64>, (lo, hi): (f64, f64), pairs: Option<i64>) -> Self {
        Ci { ratio_median, lo, hi, pairs, contains_one: lo <= 1.0 && hi >= 1.0 }
    }
}

/// The winner against cublaslt_best: ratio = cublaslt_best time / our time,
/// so ratio x 100 is % of cublaslt_best speed (> 100: faster).
#[derive(Clone, Debug, Serialize)]
pub struct VsBaseline {
    pub pct_of_cublaslt_best: Option<f64>,
    pub ci: Option<Ci>,
    /// "tie", "faster" or "slower" from the CI; None without a paired test.
    pub verdict: Option<&'static str>,
    /// The config the paired test ran (the fastest config; differs from the
    /// pick only when a tie-break chose the runner-up).
    pub tested_impl: Option<String>,
}

/// The tie call against the runner-up: ratio = runner-up time / fastest time.
#[derive(Clone, Debug, Serialize)]
pub struct Tie {
    /// "paired" (bootstrap CI), "paired_swap" (runner-up faster in the paired
    /// test), "band" (no paired test: runner-up median inside p10-p90), "none".
    pub method: Option<String>,
    pub tied: bool,
    pub tie_set: Vec<String>,
    /// The other config of the runner-up paired test.
    pub contender: Option<String>,
    pub ci: Option<Ci>,
    /// (ratio_median - 1) x 100: how much slower the runner-up was, in %.
    pub runner_up_gap_pct: Option<f64>,
    pub pick_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Winner {
    pub sm_arch: i64,
    pub op: String,
    pub dtype: String,
    pub shape_bucket: String,
    pub m: i64,
    pub n: i64,
    pub k: i64,
    /// M <= 16: held to the read-bandwidth roof.
    pub decode: bool,
    pub kernel_id: String,
    #[serde(rename = "impl")]
    pub impl_: String,
    pub config: Value,
    pub regs: Option<i64>,
    pub smem_bytes: Option<i64>,
    pub local_bytes: Option<i64>,
    pub run_id: String,
    pub git_sha: Option<String>,
    pub protocol_version: i64,
    pub median_us: f64,
    pub warm_median_us: Option<f64>,
    pub vs_cublaslt_best: VsBaseline,
    /// % of default cuBLAS: context only, never the headline (rule 5).
    pub pct_of_cublas: Option<f64>,
    pub tie: Tie,
    /// None when the arch file is missing ("not measured").
    pub roof: Option<RoofMetrics>,
}

/// Negative register counts mark baselines Core cannot inspect.
pub(crate) fn measured(v: Option<i64>) -> Option<i64> {
    v.filter(|&x| x >= 0)
}

fn from_view(w: view::Winner, roof: Option<RoofMetrics>) -> Winner {
    let pick = w.kernel.impl_.clone();
    let role = |r: &str| w.paired.iter().find(|p| p.role.as_deref() == Some(r));

    // The pick's own test against cublaslt_best (Core 4adfb62 pairs the
    // runner-up too when it can be dispatched); DBs tuned before that have
    // only the fastest config's.
    let lt = w
        .paired
        .iter()
        .find(|p| p.role.as_deref() == Some("cublaslt_best") && p.a_impl == pick)
        .or_else(|| role("cublaslt_best"));
    let lt_ci = w.lt_ratio_ci.map(|ci| Ci::new(lt.map(|p| p.ratio_median), ci, lt.and_then(|p| p.pairs)));
    let verdict = lt_ci.as_ref().map(|c| if c.contains_one { "tie" } else if c.lo > 1.0 { "faster" } else { "slower" });

    let ru = role("runner_up");
    let contender = ru.map(|p| if p.a_impl == pick { p.b_impl.clone() } else { p.a_impl.clone() });
    // paired_swap stores the CI inverted (runner-up was faster); the paired
    // row's median is in its own direction, so only "paired" carries the gap.
    let swapped = w.tie_method.as_deref() == Some("paired_swap");
    let ru_median = ru.filter(|_| !swapped).map(|p| p.ratio_median);
    let ci = w.ratio_ci.map(|ci| Ci::new(ru_median, ci, ru.and_then(|p| p.pairs)));
    // Rule 6: with a paired test, tied means the CI contains 1.0.
    let tied = ci.as_ref().map(|c| c.contains_one).unwrap_or(w.tied);

    Winner {
        sm_arch: w.sm_arch,
        decode: w.m as f64 <= aegis_perf::params::DECODE_MAX_M,
        kernel_id: w.kernel.kernel_id.clone(),
        config: serde_json::from_str(&w.kernel.config_json).unwrap_or(Value::String(w.kernel.config_json.clone())),
        regs: measured(w.kernel.regs),
        smem_bytes: measured(w.kernel.smem_bytes),
        local_bytes: measured(w.kernel.local_bytes),
        vs_cublaslt_best: VsBaseline {
            pct_of_cublaslt_best: w.pct_of_cublaslt_best,
            ci: lt_ci,
            verdict,
            tested_impl: w.lt_ratio_ci.and(lt.map(|p| p.a_impl.clone())),
        },
        tie: Tie {
            method: w.tie_method,
            tied,
            tie_set: w.tie_set,
            contender,
            runner_up_gap_pct: ru_median.map(|r| (r - 1.0) * 100.0),
            ci,
            pick_reason: w.pick_reason,
        },
        impl_: pick,
        op: w.op,
        dtype: w.dtype,
        shape_bucket: w.shape_bucket,
        m: w.m,
        n: w.n,
        k: w.k,
        run_id: w.run_id,
        git_sha: w.git_sha,
        protocol_version: w.protocol_version,
        median_us: w.median_us,
        warm_median_us: w.warm_median_us,
        pct_of_cublas: w.pct_of_cublas,
        roof,
    }
}

/// Winners of arch `sm`, roof metrics computed now from its arch file.
pub fn winners(src: &Sources, con: &Connection, sm: i64) -> Result<Vec<Winner>> {
    let params = roof::load(src, sm)?;
    Ok(view::winners(con, Some(sm))?
        .into_iter()
        .map(|w| {
            let r = params.as_ref().map(|p| roof::metrics(p, w.m, w.n, w.k, w.median_us));
            from_view(w, r)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paired(a: &str, role: &str, median: f64) -> view::Paired {
        view::Paired {
            run_id: "r".into(),
            a_impl: a.into(),
            b_impl: if role == "runner_up" { "other".into() } else { "cublaslt_best".into() },
            role: Some(role.into()),
            pairs: Some(30),
            ratio_median: median,
            ratio_ci_lo: median - 0.01,
            ratio_ci_hi: median + 0.01,
            tied: false,
        }
    }

    fn winner(lt_ci: Option<(f64, f64)>, paired: Vec<view::Paired>) -> view::Winner {
        view::Winner {
            sm_arch: 121,
            op: "gemm".into(),
            dtype: "f16f32f16".into(),
            shape_bucket: "64x64x64".into(),
            m: 64,
            n: 64,
            k: 64,
            kernel: view::Kernel {
                kernel_id: "kp".into(),
                op: "gemm".into(),
                impl_: "pick".into(),
                config_json: "{}".into(),
                regs: Some(64),
                smem_bytes: Some(0),
                local_bytes: Some(0),
                ptx_hash: None,
                sass_path: None,
            },
            run_id: "r".into(),
            git_sha: None,
            median_us: 10.0,
            warm_median_us: None,
            pct_of_cublas: None,
            pct_of_cublaslt_best: Some(88.0),
            tied: true,
            tie_set: vec!["fast".into(), "pick".into()],
            pick_reason: Some("tie-break".into()),
            protocol_version: 2,
            tie_method: Some("paired".into()),
            ratio_ci: Some((0.99, 1.01)),
            lt_ratio_ci: lt_ci,
            paired,
        }
    }

    /// With both configs of a tie paired against cublaslt_best, the pick's
    /// row is used, whatever the row order.
    #[test]
    fn baseline_row_is_the_picks() {
        let rows = vec![paired("fast", "cublaslt_best", 0.90), paired("pick", "cublaslt_best", 0.88)];
        let w = from_view(winner(Some((0.87, 0.89)), rows), None);
        let ci = w.vs_cublaslt_best.ci.unwrap();
        assert_eq!(ci.ratio_median, Some(0.88));
        assert_eq!(w.vs_cublaslt_best.tested_impl.as_deref(), Some("pick"));
    }

    /// No CI for the pick: no verdict, and no config named as "tested".
    #[test]
    fn no_ci_names_no_config() {
        let w = from_view(winner(None, vec![paired("fast", "cublaslt_best", 0.90)]), None);
        assert!(w.vs_cublaslt_best.ci.is_none() && w.vs_cublaslt_best.verdict.is_none());
        assert!(w.vs_cublaslt_best.tested_impl.is_none());
        assert_eq!(w.vs_cublaslt_best.pct_of_cublaslt_best, Some(88.0));
    }
}

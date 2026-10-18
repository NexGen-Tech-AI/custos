//! Winners and ties: per shape, the dispatched config, % of cublaslt_best
//! (rule 5) with its paired 95% CI, and the statistical tie call (rule 6).
use aegis_perf::rusqlite::Connection;
use aegis_perf::{tune, view};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::roof::{self, RoofMetrics};
use crate::core_fallbacks::{self, LtAlgo};
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
    /// The unpaired median % lies outside the paired CI by more than
    /// `core_fallbacks::DISAGREE_PTS` points. The paired CI is the number of
    /// record; the median is secondary.
    pub disagreement: Option<Disagreement>,
}

/// "paired and unpaired disagree: median X%, paired CI [a, b]". Provisional:
/// the 2-point threshold is a core_fallbacks constant.
#[derive(Clone, Debug, Serialize)]
pub struct Disagreement {
    pub median_pct: f64,
    pub ci_lo_pct: f64,
    pub ci_hi_pct: f64,
    /// Distance from the median to the nearer CI bound, in points of %.
    pub off_by_pts: f64,
    pub threshold_pts: f64,
    pub provisional: bool,
}

/// Compared only when the paired test ran the pick itself (a tie-break pick
/// was not paired, so its median and the CI are of different configs).
fn disagreement(pct: Option<f64>, ci: Option<&Ci>, same_config: bool) -> Option<Disagreement> {
    let (p, c) = (pct?, ci?);
    let (lo, hi) = (c.lo * 100.0, c.hi * 100.0);
    let off = if p < lo { lo - p } else if p > hi { p - hi } else { 0.0 };
    let threshold = core_fallbacks::DISAGREE_PTS;
    (same_config && off > threshold).then_some(Disagreement {
        median_pct: p,
        ci_lo_pct: lo,
        ci_hi_pct: hi,
        off_by_pts: off,
        threshold_pts: threshold,
        provisional: true,
    })
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

/// Where `aegis::matmul` sends the shape, and what that path achieves
/// (contract rule 10: kernel % and dispatch % are separate numbers), by Core's
/// own rule and floor (`aegis_perf::tune::dispatch`, `tune::DISPATCH_FLOOR`),
/// the same call `emit-header` makes for the winners header.
#[derive(Clone, Debug, Serialize)]
pub struct Dispatch {
    /// "aegis" (the tuned kernel) or "cublaslt" (the dispatch floor).
    pub target: &'static str,
    /// % of cublaslt_best of what is dispatched. "aegis": the kernel's own
    /// %. "cublaslt": None: aegis::matmul runs cublaslt_best's stored
    /// algorithm, but no measurement row times that path (Core measures it as
    /// `db::DISPATCH_IMPL` in nightly sweeps; none in the DB yet).
    pub pct_of_cublaslt_best: Option<f64>,
    /// The ratio (cublaslt_best / kernel time) the decision used, and its
    /// basis: "paired" (the CI's upper bound), "unpaired" (medians), "none".
    pub decided_on: Option<f64>,
    pub basis: &'static str,
    pub floor: f64,
    /// What Core stored for the shape: the winners header's dispatch column
    /// (`sm_<arch>.h`, read by aegis-perf's `regress::header_dispatch`),
    /// "aegis" or "cublaslt". None: no header, or no row for the shape.
    pub stored: Option<String>,
    /// The header the stored dispatch comes from.
    pub stored_source: Option<String>,
    /// The stored dispatch differs from Core's rule applied to this winner's
    /// paired CI (`target`). Shown, never hidden (docs/core-requests.md #4).
    pub mismatch: bool,
}

/// The winners header's dispatch per shape, as aegis-perf parses it.
pub struct StoredDispatch {
    pub source: String,
    pub rows: Vec<((i64, i64, i64), String)>,
}

impl StoredDispatch {
    /// The header `src` names for `sm`; None when there is none.
    pub fn load(src: &Sources, sm: i64) -> Option<StoredDispatch> {
        let path = src.winners_header(sm);
        let text = std::fs::read_to_string(&path).ok()?;
        Some(StoredDispatch { source: path.display().to_string(), rows: aegis_perf::regress::header_dispatch(&text) })
    }

    fn get(&self, shape: (i64, i64, i64)) -> Option<String> {
        self.rows.iter().find(|(s, _)| *s == shape).map(|(_, d)| d.clone())
    }
}

fn dispatch(lt_ci: Option<(f64, f64)>, pct_of_cublaslt_best: Option<f64>, stored: Option<(String, &str)>) -> Dispatch {
    let to_lt = tune::dispatch(lt_ci, pct_of_cublaslt_best) == tune::Dispatch::Cublaslt;
    // What the decision looked at, as tune::dispatch documents it: the paired
    // CI's upper bound, else the unpaired median ratio.
    let (decided_on, basis) = match (lt_ci, pct_of_cublaslt_best) {
        (Some((_, hi)), _) => (Some(hi), "paired"),
        (None, Some(p)) => (Some(p / 100.0), "unpaired"),
        (None, None) => (None, "none"),
    };
    let target = if to_lt { "cublaslt" } else { "aegis" };
    let (stored, stored_source) = match stored {
        Some((d, source)) => (Some(d), Some(source.to_string())),
        None => (None, None),
    };
    Dispatch {
        target,
        pct_of_cublaslt_best: if to_lt { None } else { pct_of_cublaslt_best },
        decided_on,
        basis,
        floor: tune::DISPATCH_FLOOR,
        mismatch: stored.as_deref().is_some_and(|s| s != target),
        stored,
        stored_source,
    }
}

/// The kernel against the production bars (Core's Production bar 3), on the
/// paired CI like Core's dispatch test: below a bar when the CI of
/// cublaslt_best / kernel time lies entirely below it (upper bound < bar), so
/// a statistical tie with the bar meets it ("decode: a tie or a win").
/// Without a paired CI, the unpaired median ratio. Provisional: the bars and
/// the large-shape definition are core_fallbacks constants; the floor is
/// Core's (`tune::DISPATCH_FLOOR`).
#[derive(Clone, Debug, Serialize)]
pub struct Bars {
    /// "decode" (M <= DECODE_MAX_M), "large" (every dim >= 1024) or "other".
    pub class: &'static str,
    /// The class's bar as a fraction of cublaslt_best (other: the floor).
    pub bar: f64,
    pub floor: f64,
    /// "pass" or "fail" against the class bar; None without any measurement.
    pub verdict: Option<&'static str>,
    /// "clear" (the whole CI on the verdict's side) or "within CI" (the CI
    /// straddles the bar).
    pub margin: Option<&'static str>,
    /// The kernel is below the 80% floor (and so dispatched to cuBLASLt).
    pub below_floor: Option<bool>,
    pub basis: &'static str,
    pub provisional: bool,
}

fn bars(m: i64, n: i64, k: i64, lt_ci: Option<(f64, f64)>, pct_of_cublaslt_best: Option<f64>) -> Bars {
    let floor = tune::DISPATCH_FLOOR;
    let (class, bar) = if m as f64 <= aegis_perf::params::DECODE_MAX_M {
        ("decode", core_fallbacks::DECODE_BAR)
    } else if m.min(n).min(k) >= core_fallbacks::LARGE_SHAPE_MIN_DIM {
        ("large", core_fallbacks::LARGE_BAR)
    } else {
        ("other", floor)
    };
    let (range, basis) = match (lt_ci, pct_of_cublaslt_best) {
        (Some(ci), _) => (Some(ci), "paired"),
        (None, Some(p)) => (Some((p / 100.0, p / 100.0)), "unpaired"),
        (None, None) => (None, "none"),
    };
    let verdict = range.map(|(_, hi)| if hi >= bar { "pass" } else { "fail" });
    let margin = range.map(|(lo, hi)| if hi < bar || lo >= bar { "clear" } else { "within CI" });
    Bars { class, bar, floor, verdict, margin, below_floor: range.map(|(_, hi)| hi < floor), basis, provisional: true }
}

/// A stored paired-ab result against cublaslt_best (`paired_results`): the
/// two impls on one shape, alternating processes, as a % of cublaslt_best's
/// speed (100 / (impl time / cublaslt_best time)) with its 95% CI. A call
/// ("win", "tie", "loss") is confirmed only from a clean build linked to the
/// runs (docs/core-requests.md #5); otherwise it is labeled.
#[derive(Clone, Debug, Serialize)]
pub struct AbResult {
    /// "paired_results #<id>".
    pub source: String,
    pub id: i64,
    /// The impl measured against cublaslt_best.
    #[serde(rename = "impl")]
    pub impl_: String,
    pub sha_a: Option<String>,
    pub sha_b: Option<String>,
    pub pct_of_cublaslt_best: f64,
    pub ci_lo_pct: f64,
    pub ci_hi_pct: f64,
    pub pairs: i64,
    /// From the CI: "win" (above 100%), "tie" (contains it) or "loss".
    pub verdict: &'static str,
    pub provenance: &'static str,
    pub provenance_label: Option<&'static str>,
    /// The verdict counts: the result is from a clean, linked build.
    pub confirmed: bool,
    /// "win (confirmed)", "win (unreproducible: dirty build)", "tie (unlinked build)".
    pub label: String,
    pub started_at: String,
    /// Matching results left out: disturbed, or busy / unread idle guard (rule 2).
    pub excluded: usize,
}

/// The newest clean-GPU paired-ab of `impl_` against cublaslt_best at `shape`
/// (protocol 2, cold), either stored order.
fn ab_vs_cublaslt(results: &[view::PairedResult], run_shas: &[String], shape: (i64, i64, i64), impl_: &str) -> Option<AbResult> {
    let mut excluded = 0;
    let mut hit = None;
    for p in results.iter().filter(|p| (p.m, p.n, p.k) == shape && p.protocol_version == 2 && p.cache_mode == "cold") {
        // time ratio impl / cublaslt_best: stored as B / A.
        let ratio = if p.impl_a == "cublaslt_best" && p.impl_b == impl_ {
            (p.ratio, p.ci_lo, p.ci_hi)
        } else if p.impl_b == "cublaslt_best" && p.impl_a == impl_ {
            (1.0 / p.ratio, 1.0 / p.ci_hi, 1.0 / p.ci_lo)
        } else {
            continue;
        };
        if p.disturbed == Some(true) || p.busy() {
            excluded += 1;
            continue;
        }
        hit = Some((p, ratio)); // oldest first: the last is the newest
    }
    let (p, (r, lo, hi)) = hit?;
    let (pct, ci_lo_pct, ci_hi_pct) = (100.0 / r, 100.0 / hi, 100.0 / lo);
    let verdict = if ci_lo_pct > 100.0 { "win" } else if ci_hi_pct < 100.0 { "loss" } else { "tie" };
    let prov = crate::measure::Provenance::of(p, run_shas);
    let confirmed = prov.provenance == "clean";
    let label = match prov.provenance {
        "clean" => format!("{verdict} (confirmed)"),
        "dirty" => format!("{verdict} (unreproducible: dirty build)"),
        _ => format!("{verdict} (unlinked build)"),
    };
    Some(AbResult {
        source: format!("paired_results #{}", p.id),
        id: p.id,
        impl_: impl_.to_string(),
        sha_a: p.sha_a.clone(),
        sha_b: p.sha_b.clone(),
        pct_of_cublaslt_best: pct,
        ci_lo_pct,
        ci_hi_pct,
        pairs: p.pairs,
        verdict,
        provenance: prov.provenance,
        provenance_label: prov.provenance_label,
        confirmed,
        label,
        started_at: p.started_at.clone(),
        excluded,
    })
}

/// Paired-ab results of the shape against cublaslt_best: the winner kernel
/// itself, and the dispatch as a caller sees it (`db::DISPATCH_IMPL`,
/// aegis::matmul). None: no such result.
#[derive(Clone, Debug, Serialize)]
pub struct PairedAb {
    pub kernel: Option<AbResult>,
    pub dispatch: Option<AbResult>,
}

/// What the decode spotlight shows for a decode shape (M <= DECODE_MAX_M)
/// beyond the row: its position against the read-bandwidth roof, the impl
/// family and split-K, and a diagnosis only where Core states one.
#[derive(Clone, Debug, Serialize)]
pub struct DecodeSpotlight {
    /// % of the read roof (compulsory traffic, the read bandwidth of the
    /// arch file), as `aegis-perf report` prints it; None without an arch file.
    pub pct_of_read_roof: Option<f64>,
    pub read_bw_gbps: Option<f64>,
    /// The impl family: the impl name up to its first numeric field
    /// ("gemv_tc", "gemv", "mma_pipe").
    pub family: String,
    /// The config's data path ("tensor_core"); None when the config has none.
    pub path: Option<String>,
    /// The config's requested split-K count (`S`; 0 = auto, one wave). The
    /// effective count per call is Core's (`gemv_split_count`), not stored.
    pub split_k: Option<i64>,
    /// A diagnosis Core states for the shape, with its source; None: no
    /// statement, so the number stands alone.
    pub diagnosis: Option<Diagnosis>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Diagnosis {
    pub label: &'static str,
    pub source: crate::docs::DocRef,
}

pub fn family(impl_: &str) -> String {
    impl_.split('_').take_while(|t| !t.starts_with(|c: char| c.is_ascii_digit())).collect::<Vec<_>>().join("_")
}

fn spotlight(src: &Sources, w: &Winner) -> DecodeSpotlight {
    let diagnosis = core_fallbacks::STATED_DIAGNOSES.iter().filter(|d| d.shapes.contains(&w.shape_bucket.as_str())).find_map(|d| {
        Some(Diagnosis { label: d.label, source: crate::docs::stated(src, d.doc, d.heading, d.quotes)? })
    });
    let read = w.roof.as_ref().filter(|r| r.roof == "read");
    DecodeSpotlight {
        pct_of_read_roof: read.map(|r| r.pct_roof),
        read_bw_gbps: read.map(|r| r.roof_gbps),
        family: family(&w.impl_),
        path: w.config.get("path").and_then(Value::as_str).map(str::to_string),
        split_k: w.config.get("S").and_then(Value::as_i64),
        diagnosis,
    }
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
    /// The kernel against cublaslt_best: kernel % (pct_of_cublaslt_best,
    /// unpaired medians, as Core's report) and the paired CI.
    pub vs_cublaslt_best: VsBaseline,
    pub dispatch: Dispatch,
    pub bars: Bars,
    /// % of default cuBLAS: context only, never the headline (rule 5).
    pub pct_of_cublas: Option<f64>,
    pub tie: Tie,
    /// None when the arch file is missing ("not measured").
    pub roof: Option<RoofMetrics>,
    /// The cuBLASLt algorithm cublaslt_best picked at this shape (stored by
    /// Core, schema v4): the baseline's algorithm, and what aegis::matmul
    /// runs when the shape dispatches to cuBLASLt. None: not stored.
    pub lt_algo: Option<LtAlgo>,
    /// Stored paired-ab results against cublaslt_best (kernel, dispatch).
    pub paired_ab: PairedAb,
    /// Decode shapes only.
    pub decode_spotlight: Option<DecodeSpotlight>,
    /// Set on the one shape the win chain view explains (`chain_pick`).
    pub win_chain: Option<ChainPick>,
}

/// Why a shape is the win chain's: the decode win with the strongest clean
/// paired-ab result (highest CI lower bound vs cublaslt_best); when no decode
/// win is clean, the strongest one regardless, labeled.
#[derive(Clone, Debug, Serialize)]
pub struct ChainPick {
    pub clean: bool,
    /// "strongest clean paired result" or "no clean paired result: strongest
    /// unreproducible one (dirty build)" (or "(unlinked build)").
    pub basis: String,
    /// The paired-ab result it was picked on.
    pub source: String,
    pub ci_lo_pct: f64,
}

fn best(pool: Vec<(usize, &AbResult)>) -> Option<(usize, &AbResult)> {
    pool.into_iter().max_by(|a, b| a.1.ci_lo_pct.total_cmp(&b.1.ci_lo_pct))
}

/// The win chain's shape among `ws` (decode wins with a paired-ab result).
pub fn chain_pick(ws: &[Winner]) -> Option<(usize, ChainPick)> {
    let wins: Vec<(usize, &AbResult)> = ws
        .iter()
        .enumerate()
        .filter(|(_, w)| w.decode)
        .filter_map(|(i, w)| Some((i, w.paired_ab.kernel.as_ref().filter(|a| a.verdict == "win")?)))
        .collect();

    let clean: Vec<_> = wins.iter().copied().filter(|(_, a)| a.confirmed).collect();
    let (i, a, clean) = match best(clean) {
        Some((i, a)) => (i, a, true),
        None => {
            let (i, a) = best(wins)?;
            (i, a, false)
        }
    };
    let basis = if clean {
        "strongest clean paired result".to_string()
    } else {
        format!("no clean paired result: strongest {}", a.provenance_label.unwrap_or("unconfirmed"))
    };
    Some((i, ChainPick { clean, basis, source: a.source.clone(), ci_lo_pct: a.ci_lo_pct }))
}

/// Negative register counts mark baselines Core cannot inspect.
pub(crate) fn measured(v: Option<i64>) -> Option<i64> {
    v.filter(|&x| x >= 0)
}

fn from_view(w: view::Winner, roof: Option<RoofMetrics>, lt_algo: Option<LtAlgo>, stored: Option<(String, &str)>) -> Winner {
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
        dispatch: dispatch(w.lt_ratio_ci, w.pct_of_cublaslt_best, stored),
        bars: bars(w.m, w.n, w.k, w.lt_ratio_ci, w.pct_of_cublaslt_best),
        vs_cublaslt_best: VsBaseline {
            disagreement: disagreement(
                w.pct_of_cublaslt_best,
                lt_ci.as_ref(),
                lt.is_some_and(|p| p.a_impl == pick),
            ),
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
        lt_algo,
        paired_ab: PairedAb { kernel: None, dispatch: None },
        decode_spotlight: None,
        win_chain: None,
    }
}

/// Winners of arch `sm`, roof metrics computed now from its arch file.
pub fn winners(src: &Sources, con: &Connection, sm: i64) -> Result<Vec<Winner>> {
    let params = roof::load(src, sm)?;
    let lt = core_fallbacks::stored_lt_algos(con, sm)?;
    let header = StoredDispatch::load(src, sm);
    let ab = view::paired_results(con, &view::PairedResultFilter::default())?;
    let run_shas = crate::measure::run_shas(con)?;
    let mut ws: Vec<Winner> = view::winners(con, Some(sm))?
        .into_iter()
        .map(|w| {
            let r = params.as_ref().map(|p| roof::metrics(p, w.m, w.n, w.k, w.median_us));
            let algo = if w.op == "gemm" { lt.get(&(w.m, w.n, w.k)).copied() } else { None };
            let stored = header.as_ref().filter(|_| w.op == "gemm").and_then(|h| Some((h.get((w.m, w.n, w.k))?, h.source.as_str())));
            let mut x = from_view(w, r, algo, stored);
            // paired_results carry no arch or dtype (core-requests #5): matched on
            // shape and impls, so only for the arch the DB was measured on.
            let shape = (x.m, x.n, x.k);
            x.paired_ab = PairedAb {
                kernel: ab_vs_cublaslt(&ab, &run_shas, shape, &x.impl_),
                dispatch: ab_vs_cublaslt(&ab, &run_shas, shape, aegis_perf::db::DISPATCH_IMPL),
            };
            if x.decode {
                x.decode_spotlight = Some(spotlight(src, &x));
            }
            x
        })
        .collect();
    if let Some((i, pick)) = chain_pick(&ws) {
        ws[i].win_chain = Some(pick);
    }
    Ok(ws)
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
        let w = from_view(winner(Some((0.87, 0.89)), rows), None, None, None);
        let ci = w.vs_cublaslt_best.ci.unwrap();
        assert_eq!(ci.ratio_median, Some(0.88));
        assert_eq!(w.vs_cublaslt_best.tested_impl.as_deref(), Some("pick"));
    }

    /// No CI for the pick: no verdict, and no config named as "tested".
    #[test]
    fn no_ci_names_no_config() {
        let w = from_view(winner(None, vec![paired("fast", "cublaslt_best", 0.90)]), None, None, None);
        assert!(w.vs_cublaslt_best.ci.is_none() && w.vs_cublaslt_best.verdict.is_none());
        assert!(w.vs_cublaslt_best.tested_impl.is_none());
        assert_eq!(w.vs_cublaslt_best.pct_of_cublaslt_best, Some(88.0));
        assert!(w.vs_cublaslt_best.disagreement.is_none());
    }

    /// 256x256x256 as the v0.3.0 fixture had it (run 41cc8ffb03fd): header
    /// 98.24% against a paired CI of [0.8985, 0.9018], 8 points apart.
    #[test]
    fn median_outside_the_paired_ci_is_flagged() {
        let mut v = winner(Some((0.8985, 0.9018)), vec![paired("pick", "cublaslt_best", 0.90)]);
        v.pct_of_cublaslt_best = Some(98.24);
        let d = from_view(v, None, None, None).vs_cublaslt_best.disagreement.unwrap();
        assert_eq!((d.median_pct, d.threshold_pts), (98.24, 2.0));
        assert!((d.off_by_pts - 8.06).abs() < 1e-9 && d.provisional);
        // Within 2 points of the CI: not flagged.
        let mut v = winner(Some((0.8985, 0.9018)), vec![paired("pick", "cublaslt_best", 0.90)]);
        v.pct_of_cublaslt_best = Some(92.0);
        assert!(from_view(v, None, None, None).vs_cublaslt_best.disagreement.is_none());
    }

    /// The paired test ran another config of the tie: no comparison.
    #[test]
    fn a_tie_break_pick_is_not_compared() {
        let mut v = winner(Some((0.8985, 0.9018)), vec![paired("fast", "cublaslt_best", 0.90)]);
        v.pct_of_cublaslt_best = Some(98.24);
        assert!(from_view(v, None, None, None).vs_cublaslt_best.disagreement.is_none());
    }
}

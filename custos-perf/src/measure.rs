//! Measurements (default protocol v2, cold, idle: rule 2) and build-over-build
//! regression compare by git SHA.
use std::collections::BTreeMap;

use aegis_perf::db::Selection;
use aegis_perf::rusqlite::Connection;
use aegis_perf::view::{self, MeasurementFilter};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::roof::{PerCall, RoofMetrics};
use crate::Sources;

/// Which rows to read. Every field is optional; the defaults are the
/// contract's: protocol 2, cold cache, idle GPU.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Filter {
    pub sm_arch: Option<i64>,
    pub protocol: Option<i64>,
    pub cache: Option<String>,
    pub include_busy: bool,
    pub device_id: Option<String>,
    pub kernel_id: Option<String>,
    #[serde(rename = "impl")]
    pub impl_: Option<String>,
    pub m: Option<i64>,
    pub n: Option<i64>,
    pub k: Option<i64>,
    pub git_sha: Option<String>,
    pub run_id: Option<String>,
}

impl Filter {
    pub fn selection(&self) -> Result<Selection> {
        let protocol = self.protocol.unwrap_or(2);
        let cache = self.cache.clone().unwrap_or_else(|| "cold".to_string());
        if !matches!(protocol, 1 | 2) {
            bail!("protocol must be 1 or 2, got {protocol}");
        }
        if !matches!(cache.as_str(), "cold" | "warm") {
            bail!("cache must be cold or warm, got {cache}");
        }
        Ok(Selection { protocol, cache, include_busy: self.include_busy })
    }

    fn to_view(&self) -> Result<MeasurementFilter> {
        let shape = match (self.m, self.n, self.k) {
            (Some(m), Some(n), Some(k)) => Some((m, n, k)),
            (None, None, None) => None,
            _ => bail!("a shape filter needs all of m, n and k"),
        };
        Ok(MeasurementFilter {
            sel: self.selection()?,
            arch: self.sm_arch,
            device_id: self.device_id.clone(),
            kernel_id: self.kernel_id.clone(),
            impl_: self.impl_.clone(),
            shape,
            git_sha: self.git_sha.clone(),
            run_id: self.run_id.clone(),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Measurement {
    pub run_id: String,
    pub kernel_id: String,
    #[serde(rename = "impl")]
    pub impl_: String,
    pub op: String,
    pub dtype: String,
    pub m: i64,
    pub n: i64,
    pub k: i64,
    pub median_us: f64,
    pub p10_us: Option<f64>,
    pub p90_us: Option<f64>,
    pub reps: Option<i64>,
    pub checked: bool,
    pub pass: bool,
    pub rel_err: Option<f64>,
    pub protocol_version: i64,
    /// Protocol v1 rows are recorded history (rule 2): label them as such.
    pub history: bool,
    pub cache_mode: Option<String>,
    pub batch_n: Option<i64>,
    pub buffer_sets: Option<i64>,
    pub allow_busy: bool,
    pub idle_util_pct: Option<f64>,
    pub power_w: Option<f64>,
    pub sm_arch: i64,
    pub device_id: String,
    pub git_sha: Option<String>,
    pub started_at: String,
    pub roof: Option<RoofMetrics>,
}

fn rows(src: &Sources, con: &Connection, f: &MeasurementFilter) -> Result<Vec<Measurement>> {
    let mut roofs = PerCall::new(src);
    view::measurements(con, f)?
        .into_iter()
        .map(|r| {
            Ok(Measurement {
                roof: roofs.metrics(r.sm_arch, r.m, r.n, r.k, r.median_us)?,
                history: r.protocol_version < 2,
                run_id: r.run_id,
                kernel_id: r.kernel_id,
                impl_: r.impl_,
                op: r.op,
                dtype: r.dtype,
                m: r.m,
                n: r.n,
                k: r.k,
                median_us: r.median_us,
                p10_us: r.p10_us,
                p90_us: r.p90_us,
                reps: r.reps,
                checked: r.checked,
                pass: r.pass,
                rel_err: r.rel_err,
                protocol_version: r.protocol_version,
                cache_mode: r.cache_mode,
                batch_n: r.batch_n,
                buffer_sets: r.buffer_sets,
                allow_busy: r.allow_busy,
                idle_util_pct: r.idle_util_pct,
                power_w: r.power_w,
                sm_arch: r.sm_arch,
                device_id: r.device_id,
                git_sha: r.git_sha,
                started_at: r.started_at,
            })
        })
        .collect()
}

pub fn measurements(src: &Sources, con: &Connection, f: &Filter) -> Result<Vec<Measurement>> {
    rows(src, con, &f.to_view()?)
}

/// Median shifts above this many percent are flagged.
pub const REGRESSION_PCT: f64 = 3.0;

#[derive(Clone, Debug, Serialize)]
pub struct Side {
    pub run_id: String,
    pub kernel_id: String,
    pub median_us: f64,
    pub p10_us: Option<f64>,
    pub p90_us: Option<f64>,
}

/// A paired result for the same impl and shape across the two builds:
/// ratio = b time / a time, 95% CI (`aegis-perf paired-ab`).
#[derive(Clone, Debug, Serialize)]
pub struct PairedEvidence {
    pub source: String,
    pub pairs: Option<i64>,
    pub ratio_median: f64,
    pub ratio_ci_lo: f64,
    pub ratio_ci_hi: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompareRow {
    pub device_id: String,
    pub sm_arch: i64,
    #[serde(rename = "impl")]
    pub impl_: String,
    pub dtype: String,
    pub m: i64,
    pub n: i64,
    pub k: i64,
    pub a: Side,
    pub b: Side,
    /// b median / a median (unpaired): > 1 means build b is slower.
    pub ratio: f64,
    pub change_pct: f64,
    /// Direction of the unpaired median shift: "slower" (> +3%), "faster"
    /// (< -3%) or "within".
    pub flag: &'static str,
    /// What the shift amounts to (contract rule 6: never a single median):
    /// - "within": the medians moved less than 3%
    /// - "unconfirmed": a > 3% shift with no paired result behind it
    /// - "confirmed": a paired CI lies entirely on the flag's side of 1.0
    /// - "not_confirmed": a paired result exists and does not back the shift
    pub status: &'static str,
    pub paired: Option<PairedEvidence>,
    /// The two p10-p90 bands overlap: the unpaired shift sits inside the noise.
    pub bands_overlap: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NotComparable {
    /// Which build has the row: "a" or "b".
    pub only_in: &'static str,
    pub device_id: String,
    pub sm_arch: i64,
    #[serde(rename = "impl")]
    pub impl_: String,
    pub m: i64,
    pub n: i64,
    pub k: i64,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Compare {
    pub sha_a: String,
    pub sha_b: String,
    pub protocol: i64,
    pub cache: String,
    pub include_busy: bool,
    pub threshold_pct: f64,
    pub rows: Vec<CompareRow>,
    pub not_comparable: Vec<NotComparable>,
    /// Rows of each build outside the selection (other protocol or cache
    /// mode, or busy GPU): never compared.
    pub excluded_a: usize,
    pub excluded_b: usize,
    /// Slowdowns > 3% backed by a paired CI.
    pub confirmed_slower: usize,
    /// Slowdowns > 3% without a paired result: not a regression call yet.
    pub unconfirmed_slower: usize,
    pub faster: usize,
    pub within: usize,
}

// device, arch, impl, dtype, m, n, k. Keyed by impl, not kernel_id: a code
// change that alters the config serialization gives the same impl a new
// kernel_id (Core 16d33ec, "smem":"pad8" -> "xor"), and build-over-build is
// exactly that case.
type Key = (String, i64, String, String, i64, i64, i64);

fn key(r: &view::Measurement) -> Key {
    (r.device_id.clone(), r.sm_arch, r.impl_.clone(), r.dtype.clone(), r.m, r.n, r.k)
}

/// Latest row per key of one build (rows come oldest first).
fn latest(rows: Vec<view::Measurement>) -> BTreeMap<Key, view::Measurement> {
    rows.into_iter().map(|r| (key(&r), r)).collect()
}

/// The status of one median shift, given any paired evidence (b / a).
pub fn status(flag: &str, paired: Option<&PairedEvidence>) -> &'static str {
    match (flag, paired) {
        ("within", _) => "within",
        (_, None) => "unconfirmed",
        ("slower", Some(p)) if p.ratio_ci_lo > 1.0 => "confirmed",
        ("faster", Some(p)) if p.ratio_ci_hi < 1.0 => "confirmed",
        _ => "not_confirmed",
    }
}

/// Build b against build a over already-selected rows. `evidence` returns the
/// paired result for a matched (a row, b row), if one exists.
pub fn compare_rows(
    sha_a: &str,
    sha_b: &str,
    a_rows: Vec<view::Measurement>,
    b_rows: Vec<view::Measurement>,
    evidence: impl Fn(&view::Measurement, &view::Measurement) -> Option<PairedEvidence>,
) -> (Vec<CompareRow>, Vec<NotComparable>) {
    let (a, b) = (latest(a_rows), latest(b_rows));
    let mut rows = Vec::new();
    let mut not_comparable = Vec::new();
    for (k, ra) in &a {
        let Some(rb) = b.get(k) else {
            not_comparable.push(nc("a", ra, sha_b));
            continue;
        };
        let ratio = rb.median_us / ra.median_us;
        let change_pct = (ratio - 1.0) * 100.0;
        let flag = if change_pct > REGRESSION_PCT {
            "slower"
        } else if change_pct < -REGRESSION_PCT {
            "faster"
        } else {
            "within"
        };
        let paired = evidence(ra, rb);
        let bands_overlap = match (ra.p10_us, ra.p90_us, rb.p10_us, rb.p90_us) {
            (Some(a10), Some(a90), Some(b10), Some(b90)) => Some(a10 <= b90 && b10 <= a90),
            _ => None,
        };
        let side = |r: &view::Measurement| Side {
            run_id: r.run_id.clone(),
            kernel_id: r.kernel_id.clone(),
            median_us: r.median_us,
            p10_us: r.p10_us,
            p90_us: r.p90_us,
        };
        rows.push(CompareRow {
            device_id: ra.device_id.clone(),
            sm_arch: ra.sm_arch,
            impl_: ra.impl_.clone(),
            dtype: ra.dtype.clone(),
            m: ra.m,
            n: ra.n,
            k: ra.k,
            a: side(ra),
            b: side(rb),
            ratio,
            change_pct,
            flag,
            status: status(flag, paired.as_ref()),
            paired,
            bands_overlap,
        });
    }
    for (k, rb) in &b {
        if !a.contains_key(k) {
            not_comparable.push(nc("b", rb, sha_a));
        }
    }
    (rows, not_comparable)
}

fn count_all(con: &Connection, base: &MeasurementFilter) -> Result<usize> {
    let mut n = 0;
    for protocol in [1, 2] {
        for cache in ["cold", "warm"] {
            if protocol == 1 && cache == "warm" {
                continue; // v1 ignores cache mode
            }
            let sel = Selection { protocol, cache: cache.to_string(), include_busy: true };
            n += view::measurements(con, &MeasurementFilter { sel, ..base.clone() })?.len();
        }
    }
    Ok(n)
}

/// Build b against build a: same device, arch, impl, shape, protocol and
/// cache mode (from `f`; git_sha in `f` is ignored).
///
/// Paired evidence: the perf DB holds paired tests only within one run (tie
/// tests); cross-build paired results (`aegis-perf paired-ab`) are not
/// stored, so every > 3% shift is "unconfirmed" until Core records them.
pub fn compare(con: &Connection, sha_a: &str, sha_b: &str, f: &Filter) -> Result<Compare> {
    let base = MeasurementFilter { git_sha: None, ..f.to_view()? };
    let get = |sha: &str| -> Result<(Vec<view::Measurement>, usize)> {
        let fs = MeasurementFilter { git_sha: Some(sha.to_string()), ..base.clone() };
        let rows = view::measurements(con, &fs)?;
        let excluded = count_all(con, &fs)? - rows.len();
        Ok((rows, excluded))
    };
    let (a_rows, excluded_a) = get(sha_a)?;
    let (b_rows, excluded_b) = get(sha_b)?;
    let (rows, not_comparable) = compare_rows(sha_a, sha_b, a_rows, b_rows, |_, _| None);
    let count = |flag: &str, status: &str| rows.iter().filter(|r| r.flag == flag && r.status == status).count();
    let sel = base.sel;
    Ok(Compare {
        sha_a: sha_a.to_string(),
        sha_b: sha_b.to_string(),
        protocol: sel.protocol,
        cache: sel.cache.clone(),
        include_busy: sel.include_busy,
        threshold_pct: REGRESSION_PCT,
        confirmed_slower: count("slower", "confirmed"),
        unconfirmed_slower: count("slower", "unconfirmed"),
        faster: rows.iter().filter(|r| r.flag == "faster").count(),
        within: count("within", "within"),
        rows,
        not_comparable,
        excluded_a,
        excluded_b,
    })
}

fn nc(only_in: &'static str, r: &view::Measurement, other_sha: &str) -> NotComparable {
    NotComparable {
        only_in,
        device_id: r.device_id.clone(),
        sm_arch: r.sm_arch,
        impl_: r.impl_.clone(),
        m: r.m,
        n: r.n,
        k: r.k,
        reason: format!(
            "no {} row for this impl and shape on {} at {other_sha} (same protocol and cache mode)",
            r.dtype, r.device_id
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(run: &str, kernel_id: &str, impl_: &str, median_us: f64) -> view::Measurement {
        view::Measurement {
            run_id: run.into(),
            kernel_id: kernel_id.into(),
            op: "gemm".into(),
            impl_: impl_.into(),
            dtype: "f16f32f16".into(),
            m: 64,
            n: 64,
            k: 64,
            median_us,
            p10_us: Some(median_us * 0.99),
            p90_us: Some(median_us * 1.01),
            reps: None,
            checked: true,
            pass: true,
            max_abs_err: None,
            rel_err: None,
            power_w: None,
            protocol_version: 2,
            batch_n: None,
            timer_res_ns: None,
            cache_mode: Some("cold".into()),
            buffer_sets: None,
            window_ms: None,
            allow_busy: false,
            idle_util_pct: None,
            sm_arch: 121,
            device_id: "dev".into(),
            git_sha: None,
            started_at: String::new(),
        }
    }

    fn ev(lo: f64, hi: f64) -> PairedEvidence {
        PairedEvidence { source: "test".into(), pairs: Some(30), ratio_median: (lo + hi) / 2.0, ratio_ci_lo: lo, ratio_ci_hi: hi }
    }

    /// A 10% slower median is "unconfirmed" without a paired result,
    /// "confirmed" only by a CI entirely above 1.0, and "not_confirmed" by a
    /// CI containing 1.0.
    #[test]
    fn slowdowns_need_paired_evidence() {
        let a = || vec![row("ra", "k_old", "mma_x", 10.0)];
        let b = || vec![row("rb", "k_old", "mma_x", 11.0)];
        let (r, _) = compare_rows("a", "b", a(), b(), |_, _| None);
        assert_eq!((r[0].flag, r[0].status), ("slower", "unconfirmed"));
        assert!(r[0].paired.is_none());
        let (r, _) = compare_rows("a", "b", a(), b(), |_, _| Some(ev(1.06, 1.12)));
        assert_eq!((r[0].flag, r[0].status), ("slower", "confirmed"));
        let (r, _) = compare_rows("a", "b", a(), b(), |_, _| Some(ev(0.98, 1.04)));
        assert_eq!((r[0].flag, r[0].status), ("slower", "not_confirmed"));
        // Within 3%: no call either way, evidence or not.
        let (r, _) = compare_rows("a", "b", a(), vec![row("rb", "k_old", "mma_x", 10.2)], |_, _| None);
        assert_eq!((r[0].flag, r[0].status), ("within", "within"));
    }

    /// The same impl under a new kernel_id (config serialization changed
    /// between builds) is still compared.
    #[test]
    fn keyed_by_impl_across_kernel_id_change() {
        let (r, nc) = compare_rows(
            "a",
            "b",
            vec![row("ra", "k_pad8", "mma_x", 10.0)],
            vec![row("rb", "k_xor", "mma_x", 9.0)],
            |_, _| None,
        );
        assert!(nc.is_empty());
        assert_eq!((r[0].a.kernel_id.as_str(), r[0].b.kernel_id.as_str()), ("k_pad8", "k_xor"));
        assert_eq!((r[0].flag, r[0].status), ("faster", "unconfirmed"));
    }
}

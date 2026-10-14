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

/// Slowdowns above this many percent are flagged.
pub const REGRESSION_PCT: f64 = 3.0;

#[derive(Clone, Debug, Serialize)]
pub struct Side {
    pub run_id: String,
    pub median_us: f64,
    pub p10_us: Option<f64>,
    pub p90_us: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompareRow {
    pub device_id: String,
    pub sm_arch: i64,
    pub kernel_id: String,
    #[serde(rename = "impl")]
    pub impl_: String,
    pub dtype: String,
    pub m: i64,
    pub n: i64,
    pub k: i64,
    pub a: Side,
    pub b: Side,
    /// b median / a median: > 1 means build b is slower.
    pub ratio: f64,
    pub change_pct: f64,
    /// "slower" (> +3%), "faster" (< -3%) or "within".
    pub flag: &'static str,
    /// The two p10-p90 bands overlap: an unpaired median shift inside the
    /// noise. Confirm any flag with `aegis-perf paired-ab`.
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
    pub slower: usize,
    pub faster: usize,
    pub within: usize,
}

type Key = (String, i64, String, String, i64, i64, i64); // device, arch, kernel, dtype, m, n, k

/// Latest row per (device, arch, kernel, dtype, shape) of one build.
fn latest(rows: Vec<view::Measurement>) -> BTreeMap<Key, view::Measurement> {
    let mut out = BTreeMap::new();
    for r in rows {
        // rows come oldest first: later runs of the same build overwrite.
        out.insert((r.device_id.clone(), r.sm_arch, r.kernel_id.clone(), r.dtype.clone(), r.m, r.n, r.k), r);
    }
    out
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

/// Build b against build a: same device, arch, kernel, shape, protocol and
/// cache mode (from `f`; git_sha in `f` is ignored).
pub fn compare(con: &Connection, sha_a: &str, sha_b: &str, f: &Filter) -> Result<Compare> {
    let base = MeasurementFilter { git_sha: None, ..f.to_view()? };
    let get = |sha: &str| -> Result<(BTreeMap<Key, view::Measurement>, usize)> {
        let fa = MeasurementFilter { git_sha: Some(sha.to_string()), ..base.clone() };
        let rows = view::measurements(con, &fa)?;
        let selected = rows.len();
        Ok((latest(rows), count_all(con, &fa)? - selected))
    };
    let (a, excluded_a) = get(sha_a)?;
    let (b, excluded_b) = get(sha_b)?;

    let mut rows = Vec::new();
    let mut not_comparable = Vec::new();
    for (key, ra) in &a {
        let Some(rb) = b.get(key) else {
            not_comparable.push(nc("a", ra, sha_b));
            continue;
        };
        let ratio = rb.median_us / ra.median_us;
        let change_pct = (ratio - 1.0) * 100.0;
        let bands_overlap = match (ra.p10_us, ra.p90_us, rb.p10_us, rb.p90_us) {
            (Some(a10), Some(a90), Some(b10), Some(b90)) => Some(a10 <= b90 && b10 <= a90),
            _ => None,
        };
        let side = |r: &view::Measurement| Side { run_id: r.run_id.clone(), median_us: r.median_us, p10_us: r.p10_us, p90_us: r.p90_us };
        rows.push(CompareRow {
            device_id: ra.device_id.clone(),
            sm_arch: ra.sm_arch,
            kernel_id: ra.kernel_id.clone(),
            impl_: ra.impl_.clone(),
            dtype: ra.dtype.clone(),
            m: ra.m,
            n: ra.n,
            k: ra.k,
            a: side(ra),
            b: side(rb),
            ratio,
            change_pct,
            flag: if change_pct > REGRESSION_PCT {
                "slower"
            } else if change_pct < -REGRESSION_PCT {
                "faster"
            } else {
                "within"
            },
            bands_overlap,
        });
    }
    for (key, rb) in &b {
        if !a.contains_key(key) {
            not_comparable.push(nc("b", rb, sha_a));
        }
    }
    let count = |f: &str| rows.iter().filter(|r| r.flag == f).count();
    let sel = base.sel;
    Ok(Compare {
        sha_a: sha_a.to_string(),
        sha_b: sha_b.to_string(),
        protocol: sel.protocol,
        cache: sel.cache.clone(),
        include_busy: sel.include_busy,
        threshold_pct: REGRESSION_PCT,
        slower: count("slower"),
        faster: count("faster"),
        within: count("within"),
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
            "no {} row for this kernel and shape on {} at {other_sha} (same protocol and cache mode)",
            r.dtype, r.device_id
        ),
    }
}

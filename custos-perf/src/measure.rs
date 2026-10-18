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

/// Median shifts above this many percent are flagged: Core's regression gate
/// (`aegis_perf::regress::REGRESSION`, 3%), never a Custos number (rule 12).
pub const REGRESSION_PCT: f64 = aegis_perf::regress::REGRESSION * 100.0;

#[derive(Clone, Debug, Serialize)]
pub struct Side {
    pub run_id: String,
    pub kernel_id: String,
    pub median_us: f64,
    pub p10_us: Option<f64>,
    pub p90_us: Option<f64>,
}

/// A stored paired-ab result (`paired_results`, `aegis-perf paired-ab`) for
/// the same impl and shape across the two builds, oriented as compare() is:
/// ratio = build b time / build a time, with its 95% CI.
#[derive(Clone, Debug, Serialize)]
pub struct PairedEvidence {
    /// "paired_results #<id>".
    pub source: String,
    pub id: i64,
    /// The builds as stored (`-dirty`: built with uncommitted changes).
    pub sha_a: Option<String>,
    pub sha_b: Option<String>,
    /// Stored as (b, a): ratio and CI inverted here.
    pub inverted: bool,
    /// A stored build had uncommitted changes (`-dirty`). It is matched on its
    /// commit: runs.git_sha does not record dirty state either.
    pub dirty: bool,
    /// Both stored builds name exactly one `runs.git_sha` (at least its 7 hex
    /// digits). An unlinked build cannot be tied to the measured runs.
    pub linked: bool,
    /// "clean", "dirty" or "unlinked". Only "clean" evidence can confirm or
    /// rule out a shift; the rest is shown, labeled, and the shift stays
    /// "unconfirmed" (docs/core-requests.md #5).
    pub provenance: &'static str,
    /// "unreproducible (dirty build)" or "unlinked build"; None when clean.
    pub provenance_label: Option<&'static str>,
    pub pairs: Option<i64>,
    pub ratio_median: f64,
    pub ratio_ci_lo: f64,
    pub ratio_ci_hi: f64,
    pub started_at: String,
    /// Older matching results; the newest is the evidence.
    pub older_matches: usize,
}

impl PairedEvidence {
    /// Evidence a shift can be called on: a clean build on both sides, each
    /// linked to its runs row.
    pub fn usable(&self) -> bool {
        self.provenance == "clean"
    }
}

/// Git's shortest abbreviation: a stored build shorter than this names nothing.
const MIN_ABBREV: usize = 4;
/// runs.git_sha keeps 7 hex digits: a shorter stored build cannot be linked.
const RUNS_SHA_LEN: usize = 7;

fn commit(sha: &str) -> &str {
    sha.strip_suffix("-dirty").unwrap_or(sha)
}

/// Does a stored build (`sha`, maybe `-dirty`) name the commit `want`? Either
/// may be the shorter prefix (runs keep 7 hex digits, paired_results 12).
fn same_build(stored: Option<&str>, want: &str) -> bool {
    let Some(s) = stored else { return false };
    let s = commit(s);
    let n = s.len().min(want.len());
    n >= MIN_ABBREV && s[..n].eq_ignore_ascii_case(&want[..n])
}

/// The stored build names exactly one distinct runs.git_sha, with at least
/// the 7 hex digits runs keep.
fn linked(stored: Option<&str>, run_shas: &[String]) -> bool {
    let Some(s) = stored else { return false };
    commit(s).len() >= RUNS_SHA_LEN && run_shas.iter().filter(|r| same_build(Some(s), r)).count() == 1
}

/// Whether a stored paired result can be reproduced and tied to the measured
/// runs (docs/core-requests.md #5).
pub struct Provenance {
    /// A build had uncommitted changes (`-dirty`).
    pub dirty: bool,
    /// Both builds name exactly one runs.git_sha.
    pub linked: bool,
    /// "clean", "dirty" or "unlinked"; only "clean" decides anything.
    pub provenance: &'static str,
    /// "unreproducible (dirty build)" or "unlinked build"; None when clean.
    pub provenance_label: Option<&'static str>,
}

impl Provenance {
    pub fn of(p: &view::PairedResult, run_shas: &[String]) -> Provenance {
        let dirty = |s: &Option<String>| s.as_deref().is_some_and(|s| s.ends_with("-dirty"));
        let dirty = dirty(&p.sha_a) || dirty(&p.sha_b);
        let linked = linked(p.sha_a.as_deref(), run_shas) && linked(p.sha_b.as_deref(), run_shas);
        let (provenance, provenance_label) = if dirty {
            ("dirty", Some("unreproducible (dirty build)"))
        } else if !linked {
            ("unlinked", Some("unlinked build"))
        } else {
            ("clean", None)
        };
        Provenance { dirty, linked, provenance, provenance_label }
    }
}

/// Every distinct runs.git_sha, for [`Provenance::of`].
pub fn run_shas(con: &Connection) -> Result<Vec<String>> {
    let mut shas: Vec<String> = view::runs(con)?.into_iter().filter_map(|r| r.git_sha).collect();
    shas.sort();
    shas.dedup();
    Ok(shas)
}

/// The stored paired result backing row `ra` (build a) vs build b: same shape,
/// the same impl on both sides, the selection's protocol and cache mode, the
/// two builds in either order. Disturbed or busy results (idle reading above
/// Core's limit, or unread) are excluded unless `sel.include_busy` (rule 2);
/// they are counted in the second value.
fn paired_evidence(
    results: &[view::PairedResult],
    run_shas: &[String],
    sel: &Selection,
    (sha_a, sha_b): (&str, &str),
    ra: &view::Measurement,
) -> (Option<PairedEvidence>, usize) {
    let mut excluded = 0;
    let mut hits: Vec<(&view::PairedResult, bool)> = Vec::new();
    for p in results {
        let same_row = (p.m, p.n, p.k) == (ra.m, ra.n, ra.k)
            && p.impl_a == ra.impl_
            && p.impl_b == ra.impl_
            && p.protocol_version == sel.protocol
            && (sel.protocol < 2 || p.cache_mode == sel.cache);
        if !same_row {
            continue;
        }
        let (sa, sb) = (p.sha_a.as_deref(), p.sha_b.as_deref());
        let inverted = if same_build(sa, sha_a) && same_build(sb, sha_b) {
            false
        } else if same_build(sa, sha_b) && same_build(sb, sha_a) {
            true
        } else {
            continue;
        };
        if !sel.include_busy && (p.disturbed == Some(true) || p.busy()) {
            excluded += 1;
            continue;
        }
        hits.push((p, inverted));
    }
    // view::paired_results returns them oldest first: the newest is the evidence.
    let older = hits.len().saturating_sub(1);
    let ev = hits.last().map(|&(p, inverted)| {
        let (ratio, lo, hi) = if inverted { (1.0 / p.ratio, 1.0 / p.ci_hi, 1.0 / p.ci_lo) } else { (p.ratio, p.ci_lo, p.ci_hi) };
        let Provenance { dirty, linked, provenance, provenance_label } = Provenance::of(p, run_shas);
        PairedEvidence {
            source: format!("paired_results #{}", p.id),
            id: p.id,
            sha_a: p.sha_a.clone(),
            sha_b: p.sha_b.clone(),
            inverted,
            dirty,
            linked,
            provenance,
            provenance_label,
            pairs: Some(p.pairs),
            ratio_median: ratio,
            ratio_ci_lo: lo,
            ratio_ci_hi: hi,
            started_at: p.started_at.clone(),
            older_matches: older,
        }
    });
    (ev, excluded)
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
    /// - "unconfirmed": a > 3% shift with no clean paired result behind it
    ///   (a dirty or unlinked one is attached, labeled, but never decides)
    /// - "confirmed": a paired CI lies entirely on the flag's side of 1.0
    /// - "not_confirmed": a paired result exists and does not back the shift
    pub status: &'static str,
    pub paired: Option<PairedEvidence>,
    /// Paired results for these builds, impl and shape left out because they
    /// were disturbed or measured on a busy GPU (rule 2; see include_busy).
    pub paired_excluded: usize,
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
    /// Slowdowns > 3% a paired result does not back (its CI reaches 1.0 or below).
    pub not_confirmed_slower: usize,
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

/// The status of one median shift, given any paired evidence (b / a). Only
/// usable (clean, linked) evidence confirms or rules out a shift.
pub fn status(flag: &str, paired: Option<&PairedEvidence>) -> &'static str {
    match (flag, paired.filter(|p| p.usable())) {
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
    evidence: impl Fn(&view::Measurement, &view::Measurement) -> (Option<PairedEvidence>, usize),
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
        let (paired, paired_excluded) = evidence(ra, rb);
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
            paired_excluded,
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
/// A median shift over the regression threshold is "confirmed" or
/// "not_confirmed" when a stored paired-ab result matches it (`paired_results`:
/// same shape, the same impl on both sides, protocol and cache mode, these two
/// builds in either order; disturbed and busy results only with include_busy);
/// otherwise it stays "unconfirmed" (contract rule 6).
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
    let sel = base.sel;
    let stored = view::paired_results(con, &view::PairedResultFilter::default())?;
    let run_shas = run_shas(con)?;
    let (rows, not_comparable) = compare_rows(sha_a, sha_b, a_rows, b_rows, |ra, _| {
        paired_evidence(&stored, &run_shas, &sel, (sha_a, sha_b), ra)
    });
    let count = |flag: &str, status: &str| rows.iter().filter(|r| r.flag == flag && r.status == status).count();
    Ok(Compare {
        sha_a: sha_a.to_string(),
        sha_b: sha_b.to_string(),
        protocol: sel.protocol,
        cache: sel.cache.clone(),
        include_busy: sel.include_busy,
        threshold_pct: REGRESSION_PCT,
        confirmed_slower: count("slower", "confirmed"),
        unconfirmed_slower: count("slower", "unconfirmed"),
        not_confirmed_slower: count("slower", "not_confirmed"),
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
        PairedEvidence {
            source: "test".into(),
            id: 0,
            sha_a: None,
            sha_b: None,
            inverted: false,
            dirty: false,
            linked: true,
            provenance: "clean",
            provenance_label: None,
            pairs: Some(30),
            ratio_median: (lo + hi) / 2.0,
            ratio_ci_lo: lo,
            ratio_ci_hi: hi,
            started_at: String::new(),
            older_matches: 0,
        }
    }

    /// A 10% slower median is "unconfirmed" without a paired result,
    /// "confirmed" only by a CI entirely above 1.0, and "not_confirmed" by a
    /// CI containing 1.0.
    #[test]
    fn slowdowns_need_paired_evidence() {
        let a = || vec![row("ra", "k_old", "mma_x", 10.0)];
        let b = || vec![row("rb", "k_old", "mma_x", 11.0)];
        let (r, _) = compare_rows("a", "b", a(), b(), |_, _| (None, 0));
        assert_eq!((r[0].flag, r[0].status), ("slower", "unconfirmed"));
        assert!(r[0].paired.is_none());
        let (r, _) = compare_rows("a", "b", a(), b(), |_, _| (Some(ev(1.06, 1.12)), 0));
        assert_eq!((r[0].flag, r[0].status), ("slower", "confirmed"));
        let (r, _) = compare_rows("a", "b", a(), b(), |_, _| (Some(ev(0.98, 1.04)), 0));
        assert_eq!((r[0].flag, r[0].status), ("slower", "not_confirmed"));
        // A dirty or unlinked result neither confirms nor rules out.
        for (provenance, ci) in [("dirty", (1.06, 1.12)), ("unlinked", (1.06, 1.12)), ("dirty", (0.98, 1.04))] {
            let p = PairedEvidence { provenance, ..ev(ci.0, ci.1) };
            let (r, _) = compare_rows("a", "b", a(), b(), |_, _| (Some(p.clone()), 0));
            assert_eq!((r[0].flag, r[0].status), ("slower", "unconfirmed"), "{provenance}");
        }
        // Within 3%: no call either way, evidence or not.
        let (r, _) = compare_rows("a", "b", a(), vec![row("rb", "k_old", "mma_x", 10.2)], |_, _| (None, 0));
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
            |_, _| (None, 0),
        );
        assert!(nc.is_empty());
        assert_eq!((r[0].a.kernel_id.as_str(), r[0].b.kernel_id.as_str()), ("k_pad8", "k_xor"));
        assert_eq!((r[0].flag, r[0].status), ("faster", "unconfirmed"));
    }
}

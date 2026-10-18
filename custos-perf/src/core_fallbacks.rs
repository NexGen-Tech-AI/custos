//! What Custos needs from AEGIS Core but aegis-perf (the pinned tag) does not
//! provide yet (contract rule 12). Each item cites its docs/core-requests.md
//! entry and goes away when Core ships it (then a pin bump, rule 23). The UI
//! labels every value derived from a constant here "provisional".
use std::path::Path;

use aegis_perf::rusqlite::{Connection, OpenFlags};
use anyhow::{Context, Result};

/// The schema version of a perf DB that `aegis_perf::db::connect_ro` refused,
/// so the UI can say which way it is off. aegis-perf only returns the refusal
/// as text ("DB schema vN, binary expects vM"); this opens the file read-only
/// (never a write, never a migration) and asks aegis-perf's own
/// `db::schema_version`. A DB without the table is v1, as Core counts it.
/// docs/core-requests.md #3 (a typed schema check).
pub fn db_schema_version(db: &Path) -> Result<i64> {
    let con = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .with_context(|| format!("open {} read-only", db.display()))?;
    Ok(aegis_perf::db::schema_version(&con)?.unwrap_or(1))
}

/// Production bar 3 (Core CLAUDE.md, "Production bar"): shapes >= 1024 in
/// every dimension are "large". Not in aegis-perf. docs/core-requests.md #4.
pub const LARGE_SHAPE_MIN_DIM: i64 = 1024;
/// Large shapes: >= 90% of cublaslt_best. docs/core-requests.md #4.
pub const LARGE_BAR: f64 = 0.90;
/// Decode shapes (M <= aegis_perf::params::DECODE_MAX_M, which is Core's):
/// >= 100% of cublaslt_best, "a tie or a win". docs/core-requests.md #4.
pub const DECODE_BAR: f64 = 1.00;
// Every shape: not below the floor, aegis_perf::tune::DISPATCH_FLOOR (Core's).

/// A winner's unpaired median % of cublaslt_best (Core's report and header)
/// and its paired CI disagree when the median lies more than this many points
/// outside the CI. Core has no such rule. docs/core-requests.md #4.
pub const DISAGREE_PTS: f64 = 2.0;

/// The cuBLASLt algorithm cublaslt_best picked at a shape (schema v4
/// `winners.lt_algo`), as aegis-perf renders it: an
/// `aegis::detail::LtAlgoConfig` (`tune::lt_config`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct LtAlgo {
    pub algo_id: i64,
    pub tile_id: i64,
    pub stages_id: i64,
    pub splitk: i64,
    pub reduction: i64,
    pub swizzle: i64,
    pub custom: i64,
    pub inner_shape: i64,
    pub cluster_shape: i64,
}

/// Each winner shape's stored cuBLASLt algorithm. aegis-perf (v0.4.0, v0.5.0) stores it
/// but `view::Winner` does not return it; the one library path is
/// `tune::header_text`, which reads it with Core's own query and writes it as
/// the last field of each winners-header row (`{id, tile, stages, splitk,
/// reduction, swizzle, custom, inner_shape, cluster_shape}`, `{}` when none).
/// Reads only. docs/core-requests.md #7.
pub fn stored_lt_algos(con: &Connection, arch: i64) -> Result<std::collections::HashMap<(i64, i64, i64), LtAlgo>> {
    let (text, _) = aegis_perf::tune::header_text(con, arch, "custos")?;
    let mut out = std::collections::HashMap::new();
    for line in text.lines().map(str::trim).filter(|l| l.starts_with('{')) {
        let code = line.split("//").next().unwrap_or("");
        let dims: Vec<i64> = code.trim_start_matches('{').split(',').take(3).filter_map(|d| d.trim().parse().ok()).collect();
        let [m, n, k] = dims[..] else { continue };
        let Some(open) = code.rfind('{') else { continue };
        let fields: Vec<i64> = code[open + 1..].split('}').next().unwrap_or("").split(',').filter_map(|f| f.trim().parse().ok()).collect();
        if let [algo_id, tile_id, stages_id, splitk, reduction, swizzle, custom, inner_shape, cluster_shape] = fields[..] {
            out.insert((m, n, k), LtAlgo { algo_id, tile_id, stages_id, splitk, reduction, swizzle, custom, inner_shape, cluster_shape });
        }
    }
    Ok(out)
}

/// A diagnosis Core states in prose in its docs, which Custos shows on the
/// shapes it names. Core has no machine-readable diagnosis per shape
/// (docs/core-requests.md #9), so each entry here names the doc section
/// and the sentences that state it; Custos shows the label only while that
/// section still states them (`docs::stated`), and links it. Never a Custos
/// judgement: an entry is added only for a statement Core made.
pub struct StatedDiagnosis {
    pub shapes: &'static [&'static str],
    pub label: &'static str,
    /// Under Core's docs/: "LOG.md" or "analysis/<name>.md".
    pub doc: &'static str,
    pub heading: &'static str,
    /// Each must appear verbatim in the section.
    pub quotes: &'static [&'static str],
}

pub const STATED_DIAGNOSES: &[StatedDiagnosis] = &[StatedDiagnosis {
    shapes: &["1x896x896", "16x896x896"],
    label: "below floor: launch-overhead bound",
    doc: "LOG.md",
    heading: "2026-10-17 — Phase C step 4: decode results, winners and dispatch",
    quotes: &["**The 896x896 shapes** run at ~65-70% of the floor", "They are bound by launch overhead"],
}];

/// The winners header the build `git_sha` dispatched, for the regression
/// check of a run of that build: `<winners_dir>/<sha>/sm_<arch>.h` (a copy of
/// that commit's header; the fixtures hold 9157a34's, tag v0.5.0's is the
/// current one). Core does not record which header a nightly checked against
/// (docs/core-requests.md #11). None: no copy for that build.
pub fn build_header(src: &crate::Sources, arch: i64, git_sha: &str) -> Option<std::path::PathBuf> {
    let sha = git_sha.strip_suffix("-dirty").unwrap_or(git_sha);
    std::fs::read_dir(&src.winners_dir).ok()?.flatten().map(|e| e.path()).find_map(|d| {
        let name = d.file_name()?.to_str()?.to_string();
        let n = name.len().min(sha.len());
        let f = d.join(format!("sm_{arch}.h"));
        (n >= 7 && name[..n].eq_ignore_ascii_case(&sha[..n]) && f.is_file()).then_some(f)
    })
}

/// One night's fuzz run: the summary line `aegis_fuzz` writes to
/// `results/nightly/fuzz-<stamp>.txt`, and the cases it reported. Not in the
/// perf DB and no aegis-perf parser (docs/core-requests.md #10).
#[derive(Clone, Debug, serde::Serialize)]
pub struct FuzzNight {
    pub file: String,
    /// `<date>-<time>` from the file name.
    pub stamp: String,
    pub seed: Option<i64>,
    pub cases: Option<i64>,
    pub failures: Option<i64>,
    pub fp64_reference: Option<i64>,
    pub cublaslt_reference: Option<i64>,
    pub nan_inf: Option<i64>,
    pub misaligned: Option<i64>,
    /// cuBLASLt-reference failures the FP64 re-check overruled.
    pub overruled_by_fp64: Option<i64>,
    pub seconds: Option<f64>,
    pub cases_reported: Vec<FuzzCase>,
}

/// A `FAIL case` or `note case` line and the detail line under it.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FuzzCase {
    pub kind: String,
    pub case: i64,
    pub line: String,
    pub detail: Option<String>,
    /// FP64's verdict on the case, where Core's LOG records it.
    pub adjudication: Option<FuzzAdjudication>,
}

/// From Core's LOG: the failing element's error against FP64, ours and
/// cuBLASLt's, in FP16 ulp, and Core's verdict.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FuzzAdjudication {
    pub ours_ulp: f64,
    pub cublaslt_ulp: f64,
    pub verdict: String,
    pub source: crate::docs::DocRef,
}

fn after(text: &str, key: &str) -> Option<i64> {
    let i = text.find(key)?;
    text[..i].split_whitespace().last()?.trim_matches(|c| c == '(' || c == ',').parse().ok()
}

fn summary(night: &mut FuzzNight, l: &str) {
    night.cases = after(l, "cases,");
    night.failures = after(l, "failures");
    night.fp64_reference = after(l, "CPU-FP64 reference");
    night.cublaslt_reference = after(l, "cuBLASLt;");
    night.nan_inf = after(l, "with NaN/Inf");
    night.misaligned = after(l, "misaligned");
    night.overruled_by_fp64 = after(l, "cuBLASLt-reference failures overruled");
    night.seconds = l.find(" s, seed").and_then(|i| l[..i].split_whitespace().last()?.parse().ok());
    night.seed = l.rsplit("seed ").next().and_then(|s| s.trim().parse().ok());
}

/// The adjudication table of the LOG section about `case` ("Fuzz case N"):
/// the row of the failing element, "| ... (the failure) | FP64 | ours (X ulp ...) | cuBLASLt (Y ulp ...) |".
pub fn fuzz_adjudication(src: &crate::Sources, case: i64) -> Option<FuzzAdjudication> {
    let path = src.docs_dir.join("LOG.md");
    let text = std::fs::read_to_string(&path).ok()?;
    let s = crate::docs::sections(&text).into_iter().find(|s| s.heading.contains(&format!("Fuzz case {case}")))?;
    let row = s.body.lines().find(|l| l.starts_with('|') && l.contains("(the failure)"))?;
    let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).collect();
    let ulp = |c: &str| -> Option<f64> { c.split('(').nth(1)?.trim_start_matches("**").split_whitespace().next()?.parse().ok() };
    let verdict = s.body.lines().find_map(|l| l.strip_prefix("**Verdict: "))?.split(".**").next()?.to_string();
    Some(FuzzAdjudication {
        ours_ulp: ulp(cells.get(2)?)?,
        cublaslt_ulp: ulp(cells.get(3)?)?,
        verdict,
        source: crate::docs::DocRef {
            doc: "docs/LOG.md".into(),
            path: path.display().to_string(),
            heading: s.heading.clone(),
            line: s.line,
            why: None,
        },
    })
}

/// Every `fuzz-*.txt` in the nightly directory, oldest first.
pub fn nightly_fuzz(src: &crate::Sources) -> Vec<FuzzNight> {
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&src.nightly_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|f| f.to_str()).is_some_and(|f| f.starts_with("fuzz-") && f.ends_with(".txt")))
        .collect();
    files.sort();
    files
        .into_iter()
        .filter_map(|p| {
            let text = std::fs::read_to_string(&p).ok()?;
            let name = p.file_name()?.to_string_lossy().into_owned();
            let mut night = FuzzNight {
                stamp: name.trim_start_matches("fuzz-").trim_end_matches(".txt").to_string(),
                file: p.display().to_string(),
                seed: None,
                cases: None,
                failures: None,
                fp64_reference: None,
                cublaslt_reference: None,
                nan_inf: None,
                misaligned: None,
                overruled_by_fp64: None,
                seconds: None,
                cases_reported: Vec::new(),
            };
            let lines: Vec<&str> = text.lines().collect();
            for (i, l) in lines.iter().enumerate() {
                if l.starts_with("aegis_fuzz:") && l.contains(" cases, ") {
                    summary(&mut night, l);
                }
                for kind in ["FAIL", "note"] {
                    let Some(rest) = l.strip_prefix(&format!("{kind} case ")) else { continue };
                    let Some(case) = rest.split_whitespace().next().and_then(|c| c.parse().ok()) else { continue };
                    let detail = lines.get(i + 1).filter(|d| d.starts_with(' ')).map(|d| d.trim().to_string());
                    night.cases_reported.push(FuzzCase {
                        kind: kind.to_string(),
                        case,
                        line: l.to_string(),
                        detail,
                        adjudication: fuzz_adjudication(src, case),
                    });
                }
            }
            Some(night)
        })
        .collect()
}

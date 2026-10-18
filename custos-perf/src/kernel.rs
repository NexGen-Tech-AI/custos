//! Kernel detail: config, registers, spills, shared memory, measurements,
//! and Core's artifacts for it: the SASS listing, its instruction mix, ptxas
//! resource usage, Nsight reports. Anything Core has not produced is None
//! ("not measured" / "not profiled"), never estimated.
//!
//! SASS is found by the kernel symbol inside each listing (`Function : ...`),
//! never by file name: Core's dump truncates names, so the row- and
//! column-major instantiations of one config share a file name. The measured
//! kernel is the row-major one (Layout 0, 0: what bench_gemm runs).
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use aegis_perf::rusqlite::Connection;
use aegis_perf::view;
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::measure::{self, Filter, Measurement};
use crate::winners::measured;
use crate::Sources;

#[derive(Clone, Debug, Serialize)]
pub struct Sass {
    pub path: String,
    /// The kernel symbol the listing is for (its `Function :` line).
    pub symbol: String,
    pub lines: usize,
    /// Raw SASS as cuobjdump prints it; control codes are not parsed.
    pub text: String,
    pub origin: SassOrigin,
}

/// Where the listing comes from: Core's dump (`artifacts/sass/`), or
/// compiled by Custos from a Core tag (an `ORIGIN` file in the directory, as
/// in tests/fixtures/sass/: Core's dump has no usable listing, core-requests #6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SassOrigin {
    CoreArtifact,
    /// `note`: what differs from the measured kernel, as recorded with it
    /// (e.g. the tag's code is not the build the tune measured).
    CompiledFromTag { tag: String, source: Option<String>, note: Option<String> },
}

/// The ORIGIN entry for `file`: keys before the first `[file]` section apply
/// to every listing; a `[<file name>]` section overrides them for that file.
fn sass_origin(dir: &Path, file: &str) -> SassOrigin {
    let Ok(text) = std::fs::read_to_string(dir.join("ORIGIN")) else { return SassOrigin::CoreArtifact };
    let mut section: Option<String> = None;
    let mut keys: BTreeMap<(bool, String), String> = BTreeMap::new();
    for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if let Some(name) = l.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = Some(name.trim().to_string());
        } else if let Some((k, v)) = l.split_once('=') {
            match &section {
                None => keys.insert((false, k.trim().to_string()), v.trim().to_string()),
                Some(s) if s == file => keys.insert((true, k.trim().to_string()), v.trim().to_string()),
                Some(_) => None,
            };
        }
    }
    let get = |k: &str| keys.get(&(true, k.to_string())).or_else(|| keys.get(&(false, k.to_string()))).cloned();
    // A file section names its own provenance: a default note never carries over.
    let own = keys.keys().any(|(in_section, _)| *in_section);
    let note = keys.get(&(own, "note".to_string())).cloned();
    match get("compiled_from_tag") {
        Some(tag) => SassOrigin::CompiledFromTag { tag, source: get("source"), note },
        None => SassOrigin::CoreArtifact,
    }
}

/// ptxas resource usage for the kernel (`resource-usage.txt`, cuobjdump -res-usage).
#[derive(Clone, Debug, Serialize)]
pub struct ResourceUsage {
    pub regs: Option<i64>,
    pub stack: Option<i64>,
    pub shared: Option<i64>,
    pub local: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArchArtifacts {
    pub sm: i64,
    pub sass: Option<Sass>,
    /// Why there is no SASS listing, when there is none.
    pub sass_note: Option<String>,
    /// Lines of the listing with each opcode (HMMA, LDSM, LDGSTS, LDG, STS),
    /// counted as tools/sass_dump.sh counts them (`grep -c '\bOP'`). None
    /// without a listing.
    pub instruction_mix: Option<BTreeMap<String, i64>>,
    pub resource_usage: Option<ResourceUsage>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NsightReport {
    pub shape: String,
    pub path: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct KernelDetail {
    pub kernel_id: String,
    pub op: String,
    #[serde(rename = "impl")]
    pub impl_: String,
    pub config: Value,
    pub baseline: bool,
    pub regs: Option<i64>,
    pub smem_bytes: Option<i64>,
    /// Local memory per thread: non-zero means register spills.
    pub local_bytes: Option<i64>,
    /// Shapes where this kernel is the winner ("sm_121 1x896x896").
    pub winner_of: Vec<String>,
    /// Protocol v2, cold, clean rows (rule 2).
    pub measurements: Vec<Measurement>,
    pub artifacts: Vec<ArchArtifacts>,
    /// Nsight Compute reports (.ncu-rep) Core captured for this kernel; empty
    /// means "not profiled".
    pub nsight_reports: Vec<NsightReport>,
    /// Stall and pipe metrics: Custos does not read .ncu-rep files, and Core's
    /// text summaries truncate kernel names; None until Core provides them
    /// per impl and shape (docs/core-requests.md #6).
    pub nsight_stalls: Option<Value>,
}

/// Mangled-name fragments of the measured (row-major A and B, `Layout 0, 0`)
/// instantiation of a config; a listing matches if its symbol contains any.
/// - mma_pipe: `gemm_mma_pipe_kernel<Tile<BM, BN, BK, WM, WN, Layout 0, Layout 0>, STAGES>(KParams, bool, bool)`;
///   the layout back-reference is `S5_` up to aegis-perf-v0.4.0 and `S6_` from
///   v0.5.0 (the kernel moved into `mma_pipe_detail`).
/// - gemv_tc: `gemv_tc_kernel<DecTile<BN, BK, WARPS_N, Layout 0, Layout 0>, STAGES>(KParams, TcArgs, bool)`;
///   split-K is a launch argument, so `_k1` and `_k3` of a tile share a kernel.
/// - mma_tma: `gemm_mma_tma_kernel<TmaTile<BM, BN, BK, WM, WN, Layout 0, Layout 0>, STAGES>(CUtensorMap, CUtensorMap, KParams, bool)`.
///
/// Other impl families: None (no symbol known for them yet).
fn symbol(impl_: &str, cfg: &Value) -> Option<Vec<String>> {
    let g = |k: &str| cfg.get(k).and_then(Value::as_i64);
    let li = |keys: &[&str]| -> Option<String> { keys.iter().map(|k| g(k).map(|x| format!("Li{x}E"))).collect() };
    if impl_.starts_with("mma_pipe_") {
        let t = li(&["BM", "BN", "BK", "WARPS_M", "WARPS_N"])?;
        let s = g("STAGES")?;
        return Some(
            ["S5_", "S6_"]
                .iter()
                .map(|r| format!("gemm_mma_pipe_kernelINS0_10mma_detail4TileI{t}LNS0_6LayoutE0EL{r}0EEELi{s}EEEvNS0_7KParamsEbb"))
                .collect(),
        );
    }
    if impl_.starts_with("gemv_tc_") {
        let t = li(&["BN", "BK", "WARPS_N"])?;
        return Some(vec![format!(
            "gemv_tc_kernelINS1_7DecTileI{t}LNS0_6LayoutE0ELS4_0EEELi{}EEEvNS0_7KParamsENS1_6TcArgsEb",
            g("STAGES")?
        )]);
    }
    if impl_.starts_with("mma_tma_") {
        let t = li(&["BM", "BN", "BK", "WARPS_M", "WARPS_N"])?;
        return Some(vec![format!(
            "gemm_mma_tma_kernelINS1_7TmaTileI{t}LNS0_6LayoutE0ELS4_0EEELi{}EEEv14CUtensorMap_stS6_NS0_7KParamsEb",
            g("STAGES")?
        )]);
    }
    None
}

fn matches(symbol: &str, sym: &[String]) -> bool {
    sym.iter().any(|s| symbol.contains(s.as_str()))
}

/// The kernel symbol a SASS listing is for (its first `Function :` line).
fn listing_symbol(path: &Path) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    BufReader::new(f).lines().take(64).map_while(Result::ok).find_map(|l| {
        l.trim().strip_prefix("Function : ").map(|s| s.trim().to_string())
    })
}

fn sass(dir: &Path, sym: &[String]) -> Result<(Option<Sass>, Option<String>)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok((None, Some(format!("no SASS dump ({} missing)", dir.display()))));
    };
    let mut hits: Vec<(PathBuf, String)> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "sass"))
        .filter_map(|p| listing_symbol(&p).filter(|s| matches(s, sym)).map(|s| (p, s)))
        .collect();
    hits.sort();
    match &hits[..] {
        [(p, s)] => {
            let text = std::fs::read_to_string(p)?;
            let origin = sass_origin(dir, &p.file_name().unwrap_or_default().to_string_lossy());
            Ok((Some(Sass { path: p.display().to_string(), symbol: s.clone(), lines: text.lines().count(), text, origin }), None))
        }
        [] => Ok((None, Some("no SASS listing of the row-major instantiation in the dump".into()))),
        _ => Ok((None, Some(format!("{} listings claim this kernel; showing none", hits.len())))),
    }
}

/// `grep -cE "\bOP"`: lines with OP at a word start (tools/sass_dump.sh).
fn count_lines(text: &str, op: &str) -> i64 {
    let starts_word = |line: &str, i: usize| i == 0 || !line.as_bytes()[i - 1].is_ascii_alphanumeric() && line.as_bytes()[i - 1] != b'_';
    text.lines().filter(|l| l.match_indices(op).any(|(i, _)| starts_word(l, i))).count() as i64
}

fn instruction_mix(s: &Sass) -> BTreeMap<String, i64> {
    [("HMMA", "HMMA"), ("LDSM", "LDSM"), ("LDGSTS", "LDGSTS"), ("LDG", "LDG."), ("STS", "STS")]
        .into_iter()
        .map(|(name, op)| (name.to_string(), count_lines(&s.text, op)))
        .collect()
}

fn resource_usage(dir: &Path, sym: &[String]) -> Result<Option<ResourceUsage>> {
    let Ok(text) = std::fs::read_to_string(dir.join("resource-usage.txt")) else { return Ok(None) };
    let lines: Vec<&str> = text.lines().collect();
    let found: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].trim_start().starts_with("Function ") && matches(lines[i], sym))
        .collect();
    let [i] = found[..] else { return Ok(None) };
    let Some(usage) = lines.get(i + 1) else { return Ok(None) };
    let field = |k: &str| {
        usage.split_whitespace().find_map(|t| t.strip_prefix(k).and_then(|v| v.strip_prefix(':'))).and_then(|v| v.parse().ok())
    };
    Ok(Some(ResourceUsage { regs: field("REG"), stack: field("STACK"), shared: field("SHARED"), local: field("LOCAL") }))
}

fn nsight(src: &Sources, impl_: &str) -> Vec<NsightReport> {
    let dir = &src.ncu_dir;
    let prefix = format!("{impl_}_");
    let mut out: Vec<NsightReport> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let f = e.file_name().to_string_lossy().into_owned();
            let shape = f.strip_suffix(".ncu-rep")?.strip_prefix(&prefix)?;
            // The rest must be exactly a shape, so mma_pipe_128x128x32_2x4_s2 never
            // matches a report of mma_pipe_128x128x32_2x4_s2_<something else>.
            let dims: Vec<&str> = shape.split('x').collect();
            (dims.len() == 3 && dims.iter().all(|d| d.parse::<i64>().is_ok()))
                .then(|| NsightReport { shape: shape.to_string(), path: e.path().display().to_string() })
        })
        .collect();
    out.sort_by(|a, b| a.shape.cmp(&b.shape));
    out
}

pub fn kernel_detail(src: &Sources, con: &Connection, kernel_id: &str) -> Result<Option<KernelDetail>> {
    let Some(k) = view::kernel(con, kernel_id)? else { return Ok(None) };
    let config: Value = serde_json::from_str(&k.config_json).unwrap_or(Value::String(k.config_json.clone()));
    let measurements = measure::measurements(src, con, &Filter { kernel_id: Some(kernel_id.to_string()), ..Default::default() })?;
    let winner_of = view::winners(con, None)?
        .into_iter()
        .filter(|w| w.kernel.kernel_id == kernel_id)
        .map(|w| format!("sm_{} {}", w.sm_arch, w.shape_bucket))
        .collect();

    // Artifacts for every arch the kernel was measured on, else every arch with a SASS dump.
    let mut archs: Vec<i64> = measurements.iter().map(|m| m.sm_arch).collect();
    if archs.is_empty() {
        archs = std::fs::read_dir(&src.sass_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().strip_prefix("sm_")?.parse().ok())
            .collect();
    }
    archs.sort();
    archs.dedup();
    let sym = symbol(&k.impl_, &config);
    let mut artifacts = Vec::new();
    for sm in archs {
        let dir = src.sass_dir.join(format!("sm_{sm}"));
        artifacts.push(match &sym {
            Some(sym) => {
                let (sass, sass_note) = sass(&dir, sym)?;
                ArchArtifacts {
                    sm,
                    instruction_mix: sass.as_ref().map(instruction_mix),
                    sass,
                    sass_note,
                    resource_usage: resource_usage(&dir, sym)?,
                }
            }
            None => ArchArtifacts {
                sm,
                sass: None,
                sass_note: Some(if aegis_perf::db::is_baseline(&k.impl_) {
                    "a cuBLAS baseline: no AEGIS SASS".into()
                } else {
                    format!("no kernel symbol known for {} (only the mma_pipe, gemv_tc and mma_tma families)", k.impl_)
                }),
                instruction_mix: None,
                resource_usage: None,
            },
        });
    }

    Ok(Some(KernelDetail {
        baseline: aegis_perf::db::is_baseline(&k.impl_),
        nsight_reports: nsight(src, &k.impl_),
        nsight_stalls: None,
        regs: measured(k.regs),
        smem_bytes: measured(k.smem_bytes),
        local_bytes: measured(k.local_bytes),
        kernel_id: k.kernel_id,
        op: k.op,
        impl_: k.impl_,
        config,
        winner_of,
        measurements,
        artifacts,
    }))
}

//! Kernel detail: config, registers, spills, shared memory, measurements,
//! and Core's artifacts for it: raw SASS, instruction mix, ptxas resource
//! usage, Nsight reports. Anything Core has not produced is None ("not
//! measured" / "not profiled"), never estimated.
use std::collections::BTreeMap;
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
    pub lines: usize,
    /// Raw SASS; control codes are not parsed yet (Core stage 2).
    pub text: String,
}

/// ptxas resource usage for the kernel (artifacts/sass/<arch>/resource-usage.txt).
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
    /// Static instruction counts (HMMA, LDSM, LDGSTS, LDG, STS) from instruction-mix.txt.
    pub instruction_mix: Option<BTreeMap<String, i64>>,
    pub resource_usage: Option<ResourceUsage>,
}

/// An Nsight Compute report for this kernel.
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
    /// Shapes where this kernel is the dispatched winner ("sm_121 1x896x896").
    pub winner_of: Vec<String>,
    /// Protocol v2, cold, idle rows (rule 2).
    pub measurements: Vec<Measurement>,
    pub artifacts: Vec<ArchArtifacts>,
    /// Nsight Compute reports (.ncu-rep) Core captured for this kernel; empty
    /// means "not profiled". Stall and pipe metrics are not extracted yet.
    pub nsight_reports: Vec<NsightReport>,
}

/// The kernel's names in Core's artifacts: the demangled template name in
/// instruction-mix.txt, a fragment of the SASS file name, and a fragment of
/// the mangled name in resource-usage.txt.
struct Names {
    demangled: String,
    file: String,
    mangled: String,
}

fn names(impl_: &str, cfg: &Value) -> Option<Names> {
    let g = |k: &str| cfg.get(k).and_then(Value::as_i64);
    let li = |v: &[i64]| v.iter().map(|x| format!("Li{x}E")).collect::<String>();
    if impl_ == "naive" || impl_ == "tiled" {
        let n = format!("gemm_{impl_}_kernel");
        return Some(Names { demangled: n.clone(), file: format!("{n}___half"), mangled: format!("{n}EPK6__half") });
    }
    if impl_.starts_with("regblock_") {
        let d = [g("BM")?, g("BN")?, g("BK")?, g("TM")?, g("TN")?];
        let csv = d.map(|x| x.to_string()).join(", ");
        let us = d.map(|x| x.to_string()).join("__");
        return Some(Names {
            demangled: format!("gemm_regblock_kernel<{csv}>"),
            file: format!("gemm_regblock_kernel_{us}____half"),
            mangled: format!("gemm_regblock_kernelI{}EE", li(&d)),
        });
    }
    if impl_.starts_with("mma_") {
        let t = [g("BM")?, g("BN")?, g("BK")?, g("WARPS_M")?, g("WARPS_N")?];
        let csv = t.map(|x| x.to_string()).join(", ");
        let us = t.map(|x| x.to_string()).join("__");
        return Some(match g("STAGES") {
            Some(s) => Names {
                demangled: format!("gemm_mma_pipe_kernel<aegis::gemm::mma_detail::Tile<{csv}>, {s}>"),
                file: format!("gemm_mma_pipe_kernel_aegis__gemm__mma_detail__Tile_{us}___{s}__"),
                mangled: format!("gemm_mma_pipe_kernelINS0_10mma_detail4TileI{}EE{}EE", li(&t), li(&[s])),
            },
            None => Names {
                demangled: format!("gemm_mma_kernel<aegis::gemm::mma_detail::Tile<{csv}> >"),
                file: format!("gemm_mma_kernel_aegis__gemm__mma_detail__Tile_{us}______half"),
                mangled: format!("gemm_mma_kernelINS0_10mma_detail4TileI{}EEEEEv", li(&t)),
            },
        });
    }
    None // baselines (cuBLAS) have no AEGIS artifacts
}

fn sass(dir: &Path, n: &Names) -> Result<Option<Sass>> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Ok(None) };
    let mut hits: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|e| e == "sass")
                && p.file_name().is_some_and(|f| f.to_string_lossy().contains(&n.file))
        })
        .collect();
    hits.sort();
    match &hits[..] {
        [p] => {
            let text = std::fs::read_to_string(p)?;
            Ok(Some(Sass { path: p.display().to_string(), lines: text.lines().count(), text }))
        }
        _ => Ok(None), // none, or ambiguous: show nothing rather than the wrong kernel
    }
}

fn instruction_mix(dir: &Path, n: &Names) -> Result<Option<BTreeMap<String, i64>>> {
    let Ok(text) = std::fs::read_to_string(dir.join("instruction-mix.txt")) else { return Ok(None) };
    let mut lines = text.lines();
    let Some(header) = lines.next() else { return Ok(None) };
    let cols: Vec<&str> = header.split_whitespace().skip(1).collect();
    for line in lines {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() <= cols.len() {
            continue;
        }
        let (name, counts) = toks.split_at(toks.len() - cols.len());
        if name.join(" ") != n.demangled {
            continue;
        }
        let counts: Option<Vec<i64>> = counts.iter().map(|c| c.parse().ok()).collect();
        return Ok(counts.map(|c| cols.iter().map(|s| s.to_string()).zip(c).collect()));
    }
    Ok(None)
}

fn resource_usage(dir: &Path, n: &Names) -> Result<Option<ResourceUsage>> {
    let Ok(text) = std::fs::read_to_string(dir.join("resource-usage.txt")) else { return Ok(None) };
    let lines: Vec<&str> = text.lines().collect();
    let found: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].trim_start().starts_with("Function ") && lines[i].contains(&n.mangled))
        .collect();
    let [i] = found[..] else { return Ok(None) };
    let Some(usage) = lines.get(i + 1) else { return Ok(None) };
    let field = |k: &str| {
        usage.split_whitespace().find_map(|t| t.strip_prefix(k).and_then(|v| v.strip_prefix(':'))).and_then(|v| v.parse().ok())
    };
    Ok(Some(ResourceUsage { regs: field("REG"), stack: field("STACK"), shared: field("SHARED"), local: field("LOCAL") }))
}

fn nsight(src: &Sources, impl_: &str) -> Vec<NsightReport> {
    let dir = src.core_path("artifacts/ncu");
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
        archs = std::fs::read_dir(src.core_path("artifacts/sass"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().strip_prefix("sm_")?.parse().ok())
            .collect();
    }
    archs.sort();
    archs.dedup();
    let names = names(&k.impl_, &config);
    let mut artifacts = Vec::new();
    for sm in archs {
        let dir = src.core_path(format!("artifacts/sass/sm_{sm}"));
        artifacts.push(match &names {
            Some(n) => ArchArtifacts {
                sm,
                sass: sass(&dir, n)?,
                instruction_mix: instruction_mix(&dir, n)?,
                resource_usage: resource_usage(&dir, n)?,
            },
            None => ArchArtifacts { sm, sass: None, instruction_mix: None, resource_usage: None },
        });
    }

    Ok(Some(KernelDetail {
        baseline: aegis_perf::db::is_baseline(&k.impl_),
        nsight_reports: nsight(src, &k.impl_),
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

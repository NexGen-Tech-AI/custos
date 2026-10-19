//! Nsight Systems: an `nsys export --type sqlite` file, queried directly.
//!
//! Read: the GPU (TARGET_INFO_GPU), the kernel, memcpy and memset timeline
//! (CUPTI_ACTIVITY_KIND_*), CUDA API calls (CUPTI_ACTIVITY_KIND_RUNTIME) and
//! OS runtime calls (OSRT_API) per CPU thread, and the capture's start time.
//! Nothing else: the export's system environment, process command lines and
//! file streams (paths, host names) are never read (CLAUDE.md rule 28).
//!
//! The export's schema version (META_DATA_EXPORT.EXPORT_SCHEMA_VERSION) is
//! checked first: this adapter reads major 3 up to minor [`MAX_MINOR`] (the
//! columns below are the documented ones of 3.20.3, Nsight Systems 2025.3.2).
//! Any other version fails with a message naming it, before any query; a
//! missing column fails the same way, never a misparse.
//!
//! The export records neither the nsys version nor the build profiled.
//! `tools/capture_fixtures.sh` writes them into a sidecar `<export>.meta.json`
//! ([`Sidecar`]); without one they are "not recorded".
//!
//! Every time here is a profiler timing (CLAUDE.md rule 25).
use std::path::Path;

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;

use crate::adapter::{command_availability, Adapter, Availability, Ingest, TOOL_DIRS};
use crate::model::{Capture, Device, EventKind, Kernel, Launch, ProfilerTiming, Run, Timeline, TimelineEvent, Value};
use crate::provenance::{Build, Clocks, Known, Provenance, Source};

pub const SUPPORTED_MAJOR: u32 = 3;
/// The newest minor version whose documented schema this adapter was written against.
pub const MAX_MINOR: u32 = 20;

/// Columns read per table: (table, required, optional table?).
const COLUMNS: &[(&str, &[&str], bool)] = &[
    ("StringIds", &["id", "value"], false),
    ("META_DATA_EXPORT", &["name", "value"], false),
    (
        "CUPTI_ACTIVITY_KIND_KERNEL",
        &[
            "start", "end", "deviceId", "streamId", "correlationId", "demangledName", "shortName", "mangledName",
            "registersPerThread", "gridX", "gridY", "gridZ", "blockX", "blockY", "blockZ", "staticSharedMemory",
            "dynamicSharedMemory", "localMemoryPerThread", "gridId",
        ],
        true,
    ),
    ("CUPTI_ACTIVITY_KIND_MEMCPY", &["start", "end", "deviceId", "streamId", "correlationId", "bytes", "copyKind"], true),
    ("CUPTI_ACTIVITY_KIND_MEMSET", &["start", "end", "deviceId", "streamId", "correlationId", "bytes"], true),
    ("CUPTI_ACTIVITY_KIND_RUNTIME", &["start", "end", "globalTid", "correlationId", "nameId"], true),
    ("OSRT_API", &["start", "end", "globalTid", "nameId"], true),
    ("TARGET_INFO_GPU", &["id", "name", "smCount", "computeMajor", "computeMinor"], true),
    ("ENUM_CUDA_MEMCPY_OPER", &["id", "label"], true),
    ("TARGET_INFO_SESSION_START_TIME", &["utcTime"], true),
];

/// What `tools/capture_fixtures.sh` records beside an export.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Sidecar {
    /// `nsys --version`.
    pub tool_version: Option<String>,
    /// The profiled build (`bench_gemm --build-info`): 40 hex digits and dirty.
    pub build_sha: Option<String>,
    pub build_dirty: Option<bool>,
    /// A hand-built fixture.
    #[serde(default)]
    pub synthetic: bool,
}

impl Sidecar {
    pub fn for_export(export: &Path) -> Result<Option<Sidecar>> {
        let p = export.with_extension("meta.json");
        if !p.exists() {
            return Ok(None);
        }
        let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
        Ok(Some(serde_json::from_str(&s).with_context(|| format!("parse {}", p.display()))?))
    }
}

pub struct Nsys {
    /// The PATH to search (None: the process's).
    pub path: Option<std::ffi::OsString>,
}

impl Adapter for Nsys {
    fn source(&self) -> Source {
        Source::Nsys
    }
    fn availability(&self) -> Availability {
        let path = self.path.clone().or_else(|| std::env::var_os("PATH"));
        command_availability("nsys", path.as_deref(), TOOL_DIRS)
    }
}

impl Ingest for Nsys {
    type Input = Path;
    fn ingest(&self, export: &Path) -> Result<Capture> {
        ingest(export)
    }
}

/// The export's schema version, checked: Ok only for a version this adapter reads.
pub fn schema_version(con: &Connection) -> Result<(u32, u32, u32)> {
    let has: bool = con
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'META_DATA_EXPORT'")?
        .exists([])?;
    if !has {
        bail!("not an Nsight Systems SQLite export: no META_DATA_EXPORT table");
    }
    let v: Option<String> = con
        .query_row("SELECT value FROM META_DATA_EXPORT WHERE name = 'EXPORT_SCHEMA_VERSION'", [], |r| r.get(0))
        .ok();
    let v = v.context("nsys export without EXPORT_SCHEMA_VERSION; cannot tell its schema, so it is not read")?;
    let parts: Vec<u32> = v.trim().split('.').map(|p| p.parse().ok()).collect::<Option<_>>().unwrap_or_default();
    let [major, minor, micro] = parts[..] else {
        bail!("nsys export schema version '{v}' is not major.minor.micro; not read")
    };
    if major != SUPPORTED_MAJOR || minor > MAX_MINOR {
        bail!(
            "nsys export schema {v} is not one Custos reads (it reads {SUPPORTED_MAJOR}.0 to {SUPPORTED_MAJOR}.{MAX_MINOR}.x, \
             Nsight Systems up to 2025.3). Re-export with a supported Nsight Systems, or update Custos's nsys adapter \
             to the new schema (export_schema_version_notes.txt lists the changes)."
        );
    }
    Ok((major, minor, micro))
}

fn table_exists(con: &Connection, t: &str) -> Result<bool> {
    Ok(con.prepare("SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?")?.exists([t])?)
}

/// Every table read has every column read; optional tables may be absent (a note says so).
fn check_columns(con: &Connection, notes: &mut Vec<String>) -> Result<Vec<&'static str>> {
    let mut present = Vec::new();
    for (t, cols, optional) in COLUMNS {
        if !table_exists(con, t)? {
            if *optional {
                notes.push(format!("{t}: not in this capture"));
                continue;
            }
            bail!("nsys export without the {t} table; not read");
        }
        for c in *cols {
            let has: bool = con.prepare(&format!("SELECT 1 FROM pragma_table_info('{t}') WHERE name = ?"))?.exists([c])?;
            if !has {
                bail!("nsys export: {t} has no column {c} (schema changed?); not read");
            }
        }
        present.push(*t);
    }
    Ok(present)
}

/// CUDA API names as nsys's own reports show them: without the "_v<version>" suffix.
fn api_name(n: &str) -> String {
    match n.rfind("_v") {
        Some(i) if n[i + 2..].chars().all(|c| c.is_ascii_digit()) && i + 2 < n.len() => n[..i].to_string(),
        _ => n.to_string(),
    }
}

/// CPU thread id of a serialized globalTid (nsys reports: tid = gtid & 0xFFFFFF).
fn tid(gtid: i64) -> i64 {
    gtid & 0x00FF_FFFF
}

pub fn ingest(export: &Path) -> Result<Capture> {
    let con = Connection::open_with_flags(export, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .with_context(|| format!("open {} read-only", export.display()))?;
    let (major, minor, micro) = schema_version(&con)?;
    let mut c = Capture::default();
    let tables = check_columns(&con, &mut c.notes)?;
    let has = |t: &str| tables.contains(&t);
    let side = Sidecar::for_export(export)?.unwrap_or_default();
    let file = export.file_name().map_or_else(|| "export".to_string(), |f| f.to_string_lossy().into_owned());
    let run_id = format!("nsys:{}", export.file_stem().map_or_else(String::new, |f| f.to_string_lossy().into_owned()));

    let mut prov = Provenance::new(
        Source::Nsys,
        "nsys",
        side.tool_version
            .clone()
            .map_or(Known::Unknown(format!("not recorded (the export records only its schema, {major}.{minor}.{micro})")), Known::Known),
        &format!("{file} (export schema {major}.{minor}.{micro})"),
    );
    prov.synthetic = side.synthetic;
    prov.build = match (&side.build_sha, side.build_dirty) {
        (Some(s), Some(d)) => Build::full(s, d),
        _ => None,
    };
    prov.clocks = Clocks::unknown("Nsight Systems neither controls nor records GPU clocks");
    if has("TARGET_INFO_SESSION_START_TIME") {
        prov.captured_at = con.query_row("SELECT utcTime FROM TARGET_INFO_SESSION_START_TIME", [], |r| r.get(0)).ok().flatten();
    }

    if has("TARGET_INFO_GPU") {
        let mut s = con.prepare("SELECT id, name, smCount, computeMajor, computeMinor FROM TARGET_INFO_GPU ORDER BY id")?;
        let rows = s.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<i64>>(2)?, r.get::<_, Option<i64>>(3)?, r.get::<_, Option<i64>>(4)?))
        })?;
        for row in rows {
            let (id, name, sms, maj, min) = row?;
            c.devices.push(Device {
                id: format!("gpu{id}"),
                name: Value::from_option(name),
                sm_arch: match (maj, min) {
                    (Some(a), Some(b)) => Value::Present(a * 10 + b),
                    _ => Value::NotMeasured,
                },
                sm_count: Value::from_option(sms),
                provenance: prov.clone(),
            });
        }
    }
    c.runs.push(Run { id: run_id.clone(), kind: "nsys-capture".into(), device: c.devices.first().map(|d| d.id.clone()), provenance: prov.clone() });

    let mut events = Vec::new();
    if has("CUPTI_ACTIVITY_KIND_KERNEL") {
        let mut s = con.prepare(
            "SELECT k.start, k.end, k.deviceId, k.streamId, k.correlationId, dn.value, mn.value, k.registersPerThread, \
                    k.gridX, k.gridY, k.gridZ, k.blockX, k.blockY, k.blockZ, k.staticSharedMemory, k.dynamicSharedMemory, \
                    k.localMemoryPerThread, k.gridId \
             FROM CUPTI_ACTIVITY_KIND_KERNEL k JOIN StringIds dn ON dn.id = k.demangledName \
             LEFT JOIN StringIds mn ON mn.id = k.mangledName ORDER BY k.start",
        )?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            let name: String = r.get(5)?;
            let timing = ProfilerTiming { start_ns: r.get(0)?, end_ns: r.get(1)? };
            let launch_id = format!("{run_id}:grid{}", r.get::<_, i64>(17)?);
            if c.kernel(&name).is_none() {
                c.kernels.push(Kernel {
                    id: name.clone(),
                    name: name.clone(),
                    mangled: r.get(6)?,
                    impl_: None,
                    registers_per_thread: Value::Present(r.get(7)?),
                    static_smem_bytes: Value::Present(r.get(14)?),
                    local_bytes_per_thread: Value::Present(r.get(16)?),
                    provenance: prov.clone(),
                });
            }
            c.launches.push(Launch {
                id: launch_id.clone(),
                run: run_id.clone(),
                kernel: name.clone(),
                device: Some(format!("gpu{}", r.get::<_, i64>(2)?)),
                grid: [r.get(8)?, r.get(9)?, r.get(10)?],
                block: [r.get(11)?, r.get(12)?, r.get(13)?],
                dynamic_smem_bytes: Value::Present(r.get(15)?),
                stream: Some(r.get(3)?),
                correlation_id: r.get(4)?,
                timing: Some(timing),
                provenance: prov.clone(),
            });
            events.push(TimelineEvent {
                kind: EventKind::Kernel,
                name,
                timing,
                thread: None,
                stream: Some(r.get(3)?),
                correlation_id: r.get(4)?,
                bytes: None,
                launch: Some(launch_id),
            });
        }
    }
    if has("CUPTI_ACTIVITY_KIND_MEMCPY") {
        let label = if has("ENUM_CUDA_MEMCPY_OPER") { "o.label" } else { "NULL" };
        let join = if has("ENUM_CUDA_MEMCPY_OPER") { "LEFT JOIN ENUM_CUDA_MEMCPY_OPER o ON o.id = m.copyKind" } else { "" };
        let mut s = con.prepare(&format!(
            "SELECT m.start, m.end, m.streamId, m.correlationId, m.bytes, {label}, m.copyKind FROM CUPTI_ACTIVITY_KIND_MEMCPY m {join}"
        ))?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            let kind: Option<String> = r.get(5)?;
            events.push(TimelineEvent {
                kind: EventKind::Memcpy,
                name: format!("[CUDA memcpy {}]", kind.unwrap_or_else(|| format!("kind {}", r.get::<_, i64>(6).unwrap_or(-1)))),
                timing: ProfilerTiming { start_ns: r.get(0)?, end_ns: r.get(1)? },
                thread: None,
                stream: Some(r.get(2)?),
                correlation_id: r.get(3)?,
                bytes: Some(r.get(4)?),
                launch: None,
            });
        }
    }
    if has("CUPTI_ACTIVITY_KIND_MEMSET") {
        let mut s = con.prepare("SELECT start, end, streamId, correlationId, bytes FROM CUPTI_ACTIVITY_KIND_MEMSET")?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            events.push(TimelineEvent {
                kind: EventKind::Memset,
                name: "[CUDA memset]".into(),
                timing: ProfilerTiming { start_ns: r.get(0)?, end_ns: r.get(1)? },
                thread: None,
                stream: Some(r.get(2)?),
                correlation_id: r.get(3)?,
                bytes: Some(r.get(4)?),
                launch: None,
            });
        }
    }
    for (table, kind) in [("CUPTI_ACTIVITY_KIND_RUNTIME", EventKind::CudaApi), ("OSRT_API", EventKind::OsRuntime)] {
        if !has(table) {
            continue;
        }
        let corr = if table == "OSRT_API" { "NULL" } else { "t.correlationId" };
        let mut s = con.prepare(&format!(
            "SELECT t.start, t.end, t.globalTid, {corr}, n.value FROM {table} t JOIN StringIds n ON n.id = t.nameId"
        ))?;
        let mut rows = s.query([])?;
        while let Some(r) = rows.next()? {
            let name: String = r.get(4)?;
            events.push(TimelineEvent {
                kind: kind.clone(),
                name: if kind == EventKind::CudaApi { api_name(&name) } else { name },
                timing: ProfilerTiming { start_ns: r.get(0)?, end_ns: r.get(1)? },
                thread: r.get::<_, Option<i64>>(2)?.map(tid),
                stream: None,
                correlation_id: r.get(3)?,
                bytes: None,
                launch: None,
            });
        }
    }
    events.sort_by_key(|e| (e.timing.start_ns, e.timing.end_ns));
    c.timelines.push(Timeline { run: run_id, events, provenance: prov });
    Ok(c)
}

/// `nsys export --type sqlite` of a report (needs nsys; never run by the tests).
pub fn export(nsys: &Path, report: &Path, out: &Path) -> Result<()> {
    let o = std::process::Command::new(nsys)
        .args(["export", "--type", "sqlite", "--force-overwrite", "true", "--output"])
        .arg(out)
        .arg(report)
        .output()
        .with_context(|| format!("run {} export", nsys.display()))?;
    if !o.status.success() {
        bail!("nsys export failed ({}): {}", o.status, String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or(""));
    }
    Ok(())
}

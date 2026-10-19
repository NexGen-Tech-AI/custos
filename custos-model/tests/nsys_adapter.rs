//! The Nsight Systems adapter on the synthetic export (tests/fixtures/nsys/,
//! an SQL dump in the documented schema 3.20.3, loaded into a temporary SQLite).
use std::path::{Path, PathBuf};

use custos_model::adapter::{Adapter, Availability};
use custos_model::contract::violations;
use custos_model::model::{EventKind, Value};
use custos_model::nsys::{self, Nsys};
use custos_model::provenance::{ClockControl, Source};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nsys").join(name)
}

/// The SQL dump as an SQLite export in a temp dir (with its sidecar); `edit` runs on it first.
fn export(tag: &str, edit: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("custos-nsys-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("decode-synthetic.sqlite");
    let _ = std::fs::remove_file(&db);
    let con = rusqlite::Connection::open(&db).unwrap();
    con.execute_batch(&std::fs::read_to_string(fixture("decode-synthetic.sql")).unwrap()).unwrap();
    con.execute_batch(edit).unwrap();
    std::fs::copy(fixture("decode-synthetic.meta.json"), dir.join("decode-synthetic.meta.json")).unwrap();
    db
}

#[test]
fn normalizes_the_capture_with_provenance() {
    let c = nsys::ingest(&export("ok", "")).unwrap();
    assert!(violations(&c).is_empty(), "{:?}", violations(&c));
    assert!(c.notes.is_empty(), "{:?}", c.notes);
    let d = &c.devices[0];
    assert_eq!((d.id.as_str(), &d.sm_arch, &d.sm_count), ("gpu0", &Value::Present(121), &Value::Present(48)));
    let p = &d.provenance;
    assert_eq!((p.source, p.tool.name.as_str(), p.synthetic), (Source::Nsys, "nsys", true));
    assert!(p.tool.version.known().is_none(), "the export records no nsys version");
    assert_eq!(p.captured_at.as_deref(), Some("2026-10-18T00:00:00.000Z"));
    assert_eq!(p.origin, "decode-synthetic.sqlite (export schema 3.20.3)");
    assert_eq!(p.clocks.control, ClockControl::Unknown);
    assert_eq!(p.build, None);

    assert_eq!(c.kernels.len(), 1);
    let k = &c.kernels[0];
    assert!(k.name.starts_with("void aegis::gemm::gemv_tc_kernel<") && k.mangled.as_deref().unwrap().starts_with("_ZN5aegis"));
    assert_eq!((&k.registers_per_thread, &k.static_smem_bytes), (&Value::Present(70), &Value::Present(0)));
    assert_eq!(c.launches.len(), 5);
    let l = &c.launches[0];
    assert_eq!((l.grid, l.block, l.blocks(), l.threads_per_block()), ([14, 1, 1], [128, 1, 1], 14, 128));
    assert_eq!((l.dynamic_smem_bytes.clone(), l.stream, l.correlation_id), (Value::Present(49152), Some(13), Some(3)));
    assert_eq!(l.timing.unwrap().duration_ns(), 9000);

    let t = &c.timelines[0];
    let count = |k: EventKind| t.events.iter().filter(|e| e.kind == k).count();
    assert_eq!((count(EventKind::Kernel), count(EventKind::Memcpy), count(EventKind::Memset), count(EventKind::CudaApi), count(EventKind::OsRuntime)), (5, 1, 1, 8, 1));
    assert!(t.events.windows(2).all(|w| w[0].timing.start_ns <= w[1].timing.start_ns), "sorted by start");
    let api: Vec<&str> = t.events.iter().filter(|e| e.kind == EventKind::CudaApi).map(|e| e.name.as_str()).collect();
    assert_eq!(api[..3], ["cudaMemcpyAsync", "cudaMemsetAsync", "cudaLaunchKernel"], "the _v<version> suffix is dropped");
    let m = t.events.iter().find(|e| e.kind == EventKind::Memcpy).unwrap();
    assert_eq!((m.name.as_str(), m.bytes), ("[CUDA memcpy Host-to-Device]", Some(8028160)));
    assert!(t.events.iter().filter(|e| e.thread.is_some()).all(|e| e.thread == Some(4097)));
    // Each kernel event names its launch, and the launch call shares its correlation id.
    let k3 = t.events.iter().find(|e| e.kind == EventKind::Kernel).unwrap();
    let call = t.events.iter().find(|e| e.kind == EventKind::CudaApi && e.correlation_id == k3.correlation_id).unwrap();
    assert_eq!((call.name.as_str(), k3.launch.as_deref()), ("cudaLaunchKernel", Some(l.id.as_str())));
}

#[test]
fn unknown_schema_versions_fail_clearly() {
    for (v, want) in [("4.0.0", "4.0.0 is not one Custos reads"), ("3.21.0", "3.21.0 is not one Custos reads"), ("3.x", "not major.minor.micro")] {
        let e = nsys::ingest(&export(&format!("v{v}"), &format!("UPDATE META_DATA_EXPORT SET value = '{v}';"))).unwrap_err().to_string();
        assert!(e.contains(want), "{v}: {e}");
    }
    let e = nsys::ingest(&export("noversion", "DELETE FROM META_DATA_EXPORT;")).unwrap_err().to_string();
    assert!(e.contains("without EXPORT_SCHEMA_VERSION"), "{e}");
    let e = nsys::ingest(&export("notnsys", "DROP TABLE META_DATA_EXPORT;")).unwrap_err().to_string();
    assert!(e.contains("not an Nsight Systems SQLite export"), "{e}");
    // A renamed column: refused before any query reads the table.
    let e = nsys::ingest(&export("col", "ALTER TABLE CUPTI_ACTIVITY_KIND_KERNEL RENAME COLUMN gridId TO gridIdent;")).unwrap_err().to_string();
    assert!(e.contains("CUPTI_ACTIVITY_KIND_KERNEL has no column gridId"), "{e}");
}

#[test]
fn a_capture_without_cpu_traces_is_read_with_notes() {
    let c = nsys::ingest(&export("noapi", "DROP TABLE CUPTI_ACTIVITY_KIND_RUNTIME; DROP TABLE OSRT_API;")).unwrap();
    assert_eq!(c.launches.len(), 5);
    assert_eq!(c.notes, ["CUPTI_ACTIVITY_KIND_RUNTIME: not in this capture", "OSRT_API: not in this capture"]);
}

#[test]
fn nsys_missing_is_unavailable() {
    let a = Nsys { path: Some("".into()) }.availability();
    // Unavailable unless installed in /usr/local/cuda/bin (then it names its version).
    match a {
        Availability::Unavailable { reason } => assert!(reason.contains("nsys is not installed")),
        Availability::Available { tool, .. } => assert_eq!(tool, "nsys"),
    }
}

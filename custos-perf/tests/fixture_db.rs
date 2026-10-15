//! custos-perf against fixture snapshots (CLAUDE.md rule 16), never the live
//! Core tree (another session changes it at will):
//! - the perf DB: ~/custos-fixtures/aegis_perf.db (AEGIS_PERFDB)
//! - Core files: ~/custos-fixtures/core (AEGIS_FIXTURE_CORE): the arch file,
//!   manifest, artifacts/sass and artifacts/ncu, as of the DB copy (2026-10-14;
//!   arch file generated 20:14 UTC).
//!
//! Re-snapshotting changes the expected values: update the numbers here, and
//! regenerate tests/fixtures/roofline-sm121.txt with
//! `aegis-perf --db <copy> roofline --arch 121` (run on a scratch copy: the
//! CLI's connect migrates the DB).
use custos_perf::{Filter, Sources};

fn src() -> Sources {
    let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let s = Sources {
        core: std::env::var_os("AEGIS_FIXTURE_CORE").map(Into::into).unwrap_or(home.join("custos-fixtures/core")),
        ..Sources::from_env()
    };
    assert!(s.arch_file(121).exists(), "fixture Core snapshot {} missing", s.core.display());
    assert!(
        s.db.exists(),
        "fixture DB {} missing; cp ~/Documents/projects/aegis/results/aegis_perf.db ~/custos-fixtures/",
        s.db.display()
    );
    s
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9 * b.abs().max(1.0)
}

#[test]
fn opens_read_only() {
    let con = src().open().unwrap();
    assert!(con.execute("DELETE FROM winners", []).is_err(), "fixture DB must be read-only");
}

#[test]
fn devices_lists_the_spark_with_manifest() {
    let s = src();
    let con = s.open().unwrap();
    let d = custos_perf::devices(&s, &con).unwrap();
    assert_eq!(d.len(), 1);
    let spark = &d[0];
    assert_eq!((spark.device_id.as_str(), spark.sm_arch), ("spark-5822", 121));
    assert_eq!(spark.gpu_name.as_deref(), Some("NVIDIA GB10"));
    assert_eq!(spark.runs, 22);
    let m = spark.manifest.as_ref().expect("manifest-spark-5822.json");
    assert_eq!((m.sm_count, m.l2_bytes, m.integrated), (Some(48), Some(25165824), Some(true)));
    assert!(spark.arch_file.is_some());
}

#[test]
fn arch_model_links_values_to_source_runs() {
    let s = src();
    let con = s.open().unwrap();
    let a = custos_perf::arch_model(&s, &con, 121).unwrap().expect("sm_121 arch file");
    let copy = a.copy_bw.as_ref().unwrap();
    assert!(close(copy.gbps, 236.696));
    assert_eq!(copy.reps.len(), 5);
    assert_eq!(copy.source.run_id, "941ff9215564");
    assert_eq!(copy.source.detail.as_deref(), Some("memcpy_d2d"));
    assert_eq!(copy.source.git_sha.as_deref(), Some("3b46bf9"));
    assert_eq!(copy.source.superseded_rows, 0);
    assert!(close(a.read_bw.as_ref().unwrap().gbps, 257.841));
    let mma = a.mma_peak.as_ref().unwrap();
    assert!(close(mma.tflops, 125.597));
    assert_eq!(mma.source.run_id, "eb3e197afc8e");
    let l2 = a.l2_latency.as_ref().unwrap();
    assert!(close(l2.ns, 132.292));
    // Three ptr_chase runs; two of them have since been superseded by the
    // third, which the view reports per source run (the UI warns on it).
    let sup: Vec<(&str, usize)> = l2.sources.iter().map(|s| (s.run_id.as_str(), s.superseded_rows)).collect();
    assert_eq!(sup, [("6141123bbcc4", 144), ("f1925d6a0fa4", 144), ("a825f4e557a3", 0)]);
    assert!(close(a.dram_latency.as_ref().unwrap().ns, 381.25));
    assert!(close(a.roofs.copy_bw_gbps, 236.696) && close(a.roofs.peak_tflops, 125.597));
    assert!(a.power.is_none(), "no power controls in the arch file yet: not measured");
    // Rule 7: the probe summary counts current rows only.
    let dram = a.probes.iter().find(|p| p.probe == "dram_bandwidth").unwrap();
    assert_eq!(dram.rows, 12);
    let ptr = a.probes.iter().find(|p| p.probe == "ptr_chase_latency").unwrap();
    assert_eq!(ptr.rows, 144);
}

#[test]
fn unmeasured_arch_is_none() {
    let s = src();
    let con = s.open().unwrap();
    assert!(custos_perf::arch_model(&s, &con, 87).unwrap().is_none());
    assert!(custos_perf::roofline(&s, &con, 87).unwrap().is_none());
    assert!(custos_perf::winners(&s, &con, 87).unwrap().is_empty());
}

#[test]
fn winners_carry_ci_tie_call_and_roof() {
    let s = src();
    let con = s.open().unwrap();
    let w = custos_perf::winners(&s, &con, 121).unwrap();
    assert_eq!(w.len(), 14);
    let get = |b: &str| w.iter().find(|x| x.shape_bucket == b).unwrap();

    // 1x4864x896: runner-up CI [0.99499, 1.00248] contains 1.0 -> tied.
    let t = get("1x4864x896");
    assert!(t.tie.tied && t.tie.ci.as_ref().unwrap().contains_one);
    assert_eq!(t.tie.method.as_deref(), Some("paired"));
    assert!(t.decode);
    assert_eq!(t.roof.as_ref().unwrap().roof, "read");

    // 256^3: runner-up CI [1.09747, 1.10233] -> a clear win over the runner-up,
    // but slower than cublaslt_best (CI [0.92367, 0.93204]).
    let c = get("256x256x256");
    assert!(!c.tie.tied);
    assert_eq!(c.impl_, "mma_pipe_64x64x32_2x2_s4");
    assert_eq!(c.tie.contender.as_deref(), Some("mma_pipe_64x64x32_2x2_s3"));
    assert!(c.tie.runner_up_gap_pct.unwrap() > 9.0);
    let lt = &c.vs_cublaslt_best;
    assert_eq!(lt.verdict, Some("slower"));
    assert!(close(lt.ci.as_ref().unwrap().lo, 0.92367));
    assert!((lt.pct_of_cublaslt_best.unwrap() - 91.786).abs() < 1e-3);
    assert_eq!(c.roof.as_ref().unwrap().roof, "copy");
    assert!(!c.decode);
    assert_eq!(c.regs, Some(64));
}

#[test]
fn measurements_default_to_v2_cold_idle() {
    let s = src();
    let con = s.open().unwrap();
    let rows = custos_perf::measurements(&s, &con, &Filter::default()).unwrap();
    assert_eq!(rows.len(), 1220);
    assert!(rows.iter().all(|r| r.protocol_version == 2 && r.cache_mode.as_deref() == Some("cold") && !r.allow_busy));
    assert!(rows.iter().all(|r| !r.history && r.roof.is_some()));

    let v1 = custos_perf::measurements(&s, &con, &Filter { protocol: Some(1), ..Default::default() }).unwrap();
    assert_eq!(v1.len(), 723);
    assert!(v1.iter().all(|r| r.history), "v1 rows are labeled history");

    let one = Filter { m: Some(256), n: Some(256), k: Some(256), impl_: Some("cublaslt_best".into()), ..Default::default() };
    let r = custos_perf::measurements(&s, &con, &one).unwrap();
    assert!(!r.is_empty() && r.iter().all(|r| r.impl_ == "cublaslt_best" && r.m == 256));

    assert!(custos_perf::measurements(&s, &con, &Filter { m: Some(1), ..Default::default() }).is_err());
    assert!(custos_perf::measurements(&s, &con, &Filter { cache: Some("lukewarm".into()), ..Default::default() }).is_err());
}

#[test]
fn kernel_detail_joins_db_and_artifacts() {
    let s = src();
    let con = s.open().unwrap();
    // mma_pipe_64x64x32_2x2_s4: winner of 8 shapes, SASS dumped, never profiled.
    let k = custos_perf::kernel_detail(&s, &con, "68018941c4de922b").unwrap().unwrap();
    assert_eq!(k.impl_, "mma_pipe_64x64x32_2x2_s4");
    assert_eq!(k.winner_of.len(), 8);
    assert_eq!((k.regs, k.local_bytes), (Some(64), Some(0)));
    assert!(!k.measurements.is_empty());
    let a = &k.artifacts[0];
    assert_eq!(a.sm, 121);
    let sass = a.sass.as_ref().expect("SASS dump");
    assert!(sass.path.contains("Tile_64__64__32__2__2___4__") && sass.text.contains("HMMA"));
    let mix = a.instruction_mix.as_ref().unwrap();
    assert_eq!((mix["HMMA"], mix["LDSM"], mix["LDGSTS"]), (32, 16, 16));
    assert_eq!(a.resource_usage.as_ref().unwrap().regs, k.regs);
    assert!(k.nsight_reports.is_empty(), "not profiled");

    // mma_pipe_128x128x32_2x4_s2: profiled at 2048^3 and 4096^3.
    let p = custos_perf::kernel_detail(&s, &con, "9e2efcd73edd4fa9").unwrap().unwrap();
    let shapes: Vec<&str> = p.nsight_reports.iter().map(|r| r.shape.as_str()).collect();
    assert_eq!(shapes, ["2048x2048x2048", "4096x4096x4096"]);

    // cuBLASLt: registers unknown to Core, no AEGIS SASS.
    let lt = custos_perf::kernel_detail(&s, &con, "11c8a1f7cc9d4d83").unwrap().unwrap();
    assert!(lt.baseline && lt.regs.is_none());
    assert!(lt.artifacts.iter().all(|a| a.sass.is_none() && a.instruction_mix.is_none()));

    assert!(custos_perf::kernel_detail(&s, &con, "nope").unwrap().is_none());
}

/// Point for point against the listing `aegis-perf roofline --arch 121`
/// printed when it wrote results/roofline-sm121.svg from the same DB.
#[test]
fn roofline_matches_aegis_perf_svg_listing() {
    let s = src();
    let con = s.open().unwrap();
    let r = custos_perf::roofline(&s, &con, 121).unwrap().unwrap();
    let listing = include_str!("fixtures/roofline-sm121.txt");
    let mut expected: Vec<(String, String, String, String, String)> = listing
        .lines()
        .map(|l| {
            let (label, rest) = l.split_once(" AI ").unwrap();
            let t: Vec<&str> = rest.split_whitespace().collect();
            // [ai, tflops, "TFLOPS", "56.4%", "of", "roof", "(copy", "bw)"]
            (label.trim().to_string(), t[0].into(), t[1].into(), t[3].trim_end_matches('%').into(), t[6][1..].into())
        })
        .collect();
    let mut got: Vec<(String, String, String, String, String)> = r
        .points
        .iter()
        .map(|p| {
            (
                p.label.clone(),
                format!("{:.1}", p.roof.ai),
                format!("{:.2}", p.roof.tflops),
                format!("{:.1}", p.roof.pct_roof),
                p.roof.roof.to_string(),
            )
        })
        .collect();
    expected.sort();
    got.sort();
    assert_eq!(expected.len(), 28);
    assert_eq!(got, expected);

    // Series and hover: every point of a winner shape carries its CI.
    assert_eq!(r.points.iter().filter(|p| p.series == "winner").count(), 14);
    assert!(r.points.iter().all(|p| p.hover.config.is_some() && p.hover.vs_cublaslt_best.is_some()));
    let decode = r.points.iter().filter(|p| p.m <= 16);
    assert!(decode.into_iter().all(|p| p.roof.roof == "read"));
    assert!((r.roofs.ridge_copy - 530.6).abs() < 0.1);
}

#[test]
fn compare_flags_and_refuses_cross_protocol() {
    let s = src();
    let con = s.open().unwrap();
    // Two full protocol v2 sweeps on the Spark.
    let c = custos_perf::compare(&con, "cef5728", "7b99002", &Filter::default()).unwrap();
    assert_eq!(c.rows.len(), 294);
    assert_eq!(c.confirmed_slower + c.unconfirmed_slower + c.faster + c.within, 294);
    assert!(c.not_comparable.is_empty());
    assert_eq!((c.excluded_a, c.excluded_b), (56, 56), "warm rows are never compared with cold");
    for r in &c.rows {
        assert!(close(r.ratio, r.b.median_us / r.a.median_us));
        let expect = if r.change_pct > 3.0 { "slower" } else if r.change_pct < -3.0 { "faster" } else { "within" };
        assert_eq!(r.flag, expect);
    }
    // The DB holds no cross-build paired results: every slowdown is
    // unconfirmed, none is called a regression.
    assert!(c.unconfirmed_slower > 0, "these two sweeps differ by > 3% somewhere");
    assert_eq!(c.confirmed_slower, 0);
    assert!(c.rows.iter().filter(|r| r.flag == "slower").all(|r| r.status == "unconfirmed" && r.paired.is_none()));

    // A protocol v1 build against a v2 build: nothing comparable.
    let x = custos_perf::compare(&con, "7365a7b", "cef5728", &Filter::default()).unwrap();
    assert!(x.rows.is_empty());
    assert_eq!(x.excluded_a, 280);
    assert_eq!(x.not_comparable.len(), 294);
    assert!(x.not_comparable.iter().all(|n| n.only_in == "b"));
}

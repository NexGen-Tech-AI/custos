//! custos-perf against the committed fixtures in tests/fixtures/ (project
//! rule 19): the trimmed perf DB, the arch file and the golden outputs of the
//! pinned tag's aegis-perf CLI. No test reads from ~ or from a Core checkout.
//!
//! Regenerating the fixture changes the expected values: see
//! tests/fixtures/README.md, then update the numbers here.
use custos_perf::{Filter, Sources};

fn src() -> Sources {
    let s = Sources::repo_fixtures();
    assert!(s.db.exists(), "fixture DB {} missing", s.db.display());
    assert!(s.arch_file(121).exists(), "fixture arch file {} missing", s.arch_file(121).display());
    s
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9 * b.abs().max(1.0)
}

/// Every path the tests read lives under tests/fixtures/.
#[test]
fn fixtures_are_self_contained() {
    let s = src();
    let root = s.root.canonicalize().unwrap();
    let repo_fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures").canonicalize().unwrap();
    assert_eq!(root, repo_fixtures);
    for p in [&s.db, &s.arch_dir, &s.manifest_dir, &s.sass_dir, &s.winners_dir, &s.docs_dir, &s.nightly_dir] {
        assert!(p.canonicalize().unwrap().starts_with(&root), "{} outside the fixtures", p.display());
    }
}

#[test]
fn opens_read_only() {
    let con = src().open().unwrap();
    assert!(con.execute("DELETE FROM winners", []).is_err(), "fixture DB must be read-only");
}

/// The fixture covers what the views have to handle (tests/fixtures/README.md).
#[test]
fn fixture_covers_the_contract_cases() {
    use aegis_perf::view::{self, MicrobenchStatus, PairedResultFilter};
    let s = src();
    let con = s.open().unwrap();
    assert_eq!(aegis_perf::db::schema_version(&con).unwrap(), Some(aegis_perf::db::SCHEMA_VERSION));
    let w = view::winners(&con, Some(121)).unwrap();
    assert!(w.iter().any(|w| w.m as f64 <= aegis_perf::params::DECODE_MAX_M), "a decode shape");
    assert!(w.iter().any(|w| w.m as f64 > aegis_perf::params::DECODE_MAX_M), "a non-decode shape");
    assert!(w.iter().any(|w| w.ratio_ci.is_some_and(|(lo, hi)| lo <= 1.0 && hi >= 1.0)), "a statistical tie");
    let runs = view::runs(&con).unwrap();
    assert!(runs.iter().any(|r| r.disturbed == Some(true)), "a disturbed run");
    let mb = view::microbench(&con, 121).unwrap();
    assert!(mb.iter().any(|m| m.status == MicrobenchStatus::Valid));
    assert!(mb.iter().any(|m| m.status == MicrobenchStatus::Replaced));
    let pr = view::paired_results(&con, &PairedResultFilter::default()).unwrap();
    assert_eq!(pr.len(), 44);
    assert!(pr.iter().any(|p| p.disturbed == Some(true)), "a disturbed paired result");
    // The Phase C families: a decode winner on the tensor-core GEMV with
    // split-K (S = 3), and a tier 5 TMA winner.
    let impl_of = |b: &str| w.iter().find(|x| x.shape_bucket == b).unwrap().kernel.impl_.clone();
    assert_eq!(impl_of("1x896x4864"), "gemv_tc_16x64x64_1x4_s5_k3");
    assert_eq!(impl_of("2048x2048x2048"), "mma_tma_128x128x32_2x4_s3");
    // Nightly regression sweeps (runs without paired tests): two clean, one
    // disturbed by the in-run watch.
    for (run, disturbed) in [("b34425e97d6d", Some(false)), ("eb5bcee294d4", Some(false)), ("d1504a45376d", Some(true))] {
        assert_eq!(runs.iter().find(|r| r.run_id == run).unwrap().disturbed, disturbed, "{run}");
    }
    // The stored cuBLASLt algorithm (schema v4 lt_algo), as Core renders it:
    // 4096^3 (mma_tma) dispatches to cuBLASLt algo 67 (tile 412, stages 35, custom 31).
    let (header, n) = aegis_perf::tune::header_text(&con, 121, "fixture").unwrap();
    assert_eq!(n, 14);
    assert!(header.contains("{4096, 4096, 4096, \"mma_tma_128x256x32_2x4_s4\", aegis::detail::Dispatch::Cublaslt, 73.3, 0.7337, 0.7428, {67, 412, 35, 1, 0, 0, 31, 0, 0}}"));
}

#[test]
fn devices_lists_the_spark_with_manifest() {
    let s = src();
    let con = s.open().unwrap();
    let d = custos_perf::devices(&s, &con).unwrap();
    assert_eq!(d.len(), 1);
    let spark = &d[0];
    assert_eq!((spark.device_id.as_str(), spark.sm_arch), ("gb10-0", 121));
    assert_eq!(spark.gpu_name.as_deref(), Some("NVIDIA GB10"));
    assert_eq!(spark.runs, 40);
    let m = spark.manifest.as_ref().expect("manifest-gb10-0.json");
    assert_eq!((m.sm_count, m.l2_bytes, m.integrated), (Some(48), Some(25165824), Some(true)));
    assert_eq!(m.global_mem_bytes, Some(130663591936));
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
    assert_eq!((copy.source.status, copy.source.replaced_rows), ("valid", 0));
    assert!(close(a.read_bw.as_ref().unwrap().gbps, 257.841));
    let mma = a.mma_peak.as_ref().unwrap();
    assert!(close(mma.tflops, 125.597));
    assert_eq!(mma.source.run_id, "eb3e197afc8e");
    // Latency (arch schema 3): cycles stored, ns derived through aegis-perf at
    // the reference clock, which was not locked.
    let l2 = a.l2_latency.as_ref().unwrap();
    assert!(close(l2.cycles, 335.437));
    assert!(close(l2.ref_clock_mhz, 2406.78));
    assert!(!l2.clocks_locked);
    assert!(close(l2.ns_at_ref, 335.437 / 2406.78 * 1e3));
    assert_eq!(l2.runs.len(), 1);
    let run = &l2.runs[0];
    assert_eq!(run.source.run_id, "a825f4e557a3");
    assert_eq!(run.sm_clock_mhz, Some(2406.78));
    assert_eq!(run.clocks_locked, None, "the run did not record its clock lock state");
    assert!(close(run.ns.unwrap(), 335.437 / 2406.78 * 1e3));
    assert_eq!(run.source.status, "valid");
    let dram = a.dram_latency.as_ref().unwrap();
    assert!(close(dram.cycles, 956.6305) && close(dram.ns_at_ref, 956.6305 / 2406.78 * 1e3));
    assert!(close(a.roofs.copy_bw_gbps, 236.696) && close(a.roofs.peak_tflops, 125.597));
    // Rule 7: valid rows feed the model; replaced rows are history; the 108
    // invalidated ptr_chase rows (e3d94274b31d) are never returned.
    let dram = a.probes.iter().find(|p| p.probe == "dram_bandwidth").unwrap();
    assert_eq!((dram.rows, dram.replaced_rows), (12, 6));
    let ptr = a.probes.iter().find(|p| p.probe == "ptr_chase_latency").unwrap();
    assert_eq!((ptr.rows, ptr.replaced_rows), (144, 468));
    assert!(!ptr.runs.contains(&"e3d94274b31d".to_string()));
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

    // 1x896x4864: runner-up CI [0.99968, 1.00222] contains 1.0 -> tied;
    // against cublaslt_best the CI [1.05417, 1.05927] lies above 1: faster.
    let t = get("1x896x4864");
    assert!(t.tie.tied && t.tie.ci.as_ref().unwrap().contains_one);
    assert_eq!(t.tie.method.as_deref(), Some("paired"));
    assert_eq!(t.tie.contender.as_deref(), Some("gemv_tc_16x64x32_1x4_s6_k4"));
    assert_eq!(t.vs_cublaslt_best.verdict, Some("faster"));
    assert!(close(t.vs_cublaslt_best.ci.as_ref().unwrap().lo, 1.05417));
    assert!(t.decode);
    assert_eq!(t.roof.as_ref().unwrap().roof, "read");
    // 16x4864x896 was tied under mma_pipe; the gemv_tc winner is a clear
    // win over its runner-up (CI [1.00113, 1.00348]).
    assert!(!get("16x4864x896").tie.tied);

    // 256^3: runner-up CI [1.02543, 1.02718] -> a clear win over the
    // runner-up; against cublaslt_best the paired CI [0.88687, 0.88967]:
    // slower (unpaired medians: 88.66%).
    let c = get("256x256x256");
    assert!(!c.tie.tied);
    assert_eq!(c.impl_, "mma_pipe_64x64x32_2x2_s4");
    assert_eq!(c.run_id, "7e94c009266f");
    assert_eq!(c.tie.contender.as_deref(), Some("mma_pipe_64x64x32_2x2_s3"));
    assert!((c.tie.runner_up_gap_pct.unwrap() - 2.697).abs() < 1e-9);
    let lt = &c.vs_cublaslt_best;
    assert_eq!(lt.verdict, Some("slower"));
    assert!(close(lt.ci.as_ref().unwrap().lo, 0.88687));
    assert!((lt.pct_of_cublaslt_best.unwrap() - 88.6629).abs() < 1e-3);
    assert_eq!(c.roof.as_ref().unwrap().roof, "copy");
    assert!(!c.decode);
    assert_eq!(c.regs, Some(74));

    // A tie the tie-break settled: 512x896x4864 picks the s3 config over the
    // s4 runner-up (CI [0.99928, 1.00408], fewer registers).
    let t = get("512x896x4864");
    assert!(t.tie.tied);
    assert_eq!(t.impl_, "mma_pipe_64x64x32_2x2_s3");
    assert_eq!(t.tie.contender.as_deref(), Some("mma_pipe_64x64x32_2x2_s4"));
    // 4096^3: the mma_tma winner, a clear win over the old mma_pipe tie.
    let big = get("4096x4096x4096");
    assert!(!big.tie.tied);
    assert_eq!(big.impl_, "mma_tma_128x256x32_2x4_s4");
    assert_eq!(big.config["load"], "tma");
}

#[test]
fn measurements_default_to_v2_cold_clean() {
    let s = src();
    let con = s.open().unwrap();
    let rows = custos_perf::measurements(&s, &con, &Filter::default()).unwrap();
    // The clean runs' cold rows: tunes 7e94c009266f and 41cc8ffb03fd (378
    // each), 9fd0eab14f18 (81), 2d261d8defab (72), c2b937d8adca (516); the
    // nightlies b34425e97d6d and eb5bcee294d4 (84 each). The disturbed runs'
    // (60959720261a, nightly d1504a45376d) are excluded.
    assert_eq!(rows.len(), 378 + 378 + 81 + 72 + 516 + 84 + 84);
    assert!(rows.iter().all(|r| r.protocol_version == 2 && r.cache_mode.as_deref() == Some("cold") && !r.allow_busy));
    assert!(rows.iter().all(|r| r.run_id != "60959720261a" && r.run_id != "d1504a45376d"));
    assert!(rows.iter().all(|r| !r.history && r.roof.is_some()));

    let busy = custos_perf::measurements(&s, &con, &Filter { include_busy: true, ..Default::default() }).unwrap();
    assert_eq!(busy.len(), 1593 + 81 + 84, "on request, the disturbed runs' rows too");

    let v1 = custos_perf::measurements(&s, &con, &Filter { protocol: Some(1), ..Default::default() }).unwrap();
    assert_eq!(v1.len(), 9);
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
    // mma_pipe_64x64x32_2x2_s4: winner of 3 shapes, never profiled.
    let k = custos_perf::kernel_detail(&s, &con, "be0c6688d651513b").unwrap().unwrap();
    assert_eq!(k.impl_, "mma_pipe_64x64x32_2x2_s4");
    assert_eq!(k.winner_of.len(), 3);
    assert_eq!((k.regs, k.smem_bytes, k.local_bytes), (Some(74), Some(32768), Some(0)));
    assert!(!k.measurements.is_empty());
    assert!(k.nsight_reports.is_empty(), "not profiled");

    assert!(custos_perf::kernel_detail(&s, &con, "nope").unwrap().is_none());
}

/// Point for point against the golden `aegis-perf roofline --arch 121` listing
/// of the pinned tag, run on the same fixture DB (tests/fixtures/golden/).
#[test]
fn roofline_matches_the_golden_listing() {
    let s = src();
    let con = s.open().unwrap();
    let r = custos_perf::roofline(&s, &con, 121).unwrap().unwrap();
    let listing = include_str!("../../tests/fixtures/golden/roofline-121.txt");
    let mut expected: Vec<(String, String, String, String, String)> = listing
        .lines()
        .filter(|l| l.contains(" AI "))
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

    assert_eq!(r.points.iter().filter(|p| p.series == "winner").count(), 14);
    assert!(r.points.iter().all(|p| p.hover.config.is_some() && p.hover.vs_cublaslt_best.is_some()));
    assert!(r.points.iter().filter(|p| p.m <= 16).all(|p| p.roof.roof == "read"));
    assert!(r.points.iter().filter(|p| p.m > 16).all(|p| p.roof.roof == "copy"));
    assert!((r.roofs.ridge_copy - 530.6).abs() < 0.1);
}

#[test]
fn compare_flags_build_over_build() {
    let s = src();
    let con = s.open().unwrap();
    // The two tune runs: 7fe7a84 (41cc8ffb03fd) and 9157a34 (9fd0eab14f18).
    let c = custos_perf::compare(&con, "7fe7a84", "9157a34", &Filter::default()).unwrap();
    assert!(!c.rows.is_empty());
    assert_eq!(c.confirmed_slower + c.unconfirmed_slower + c.faster + c.within, c.rows.len());
    for r in &c.rows {
        assert!(close(r.ratio, r.b.median_us / r.a.median_us));
        let expect = if r.change_pct > 3.0 { "slower" } else if r.change_pct < -3.0 { "faster" } else { "within" };
        assert_eq!(r.flag, expect);
        assert_ne!(r.b.run_id, "60959720261a", "disturbed rows are never compared");
    }

    // A protocol v1 build against a v2 build: nothing comparable.
    let x = custos_perf::compare(&con, "1af1bc7", "9157a34", &Filter::default()).unwrap();
    assert!(x.rows.is_empty());
    assert_eq!(x.excluded_a, 9);
    assert!(x.not_comparable.iter().all(|n| n.only_in == "b"));
}

/// The dispatch Custos shows is what the pinned tag's own winners header
/// records for these winners (tests/fixtures/winners/sm_121.h, parsed by
/// aegis-perf's regress::header_dispatch), for every shape.
#[test]
fn dispatch_matches_the_tags_header() {
    let s = src();
    let con = s.open().unwrap();
    let w = custos_perf::winners(&s, &con, 121).unwrap();
    let header = include_str!("../../tests/fixtures/winners/sm_121.h");
    let rows = aegis_perf::regress::header_dispatch(header);
    assert_eq!(rows.len(), 14);
    for ((m, n, k), target) in &rows {
        let bucket = format!("{m}x{n}x{k}");
        let got = w.iter().find(|x| x.shape_bucket == bucket).unwrap_or_else(|| panic!("{bucket}"));
        assert_eq!(got.dispatch.target, target, "{bucket}");
    }
    let impls = aegis_perf::regress::header_winners(header);
    for (m, n, k, impl_) in &impls {
        let got = w.iter().find(|x| (x.m, x.n, x.k) == (*m, *n, *k)).unwrap();
        assert_eq!(&got.impl_, impl_);
    }
}

/// Roofline hover: the shape's config, % of cublaslt_best with the paired CI,
/// and the dispatch target, on both points of the shape.
#[test]
fn roofline_hover_carries_dispatch() {
    let s = src();
    let con = s.open().unwrap();
    let r = custos_perf::roofline(&s, &con, 121).unwrap().unwrap();
    let big: Vec<_> = r.points.iter().filter(|p| p.shape_bucket == "4096x4096x4096").collect();
    assert_eq!(big.len(), 2);
    for p in &big {
        let d = p.hover.dispatch.as_ref().unwrap();
        assert_eq!((d.target, d.pct_of_cublaslt_best, d.basis), ("cublaslt", None, "paired"));
        assert_eq!(p.hover.config.as_ref().unwrap()["BM"], 128);
        let lt = p.hover.vs_cublaslt_best.as_ref().unwrap();
        assert!(close(lt.ci.as_ref().unwrap().hi, 0.74275));
    }
    // A decode shape on the read roof, dispatched to the kernel.
    let dec = r.points.iter().find(|p| p.label == "1x4864x896 gemv_tc_16x128x64_1x4_s4_k1").unwrap();
    assert_eq!(dec.roof.roof, "read");
    assert_eq!(dec.hover.dispatch.as_ref().unwrap().target, "aegis");
}

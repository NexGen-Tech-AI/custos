//! Device view acceptance: every value of the measured hardware model equals
//! tests/fixtures/sm_121.json (the pinned tag's arch file) exactly, with ns
//! derived through aegis-perf, and each value linked to the run(s) the arch
//! file cites.
use aegis_perf::params;
use custos_perf::Sources;
use serde_json::Value;

fn arch_json() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/sm_121.json")).unwrap()
}

fn f(v: &Value) -> f64 {
    v.as_f64().unwrap_or_else(|| panic!("not a number: {v}"))
}

fn opt_f(v: &Value) -> Option<f64> {
    v.as_f64()
}

fn opt_s(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

#[test]
fn hardware_model_equals_the_arch_file() {
    let s = Sources::repo_fixtures();
    let con = s.open().unwrap();
    let a = custos_perf::arch_model(&s, &con, 121).unwrap().unwrap();
    let j = arch_json();

    assert_eq!(a.sm, j["sm_arch"].as_i64().unwrap());
    assert_eq!(a.sm_count, j["sm_count"].as_i64());
    assert_eq!(a.l2_bytes, j["l2_bytes"].as_i64());
    assert_eq!(a.device, opt_s(&j["device"]));
    assert_eq!(a.generated_by, opt_s(&j["generated_by"]));
    assert_eq!(a.roof_rule, opt_s(&j["roof_rule"]));

    // Bandwidths: value, reps, method, and the source run, probe and stream.
    for (got, key) in [(&a.copy_bw, "copy_bw_gbps"), (&a.read_bw, "read_bw_gbps")] {
        let got = got.as_ref().unwrap_or_else(|| panic!("{key}"));
        let e = &j[key];
        assert_eq!(got.gbps, f(&e["value"]), "{key}");
        let reps: Vec<f64> = e["reps"].as_array().unwrap().iter().map(f).collect();
        assert_eq!(got.reps, reps, "{key}");
        assert_eq!(got.method, opt_s(&e["method"]), "{key}");
        assert_eq!(got.source.run_id, e["source"]["run_id"].as_str().unwrap(), "{key}");
        assert_eq!(got.source.probe, e["source"]["probe"].as_str().unwrap(), "{key}");
        assert_eq!(got.source.detail, opt_s(&e["source"]["stream"]), "{key}");
    }
    // The roofs the views use are the same numbers.
    assert_eq!(a.roofs.copy_bw_gbps, f(&j["copy_bw_gbps"]["value"]));
    assert_eq!(a.roofs.read_bw_gbps, f(&j["read_bw_gbps"]["value"]));
    assert_eq!(a.roofs.peak_tflops, f(&j["mma_peak"]["tflops"]));

    let mma = a.mma_peak.as_ref().unwrap();
    let e = &j["mma_peak"];
    assert_eq!(mma.tflops, f(&e["tflops"]));
    assert_eq!(mma.hmma_per_clk_per_sm, opt_f(&e["hmma_per_clk_per_sm"]));
    assert_eq!(mma.instruction, opt_s(&e["instruction"]));
    assert_eq!(mma.at, e["at"]);
    assert_eq!(mma.source.run_id, e["source"]["run_id"].as_str().unwrap());
    assert_eq!(mma.source.probe, e["source"]["probe"].as_str().unwrap());

    // Latencies: cycles and clocks as stored; ns derived by aegis-perf.
    for (got, key) in [(&a.l2_latency, "l2_latency"), (&a.dram_latency, "dram_latency")] {
        let got = got.as_ref().unwrap_or_else(|| panic!("{key}"));
        let e = &j[key];
        assert_eq!(got.cycles, f(&e["cycles"]), "{key}");
        assert_eq!(got.cycles_min, opt_f(&e["cycles_min"]), "{key}");
        assert_eq!(got.cycles_max, opt_f(&e["cycles_max"]), "{key}");
        assert_eq!(got.ref_clock_mhz, f(&e["ref_clock_mhz"]), "{key}");
        assert_eq!(got.ref_clock_rule, opt_s(&e["ref_clock_rule"]), "{key}");
        assert_eq!(got.clocks_locked, e["clocks_locked"].as_bool().unwrap(), "{key}");
        assert_eq!(got.clock_spread_pct, opt_f(&e["clock_spread_pct"]), "{key}");
        assert_eq!(got.combine, opt_s(&e["combine"]), "{key}");
        assert_eq!(got.points, e["points"].as_i64(), "{key}");
        assert_eq!(got.working_sets, opt_s(&e["working_sets"]), "{key}");
        assert_eq!(got.method, opt_s(&e["method"]), "{key}");
        let typed = params::Latency {
            cycles: f(&e["cycles"]),
            ref_clock_mhz: f(&e["ref_clock_mhz"]),
            clocks_locked: e["clocks_locked"].as_bool().unwrap(),
        };
        assert_eq!(got.ns_at_ref, typed.ns(), "{key}: ns derived through aegis-perf");
        let runs = e["runs"].as_array().unwrap();
        assert_eq!(got.runs.len(), runs.len(), "{key}");
        for (g, r) in got.runs.iter().zip(runs) {
            assert_eq!(g.source.run_id, r["run_id"].as_str().unwrap(), "{key}");
            assert_eq!(g.source.probe, e["probe"].as_str().unwrap(), "{key}");
            assert_eq!(g.source.detail, opt_s(&r["layout"]), "{key}");
            assert_eq!(g.sm_clock_mhz, opt_f(&r["sm_clock_mhz"]), "{key}");
            assert_eq!(g.cycles, opt_f(&r["cycles"]), "{key}");
            assert_eq!(g.points, r["points"].as_i64(), "{key}");
            assert_eq!(g.clocks_locked, r["clocks_locked"].as_bool(), "{key}");
            assert_eq!(g.clock_lock, opt_s(&r["clock_lock"]), "{key}");
            let at_run = params::Latency { cycles: f(&r["cycles"]), ref_clock_mhz: f(&r["sm_clock_mhz"]), clocks_locked: false };
            assert_eq!(g.ns, Some(at_run.ns()), "{key}");
        }
    }

    // Power controls: the arch file has none, and no source run recorded a
    // power mode: not measured, never a default.
    assert_eq!(a.power, j.get("power").cloned());
    assert!(a.power.is_none());
    assert!(a.copy_bw.as_ref().unwrap().source.power_mode.is_none());
}

/// Values not in the arch file come from the DB or the manifest, each with
/// its source; replaced runs of each probe are history.
#[test]
fn memory_toolchain_and_history() {
    let s = Sources::repo_fixtures();
    let con = s.open().unwrap();
    let a = custos_perf::arch_model(&s, &con, 121).unwrap().unwrap();
    let manifest: Value = serde_json::from_str(include_str!("../../tests/fixtures/manifest-spark-5822.json")).unwrap();
    assert_eq!(a.global_mem_bytes, manifest["global_mem_bytes"].as_i64());
    assert!(a.manifest.as_deref().unwrap().ends_with("tests/fixtures/manifest-spark-5822.json"));

    // Toolchain of the source run (runs table).
    let src = &a.copy_bw.as_ref().unwrap().source;
    assert_eq!((src.cuda_ver, src.driver_ver, src.git_sha.as_deref()), (Some(13000), Some(13000), Some("3b46bf9")));
    assert_eq!(src.status, "valid");

    // History: the runs each probe's rows were replaced in, oldest first.
    let copy = &a.copy_bw.as_ref().unwrap().history;
    assert_eq!(copy.len(), 1);
    assert_eq!((copy[0].run_id.as_str(), copy[0].replaced_rows), ("d601cda25a28", 6));
    assert_eq!(copy[0].replaced_by, ["941ff9215564"]);
    let l2: Vec<&str> = a.l2_latency.as_ref().unwrap().history.iter().map(|h| h.run_id.as_str()).collect();
    assert_eq!(l2, ["55945fd9cbef", "fb77bc085d64", "6141123bbcc4", "f1925d6a0fa4"]);
    // Invalidated rows (e3d94274b31d, 108 ptr_chase rows) are not history: hidden.
    assert!(!l2.contains(&"e3d94274b31d"));
    assert_eq!(a.mma_peak.as_ref().unwrap().history.len(), 2);
}

//! Kernel detail on the committed fixtures: the DB's config, registers,
//! spills and shared memory; the SASS listing of the measured (row-major)
//! instantiation, found by its symbol; the instruction mix counted in it as
//! tools/sass_dump.sh counts; ptxas resource usage; Nsight: not profiled.
use custos_perf::kernel::SassOrigin;
use custos_perf::Sources;

fn src() -> Sources {
    Sources::repo_fixtures()
}

#[test]
fn winner_kernel_with_sass_and_instruction_mix() {
    let s = src();
    let con = s.open().unwrap();
    let k = custos_perf::kernel_detail(&s, &con, "be0c6688d651513b").unwrap().unwrap();
    assert_eq!(k.impl_, "mma_pipe_64x64x32_2x2_s4");
    assert_eq!(k.config["STAGES"], 4);
    assert_eq!(k.config["smem"], "xor");
    assert_eq!((k.regs, k.smem_bytes, k.local_bytes), (Some(74), Some(32768), Some(0)), "no spills");
    assert_eq!(k.winner_of.len(), 3);
    let a = &k.artifacts[0];
    assert_eq!(a.sm, 121);
    let sass = a.sass.as_ref().expect("SASS listing in tests/fixtures/sass/sm_121");
    assert!(sass.path.ends_with("tests/fixtures/sass/sm_121/mma_pipe_64x64x32_2x2_s4.sass"));
    assert!(sass.symbol.contains("TileILi64ELi64ELi32ELi2ELi2ELNS0_6LayoutE0ELS5_0EEELi4EE"), "row-major A and B");
    assert_eq!(sass.lines, 13864);
    assert!(a.sass_note.is_none());
    // Compiled by Custos from the tag, not Core's dump (tests/fixtures/README.md).
    assert_eq!(
        sass.origin,
        SassOrigin::CompiledFromTag { tag: "aegis-perf-v0.3.0".into(), source: Some("src/gemm/mma_pipe.cu".into()), note: None }
    );
    // `grep -cE '\bOP'` on the same file: HMMA 48, LDSM 24, LDGSTS 64, LDG. 558, STS 62.
    let mix = a.instruction_mix.as_ref().unwrap();
    assert_eq!((mix["HMMA"], mix["LDSM"], mix["LDGSTS"], mix["LDG"], mix["STS"]), (48, 24, 64, 558, 62));
    let ru = a.resource_usage.as_ref().unwrap();
    assert_eq!(ru.regs, k.regs, "ptxas registers equal the perf DB's");
    assert_eq!((ru.local, ru.stack), (Some(0), Some(0)));
    assert!(k.nsight_reports.is_empty() && k.nsight_stalls.is_none(), "not profiled");

    let k2 = custos_perf::kernel_detail(&s, &con, "3a1de4a04af5d621").unwrap().unwrap();
    let a2 = &k2.artifacts[0];
    let mix = a2.instruction_mix.as_ref().unwrap();
    assert_eq!((mix["HMMA"], mix["LDSM"], mix["LDGSTS"], mix["LDG"], mix["STS"]), (96, 36, 48, 782, 50));
    assert_eq!(a2.resource_usage.as_ref().unwrap().regs, Some(126));
}

#[test]
fn missing_and_other_instantiations_show_nothing() {
    let s = src();
    let con = s.open().unwrap();
    // A measured kernel without a listing in the fixtures.
    let k = custos_perf::kernel_detail(&s, &con, "0f6ca70d05db3fa0").unwrap().unwrap();
    assert_eq!(k.impl_, "mma_pipe_64x128x32_2x4_s4");
    let a = &k.artifacts[0];
    assert!(a.sass.is_none() && a.instruction_mix.is_none());
    assert_eq!(a.sass_note.as_deref(), Some("no SASS listing of the row-major instantiation in the dump"));

    // A column-major listing of the same config (what Core's truncated dump
    // keeps) is never shown as the measured kernel.
    let dir = std::env::temp_dir().join(format!("custos-sass-{}", std::process::id()));
    let sm = dir.join("sm_121");
    std::fs::create_dir_all(&sm).unwrap();
    let text = std::fs::read_to_string(s.sass_dir.join("sm_121/mma_pipe_64x64x32_2x2_s4.sass")).unwrap();
    std::fs::write(sm.join("truncated_name.sass"), text.replace("LayoutE0ELS5_0", "LayoutE1ELS5_1")).unwrap();
    let mut colmajor = src();
    colmajor.sass_dir = dir.clone();
    let k = custos_perf::kernel_detail(&colmajor, &con, "be0c6688d651513b").unwrap().unwrap();
    assert!(k.artifacts[0].sass.is_none());
    std::fs::remove_dir_all(&dir).ok();

    // cuBLASLt: no registers Core can read, no AEGIS SASS.
    let lt = custos_perf::kernel_detail(&s, &con, "11c8a1f7cc9d4d83").unwrap().unwrap();
    assert!(lt.baseline && lt.regs.is_none());
    assert!(lt.artifacts.iter().all(|a| a.sass.is_none() && a.instruction_mix.is_none()));
    assert_eq!(lt.artifacts[0].sass_note.as_deref(), Some("a cuBLAS baseline: no AEGIS SASS"));
}

/// A SASS directory without an ORIGIN file is Core's own dump.
#[test]
fn core_dump_listing_is_a_core_artifact() {
    let s = src();
    let con = s.open().unwrap();
    let dir = std::env::temp_dir().join(format!("custos-sass-core-{}", std::process::id()));
    let sm = dir.join("sm_121");
    std::fs::create_dir_all(&sm).unwrap();
    std::fs::copy(s.sass_dir.join("sm_121/mma_pipe_64x64x32_2x2_s4.sass"), sm.join("mma_pipe_64x64x32_2x2_s4.sass")).unwrap();
    let mut core = src();
    core.sass_dir = dir.clone();
    let k = custos_perf::kernel_detail(&core, &con, "be0c6688d651513b").unwrap().unwrap();
    assert_eq!(k.artifacts[0].sass.as_ref().unwrap().origin, SassOrigin::CoreArtifact);
    std::fs::remove_dir_all(dir).ok();
}

/// The Phase C families, compiled from tag aegis-perf-v0.5.0 (sass_dump.sh
/// still truncates names, core-requests #6), each found by its row-major
/// symbol, with the provenance ORIGIN records for that file.
#[test]
fn gemv_tc_and_mma_tma_listings_from_the_tag() {
    let s = src();
    let con = s.open().unwrap();
    // gemv_tc_16x64x64_1x4_s4_k1: the decode winner at 1x896x896, 16x896x896, 16x4864x896.
    let k = custos_perf::kernel_detail(&s, &con, "9bbc014a0c4cfd97").unwrap().unwrap();
    assert_eq!(k.impl_, "gemv_tc_16x64x64_1x4_s4_k1");
    assert_eq!(k.winner_of, ["sm_121 1x896x896", "sm_121 16x896x896", "sm_121 16x4864x896"]);
    let a = &k.artifacts[0];
    let sass = a.sass.as_ref().unwrap();
    assert!(sass.path.ends_with("tests/fixtures/sass/sm_121/gemv_tc_16x64x64_1x4_s4_k1.sass"));
    assert!(sass.symbol.contains("DecTileILi64ELi64ELi4ELNS0_6LayoutE0ELS4_0EEELi4EE"));
    assert_eq!(sass.lines, 7304);
    let SassOrigin::CompiledFromTag { tag, source, note } = &sass.origin else { panic!("{:?}", sass.origin) };
    assert_eq!((tag.as_str(), source.as_deref()), ("aegis-perf-v0.5.0", Some("src/gemm/gemv_tc.cu")));
    assert!(note.as_deref().unwrap().contains("build 1084490 (REG 72"));
    // The tag's kernel is not the tuned build: ptxas 70 registers, the perf DB 72.
    assert_eq!((a.resource_usage.as_ref().unwrap().regs, k.regs), (Some(70), Some(72)));
    let mix = a.instruction_mix.as_ref().unwrap();
    assert_eq!((mix["HMMA"], mix["LDSM"], mix["LDGSTS"], mix["LDG"], mix["STS"]), (24, 24, 72, 361, 69));

    // mma_tma_128x256x32_2x4_s4: the 4096^3 winner (dispatched to cuBLASLt).
    let k = custos_perf::kernel_detail(&s, &con, "03869dd12bf12c08").unwrap().unwrap();
    let a = &k.artifacts[0];
    let sass = a.sass.as_ref().unwrap();
    assert!(sass.symbol.contains("gemm_mma_tma_kernelINS1_7TmaTileILi128ELi256ELi32ELi2ELi4ELNS0_6LayoutE0ELS4_0EEELi4EE"));
    assert_eq!(sass.origin, SassOrigin::CompiledFromTag { tag: "aegis-perf-v0.5.0".into(), source: Some("src/gemm/mma_tma.cu".into()), note: None });
    assert_eq!((a.resource_usage.as_ref().unwrap().regs, k.regs), (Some(166), Some(166)));
    let mix = a.instruction_mix.as_ref().unwrap();
    assert_eq!((mix["HMMA"], mix["LDSM"], mix["LDGSTS"], mix["LDG"], mix["STS"]), (64, 16, 0, 768, 0), "TMA: no LDGSTS");
}

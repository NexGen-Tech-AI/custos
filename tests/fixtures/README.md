# Test fixtures

Everything Custos's tests read. No test reads from `~`, from Core's working
tree or from the live perf DB.

Pinned Core: tag **`aegis-perf-v0.5.0`** = aegis-core commit
**`9f3f41cc9a8545a52a191f1f9af1a8d75bf59042`** (perf DB schema v4; the
aegis-perf library is unchanged from v0.4.0).

| File | What | Source |
|---|---|---|
| `aegis_perf.db` | trimmed perf DB, schema v4 (committed) | `make_fixture.sh` from `aegis_perf_full.db` |
| `sm_121.json` | arch file (aegis-arch-params/3) | the tag: `include/aegis/arch/sm_121.json` (unchanged since v0.3.0) |
| `winners/sm_121.h` | winners header, with the dispatch column and each shape's stored cuBLASLt algorithm | the tag: `include/aegis/winners/sm_121.h` |
| `winners/9157a34/sm_121.h` | the winners header the 9157a34 nightlies ran (the regression check's shape and impl list) | tag `aegis-perf-v0.3.0` (= 9157a34): `include/aegis/winners/sm_121.h` |
| `golden/report-121.txt` | `aegis-perf report --arch 121` (report and roof tables) | v0.5.0 CLI on the trimmed fixture (`make_golden.sh`) |
| `golden/roofline-121.txt`, `golden/roofline-sm121.svg` | `aegis-perf roofline --arch 121` (stdout point list, SVG) | same |
| `golden/emit-header-sm_121.h` | `aegis-perf emit-header --arch 121` | same |
| `golden/regress-<run>.txt` | `aegis-perf regress --run <run> --header winners/9157a34/sm_121.h`, per nightly | same |
| `sass/sm_121/*.sass` | SASS of four winner kernels (mma_pipe x2, gemv_tc, mma_tma) | compiled by Custos from tags v0.3.0 and v0.5.0, not Core's dump (below) |
| `sass/sm_121/ORIGIN` | where those listings come from | written with them (below) |
| `docs/LOG.md`, `docs/analysis/gemm-large.md` | Core's run log and analysis, which Custos cites (stated diagnoses, the win chain's sources) | the tag: `docs/` (`git show aegis-perf-v0.5.0:docs/...`) |
| `nightly/fuzz-<stamp>.txt` | the nightly fuzz output, 2026-10-14 to 10-17 (case 24632 failed on 10-14) | Core `results/nightly/` (not in git), copied as is |
| `manifest-spark-5822.json` | `aegis_manifest` output (SM count, memory, toolchain) | Core `results/` (not in git); byte-identical to the 2026-10-14 copy |
| `aegis_perf_full.db` | full snapshot (gitignored) | `sqlite3 .backup` |

## The perf DB

Always `sqlite3 SRC ".backup DST"`, never `cp` (a consistent snapshot even
while Core writes).

```sh
# Last refreshed 2026-10-18 14:59 local: the live DB, schema v4, 40 runs
# (newest c2b937d8adca, 2026-10-18 04:02 UTC), 44 paired results.
sqlite3 ~/Documents/projects/aegis/results/aegis_perf.db ".backup tests/fixtures/aegis_perf_full.db"
tests/fixtures/make_fixture.sh            # -> tests/fixtures/aegis_perf.db
```

`make_fixture.sh` keeps every run, winner, paired tie test, microbench row and
paired result, and only the measurements of ten runs:

| run | build | why |
|---|---|---|
| `7e94c009266f` | eccf61f | tune run behind the 7 non-decode `mma_pipe` winners; its cublaslt_best rows carry `lt_algo` |
| `2d261d8defab` | 7e433cf | tune run behind the tier 5 `mma_tma` winners (2048³, 4096³) |
| `c2b937d8adca` | 1084490 | decode tune behind the 6 `gemv_tc` winners (split-K S = 1 and 3) |
| `41cc8ffb03fd` | 7fe7a84 | tune run; build A of the compare() pair; what the first nightly is checked against |
| `9fd0eab14f18` | 9157a34 | tune run; build B of the compare() pair |
| `b34425e97d6d` | 9157a34 | nightly regression sweep (2026-10-16): a watch, 16x4864x896 99.4 -> 96.1% |
| `eb5bcee294d4` | 9157a34 | nightly regression sweep (2026-10-17): a watch, 1x4864x896 98.1 -> 94.0% |
| `d1504a45376d` | 9157a34 | nightly regression sweep (2026-10-15), disturbed (in-run watch: every row `disturbed = 1`) |
| `60959720261a` | 9157a34 | tune run, disturbed (in-run watch, worst window 30%) |
| `624671c030a1` | 1af1bc7 | protocol v1 run (history) |

What the fixture covers (asserted in `custos-perf/tests/fixture_db.rs` and
`winners_view.rs`):
- decode shapes (M = 1, 16) on the read roof, all six won by the
  tensor-core GEMV (`gemv_tc_*`), two with split-K S = 3
  (`gemv_tc_16x64x64_1x4_s5_k3` at 1x896x4864 and 16x896x4864); non-decode
  shapes on the copy roof;
- tier 5 TMA rows: `mma_tma_128x128x32_2x4_s3` (2048³) and
  `mma_tma_128x256x32_2x4_s4` (4096³);
- statistical ties (1x896x4864, runner-up CI 0.99968-1.00222; 16x896x4864;
  512x896x4864, settled by the tie-break);
- the shapes the dispatch floor sends to cuBLASLt: 4096³ (paired CI
  0.7337-0.7428) and 512x4864x896 (0.7851-0.7903);
- the stored cuBLASLt algorithm for every winner shape (`winners.lt_algo`):
  4096³ runs algo 67, tile 412, stages 35, custom 31; 16x896x4864's
  baseline is a split-K algorithm (algo 21, split-K 3, reduction 2);
- the unpaired median outside its paired CI by more than 2 points:
  1x896x4864 (109.6% vs 105.4-105.9) and 512x4864x896 (82.2% vs 78.5-79.0);
- nightly sweeps: two watches (above) under `aegis_perf::regress` and one
  disturbed nightly. No confirmed regression exists in the live DB; the
  tests confirm one on a doctored copy (a paired-ab added through
  `aegis_perf::ab::store`);
- disturbed rows: two runs and their measurements, 7 paired results
  (ids 3, 5, 12, 14, 16, 17, 37), and the disturbed tune runs whose rows are
  not kept (d13561cb3d16 Firefox, 1903faa76c26 gnome-shell, 6a7ca188b753);
- valid, replaced and invalidated microbench rows; 44 paired results, every
  one from a `-dirty` build on at least one side (below);
- latency rows with SM clock data: 108 `ptr_chase_latency` rows of run
  `e3d94274b31d` (clocks locked at 2418 MHz, measured 2398.16 MHz), all
  invalidated ("Firefox started on the GPU mid-run"), plus its valid
  `sm_clock` row. The arch file cites `a825f4e557a3` for both latencies:
  valid rows without a per-row clock; the clock (2406.78 MHz, not locked) is
  in the arch file.

Paired results (`paired_results`, aegis-perf paired-ab), build by build. The
stored SHAs are 12 hex digits, runs.git_sha 7; "runs row" is whether a run of
that build exists (its first 7 digits match exactly one runs.git_sha):

| ids | sha_a | sha_b | runs row | what |
|---|---|---|---|---|
| 1-2 | b0bedd58fbf9 (clean) | b0bedd58fbf9-dirty | no | a build vs the same build with changes |
| 3-8 | 9157a34d24b5-dirty | same | yes | cublaslt_best vs aegis_matmul |
| 9-10 | bc353c572335-dirty | same | no | BK 32 vs 64 |
| 11-18 | eccf61f5188e-dirty | same | yes | cublaslt_best vs aegis_matmul |
| 19-25 | 7e433cf9285e-dirty | same | yes | mma_tma vs mma_pipe, cublaslt_best, aegis_matmul |
| 26-44 | 0bd0f22a35a6-dirty | same | no | the decode results: gemv_tc vs mma_pipe, cublaslt_best, aegis_matmul |

No clean-build paired result exists, so no decode win is reproducible from
the record yet: Custos shows them "win (unreproducible: dirty build)".

The nightly fuzz (50,000 cases a night) is not in the perf DB: Core writes it
to `results/nightly/fuzz-<stamp>.txt` (core-requests #10); `nightly/` holds the four
nights there were, and Custos reads case 24632's FP64 adjudication from `docs/LOG.md`.

## Golden outputs

```sh
git clone --branch aegis-perf-v0.5.0 https://github.com/Riffe007/aegis-core CORE
cargo build --release -p aegis-perf --manifest-path CORE/rust/Cargo.toml   # CPU only
tests/fixtures/make_golden.sh CORE
```

`report`, `roofline` and `regress` read only; `make_golden.sh` still runs them on a copy
because the CLI opens its DB read-write. The emit-header output has the same
rows as the tag's `winners/sm_121.h` (tested): the tag's header was generated
from the tune this fixture holds.

## SASS

**Provenance: every fixture listing was compiled by Custos from a Core tag,
not taken from Core's dump**, because of the `tools/sass_dump.sh` name
collision below (core-requests #6; `sass_dump.sh` is unchanged at
aegis-perf-v0.5.0). `sass/sm_121/ORIGIN` records it per file
(`compiled_from_tag=`, `source=`, and a `note=` on what differs from the
measured kernel); the Kernel view and the win chain read it and show
"compiled from tag". A SASS directory without that file (Core's
`artifacts/sass/`) is shown as "Core artifact".

| listing | tag | source | ptxas REG | perf DB regs |
|---|---|---|---|---|
| `mma_pipe_64x64x32_2x2_s4.sass` | aegis-perf-v0.3.0 | `src/gemm/mma_pipe.cu` | 74 | 74 |
| `mma_pipe_128x64x32_2x2_s2.sass` | aegis-perf-v0.3.0 | `src/gemm/mma_pipe.cu` | 126 | 126 |
| `gemv_tc_16x64x64_1x4_s4_k1.sass` | aegis-perf-v0.5.0 | `src/gemm/gemv_tc.cu` | **70** | **72** |
| `mma_tma_128x256x32_2x4_s4.sass` | aegis-perf-v0.5.0 | `src/gemm/mma_tma.cu` | 166 | 166 |

The gemv_tc listing is the tag's code, not the tuned build's: the decode tune
`c2b937d8adca` ran build 1084490, and Phase C step 3 (0bd0f22, in the tag)
changed the split-K reducer afterwards. Compiling `gemv_tc.cu` at 1084490
with the same flags gives REG 72, the perf DB's. ORIGIN's note says so, and
the Kernel view flags the register mismatch. (The step 4 paired-ab results
ran 0bd0f22-dirty, i.e. the tag's kernel.)

Core's `artifacts/sass/sm_121/` (gitignored, so not in the tag) has no usable
SASS for the measured kernels. The 2026-10-13 files predate the `xor` smem
layout, and in the 2026-10-17 dump `tools/sass_dump.sh` cuts names at 120
characters, so the row- and column-major instantiations of a config share a
file name. Each file keeps whichever was written last (the column-major one).
Compiled CPU only (no GPU), as tools/sass_dump.sh extracts listings:

```sh
cd CORE   # at the listing's tag
nvcc -cubin -arch=sm_121 -std=c++20 -O3 -DNDEBUG -lineinfo --expt-relaxed-constexpr \
     -Iinclude -Isrc src/gemm/mma_pipe.cu -o mma_pipe.cubin          # v0.3.0
nvcc ... src/gemm/gemv_tc.cu -o gemv_tc.cubin                        # v0.5.0
nvcc ... -DAEGIS_TMA=1 src/gemm/mma_tma.cu -o mma_tma.cubin          # v0.5.0 (CMake sets AEGIS_TMA)
cuobjdump -sass -fun <symbol> <file>.cubin > <impl>.sass
```

Symbols (`Layout 0, 0` = row-major A and B, what bench_gemm measures):

- `mma_pipe_64x64x32_2x2_s4`: `..gemm_mma_pipe_kernelINS0_10mma_detail4TileILi64ELi64ELi32ELi2ELi2ELNS0_6LayoutE0ELS5_0EEELi4EEEvNS0_7KParamsEbb`
  (from v0.5.0 the kernel lives in `mma_pipe_detail` and the back-reference is `S6_0`)
- `mma_pipe_128x64x32_2x2_s2`: `..TileILi128ELi64ELi32ELi2ELi2ELNS0_6LayoutE0ELS5_0EEELi2EEEvNS0_7KParamsEbb`
- `gemv_tc_16x64x64_1x4_s4_k1`: `..gemv_tc_kernelINS1_7DecTileILi64ELi64ELi4ELNS0_6LayoutE0ELS4_0EEELi4EEEvNS0_7KParamsENS1_6TcArgsEb`
  (split-K is a launch argument: `_k1` and `_kauto` of a tile share this kernel)
- `mma_tma_128x256x32_2x4_s4`: `..gemm_mma_tma_kernelINS1_7TmaTileILi128ELi256ELi32ELi2ELi4ELNS0_6LayoutE0ELS4_0EEELi4EEEv14CUtensorMap_stS6_NS0_7KParamsEb`

`sass/sm_121/resource-usage.txt` is `cuobjdump -res-usage` of the same
cubins, the four kernels' entries only, in Core's resource-usage format.

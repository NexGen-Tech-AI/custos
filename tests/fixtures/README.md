# Test fixtures

Everything Custos's tests read. No test reads from `~`, from Core's working
tree or from the live perf DB.

Pinned Core: tag **`aegis-perf-v0.4.0`** = aegis-core commit
**`7e433cf9285e839454bdc971efafb661f71939a0`** (perf DB schema v4).

| File | What | Source |
|---|---|---|
| `aegis_perf.db` | trimmed perf DB, schema v4 (committed) | `make_fixture.sh` from `aegis_perf_full.db` |
| `sm_121.json` | arch file (aegis-arch-params/3) | the tag: `include/aegis/arch/sm_121.json` (unchanged since v0.3.0) |
| `winners/sm_121.h` | winners header, with the dispatch column and each shape's stored cuBLASLt algorithm | the tag: `include/aegis/winners/sm_121.h` |
| `golden/report-121.txt` | `aegis-perf report --arch 121` (report and roof tables) | v0.4.0 CLI on the trimmed fixture (`make_golden.sh`) |
| `golden/roofline-121.txt`, `golden/roofline-sm121.svg` | `aegis-perf roofline --arch 121` (stdout point list, SVG) | same |
| `golden/emit-header-sm_121.h` | `aegis-perf emit-header --arch 121` | same |
| `sass/sm_121/mma_pipe_64x64x32_2x2_s4.sass`, `mma_pipe_128x64x32_2x2_s2.sass` | SASS of two winner kernels | compiled from the tag (below) |
| `manifest-spark-5822.json` | `aegis_manifest` output (SM count, memory, toolchain) | Core `results/` (not in git); byte-identical to the 2026-10-14 copy |
| `aegis_perf_full.db` | full snapshot (gitignored) | `sqlite3 .backup` |

## The perf DB

Always `sqlite3 SRC ".backup DST"`, never `cp` (a consistent snapshot even
while Core writes).

```sh
# Last refreshed 2026-10-17 16:47 local: the live DB, schema v4, 31 runs.
sqlite3 ~/Documents/projects/aegis/results/aegis_perf.db ".backup tests/fixtures/aegis_perf_full.db"
tests/fixtures/make_fixture.sh            # -> tests/fixtures/aegis_perf.db
```

`make_fixture.sh` keeps every run, winner, paired tie test, microbench row and
paired result, and only the measurements of five runs:

| run | build | why |
|---|---|---|
| `7e94c009266f` | eccf61f | tune run behind all 14 winners; its 28 cublaslt_best rows carry `lt_algo` |
| `41cc8ffb03fd` | 7fe7a84 | tune run; build A of the compare() pair |
| `9fd0eab14f18` | 9157a34 | tune run; build B of the compare() pair |
| `60959720261a` | 9157a34 | disturbed run (every row `disturbed = 1`) |
| `624671c030a1` | 1af1bc7 | protocol v1 run (history) |

What the fixture covers (asserted in `custos-perf/tests/fixture_db.rs`):
decode shapes (M = 1, 16) on the read roof and non-decode shapes on the copy
roof; statistical ties (16x4864x896, runner-up CI 0.992-1.002; 4096x4096x4096
and 512x896x4864); shapes the dispatch floor sends to cuBLASLt (4096x4096x4096,
1x896x4864, 16x896x4864, 512x4864x896); the stored cuBLASLt algorithm for
every winner shape (`winners.lt_algo`, e.g. 4096x4096x4096: algo 67, tile 412,
stages 35, custom 31); disturbed rows (a run, its measurements, 6 paired
results); valid, replaced and invalidated microbench rows; 18 paired results;
latency rows with SM clock data: 108 `ptr_chase_latency` rows of run
`e3d94274b31d` (clocks locked at 2418 MHz, measured 2398.16 MHz), all
invalidated ("Firefox started on the GPU mid-run"), plus its valid `sm_clock`
row. The arch file cites `a825f4e557a3` for both latencies: valid rows
without a per-row clock; the clock (2406.78 MHz, not locked) is in the arch
file.

## Golden outputs

```sh
git clone --branch aegis-perf-v0.4.0 https://github.com/Riffe007/aegis-core CORE
cargo build --release -p aegis-perf --manifest-path CORE/rust/Cargo.toml   # CPU only
tests/fixtures/make_golden.sh CORE
```

`report` and `roofline` read only; `make_golden.sh` still runs them on a copy
because the CLI opens its DB read-write. The emit-header output has the same
rows as the tag's `winners/sm_121.h` (tested): the tag's header was generated
from the tune this fixture holds.

## SASS

Core's `artifacts/sass/sm_121/` (gitignored, so not in the tag) has no usable
SASS for the measured kernels. The 2026-10-13 files predate the `xor` smem
layout, and in the 2026-10-17 dump `tools/sass_dump.sh` cuts names at 120
characters, so the row- and column-major instantiations of a config share a
file name. Each file keeps whichever was written last (the column-major one).
The two files here were compiled from aegis-perf-v0.3.0, CPU only;
`src/gemm/` and `include/aegis/gemm.h` are unchanged in v0.4.0:

```sh
cd CORE   # at aegis-perf-v0.3.0 (same kernel source as v0.4.0)
nvcc -cubin -arch=sm_121 -std=c++20 -O3 -DNDEBUG -lineinfo --expt-relaxed-constexpr \
     -Iinclude -Isrc src/gemm/mma_pipe.cu -o mma_pipe.cubin
cuobjdump -sass -fun <symbol> mma_pipe.cubin > <impl>.sass   # as tools/sass_dump.sh does
```

Symbols (`Layout 0, 0` = row-major A and B, what bench_gemm measures):

- `mma_pipe_64x64x32_2x2_s4`: `..gemm_mma_pipe_kernelINS0_10mma_detail4TileILi64ELi64ELi32ELi2ELi2ELNS0_6LayoutE0ELS5_0EEELi4EEEvNS0_7KParamsEbb`
- `mma_pipe_128x64x32_2x2_s2`: `..TileILi128ELi64ELi32ELi2ELi2ELNS0_6LayoutE0ELS5_0EEELi2EEEvNS0_7KParamsEbb`

`cuobjdump -res-usage` gives REG 74 and 126, the `regs` the perf DB records
for these kernels.

`sass/sm_121/resource-usage.txt` is `cuobjdump -res-usage mma_pipe.cubin` (the
same cubin), the two kernels' entries only, in Core's resource-usage format.

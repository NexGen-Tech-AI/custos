# Test fixtures

Everything Custos's tests read. No test reads from `~`, from Core's working
tree or from the live perf DB.

Pinned Core: tag **`aegis-perf-v0.3.0`** = aegis-core commit
**`9157a34d24b5368ef81f7d3add2b31f07de87301`** (perf DB schema v3).

| File | What | Source |
|---|---|---|
| `aegis_perf.db` | trimmed perf DB, schema v3 (committed) | `make_fixture.sh` from `aegis_perf_full_v3.db` |
| `sm_121.json` | arch file (aegis-arch-params/3) | the tag: `include/aegis/arch/sm_121.json` |
| `winners/sm_121.h` | winners header | the tag: `include/aegis/winners/sm_121.h` |
| `golden/report-121.txt` | `aegis-perf report --arch 121` (report and roof tables) | v0.3.0 CLI on the trimmed fixture (`make_golden.sh`) |
| `golden/roofline-121.txt`, `golden/roofline-sm121.svg` | `aegis-perf roofline --arch 121` (stdout point list, SVG) | same |
| `golden/emit-header-sm_121.h` | `aegis-perf emit-header --arch 121` | same |
| `sass/sm_121/mma_pipe_64x64x32_2x2_s4.sass`, `mma_pipe_128x64x32_2x2_s2.sass` | SASS of two winner kernels | compiled from the tag (below) |
| `manifest-spark-5822.json` | `aegis_manifest` output (SM count, memory, toolchain) | Core `results/` (not in git); byte-identical to the 2026-10-14 copy |
| `aegis_perf_full.db`, `aegis_perf_full_v3.db` | full snapshots (gitignored) | `sqlite3 .backup` |

## The perf DB

Always `sqlite3 SRC ".backup DST"`, never `cp` (a consistent snapshot even
while Core writes).

```sh
# The live DB, as of 2026-10-17 15:06 local: schema v4 (see below), not readable by v0.3.0.
sqlite3 ~/Documents/projects/aegis/results/aegis_perf.db ".backup tests/fixtures/aegis_perf_full.db"
# Core's own v3 backup, taken just before its v4 migration (2026-10-17 14:58 local).
sqlite3 ~/Documents/projects/aegis/results/aegis_perf.db.bak-v3-2026-10-17 ".backup tests/fixtures/aegis_perf_full_v3.db"
tests/fixtures/make_fixture.sh            # -> tests/fixtures/aegis_perf.db
```

The live DB had already been migrated to schema v4 (it adds `lt_algo` to
`measurements` and `winners`) by Core work that is not in any tag; v0.3.0
reads only v3 (`db::SCHEMA_VERSION = 3`, `connect_ro` refuses any other).
The fixture is therefore trimmed from Core's v3 backup. It lacks one run of
the live DB (`7e94c009266f`, 2026-10-17 21:58 UTC, the BK=64 experiment Core
did not keep) and 3 `paired_results` rows.

`make_fixture.sh` keeps every run, winner, paired tie test, microbench row and
paired result, and only the measurements of four runs:

| run | build | why |
|---|---|---|
| `41cc8ffb03fd` | 7fe7a84 | tune run behind 11 winners; build A of the compare() pair |
| `9fd0eab14f18` | 9157a34 | tune run behind 3 winners; build B of the compare() pair |
| `60959720261a` | 9157a34 | disturbed run (every row `disturbed = 1`) |
| `624671c030a1` | 1af1bc7 | protocol v1 run (history) |

What the fixture covers (asserted in `custos-perf/tests/fixture_db.rs`):
decode shapes (M = 1, 16) on the read roof and non-decode shapes on the copy
roof; a statistical tie (16x4864x896, paired CI 0.997-1.001); shapes the
dispatch floor sends to cuBLASLt (1x896x4864, 16x896x4864, 4096x4096x4096);
disturbed rows (a run, its measurements, two paired results); valid, replaced
and invalidated microbench rows; 10 paired results; latency rows with SM clock
data: 108 `ptr_chase_latency` rows of run `e3d94274b31d` (clocks locked at
2418 MHz, measured 2398.16 MHz), all invalidated ("Firefox started on the GPU
mid-run"), plus its valid `sm_clock` row. The arch file (from the tag) cites
`a825f4e557a3` for both latencies: valid rows without a per-row clock; the
clock (2406.78 MHz, not locked) is in the arch file.

## Golden outputs

```sh
git clone --branch aegis-perf-v0.3.0 https://github.com/Riffe007/aegis-core CORE
cargo build --release -p aegis-perf --manifest-path CORE/rust/Cargo.toml   # CPU only
tests/fixtures/make_golden.sh CORE
```

`report` and `roofline` read only; `make_golden.sh` still runs them on a copy
because the CLI opens its DB read-write. The emit-header output differs from
the tag's `winners/sm_121.h`: the tag's header was generated on 2026-10-15
from the DB of that day, the fixture holds the 2026-10-17 tune.

## SASS

Core's `artifacts/sass/sm_121/` (gitignored, so not in the tag) has no usable
SASS for the measured kernels. The 2026-10-13 files predate the `xor` smem
layout, and in the 2026-10-17 dump `tools/sass_dump.sh` cuts names at 120
characters, so the row- and column-major instantiations of a config share a
file name. Each file keeps whichever was written last (the column-major one).
The two files here were compiled from the tag, CPU only:

```sh
cd CORE   # at aegis-perf-v0.3.0
nvcc -cubin -arch=sm_121 -std=c++20 -O3 -DNDEBUG -lineinfo --expt-relaxed-constexpr \
     -Iinclude -Isrc src/gemm/mma_pipe.cu -o mma_pipe.cubin
cuobjdump -sass -fun <symbol> mma_pipe.cubin > <impl>.sass   # as tools/sass_dump.sh does
```

Symbols (`Layout 0, 0` = row-major A and B, what bench_gemm measures):

- `mma_pipe_64x64x32_2x2_s4`: `..gemm_mma_pipe_kernelINS0_10mma_detail4TileILi64ELi64ELi32ELi2ELi2ELNS0_6LayoutE0ELS5_0EEELi4EEEvNS0_7KParamsEbb`
- `mma_pipe_128x64x32_2x2_s2`: `..TileILi128ELi64ELi32ELi2ELi2ELNS0_6LayoutE0ELS5_0EEELi2EEEvNS0_7KParamsEbb`

`cuobjdump -res-usage` gives REG 74 and 126, the `regs` the perf DB records
for these kernels.

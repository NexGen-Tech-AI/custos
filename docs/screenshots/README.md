# Screenshots (2026-10-18)

The AEGIS views in light and dark, rendered in headless Chromium
(`--disable-gpu`, so no GPU was used) from the same command output the
frontend tests use (`src/tests/perf/fixtures/`, made by `cargo run --example
dump` on `tests/fixtures/`, pinned to aegis-perf-v0.5.0). SASS listings show
the fixture's first 200 lines.

| View | Light | Dark |
|---|---|---|
| Device (measured hardware model, the empty aegis-hw slot) | `device-light.png` | `device-dark.png` |
| Roofline, with the decode spotlight | `roofline-light.png` | `roofline-dark.png` |
| Winners (stored dispatch, cuBLASLt algorithm, paired/unpaired warnings), with the decode spotlight | `winners-light.png` | `winners-dark.png` |
| Kernel detail | `kernel-light.png` | `kernel-dark.png` |
| Win chain, 16x896x896 (`gemv_tc_16x64x64_1x4_s4_k1`) | `win-chain-light.png` | `win-chain-dark.png` |
| Regressions: nightly sweeps by build, nightly fuzz | `regression-light.png` | `regression-dark.png` |
| Incompatible perf DB: the AEGIS landing over a `sqlite3 .backup` of the live DB (schema v4), with aegis-perf v0.3.0 | `incompatible-v4-light.png` | `incompatible-v4-dark.png` |

The incompatible-DB shots (2026-10-17, before the v0.4.0 bump) use the real
backend answers for that snapshot (`dump status`, `dump devices` with
AEGIS_PERFDB at the snapshot); they are kept as the record of that state.

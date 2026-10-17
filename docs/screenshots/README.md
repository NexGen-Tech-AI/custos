# Screenshots (2026-10-17)

The AEGIS views in light and dark, rendered in headless Chromium from the
same command output the frontend tests use (`src/tests/perf/fixtures/`, made
by `cargo run --example dump` on `tests/fixtures/`, pinned to
aegis-perf-v0.3.0). The Kernel view's SASS fixture holds the listing's first
200 lines.

| View | Light | Dark |
|---|---|---|
| Device (measured hardware model) | `device-light.png` | `device-dark.png` |
| Roofline | `roofline-light.png` | `roofline-dark.png` |
| Winners | `winners-light.png` | `winners-dark.png` |
| Kernel detail | `kernel-light.png` | `kernel-dark.png` |
| Incompatible perf DB: the AEGIS landing over a `sqlite3 .backup` of the live DB (schema v4), with aegis-perf v0.3.0 | `incompatible-v4-light.png` | `incompatible-v4-dark.png` |

The incompatible-DB shots (2026-10-17, before the v0.4.0 bump) use the real
backend answers for that snapshot: `perf_status` and the perf commands as
custos-perf returned them (`dump status`, `dump devices` with AEGIS_PERFDB at
the snapshot). They are rendered in headless Chromium with `--disable-gpu`
rather than in the Tauri window, so no GPU was used while Core benchmarked.

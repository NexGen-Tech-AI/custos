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
| Perf DB status banner (perf_status mocked as a v4 DB) | `banner-light.png` | `banner-dark.png` |

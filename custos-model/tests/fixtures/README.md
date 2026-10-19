# custos-model test fixtures

Every file here is **synthetic** (hand-built, not a capture) until
`tools/capture_fixtures.sh` replaces it with a real capture (CLAUDE.md rule 27;
the user runs it in a GPU window, under the GPU lock). Each is in the exact
documented format of its tool, so the adapters read a real capture the same way.

| File | Format | Status |
|---|---|---|
| `nsys/decode-synthetic.sql` | SQL dump of an `nsys export --type sqlite` file, export schema 3.20.3 (Nsight Systems 2025.3.2 User Guide, "SQLite Schema Reference"): the tables the adapter reads, every documented column | synthetic (header comment) |
| `nsys/decode-synthetic.meta.json` | the sidecar the capture script writes (`custos_model::sidecar`: tool version, build, driver, CUDA, clock control passed, the exact command lines with paths as `<core>` / `<out>`, `synthetic`); real ncu captures get one too (`ncu/<tag>.meta.json`) | synthetic: `"synthetic": true`, placeholder versions marked "(synthetic)" |
| `ncu/decode-synthetic.{details,raw,session}.csv` | `ncu --import <report> --csv --print-units base --page details\|raw\|session`, Nsight Compute 2025.3.1 | synthetic: `ncu/decode-synthetic.synthetic` |

The parsers were also checked, outside the tests, against real exports of a
Core report (`ncu --import` of an existing `.ncu-rep`; no profiling). Those
exports are not committed: they hold the host name, IP addresses and paths.

Scrubbing (rule 28): `custos-model/tests/scrub_fixtures.rs` scans these and
every other fixture and doc. The synthetic files contain a fake host name and an
RFC 5737 address on purpose, to test that the adapters drop them.
The same scan (`tests/scrub/mod.rs`) runs on a capture's output before it can be
committed: `cargo run --example scrub_scan -- --this-machine DIR`.

## Telemetry (NVML mock, Jetson)

| File | Format | Status |
|---|---|---|
| `nvml/full-synthetic.json` | a recorded probe (`custos_model::nvml::Recorded`, what `examples/nvml_probe --record` writes): one read of every field, repeated power / energy reads | synthetic (`"synthetic": true`): a discrete GPU that reports every field |
| `nvml/gb10-like-synthetic.json` | the same | synthetic: a GB10-like device with gaps. Which fields are missing is **assumed** (to exercise "not available on this device"); the real GB10 answer comes from the probe on the device |
| `jetson/sysfs-orin-synthetic/`, `jetson/tegrastats-synthetic.txt` | an Orin-layout sysfs tree; tegrastats lines | synthetic (`jetson/README.md`) |

A recorded probe holds no UUID, serial number, PCI bus id or host name; devices
are by index.

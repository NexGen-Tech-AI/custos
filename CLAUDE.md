# AEGIS Custos — instructions for Claude Code

This app (formerly the System Detection / Custos security monitor) is becoming
**AEGIS Custos**: a GPU performance-engineering workstation over the AEGIS Core
perf DB. Core lives at `~/Documents/projects/aegis` (read its `CLAUDE.md`);
Custos reads Core's data and never writes it.

## Inventory (2026-10-14)

### Build layout

| Path | What | Notes |
|---|---|---|
| `src-tauri/` | crate `custos`: the Tauri 2 app (bin + `lib.rs`) | standalone, own `Cargo.lock`; excluded from the root workspace |
| `custos-perf/` | crate `custos-perf`: Custos's perf-DB layer over `aegis-perf` | own `[workspace]`; all Custos data logic and its tests |
| `Cargo.toml` (root) | workspace (`custos-ebpf`, `custos-ebpf-common`) **and** package `system-monitor` (`src/lib.rs`, `src/backend/*`) | `system-monitor` is not linked into the Tauri binary |
| `custos-ebpf/`, `custos-ebpf-common/` | aya eBPF program + shared types | `src-tauri` feature `ebpf` |
| `src/` (TS) | React 18 + Vite 5 + TypeScript + Tailwind 3 frontend | `src/main.tsx` → `App.tsx` → `AppWrapper.tsx` |
| `system-monitor/`, `src/ui/`, `src/inference/`, `src-ml/`, root `*.md` status files | stale copies and notes | not built |

Commands: `npm run tauri:dev` (app), `npm run build` (frontend), `npm test`
(vitest), `cargo test --manifest-path custos-perf/Cargo.toml` (Custos data
layer), `cargo check --manifest-path src-tauri/Cargo.toml` (app).

Perf views: `src/components/sections/perf/` (Device, Roofline), API and types in
`src/perf/`. Their tests (`src/tests/perf/`) run on real command output;
refresh it with `AEGIS_CORE=~/custos-fixtures/core cargo run --manifest-path
custos-perf/Cargo.toml --example dump -- devices | arch_model 121 | roofline 121`
into `src/tests/perf/fixtures/`.

`cargo test` in `src-tauri` does **not** compile today: pre-existing errors in
the security modules (`tempfile` missing in `malware/quarantine.rs` and
`malware/ml_inference.rs`, `sensors::Package` in
`ai_analysis/report_generator.rs`, `EventType` in `monitoring/ebpf_monitor.rs`).
That is why Custos logic lives in `custos-perf`, where tests run.

### Tauri (v2)

- Commands registered in `src-tauri/src/main.rs` (`tauri::generate_handler!`),
  state via `.manage()` just above it. `withGlobalTauri: true`, dev URL
  `127.0.0.1:5173`.
- Existing command areas: system monitoring (`get_system_info`,
  `start_monitoring`, `get_current_metrics`, high-perf/kernel metrics, PCI),
  hardware detection and Ollama tiers, config, API keys, sudo, and ~60
  security commands (threats, network, vulnerabilities, malware, AI analysis,
  reports).
- Perf commands (`src-tauri/src/perf.rs`) are thin wrappers over `custos-perf`.

### Hardware detection and NVIDIA telemetry

- NVML via `nvml-wrapper` 0.11 behind `src-tauri` feature `nvidia` (**off by
  default**): `monitoring.rs` (~l.400-460), `monitoring/high_perf_monitor.rs`,
  `monitoring/ultra_perf_monitor.rs` (utilization, memory, temperature, power,
  clocks). Three near-duplicate collectors.
- `hardware_detector.rs`: `nvidia-smi` / `lspci` parsing for name and VRAM.
- No tegrastats or Jetson sysfs GPU load yet (Core's idle guard reads
  `.../gpu.0/load` and `tegrastats`; mirror that when Jetson telemetry lands).
- `monitoring/high_perf_monitor.rs` sysfs probes for DPU/NPU/"external DDR"
  are speculative and report nothing on real hardware.

### Frontend

- No router, no state library: `AppWrapper.tsx` switches on a `useState`
  section id from `Sidebar.tsx`. Contexts: `ScanContext`, `ThemeContext`.
- UI kit: shadcn-style `src/components/ui/*` (Radix, lucide-react, clsx,
  tailwind-merge). Charts: **recharts** (the only chart library).
- `invoke()` from `@tauri-apps/api/core`, scattered across sections and
  `src/services/*`.
- Tests: vitest + jsdom (`src/tests/`).

### Reuse for Custos

Reusable: the Tauri 2 shell, Sidebar/AppWrapper layout, `components/ui/*`,
recharts, `MonitoringService` (CPU/mem/disk via sysinfo), the NVML collectors
(continuous telemetry only, see rule 8), `pci_devices.rs`, `config.rs`,
`errors.rs`.

Unrelated security scope (kept, not extended): `malware/`, `threat_detection/`,
`vulnerability/`, `network/`, `sensors/`, `ai_analysis/`, `storage/`
(security events), `platform_security.rs`, `sudo_auth.rs`, `keychain.rs`, and
their UI sections.

## Custos rules (non-negotiable)

### Data contract with AEGIS Core

Each rule matches a mistake Core already caught in its own data. Break one and
Custos shows numbers Core has disowned.

1. **Read-only.** Open the perf DB read-only (`aegis_perf::db::connect_ro`,
   SQLite `mode=ro`), so a running tune or sweep is never blocked or
   corrupted. Writes stay in aegis-perf.
2. **Protocol v2, cold, idle by default.** Every view defaults to
   `protocol_version = 2`, `cache_mode = cold`, rows not marked `allow_busy`.
   Version 1 rows are recorded history: shown only on request, labeled.
3. **Derived metrics at view time.** % of roof, GB/s % and TFLOPS % are
   computed from `include/aegis/arch/<sm>.json` when rendering
   (`aegis_perf::params::ArchParams::roof`). Never store or cache them; the
   bandwidth changed once (214.7 to 236.8 GB/s) and inflated older percentages.
4. **The right roof.** Decode shapes (M ≤ 16) use the read-bandwidth roof;
   everything else the copy roof. Label which roof each row uses.
5. **The right baseline.** Performance is % of `cublaslt_best`, never of
   default cuBLAS or of a naive kernel.
6. **Ties are statistical.** Show the paired ratio and its 95% CI from
   `winners`. A shape is tied when the CI contains 1.0. Never show a single
   median as a win.
7. **Superseded rows stay hidden.** Microbench rows marked superseded stay in
   the DB for history but are excluded from the hardware-model view.
8. **Two kinds of data, never mixed.** Continuous telemetry (NVML on the
   Spark; sysfs and tegrastats on Jetson) is separate from profiled kernel
   metrics (Nsight). Never imply that NVML provides hardware counters.
9. **No numbers Core doesn't have.** If a value isn't in the DB, the arch file
   or an artifact, show "not measured" (or "not profiled" for Nsight data),
   never an estimate.

### Engineering rules

10. **Rust, Tauri, React only.** No Python, no second backend language.
11. **One chart library: recharts.** Do not add another.
12. **No custom theming in v1.** Use the existing Tailwind tokens and
    `components/ui/*`; no new themes, palettes or theme switches.
13. **No metric is ever estimated.** Missing data is `None` in Rust, `null`
    in TS, and "not measured" on screen. No interpolation, no datasheet
    fallbacks (Core rule 8: datasheet figures only as labeled context).
14. **All SQL lives in aegis-perf.** Custos queries through
    `aegis_perf::view` / `db` / `roofline` (the library, never the CLI), so a
    schema change breaks Custos at compile time. A query Custos needs is
    requested in `docs/core-requests.md` (rule 18), never written in Custos.
15. **Design for many archs.** All data is sm_121 today; every command and
    view takes the arch as a parameter (sm_87 arrives with the Jetson port).
16. **Development and tests use fixture snapshots, never live Core data.**
    The DB: `~/custos-fixtures/aegis_perf.db` (`cp ~/Documents/projects/aegis/results/aegis_perf.db ~/custos-fixtures/`;
    override with `AEGIS_PERFDB`). The Core files Custos reads (arch file,
    manifest, `artifacts/sass`, `artifacts/ncu`), from the same moment:
    `~/custos-fixtures/core` (tests: `AEGIS_FIXTURE_CORE`). The app reads the
    live Core repo (`AEGIS_CORE`), which other sessions change at any time.
17. **Never run git in Core's main working tree.** Another session works
    there. To read Core at a rev, clone it elsewhere (scratch directory).
18. **Custos never commits to aegis-core.** When Custos needs a Core change
    (a query, a column, a fix), write it up in `docs/core-requests.md` (what,
    why, the Custos code waiting on it) and stop that work until Core lands it.
19. **aegis-perf is a git dependency pinned to a specific rev** of
    https://github.com/Riffe007/aegis-core (`rev = "<full sha>"` in
    `custos-perf/Cargo.toml`), never a path or a branch, so a Custos build is
    reproducible and Core's working tree never leaks into it.
20. **A pin bump is its own commit.** It changes only the rev (plus what the
    bump forces in Custos) and its message records the new Core rev, the
    previous one, and the reason for the bump.

# AEGIS Custos — project instructions

This app (formerly the System Detection / Custos security monitor) is becoming
**AEGIS Custos**: a GPU performance-engineering workstation over the AEGIS Core
perf DB. Core lives at `~/Documents/projects/aegis` (read its project instructions);
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

Commands (pnpm is the package manager; there is no package-lock.json):
`pnpm install --frozen-lockfile`, `pnpm tauri:dev` (app), `pnpm typecheck`,
`pnpm vitest run`, `cargo test --manifest-path custos-perf/Cargo.toml` (Custos data
layer), `cargo check --manifest-path src-tauri/Cargo.toml` (app).

Perf views: `src/components/sections/perf/` (Device, Roofline), API and types in
`src/perf/`. Their tests (`src/tests/perf/`) run on real command output;
refresh it with `cargo run --manifest-path custos-perf/Cargo.toml --example dump
-- devices | arch_model 121 | roofline 121` (no `AEGIS_CORE`: it reads
`tests/fixtures/`) into `src/tests/perf/fixtures/`.

Legacy code is out of the default build (it is kept, not maintained):
- `src-tauri` feature `legacy-security`: the security modules (`malware`,
  `threat_detection`, `vulnerability`, `network`, `sensors`, `ai_analysis`,
  `storage`, `keychain`, `sudo_auth`), their state and their ~76 commands.
- root crate feature `legacy-backend`: `src/backend`, `src/services`, their
  tests (`src/tests/*_tests.rs`) and the three `src/bin` tools. It does not
  compile (20 errors in `src/backend`); not fixed on purpose.
Frontend: the legacy security views (Security Dashboard, threats, network,
vulnerabilities, AI analysis, reports, scan overlay) load through the `@legacy`
alias: an empty registry (`src/legacy/disabled.tsx`) unless
`VITE_LEGACY_SECURITY=1` (`src/legacy/security.tsx`). `tsconfig.json`
excludes them; `pnpm typecheck:legacy` checks them (not expected to pass).
The default app lands on the Device view.
Default builds compile with zero errors and their tests never hang; a test
needing the network or root is `#[ignore = "<reason>"]` or feature-gated.

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

1. **Read-only DB access.** Open the perf DB only with
   `aegis_perf::db::connect_ro` (SQLite `mode=ro`), so a running tune or
   sweep is never blocked or corrupted. Writes stay in aegis-perf.
2. **Default filters: protocol v2, cold cache, not disturbed, not
   allow_busy.** Every view starts there (`aegis_perf::db::Selection::ranking`).
   Excluded rows (protocol v1, warm, disturbed, allow_busy) appear only on
   request, and labeled.
3. **Derived metrics are computed at view time** from the arch file
   (`aegis_perf::params::ArchParams::roof`): % of roof, GB/s %, TFLOPS %, ns.
   Never stored, never cached across calls. The bandwidth changed once
   (214.7 to 236.8 GB/s) and inflated every stored percentage.
4. **Roof:** decode shapes (M ≤ 16, `aegis_perf::params::DECODE_MAX_M`) use
   the read-bandwidth roof, everything else the copy roof. Every row is
   labeled with its roof.
5. **Baseline is `cublaslt_best`**, never default cuBLAS or a naive kernel
   (% of cuBLAS only as labeled context).
6. **Ties are statistical.** Show the paired ratio and its 95% CI. Tied means
   the CI contains 1.0. Never present a single median as a win.
7. **Only valid microbench rows feed the hardware model.** Replaced rows are
   history (shown labeled, with `replaced_by`); invalidated rows are hidden
   unless requested (`aegis_perf::view::microbench` never returns them).
8. **Telemetry and profiled metrics are never mixed.** Continuous telemetry
   (NVML on the Spark; sysfs and tegrastats on Jetson) is separate from
   profiled kernel metrics (Nsight). Never imply that NVML provides hardware
   counters.
9. **Nothing is estimated.** Missing data shows "not measured" (or "not
   profiled" for Nsight data), never an estimate, an interpolation or a
   datasheet figure.
10. **Kernel % and dispatch % are separate columns.** Kernel %: AEGIS's own
    kernel against `cublaslt_best`. Dispatch %: what `aegis::matmul` actually
    runs for the shape. A shape routed to cuBLASLt shows "dispatch: cuBLASLt"
    with AEGIS's own kernel % beside it, never as AEGIS's number.
11. **Latency is shown with its clock and lock state**, e.g. "335 cycles =
    139 ns at 2407 MHz (clocks not locked)". Cycles are what is stored; ns is
    derived through aegis-perf (`params::Latency::ns`, `view::Microbench::ns`).
12. **Thresholds and schema compatibility come from Core**, never hardcoded in
    Custos (`aegis_perf::db::SCHEMA_VERSION`, `aegis_perf::regress::REGRESSION`,
    `aegis_perf::sweep::IDLE_MAX_PCT`, ...). When aegis-perf lacks one,
    `custos-perf/src/core_fallbacks.rs` holds it as a named constant citing
    its `docs/core-requests.md` entry, and the UI labels every value derived
    from it "provisional".

### Engineering rules

13. **Rust, Tauri, React only.** No Python, no second backend language.
14. **One chart library: recharts.** Do not add another.
15. **No custom theming in v1.** Use the existing Tailwind tokens and
    `components/ui/*`; no new themes, palettes or theme switches.
16. **No metric is ever estimated.** Missing data is `None` in Rust, `null`
    in TS, and "not measured" on screen. No interpolation, no datasheet
    fallbacks (Core rule 8: datasheet figures only as labeled context).
17. **All SQL lives in aegis-perf.** Custos queries through
    `aegis_perf::view` / `db` / `roofline` (the library, never the CLI), so a
    schema change breaks Custos at compile time. A query Custos needs is
    requested in `docs/core-requests.md` (rule 21), never written in Custos.
18. **Design for many archs.** All data is sm_121 today; every command and
    view takes the arch as a parameter (sm_87 arrives with the Jetson port).
19. **Tests use the committed fixtures in `tests/fixtures/`, never live Core
    data** (see its README: the trimmed perf DB, the arch file, winners
    header, golden CLI outputs and SASS, all from the pinned tag). No test
    reads from `~` or from a Core checkout. A perf DB is snapshotted only with
    `sqlite3 SRC ".backup DST"`, never `cp`; the live DB is opened for nothing
    else. The app reads the live Core repo (`AEGIS_CORE`, `AEGIS_PERFDB`),
    which other sessions change at any time.
20. **Never run git in Core's main working tree.** Another session works
    there. To read Core at a rev, clone it elsewhere (scratch directory).
21. **Custos never commits to aegis-core.** When Custos needs a Core change
    (a query, a column, a fix), write it up in `docs/core-requests.md` (what,
    why, the Custos code waiting on it). If a fallback exists (rule 12), use
    it; otherwise stop that work until Core lands it.
22. **aegis-perf is a git dependency pinned to a release tag** of
    https://github.com/Riffe007/aegis-core (`tag = "aegis-perf-vX.Y.Z"` in
    `custos-perf/Cargo.toml`; both Cargo.lock files record its commit), never a
    path or a branch, so a Custos build is reproducible and Core's working
    tree never leaks into it. A local `[patch]` in `.cargo/config.toml`
    (gitignored, README) may point at a separate Core worktree for
    development; tests and CI always build from the pin.
23. **A pin bump is its own commit.** It changes only the pin (plus what the
    bump forces in Custos) and its message records the new Core rev, the
    previous one, and the reason for the bump.

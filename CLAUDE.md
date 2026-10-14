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

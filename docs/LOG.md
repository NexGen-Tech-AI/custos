# Custos log

## 2026-10-14

Landed on `custos`:

- **Project rules and inventory** (CLAUDE.md): the data contract with AEGIS
  Core (rules 1-9), engineering rules (10-17), and rules 18-20: Custos never
  commits to aegis-core (requests go in `docs/core-requests.md`); aegis-perf
  is a git dependency pinned to a full rev; a pin bump is its own commit.
- **custos-perf crate**: Custos's read-only perf-DB layer over `aegis-perf`,
  tested on fixture snapshots (`~/custos-fixtures`), never live Core data.
- **Perf commands and views**: read-only Tauri commands; Device and Roofline
  views, tested on real command output.
- **compare()**: a median shift over 3% is "unconfirmed" unless a paired
  result backs it. Paired evidence is wired but has no data yet (see below).
- **aegis-perf pinned** to aegis-core `733f1b393ad68e276ad56e1f51a0442110dfa1da`
  (git dependency, was a path). Arch file schema 2: the Device view shows
  latency in cycles and ns at the reference clock, each source run's SM
  clock and lock state, and replaced runs as history.
- **Legacy code gated** out of the default build: `src-tauri` feature
  `legacy-security`, root crate feature `legacy-backend` (does not compile;
  not fixed on purpose), frontend `VITE_LEGACY_SECURITY=1`. The default app
  lands on the Device view. Ollama tests are `#[ignore]` (network).
- **Frontend**: pnpm only (`package-lock.json` deleted); tsc 0 errors (was
  54), vitest 15/15.
- **Core requests** (`docs/core-requests.md`): (1) store `paired-ab` results
  in a `paired_results` table with a `view::paired_results` query; this
  blocks compare() step; (2) record `runs.clocks_locked` at ingest.
- README "How this was built" section; comments cite rules as
  "project rule N".

Green at end of day: custos-perf 14/14, src-tauri default 6 pass / 2 ignored,
root crate default 3 pass, tsc, vitest 15/15.

### Next session, in order

1. Bump the aegis-perf pin to the `aegis-perf-v0.2.0` rev (its own commit,
   rule 20).
2. Move the root notes (`WEEK*_PROGRESS.md`, `ANALYSIS_INDEX.md`, etc.) to
   `docs/archive/`.
3. compare() reads `paired_results`.
4. A trimmed fixture DB in `tests/fixtures/`.
5. CI, verified in a fresh worktree.

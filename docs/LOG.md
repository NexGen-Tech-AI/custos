# Custos log

## 2026-10-17

Pinned: `aegis-perf-v0.4.0` (`7e433cf9285e839454bdc971efafb661f71939a0`),
perf DB schema v4.

- **Paired vs unpaired warning** (Winners, Roofline): a winner whose median %
  lies > 2 points outside its paired CI is flagged; the CI is the number of
  record. In the v0.4.0 fixture only 512x4864x896 (82.2% vs [78.5, 79.0]).
  256x256x256 disagreed in the v0.3.0 fixture (98.2% vs [89.9, 90.2]) and
  agrees now. Threshold provisional (`DISAGREE_PTS`, core-requests #4).
- **compare() provenance:** dirty or unlinked paired results are labeled
  ("unreproducible (dirty build)", "unlinked build") and never decide. All
  18 fixture results and all 25 in the live DB have a dirty build: no clean
  paired result exists yet.
- **SASS source** in the Kernel view (compiled from tag / Core artifact).
- **Core requests:** #8 (invalidated microbench rows); #4 and #5 extended.
- **CI** (`.github/workflows/ci.yml`): default features and
  `--no-default-features`, clippy `-D warnings` everywhere (src-tauri and
  the root crate cleaned up for it).
- **Hygiene:** dist/ untracked; old root notes in `docs/archive/`.

Open: core requests #2, #3, #5, #6, #7, #8 and #4 (bars, disagreement rule,
the dispatched path's rows). Provisional constants: `LARGE_SHAPE_MIN_DIM`,
`LARGE_BAR`, `DECODE_BAR`, `DISAGREE_PTS`. The four view screenshots still
show v0.3.0 data.

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

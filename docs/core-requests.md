# Custos requests to AEGIS Core

Custos never commits to aegis-core (project rule 21). When Custos needs a
Core change, it is written up here and the Custos work waits for it. Each
request names what Custos needs, why, and the Custos code waiting on it.
Core decides the design; the shapes below are only what Custos would consume.

Pinned Core when requests 1-2 were written: rev `733f1b393ad68e276ad56e1f51a0442110dfa1da`.
Pinned now: tag `aegis-perf-v0.3.0` (`9157a34d24b5368ef81f7d3add2b31f07de87301`).

---

## 1. Store cross-build paired results (`paired_results`) and expose them in `aegis_perf::view`

**Status:** landed in aegis-perf-v0.3.0 (2026-10-17): the `paired_results`
table (written by `paired-ab`) and `view::paired_results`. Custos compare()
reads it. What is still missing is in request 4 (device, arch and dtype).

### What Custos needs

`aegis-perf paired-ab` measures the same impl and shape in two builds with
alternating processes and prints the paired ratio B/A with a 95% bootstrap
CI. The result is printed, not stored. The `paired` table holds only
within-run tie tests (one build). So no stored result can confirm or rule out
a build-over-build change.

Requested:

1. A table, e.g. `paired_results`, with one row per paired-ab comparison:
   - the two builds: full git SHA of build A and build B. paired-ab gets
     two `bench_gemm` paths today, so the binary needs a way to report the
     SHA it was built from (for example a `--version` line or a manifest
     field);
   - device_id, sm_arch, op, dtype, m, n, k;
   - a_impl, b_impl (equal for a same-impl comparison);
   - protocol_version, cache_mode, allow_busy (and idle_util_pct);
   - pairs, reps per process, ratio_median (B/A time), ratio_ci_lo,
     ratio_ci_hi, bootstrap_resamples, bootstrap_seed, started_at.
2. `paired-ab` writes that row (plus a `runs` row if that fits Core's model).
3. A read-only query in `aegis_perf::view`, e.g.
   `paired_results(con, &PairedResultFilter { sha_a, sha_b, sm_arch, device_id, sel: Selection })`
   returning typed rows. It defaults like every view (protocol 2, cold,
   allow_busy excluded) and accepts either SHA order. If it returns the
   stored order, Custos inverts the ratio and CI itself.

### Why

Project data-contract rule 6: never call a change from a single median. Custos
`compare()` flags median shifts over 3%. A shift should read "confirmed" or
"not_confirmed" only when a paired result for the same builds exists, matched
on shape, impls, protocol and cache mode. Without one it stays "unconfirmed",
which is every shift today.

### Custos code waiting on it

- `custos-perf/src/measure.rs`: `compare()` calls
  `compare_rows(..., |_, _| None)`. That closure becomes a lookup in the rows
  of `view::paired_results` for (device_id, sm_arch, dtype, m, n, k, impl,
  protocol_version, cache_mode). `status()` and `PairedEvidence` already
  handle "confirmed" and "not_confirmed", with unit tests.
- Fixture tests on the fixture DB need `paired_results` rows. The fixture
  is refreshed with `sqlite3 <live> ".backup <fixture>"`, never `cp`.
- Then a pin bump to the Core rev that ships this (its own commit, rule 23).

---

## 2. Record whether clocks were locked for each run (`runs.clocks_locked`)

**Status:** partly addressed in v0.3.0. Latency probes now record
`microbench.sm_clock_mhz`, `clocks_locked` and `clock_lock` per row, and the arch
file carries each source run's clock and lock state. `runs.clocks_locked` is
still NULL for 29 of the 30 runs in the fixture (set only on `e3d94274b31d`).
Lower priority.

`runs.clocks_locked` exists in the schema, but ingest always writes NULL. The
Device view shows each latency source run's SM clock (arch schema 2) and
whether its clocks were locked. Today that reads "clock lock not recorded"
for every run. Requested: set it at ingest. On the Spark this could come from
`nvidia-smi -q -d CLOCK` (application clocks or locked clocks); on Jetson,
from `jetson_clocks` / nvpmodel state. If the state can't be determined,
leave it NULL; Custos never guesses.

Custos code waiting: `custos-perf/src/device.rs` (`SourceRun::clocks_locked`)
and the Device view. Both already render true, false and NULL. No Custos
change is needed beyond a pin bump.

---

## 3. A typed schema check (supported range and the DB's version)

**Status:** open, 2026-10-17. Fallback in use: `custos-perf/src/core_fallbacks.rs`
(`db_schema_version`).

### What Custos needs

At startup Custos tells the user when the perf DB is outside the schema range
it reads ("Incompatible perf DB: DB schema vN, Custos supports vA–vB"). The
range comes from aegis-perf (`db::SCHEMA_VERSION`; `connect_ro` accepts
exactly that version). But when `connect_ro` refuses a DB, it returns only an
`anyhow` message ("DB schema vN, binary expects vM ..."), so Custos cannot
tell which version the DB has without parsing text or opening the file itself.

Requested, for example:

- `db::SUPPORTED_SCHEMA: RangeInclusive<i64>` (or `MIN_READ_SCHEMA`
  alongside `SCHEMA_VERSION`), so readers can say what they accept, and
- `db::check(path) -> Result<Compat>` with
  `enum Compat { Ok, TooOld { found: i64 }, TooNew { found: i64 }, MissingColumn { table, column } }`,
  or a typed error from `connect_ro` that carries `found` and `expected`.

### Why

Contract rule 12 (schema compatibility comes from Core) and rule 1 (the DB is
opened only through `connect_ro`). The fallback opens the file read-only
itself (`SQLITE_OPEN_READ_ONLY`, no writes, no migration) and calls
`db::schema_version`, the one place Custos opens the DB outside `connect_ro`.

### Custos code waiting on it

- `custos-perf/src/core_fallbacks.rs::db_schema_version` (delete it).
- `custos-perf/src/status.rs::db_status` (use `Compat`).
- Tests: `custos-perf/tests/schema_compat.rs` (doctored fixture copies at
  v2 and v4).

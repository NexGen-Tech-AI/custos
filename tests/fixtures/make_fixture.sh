#!/bin/sh
# Rebuild the trimmed fixture tests/fixtures/aegis_perf.db from a full perf DB
# snapshot. Never copy a perf DB with cp: always sqlite3 .backup (a consistent
# snapshot, even while Core writes). See tests/fixtures/README.md.
#   tests/fixtures/make_fixture.sh [FULL_SNAPSHOT]   (default: aegis_perf_full.db)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
full=${1:-$here/aegis_perf_full.db}
out=$here/aegis_perf.db
tmp=$here/aegis_perf.db.tmp
rm -f "$tmp"
sqlite3 "$full" ".backup '$tmp'"
sqlite3 "$tmp" <<'SQL'
-- Measurements of the runs the views and tests need (tests/fixtures/README.md):
--   7e94c009266f  tune (eccf61f): the 7 non-decode mma_pipe winners; lt_algo
--   2d261d8defab  tune (7e433cf): the mma_tma winners at 2048^3 and 4096^3
--   c2b937d8adca  decode tune (1084490): the 6 gemv_tc winners (split-K)
--   41cc8ffb03fd, 9fd0eab14f18  tunes (7fe7a84, 9157a34): the compare() pair,
--                 and the runs the nightlies are checked against
--   b34425e97d6d, eb5bcee294d4  nightly regression sweeps (9157a34): one watch each
--   d1504a45376d  nightly sweep, disturbed (in-run watch)
--   60959720261a  tune, disturbed (in-run watch; every row disturbed = 1)
--   624671c030a1  protocol v1 run (history)
DELETE FROM measurements WHERE run_id NOT IN
  ('7e94c009266f', '2d261d8defab', 'c2b937d8adca', '41cc8ffb03fd', '9fd0eab14f18',
   'b34425e97d6d', 'eb5bcee294d4', 'd1504a45376d', '60959720261a', '624671c030a1');
DELETE FROM kernels WHERE kernel_id NOT IN (SELECT kernel_id FROM measurements)
                      AND kernel_id NOT IN (SELECT kernel_id FROM winners);
-- runs, winners, paired, microbench and paired_results are kept whole.
VACUUM;
SQL
mv "$tmp" "$out"
sqlite3 -readonly "$out" "SELECT 'schema v' || version FROM schema_version;
  SELECT 'runs', count(*) FROM runs;
  SELECT 'measurements', count(*) FROM measurements; SELECT 'kernels', count(*) FROM kernels;
  SELECT 'winners', count(*) FROM winners; SELECT 'microbench', count(*) FROM microbench;
  SELECT 'paired_results', count(*) FROM paired_results;"
"$here/scrub.sh" "$here"
ls -l "$out"

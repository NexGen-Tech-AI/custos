#!/bin/sh
# Rebuild the trimmed fixture tests/fixtures/aegis_perf.db from a full perf DB
# snapshot. Never copy a perf DB with cp: always sqlite3 .backup (a consistent
# snapshot, even while Core writes). See tests/fixtures/README.md.
#   tests/fixtures/make_fixture.sh [FULL_SNAPSHOT]   (default: aegis_perf_full_v3.db)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
full=${1:-$here/aegis_perf_full_v3.db}
out=$here/aegis_perf.db
tmp=$here/aegis_perf.db.tmp
rm -f "$tmp"
sqlite3 "$full" ".backup '$tmp'"
sqlite3 "$tmp" <<'SQL'
-- Measurements: the two tune runs the winners come from (7fe7a84 and
-- 9157a34, also the build-over-build pair for compare()), one disturbed run
-- (every row disturbed = 1) and one protocol v1 run (history).
DELETE FROM measurements WHERE run_id NOT IN
  ('41cc8ffb03fd', '9fd0eab14f18', '60959720261a', '624671c030a1');
DELETE FROM kernels WHERE kernel_id NOT IN (SELECT kernel_id FROM measurements)
                      AND kernel_id NOT IN (SELECT kernel_id FROM winners);
-- runs, winners, paired, microbench and paired_results are kept whole.
VACUUM;
SQL
mv "$tmp" "$out"
sqlite3 -readonly "$out" "SELECT 'schema v' || version FROM schema_version;
  SELECT 'measurements', count(*) FROM measurements; SELECT 'kernels', count(*) FROM kernels;
  SELECT 'winners', count(*) FROM winners; SELECT 'microbench', count(*) FROM microbench;
  SELECT 'paired_results', count(*) FROM paired_results;"
ls -l "$out"

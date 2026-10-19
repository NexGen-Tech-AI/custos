#!/bin/sh
# Regenerate the golden outputs in tests/fixtures/golden/ with the aegis-perf
# CLI of the pinned tag, run against a copy of the trimmed fixture (the CLI
# opens its DB read-write, so it never sees the committed file). CPU only.
#   tests/fixtures/make_golden.sh CORE_CLONE
# CORE_CLONE: a clone of aegis-core checked out at the pinned tag, with the CLI
# built: cargo build --release -p aegis-perf --manifest-path CORE_CLONE/rust/Cargo.toml
set -eu
here=$(cd "$(dirname "$0")" && pwd)
core=$(cd "$1" && pwd)
cli=$core/rust/target/release/aegis-perf
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/include/aegis/arch"
cp "$here/sm_121.json" "$work/include/aegis/arch/sm_121.json"   # the tag's arch file
sqlite3 "$here/aegis_perf.db" ".backup '$work/db.db'"
cd "$work"
"$cli" --db db.db report --arch 121 > "$here/golden/report-121.txt"
"$cli" --db db.db roofline --arch 121 --out "$here/golden/roofline-sm121.svg" > "$here/golden/roofline-121.txt"
"$cli" --db db.db emit-header --arch 121 --out "$here/golden/emit-header-sm_121.h" > /dev/null
# The nightly regression check of each nightly sweep, against the winners header
# that nightly ran (its build, 9157a34 = tag aegis-perf-v0.3.0).
for run in d1504a45376d b34425e97d6d eb5bcee294d4; do
  "$cli" --db db.db regress --run "$run" --header "$here/winners/9157a34/sm_121.h" > "$here/golden/regress-$run.txt"
done
"$here/scrub.sh" "$here" > /dev/null
echo "golden outputs regenerated with $("$cli" --version) at $(git -C "$core" rev-parse HEAD)"

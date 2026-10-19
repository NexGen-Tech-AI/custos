#!/bin/sh
# Scrub machine and personal details from the fixtures (CLAUDE.md rule 28):
# the host name (Core uses it as runs.device_id and in generated headers), the
# user's home directory, and absolute paths under it. Run by make_fixture.sh and
# make_golden.sh after they write; idempotent. The host name and home directory
# are read from this machine at run time and written nowhere.
#   tests/fixtures/scrub.sh [FIXTURE_DIR]
set -eu
here=$(cd "${1:-$(dirname "$0")}" && pwd)
host=$(hostname)
home=${HOME:-/nonexistent}
user=$(id -un)
device=gb10-0   # the neutral device id the fixtures use for Core's one device
if [ -f "$here/aegis_perf.db" ]; then
  sqlite3 "$here/aegis_perf.db" "UPDATE runs SET device_id = '$device' WHERE device_id = '$host'; VACUUM;"
fi
if [ -f "$here/manifest-$host.json" ]; then
  mv "$here/manifest-$host.json" "$here/manifest-$device.json"
fi
find "$here" -type f \( -name '*.json' -o -name '*.h' -o -name '*.txt' -o -name '*.md' -o -name '*.svg' -o -name 'ORIGIN' -o -name '*.sass' \) |
while read -r f; do
  sed -i -e "s#$home/#~/#g" -e "s#~/Documents/projects/system-detection/##g" -e "s#~/Documents/projects/aegis/#<core>/#g" \
         -e "s#~/Documents/projects/aegis\b#<core>#g" -e "s#~/#<home>/#g" -e "s#$host#$device#g" -e "s#\b$user\b#<user>#g" "$f"
done
echo "scrubbed $here (host -> $device, home paths -> relative or <core>)"

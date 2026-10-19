#!/usr/bin/env bash
# Capture real Nsight fixtures for custos-model's tests (CLAUDE.md rule 27).
# Run by the user only, in a GPU window, after AEGIS Core's re-measurement:
# it profiles. Nothing in the test suite runs it.
#
#   AEGIS_CORE=<core checkout> tools/capture_fixtures.sh [OUT_DIR]
#
# What it does, under the GPU lock (rule 29):
#   1. Checks the Core build: build/bench_gemm --build-info must name a clean
#      commit (a dirty build is refused, as Core refuses it).
#   2. nsys: a quick timeline of each decode shape's winner through aegis::matmul
#      (cuda, osrt traces) -> decode-<shape>.nsys-rep -> `nsys export --type sqlite`.
#   3. ncu: full metrics (--set full, ncu's default clock control: base) of the
#      decode kernels of each shape -> decode-<shape>.ncu-rep -> CSV pages
#      (details, raw, session; --print-units base).
#   4. Writes each export's sidecar (<export>.meta.json: nsys / ncu version, the
#      build's SHA and dirty flag, synthetic: false), then scrubs the exported
#      text (host name, user, home paths, IP addresses, the profiler command
#      line's paths) so the files can be committed (rule 28).
# Then copy the files into custos-model/tests/fixtures/{nsys,ncu}/ (replacing
# the synthetic ones), run `cargo test --manifest-path custos-model/Cargo.toml`,
# and update the tests' expected values to the real capture.
#
# Environment:
#   AEGIS_CORE          Core checkout with a clean build (required)
#   CUSTOS_GPU_LOCK     lock file (default: $AEGIS_CORE/results/gpu.lock if it exists,
#                       else ${XDG_RUNTIME_DIR:-/tmp}/custos-gpu.lock); only its path is
#                       read in Core: this script creates nothing in aegis-core
#   CUSTOS_LOCK_WAIT    seconds to wait for the lock (default 600)
#   NSYS, NCU           tool paths (default: on PATH, else /usr/local/cuda/bin)
set -euo pipefail

CORE="${AEGIS_CORE:?set AEGIS_CORE to a Core checkout with a clean build}"
OUT="${1:-$(pwd)/nvtools-capture}"
BENCH="$CORE/build/bench_gemm"
WAIT="${CUSTOS_LOCK_WAIT:-600}"
tool() { command -v "$1" 2>/dev/null || { [[ -x /usr/local/cuda/bin/$1 ]] && echo "/usr/local/cuda/bin/$1"; } || true; }
NSYS="${NSYS:-$(tool nsys)}"
NCU="${NCU:-$(tool ncu)}"
[[ -n "$NSYS" ]] || { echo "nsys not installed (not on PATH, not in /usr/local/cuda/bin)" >&2; exit 2; }
[[ -n "$NCU" ]] || { echo "ncu not installed (not on PATH, not in /usr/local/cuda/bin)" >&2; exit 2; }
[[ -x "$BENCH" ]] || { echo "$BENCH not found: build Core first" >&2; exit 2; }

build="$("$BENCH" --build-info 2>/dev/null || true)"
sha="$(jq -r '.build_sha // empty' <<<"$build" 2>/dev/null || true)"
dirty="$(jq -r '.build_dirty' <<<"$build" 2>/dev/null || echo true)"
if [[ -z "$sha" || "$dirty" != false ]]; then
  echo "refusing: $BENCH is not a clean, identified build (bench_gemm --build-info: ${build:-nothing})" >&2
  exit 3
fi

if [[ -n "${CUSTOS_GPU_LOCK:-}" ]]; then LOCK="$CUSTOS_GPU_LOCK"
elif [[ -e "$CORE/results/gpu.lock" ]]; then LOCK="$CORE/results/gpu.lock"
else LOCK="${XDG_RUNTIME_DIR:-/tmp}/custos-gpu.lock"; fi
exec 9>>"$LOCK"
if ! flock -x -w "$WAIT" 9; then
  echo "GPU busy: $(head -c 300 "$LOCK" 2>/dev/null || echo 'holder unknown')" >&2
  exit 75
fi
# Core's lock convention: the holder writes itself into the file; children inherit it.
truncate -s 0 "$LOCK"
printf '%s pid %d: %s\n' "$(date -Is)" $$ "custos tools/capture_fixtures.sh" >&9
export AEGIS_GPU_LOCK_HELD=$$
trap 'truncate -s 0 "$LOCK"' EXIT

mkdir -p "$OUT"
cd "$OUT"
# Profiling permission (ncu needs GPU performance counters).
if "$NCU" --query-metrics >/dev/null 2>"$OUT/ncu-perm.txt"; then :; fi
if grep -q "ERR_NVGPUCTRPERM" "$OUT/ncu-perm.txt" 2>/dev/null; then
  cat >&2 <<'MSG'
ncu cannot read the GPU performance counters (ERR_NVGPUCTRPERM). To allow it for non-root users:
  echo 'options nvidia NVreg_RestrictProfilingToAdminUsers=0' | sudo tee /etc/modprobe.d/nvidia-profiling.conf
  sudo update-initramfs -u && reboot
or run this script with sudo for the ncu step. See https://developer.nvidia.com/ERR_NVGPUCTRPERM
MSG
  exit 4
fi

meta() { # $1 = export file, $2 = tool, $3 = version
  jq -n --arg v "$3" --arg sha "$sha" --arg tool "$2" \
    '{synthetic: false, tool: $tool, tool_version: $v, build_sha: $sha, build_dirty: false}' > "${1%.*}.meta.json"
}
nsys_v="$("$NSYS" --version | tail -1)"
ncu_v="$("$NCU" --version | tail -1)"
for shape in "1 896 896" "1 4864 896" "1 896 4864" "16 896 896" "16 4864 896" "16 896 4864"; do
  read -r m n k <<<"$shape"
  tag="decode-${m}x${n}x${k}"
  args=(--impl aegis_matmul --m "$m" --n "$n" --k "$k" --protocol 2 --cache cold --reps 20 --warmup 3)
  "$NSYS" profile --trace=cuda,osrt --sample=none --cpuctxsw=none --force-overwrite=true -o "$tag" "$BENCH" "${args[@]}" > /dev/null
  "$NSYS" export --type sqlite --force-overwrite true --output "$tag.sqlite" "$tag.nsys-rep"
  meta "$tag.sqlite" nsys "$nsys_v"
  "$NCU" --clock-control base --set full -k "regex:gemv_.*kernel" --launch-skip 3 --launch-count 1 -f -o "$tag" "$BENCH" "${args[@]}" > /dev/null
  for page in details raw session; do
    "$NCU" --import "$tag.ncu-rep" --csv --print-units base --page "$page" > "$tag.$page.csv"
  done
  meta "$tag.ncu-rep" ncu "$ncu_v"
done

# Scrub the exported text (the SQLite exports are read by the adapter, which
# never reads their environment, command-line or file-stream tables; they are
# removed here before committing).
host="$(hostname)"; user="$(id -un)"
for f in *.csv *.meta.json; do
  sed -i -E -e "s#$HOME#<home>#g" -e "s#$host#<host>#g" -e "s#\\b$user\\b#<user>#g" \
    -e 's#"Target IP Addresses","[^"]*"#"Target IP Addresses","<removed>"#' \
    -e 's#"Profiler Command Line","[^"]*"#"Profiler Command Line","ncu --clock-control base --set full (paths removed)"#' \
    -e 's#"Process Name","[^"]*"#"Process Name","<removed>"#' "$f"
done
for db in *.sqlite; do
  sqlite3 "$db" "DROP TABLE IF EXISTS TARGET_INFO_SYSTEM_ENV; DROP TABLE IF EXISTS ProcessStreams;
                 DROP TABLE IF EXISTS ANALYSIS_FILE; DROP TABLE IF EXISTS META_DATA_CAPTURE; DROP TABLE IF EXISTS PROCESSES;
                 UPDATE StringIds SET value = replace(replace(replace(value, '$HOME', '<home>'), '$host', '<host>'), '$user', '<user>');
                 VACUUM;"
  sqlite3 "$db" .dump > "${db%.sqlite}.sql"   # the tests load SQL dumps (custos-model/tests/fixtures/nsys)
done
echo "captured into $OUT (build $sha). Review, then copy into custos-model/tests/fixtures/{nsys,ncu}/."

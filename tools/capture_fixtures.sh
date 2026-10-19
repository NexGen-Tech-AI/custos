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
#   2. nsys: a timeline of each decode shape through aegis::matmul (cuda, osrt
#      traces) -> raw/<tag>.nsys-rep -> `nsys export --type sqlite`.
#   3. ncu: full metrics of the decode kernels of each shape, with
#      --clock-control passed explicitly (CUSTOS_NCU_CLOCK_CONTROL, default base)
#      -> raw/<tag>.ncu-rep -> CSV pages (details, raw, session), every page
#      with --print-units base (scaled units are not bytes).
#   4. Writes each output's sidecar (<tag>.meta.json, custos_model::sidecar):
#      nsys / ncu version, driver, CUDA (driver and toolkit), the clock control
#      passed, the build's SHA and dirty flag, and the exact command lines
#      (the Core checkout, the output directory and home written <core>,
#      <out>, <home>); synthetic: false.
#   5. Scrubs what can be committed (fixtures/: the CSV pages, the SQLite
#      exports as SQL dumps, the sidecars) of host name, user, home paths, IP
#      addresses and the process environment (rule 28), then runs the scrub
#      scan on fixtures/ (custos-model's examples/scrub_scan, the scan CI runs,
#      plus this machine's host and user). A finding fails the script: commit
#      nothing until it is clean. raw/ (the reports) is never committed.
# Then copy fixtures/{nsys,ncu}/ into custos-model/tests/fixtures/ (replacing
# the synthetic files), run `cargo test --manifest-path custos-model/Cargo.toml`,
# and update the tests' expected values to the real capture.
#
# Environment:
#   AEGIS_CORE                Core checkout with a clean build (required)
#   CUSTOS_GPU_LOCK           lock file (default: $AEGIS_CORE/results/gpu.lock if it exists,
#                             else ${XDG_RUNTIME_DIR:-/tmp}/custos-gpu.lock); only its path is
#                             read in Core: this script creates nothing in aegis-core
#   CUSTOS_LOCK_WAIT          seconds to wait for the lock (default 600)
#   CUSTOS_NCU_CLOCK_CONTROL  ncu --clock-control: base (default) or none
#   NSYS, NCU                 tool paths (default: on PATH, else /usr/local/cuda/bin)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="${AEGIS_CORE:?set AEGIS_CORE to a Core checkout with a clean build}"
CORE="$(cd "$CORE" && pwd)"
OUT="${1:-$(pwd)/nvtools-capture}"
BENCH="$CORE/build/bench_gemm"
WAIT="${CUSTOS_LOCK_WAIT:-600}"
CLOCK="${CUSTOS_NCU_CLOCK_CONTROL:-base}"
case "$CLOCK" in base|none) ;; *) echo "CUSTOS_NCU_CLOCK_CONTROL must be base or none (got $CLOCK)" >&2; exit 2 ;; esac
tool() { command -v "$1" 2>/dev/null || { [[ -x /usr/local/cuda/bin/$1 ]] && echo "/usr/local/cuda/bin/$1"; } || true; }
NSYS="${NSYS:-$(tool nsys)}"
NCU="${NCU:-$(tool ncu)}"
NVCC="$(tool nvcc)"
[[ -n "$NSYS" ]] || { echo "nsys not installed (not on PATH, not in /usr/local/cuda/bin)" >&2; exit 2; }
[[ -n "$NCU" ]] || { echo "ncu not installed (not on PATH, not in /usr/local/cuda/bin)" >&2; exit 2; }
[[ -x "$BENCH" ]] || { echo "$BENCH not found: build Core first" >&2; exit 2; }
for t in jq sqlite3 flock cargo; do command -v "$t" >/dev/null || { echo "$t not installed" >&2; exit 2; }; done

build="$("$BENCH" --build-info 2>/dev/null || true)"
sha="$(jq -r '.build_sha // empty' <<<"$build" 2>/dev/null || true)"
dirty="$(jq -r '.build_dirty' <<<"$build" 2>/dev/null || echo true)"
if [[ -z "$sha" || "$dirty" != false ]]; then
  echo "refusing: $BENCH is not a clean, identified build (bench_gemm --build-info: ${build:-nothing})" >&2
  exit 3
fi

# Build the scan before taking the lock (no GPU time spent compiling).
cargo build -q --manifest-path "$REPO/custos-model/Cargo.toml" --example scrub_scan

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

mkdir -p "$OUT/raw" "$OUT/fixtures/nsys" "$OUT/fixtures/ncu"
OUT="$(cd "$OUT" && pwd)"
RAW="$OUT/raw"; FIX="$OUT/fixtures"

# Software versions (null when a tool does not say).
nsys_v="$("$NSYS" --version | tail -1)"
ncu_v="$("$NCU" --version | tail -1)"
driver_v="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 || true)"
cuda_driver_v="$(nvidia-smi 2>/dev/null | grep -o 'CUDA Version: [0-9.]*' | head -1 | cut -d' ' -f3 || true)"
cuda_toolkit_v="$([[ -n "$NVCC" ]] && "$NVCC" --version | grep -o 'release [0-9.]*' | cut -d' ' -f2 || true)"

# Each command is run through `run`, which records its exact argv (paths
# written <core>, <out>, <home>) as one JSON array in $cmds.
cmds=()
scrub_arg() { local a="$1"; a="${a//"$CORE"/<core>}"; a="${a//"$OUT"/<out>}"; a="${a//"$HOME"/<home>}"; printf '%s' "$a"; }
record() { local x; cmds+=("$(for x in "$@"; do scrub_arg "$x"; printf '\0'; done | jq -cRs 'split("\u0000")[:-1]')"); }
run() { record "$@"; "$@"; }
meta() { # $1 = sidecar path, $2 = tool, $3 = version, $4 = clock control ("" = none)
  printf '%s\n' "${cmds[@]}" | jq -s \
    --arg tool "$2" --arg v "$3" --arg sha "$sha" --arg clock "$4" \
    --arg driver "$driver_v" --arg cudad "$cuda_driver_v" --arg cudat "$cuda_toolkit_v" \
    'def opt: if . == "" then null else . end;
     {synthetic: false, tool: $tool, tool_version: $v, build_sha: $sha, build_dirty: false,
      driver_version: ($driver|opt), cuda_driver_version: ($cudad|opt), cuda_toolkit_version: ($cudat|opt),
      clock_control: ($clock|opt), commands: .}' > "$1"
  cmds=()
}
perm_help() {
  cat >&2 <<'MSG'
ncu cannot read the GPU performance counters (ERR_NVGPUCTRPERM). To allow it for non-root users:
  echo 'options nvidia NVreg_RestrictProfilingToAdminUsers=0' | sudo tee /etc/modprobe.d/nvidia-profiling.conf
  sudo update-initramfs -u && reboot
or run this script with sudo for the ncu step. See https://developer.nvidia.com/ERR_NVGPUCTRPERM
MSG
}

for shape in "1 896 896" "1 4864 896" "1 896 4864" "16 896 896" "16 4864 896" "16 896 4864"; do
  read -r m n k <<<"$shape"
  tag="decode-${m}x${n}x${k}"
  args=(--impl aegis_matmul --m "$m" --n "$n" --k "$k" --protocol 2 --cache cold --reps 20 --warmup 3)

  run "$NSYS" profile --trace=cuda,osrt --sample=none --cpuctxsw=none --force-overwrite=true -o "$RAW/$tag" "$BENCH" "${args[@]}" > "$RAW/$tag.nsys.log" 2>&1
  run "$NSYS" export --type sqlite --force-overwrite true --output "$RAW/$tag.sqlite" "$RAW/$tag.nsys-rep" >> "$RAW/$tag.nsys.log" 2>&1
  meta "$FIX/nsys/$tag.meta.json" nsys "$nsys_v" ""

  if ! run "$NCU" --clock-control "$CLOCK" --set full -k "regex:gemv_.*kernel" --launch-skip 3 --launch-count 1 -f -o "$RAW/$tag" "$BENCH" "${args[@]}" > "$RAW/$tag.ncu.log" 2>&1; then
    grep -q ERR_NVGPUCTRPERM "$RAW/$tag.ncu.log" && { perm_help; exit 4; }
    echo "ncu failed for $tag (see $RAW/$tag.ncu.log)" >&2; exit 5
  fi
  grep -q ERR_NVGPUCTRPERM "$RAW/$tag.ncu.log" && { perm_help; exit 4; }
  for page in details raw session; do
    run "$NCU" --import "$RAW/$tag.ncu-rep" --csv --print-units base --page "$page" > "$FIX/ncu/$tag.$page.csv"
  done
  meta "$FIX/ncu/$tag.meta.json" ncu "$ncu_v" "$CLOCK"
done

# Scrub what can be committed. The CSV pages keep the profiler command line
# (the adapter reads --clock-control from it) with its paths replaced.
host="$(hostname)"; user="$(id -un)"
for f in "$FIX"/ncu/*.csv; do
  sed -i -E -e "s#$CORE#<core>#g" -e "s#$OUT#<out>#g" -e "s#$HOME#<home>#g" -e "s#$host#<host>#g" -e "s#\\b$user\\b#<user>#g" \
    -e 's#"Target IP Addresses","[^"]*"#"Target IP Addresses","<removed>"#' "$f"
done
# The SQLite exports: the adapter never reads their environment, process,
# file-stream or capture tables; they are dropped, the strings scrubbed, then
# dumped to SQL (the tests load SQL dumps: custos-model/tests/fixtures/nsys).
for db in "$RAW"/*.sqlite; do
  tag="$(basename "$db" .sqlite)"
  cp "$db" "$RAW/$tag.scrubbed.sqlite"
  sqlite3 "$RAW/$tag.scrubbed.sqlite" "DROP TABLE IF EXISTS TARGET_INFO_SYSTEM_ENV; DROP TABLE IF EXISTS ProcessStreams;
                 DROP TABLE IF EXISTS ANALYSIS_FILE; DROP TABLE IF EXISTS META_DATA_CAPTURE; DROP TABLE IF EXISTS PROCESSES;
                 UPDATE StringIds SET value = replace(replace(replace(replace(replace(value, '$CORE', '<core>'), '$OUT', '<out>'), '$HOME', '<home>'), '$host', '<host>'), '$user', '<user>');
                 VACUUM;"
  sqlite3 "$RAW/$tag.scrubbed.sqlite" .dump > "$FIX/nsys/$tag.sql"
done

# The scrub scan over everything that could be committed.
if ! cargo run -q --manifest-path "$REPO/custos-model/Cargo.toml" --example scrub_scan -- --this-machine "$FIX"; then
  echo "scrub scan failed: do not commit $FIX until it is clean (raw/ is never committed)." >&2
  exit 6
fi
echo "captured into $FIX (build $sha, ncu --clock-control $CLOCK). Review, then copy into custos-model/tests/fixtures/{nsys,ncu}/."

#!/usr/bin/env bash
# Build everything, run each target as its own process, probe it black-box
# over TCP, and write a report per target into reports/.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release -q
mkdir -p reports

run_one() {
  local impl="$1" budget="${2:-500}"
  local log="reports/$impl.target.log"
  ./target/release/scp-target --impl "$impl" --seed 1 >"$log.addr" 2>"$log.err" &
  local pid=$!
  # Wait for the ADDR= line.
  for _ in $(seq 1 100); do
    [[ -s "$log.addr" ]] && break
    sleep 0.05
  done
  local addr
  addr="$(sed -n 's/^ADDR=//p' "$log.addr" | head -1)"
  if [[ -z "$addr" ]]; then
    echo "target $impl failed to start" >&2
    cat "$log.err" >&2
    kill "$pid" 2>/dev/null || true
    return 1
  fi
  echo "=== $impl @ $addr ==="
  ./target/release/scp-probe \
    --addr "$addr" --name "$impl" \
    --max-interactions "$budget" --reps 2 --patience 2 \
    --out "reports/$impl.md" --json "reports/$impl.json" \
    >"reports/$impl.stdout" 2>"reports/$impl.stderr" || true
  grep -E '^\*\*[0-9]+ critical' "reports/$impl.md" || true
  grep -E '^### ' "reports/$impl.md" | head -20 || true
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f "$log.addr"
}

for impl in reference eager lenient sticky; do
  run_one "$impl" "${BUDGET:-500}"
done
echo "reports written to reports/"

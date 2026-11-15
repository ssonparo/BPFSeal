#!/usr/bin/env bash
set -Eeuo pipefail

cd "$HOME/bpfseal"
SOURCE="experiments/bpfseal_p1_latency.c"
BIN="experiments/bpfseal_p1_latency"
ROOT="results/performance/p1"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/full_matrix_$RUN_ID"
mkdir -p "$OUT"

exec > >(tee "$OUT/runner.log") 2>&1
trap 'echo "P1_MATRIX: FAIL at line $LINENO; results=$OUT" >&2' ERR

echo "run_id=$RUN_ID"
echo "kernel=$(uname -r)"
echo "cpus=$(nproc)"
[[ $(uname -r) == '7.0.0-2004-aws' ]] || { echo 'FAIL: unexpected kernel'; exit 1; }

TRACE=/sys/kernel/tracing
tracer=$(sudo cat "$TRACE/current_tracer")
events=$(sudo cat "$TRACE/events/enable")
kprobes=$(sudo cat "$TRACE/kprobe_events")
dynamic=$(sudo cat "$TRACE/dynamic_events")
echo "tracer=$tracer events_enabled=$events"
[[ "$tracer" == nop && "$events" == 0 && -z "$kprobes" && -z "$dynamic" ]] || {
  echo 'FAIL: tracing is not confirmed disabled'; exit 1;
}
[[ -r "$SOURCE" ]] || { echo "FAIL: missing $SOURCE"; exit 1; }

echo "source_sha256=$(sha256sum "$SOURCE" | awk '{print $1}')"
echo "compiler=$(gcc -dumpfullversion -dumpversion)"
gcc -std=gnu11 -O2 -Wall -Wextra -pthread -o "$BIN" "$SOURCE"
echo "binary_sha256=$(sha256sum "$BIN" | awk '{print $1}')"

printf 'run_id,kernel,trial,writers,ops_per_writer,successful_updates,elapsed_s,throughput_ops_s,p50_ns,p95_ns,p99_ns,csv_file\n' > "$OUT/summary.csv"

# Warm-up is NOT included in any measured CSV or summary.
echo 'Running separate warm-up (1 writer x 1000 operations)...'
sudo "$BIN" 1 1000 1 "$OUT/warmup.csv" > "$OUT/warmup.log"

for writers in 1 4 8 16; do
  for trial in 1 2 3 4 5; do
    name="w${writers}_t${trial}"
    csv="$OUT/${name}.csv"
    log="$OUT/${name}.log"
    echo "=== writers=$writers trial=$trial ops_per_writer=10000 ==="
    sudo "$BIN" "$writers" 10000 "$trial" "$csv" > "$log"
    cat "$log"
    python3 - "$log" "$csv" "$OUT/summary.csv" "$RUN_ID" "$(uname -r)" "$trial" "$writers" <<'PY'
import csv, pathlib, re, sys
log, samples, summary, run_id, kernel, trial, writers = sys.argv[1:]
text = pathlib.Path(log).read_text()
pattern = (r'P1_PASS trial=(\d+) writers=(\d+) ops_per_writer=(\d+) '
           r'successes=(\d+) elapsed_s=([0-9.]+) throughput_ops_s=([0-9.]+) '
           r'p50_ns=(\d+) p95_ns=(\d+) p99_ns=(\d+) csv=(\S+)')
m = re.search(pattern, text)
if not m:
    raise SystemExit('FAIL: missing P1_PASS measurement line')
tr, w, ops, successes = map(int, m.group(1, 2, 3, 4))
if tr != int(trial) or w != int(writers) or ops != 10000 or successes != w*ops:
    raise SystemExit('FAIL: unexpected benchmark counts')
with pathlib.Path(samples).open(newline='') as f:
    reader = csv.reader(f)
    header = next(reader)
    if header != ['trial','writers','ops_per_writer','writer','op','latency_ns']:
        raise SystemExit('FAIL: unexpected CSV header')
    rows = sum(1 for _ in reader)
if rows != successes:
    raise SystemExit(f'FAIL: raw CSV has {rows} rows, expected {successes}')
with pathlib.Path(summary).open('a', newline='') as f:
    csv.writer(f).writerow([run_id, kernel, tr, w, ops, successes,
                           *m.group(5, 6, 7, 8, 9), samples])
PY
  done
done

sha256sum "$OUT"/*.csv > "$OUT/csv_sha256.txt"
echo "results_dir=$OUT"
echo 'P1_FULL_MATRIX: PASS (measurements collected; baseline comparison not yet performed)'

#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/bpfseal"
mkdir -p results/performance/p1
log=results/performance/p1/environment_v2.txt
trace=/sys/kernel/tracing
printf 'kernel=%s\n' "$(uname -r)" | tee "$log"
printf 'cpus=%s\n' "$(nproc)" | tee -a "$log"
if [[ "$(uname -r)" != '7.0.0-2004-aws' ]]; then
  echo 'FAIL: expected patched kernel 7.0.0-2004-aws'; exit 1
fi
# Verify tracing state as root: tracefs is not readable by ordinary users.
tracer=$(sudo cat "$trace/current_tracer")
events=$(sudo cat "$trace/events/enable")
probes=$(sudo cat "$trace/kprobe_events")
dynamic=$(sudo cat "$trace/dynamic_events")
printf 'tracer=%s\nevents_enabled=%s\nregistered_kprobes=%s\nregistered_dynamic_events=%s\n' \
  "$tracer" "$events" "${probes:-none}" "${dynamic:-none}" | tee -a "$log"
if [[ "$tracer" != 'nop' || "$events" != '0' || -n "$probes" || -n "$dynamic" ]]; then
  echo 'FAIL: tracing is active or state is unexpected; no benchmark run'; exit 1
fi
if [[ ! -f experiments/bpfseal_p1_latency.c ]]; then
  echo 'FAIL: missing original benchmark source'; exit 1
fi
gcc -std=gnu11 -O2 -Wall -Wextra -pthread \
  -o experiments/bpfseal_p1_latency experiments/bpfseal_p1_latency.c
printf '%s\n' 'Preflight PASS. Running patched-kernel P1 pilot: 1 writer x 1000 updates.'
sudo ./experiments/bpfseal_p1_latency 1 1000 1 \
  results/performance/p1/pilot_1writer_trial1.csv \
  | tee results/performance/p1/pilot_summary_v2.txt
sha256sum results/performance/p1/pilot_1writer_trial1.csv

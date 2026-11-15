#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/bpfseal"
mkdir -p results/performance/p1
printf 'kernel=%s\n' "$(uname -r)" | tee results/performance/p1/environment.txt
printf 'cpus=%s\n' "$(nproc)" | tee -a results/performance/p1/environment.txt
printf 'tracer=%s\n' "$(cat /sys/kernel/tracing/current_tracer 2>/dev/null || echo unavailable)" | tee -a results/performance/p1/environment.txt
printf 'events_enabled=%s\n' "$(cat /sys/kernel/tracing/events/enable 2>/dev/null || echo unavailable)" | tee -a results/performance/p1/environment.txt
if [[ "$(uname -r)" != "7.0.0-2004-aws" ]]; then echo 'Expected patched kernel 7.0.0-2004-aws'; exit 1; fi
if [[ -s /sys/kernel/tracing/kprobe_events ]]; then echo 'Active kprobes detected; stop before benchmarking'; exit 1; fi
if [[ "$(cat /sys/kernel/tracing/events/enable 2>/dev/null || echo unknown)" != 0 ]]; then echo 'Trace-event state not confirmed disabled'; exit 1; fi
gcc -std=gnu11 -O2 -Wall -Wextra -pthread -o experiments/bpfseal_p1_latency experiments/bpfseal_p1_latency.c
sudo ./experiments/bpfseal_p1_latency 1 1000 1 results/performance/p1/pilot_1writer_trial1.csv | tee results/performance/p1/pilot_summary.txt
sha256sum results/performance/p1/pilot_1writer_trial1.csv

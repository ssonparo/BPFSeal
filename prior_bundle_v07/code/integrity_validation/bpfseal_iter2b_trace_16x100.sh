#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/bpfseal"
mkdir -p results/iteration2b/stage_b2
OUT="results/iteration2b/stage_b2/generations_16x100.txt"
TRACE=$(mktemp /tmp/bpfseal-b2-XXXXXX.bt)
trap 'rm -f "$TRACE"' EXIT
cat > "$TRACE" <<'BT'
kfunc:bpfseal_iter1c_digest
{
    @array[tid] = (uint64)args.array;
}
kretfunc:bpfseal_iter1c_digest
/@array[tid]/
{
    $array = (struct bpf_array *)@array[tid];
    $gen = $array->aux->bpfseal_generation;
    @generation_seen[$gen] = count();
    delete(@array[tid]);
}
BT
printf 'Running 16 writers x 100 updates with bpftrace...\n'
if sudo bpftrace "$TRACE" -c './experiments/bpfseal_iter2a_concurrent 16 100' > "$OUT" 2>&1; then
  echo 'Tracing exit status: 0'
else
  result=$?
  echo "Tracing exit status: $result"
  tail -n 30 "$OUT"
  exit "$result"
fi
python3 - "$OUT" <<'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(errors='replace')
entries = re.findall(r'^@generation_seen\[(\d+)\]: (\d+)$', text, re.M)
counts = {int(g): int(c) for g,c in entries}
expected = set(range(1,1603))
missing = sorted(expected - counts.keys())
extra = sorted(counts.keys() - expected)
duplicates = sorted(g for g,c in counts.items() if c != 1)
summary = re.search(r'^summary writers=(\d+) ops=(\d+) successful_updates=(\d+) failed_updates=(\d+) failed_reads=(\d+) expected_generation=(\d+)$',text,re.M)
summary_ok = bool(summary and tuple(map(int,summary.groups())) == (16,100,1600,0,0,1601) and 'CONCURRENT_TEST: PASS' in text)
print(f'expected_generations={len(expected)}')
print(f'observed_generations={len(counts)}')
print(f'missing_generations={len(missing)}')
print(f'unexpected_generations={len(extra)}')
print(f'nonunit_generation_counts={len(duplicates)}')
print("harness_summary=" + ("PASS" if summary_ok else "FAIL"))
if summary_ok and not missing and not extra and not duplicates:
    print('ITERATION2B_16_WRITER_TRACE_COVERAGE: PASS')
else:
    print('ITERATION2B_16_WRITER_TRACE_COVERAGE: INCONCLUSIVE_OR_FAIL')
    print('first_missing=',missing[:10])
    sys.exit(1)
PY

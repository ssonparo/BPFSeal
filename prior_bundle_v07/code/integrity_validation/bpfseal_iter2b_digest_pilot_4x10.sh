#!/usr/bin/env bash
# BPFSeal Iteration 2B: 4x10 pilot to inspect tagged digest capture formatting.
# Not a correctness validation; deliberately fails closed if evidence is incomplete.
set -euo pipefail
cd "$HOME/bpfseal"
DIR="results/iteration2b/stage_b2"
mkdir -p "$DIR"
BT="$DIR/digest_pilot_4x10.bt"
OUT="$DIR/digest_pilot_4x10.txt"
cat > "$BT" <<'BT'
kfunc:bpfseal_iter1c_digest
{
    @array[tid] = (uint64)args.array;
}
kretfunc:bpfseal_iter1c_digest
/@array[tid]/
{
    $array = (struct bpf_array *)@array[tid];
    $gen = $array->aux->bpfseal_generation;
    $prog = (struct bpf_prog *)$array->ptrs[0];
    @seen[$gen] = count();
    @valid[$gen] = (uint64)$array->aux->bpfseal_digest_valid;
    @digest[$gen] = buf($array->aux->bpfseal_digest, 32);
    if ($prog != 0) {
        @program_id[$gen] = (uint64)$prog->aux->id;
        @load_time[$gen] = (uint64)$prog->aux->load_time;
        @tag[$gen] = buf($prog->tag, 8);
    } else {
        @program_id[$gen] = 0;
        @load_time[$gen] = 0;
    }
    delete(@array[tid]);
}
BT
printf 'Running Stage B2 digest/metadata capture pilot (4 writers x 10 updates)...\n'
set +e
sudo bpftrace "$BT" -c './experiments/bpfseal_iter2a_concurrent 4 10' > "$OUT" 2>&1
status=$?
set -e
printf 'Tracing exit status: %s\n' "$status"
if ((status != 0)); then
  printf 'Probe failed. Last output lines:\n'
  tail -35 "$OUT"
  exit "$status"
fi
python3 - "$OUT" <<'PY'
from pathlib import Path
import re,sys
text=Path(sys.argv[1]).read_text(errors='replace')
expected=set(range(1,43))
for name,required in [('seen',expected),('valid',expected),('program_id',expected),('load_time',expected),('digest',expected),('tag',set(range(1,42)))]:
    vals=re.findall(r'^@'+name+r'\[(\d+)\]: (.*)$',text,re.M)
    keys=[int(k) for k,v in vals]
    print(f'{name}_entries={len(keys)} expected={len(required)} unique={len(set(keys))==len(keys)} coverage={set(keys)==required}')
for name in ('tag','digest'):
    records=re.findall(r'^@'+name+r'\[(\d+)\]: (.*)$',text,re.M)
    if records:
        print(f'{name}_sample_generation={records[0][0]}')
        print(f'{name}_sample_repr={records[0][1]!r}')
summary=all(s in text for s in ('successful_updates=40','failed_updates=0','failed_reads=0','CONCURRENT_TEST: PASS'))
print(f'harness_summary_pass={summary}')
print('DIGEST_PILOT: CAPTURE_ONLY; INDEPENDENT_SHA256_NOT_YET_TESTED')
PY
printf 'Output saved to: %s\n' "$OUT"

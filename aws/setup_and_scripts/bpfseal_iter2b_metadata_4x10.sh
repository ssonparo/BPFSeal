#!/usr/bin/env bash
# Stage B2: bounded pilot for recording the committed slot identity by generation.
# Does not independently verify SHA-256 yet.
set -euo pipefail
cd "$HOME/bpfseal"
mkdir -p results/iteration2b/stage_b2
OUT="results/iteration2b/stage_b2/metadata_4x10.txt"
SCRIPT="results/iteration2b/stage_b2/metadata_4x10.bt"
cat > "$SCRIPT" <<'BT'
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
    @generation_seen[$gen] = count();
    @digest_ok[$gen] = (int64)retval;
    @valid[$gen] = (int64)$array->aux->bpfseal_digest_valid;
    if ($prog != 0) {
        @program_id[$gen] = (uint64)$prog->aux->id;
        @load_time[$gen] = (uint64)$prog->aux->load_time;
    } else {
        @program_id[$gen] = 0;
        @load_time[$gen] = 0;
    }
    delete(@array[tid]);
}
BT
printf 'Running 4 writers x 10 operations; collecting per-generation metadata...\n'
set +e
sudo bpftrace "$SCRIPT" -c './experiments/bpfseal_iter2a_concurrent 4 10' > "$OUT" 2>&1
status=$?
set -e
printf 'Tracing exit status: %d\n' "$status"
if (( status != 0 )); then tail -40 "$OUT"; exit "$status"; fi
python3 - "$OUT" <<'PY'
import re, sys
from pathlib import Path
s = Path(sys.argv[1]).read_text(errors='replace')
def field(name):
    vals = re.findall(r'^@'+name+r'\[(\d+)\]: (\d+)\s*$', s, re.M)
    data = {}
    for k,v in vals:
        k=int(k);v=int(v)
        if k in data:
            raise ValueError(f'duplicate printed map entry for {name}[{k}]')
        data[k]=v
    return data
try:
    seen = field('generation_seen')
    progs = field('program_id')
    loads = field('load_time')
    valid = field('valid')
    ret = field('digest_ok')
except ValueError as ex:
    sys.exit(f'INCONCLUSIVE: {ex}')
expected=set(range(1,43))
summary_ok = all(x in s for x in ['successful_updates=40','failed_updates=0','failed_reads=0','CONCURRENT_TEST: PASS'])
keys_ok = all(set(d)==expected for d in (seen,progs,loads,valid,ret))
counts_ok=all(v==1 for v in seen.values())
nonzero_ids={v for g,v in progs.items() if g<42 and v!=0}
prog_ok=(len(nonzero_ids)==2 and all(progs.get(g,0)>0 and loads.get(g,0)>0 for g in range(1,42)) and progs.get(42)==0 and loads.get(42)==0)
checks_ok=all(v==1 for v in valid.values()) and all(v==1 for v in ret.values())
print(f'expected_generations=42 observed_generations={len(seen)}')
print(f'all_metadata_maps_complete={keys_ok}')
print(f'one_observation_per_generation={counts_ok}')
print(f'two_program_ids={len(nonzero_ids)==2}')
print(f'final_generation_empty={progs.get(42)==0}')
print(f'digest_function_success_and_valid={checks_ok}')
print(f'harness_summary_pass={summary_ok}')
if summary_ok and keys_ok and counts_ok and prog_ok and checks_ok:
    print('ITERATION2B_METADATA_PILOT: PASS')
else:
    print('ITERATION2B_METADATA_PILOT: INCONCLUSIVE_OR_FAIL')
    sys.exit(1)
PY
printf 'Trace saved: %s\n' "$OUT"

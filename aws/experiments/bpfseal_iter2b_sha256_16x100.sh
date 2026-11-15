#!/usr/bin/env bash
# BPFSeal Stage B2: 16 writer x 100 update, full generation/state/digest validation.
# Does not modify kernel or previous result files.
set -euo pipefail
cd "$HOME/bpfseal"
DIR="results/iteration2b/stage_b2"
mkdir -p "$DIR"
BT="$DIR/digest_full_16x100.bt"
OUT="$DIR/digest_full_16x100.txt"
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
printf 'Running 16 writers x 100 updates with generation/state/digest tracing...\n'
set +e
sudo env BPFTRACE_MAX_MAP_KEYS=4096 bpftrace "$BT" -c './experiments/bpfseal_iter2a_concurrent 16 100' > "$OUT" 2>&1
status=$?
set -e
printf 'Tracing exit status: %s\n' "$status"
if ((status != 0)); then
    printf 'Trace or workload failed; output tail follows:\n'
    tail -40 "$OUT"
    exit "$status"
fi
python3 experiments/bpfseal_iter2b_independent_sha256_16x100.py "$OUT"
printf 'Trace saved: %s\n' "$OUT"

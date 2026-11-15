#!/usr/bin/env python3
"""BPFSeal Iteration 2B Stage A: validate observed ioctl snapshots.

No kernel log input is needed. This does NOT prove that every committed
mutation was associated with its correct generation/state.
"""
import argparse
import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path


def fail(message):
    print(f"ITERATION2B_STAGE_A: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def one(pattern, text, label):
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        fail(f"expected one {label}, found {len(matches)}")
    return matches[0]


def expected_digest(cookie, slots, program=None):
    canonical = bytearray(28 + 64 * 17)
    canonical[:16] = b"BPFSeal-array-v1"
    canonical[16:24] = cookie.to_bytes(8, 'big')
    canonical[24:28] = slots.to_bytes(4, 'big')
    if program is not None:
        tag, load_time = program
        canonical[28] = 1
        canonical[29:37] = tag
        canonical[37:45] = load_time.to_bytes(8, 'big')
    return hashlib.sha256(canonical).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_file', type=Path)
    args = parser.parse_args()
    try:
        run = args.run_file.read_text(encoding='utf-8')
    except OSError as exc:
        fail(str(exc))

    mid, slots = map(int, one(r'^map_id=(\d+) max_entries=(\d+)\s*$', run, 'map info'))
    if slots != 1:
        fail(f'expected one-slot PROG_ARRAY, got {slots}')

    programs = {}
    for name, tag, load_time, pid in re.findall(
        r'^program=([AB]) tag=([0-9a-f]{16}) load_time=(\d+) id=(\d+)\s*$', run, re.MULTILINE
    ):
        if name in programs:
            fail(f'duplicate program {name}')
        programs[name] = (bytes.fromhex(tag), int(load_time))
    if set(programs) != {'A', 'B'}:
        fail('missing A/B program metadata')

    w, ops, ok, bad, readbad, last = map(int, one(
        r'^summary writers=(\d+) ops=(\d+) successful_updates=(\d+) failed_updates=(\d+) failed_reads=(\d+) expected_generation=(\d+)\s*$',
        run, 'summary'))
    if w not in (4, 8, 16) or not 1 <= ops <= 100:
        fail('unsupported writers/ops')
    if ok != w * ops or bad or readbad or last != ok + 1:
        fail('harness summary inconsistent or contains errors')
    if len(re.findall(r'^CONCURRENT_TEST: PASS\s*$', run, re.MULTILINE)) != 1:
        fail('harness did not report PASS')

    rows = re.findall(
        r'^snapshot reader=(\d+) gen=(\d+) map=(\d+) cookie=(\d+) digest=([0-9a-f]{64})\s*$',
        run, re.MULTILINE)
    if not rows:
        fail('no snapshots recorded')
    final_gen, final_cookie, final_digest = one(
        r'^final gen=(\d+) cookie=(\d+) digest=([0-9a-f]{64})\s*$', run, 'final evidence')
    final_gen, final_cookie = int(final_gen), int(final_cookie)
    if final_gen != last:
        fail(f'final generation {final_gen} does not match expected {last}')

    expected_a = expected_digest(final_cookie, slots, programs['A'])
    expected_b = expected_digest(final_cookie, slots, programs['B'])
    if expected_a == expected_b:
        fail('A/B states not cryptographically distinguishable')
    allowed = {expected_a, expected_b}
    if final_digest not in allowed:
        fail('final digest does not match independently calculated state A or B')

    readers = set()
    last_by_reader = {}
    observations = defaultdict(set)
    counts = defaultdict(int)
    for reader_s, gen_s, mid_s, cookie_s, digest in rows:
        reader, gen = int(reader_s), int(gen_s)
        readers.add(reader)
        counts[reader] += 1
        if reader not in range(4):
            fail(f'unexpected reader ID {reader}')
        if int(mid_s) != mid or int(cookie_s) != final_cookie:
            fail(f'map identity/cookie mismatch at reader={reader} gen={gen}')
        if not 1 <= gen <= last:
            fail(f'out of range generation {gen}')
        if gen < last_by_reader.get(reader, 0):
            fail(f'reader {reader} generation regressed {last_by_reader[reader]} -> {gen}')
        last_by_reader[reader] = gen
        if digest not in allowed:
            fail(f'unknown state digest at generation {gen}')
        observations[gen].add(digest)
        if len(observations[gen]) != 1:
            fail(f'conflicting digests for the same generation {gen}')
    if readers != {0, 1, 2, 3}:
        fail(f'expected readers 0..3, found {sorted(readers)}')
    if (last in observations and final_digest not in observations[last]):
        fail('final digest differs from snapshot of the same generation')
    if len(observations) < 2:
        print('ITERATION2B_STAGE_A: INCONCLUSIVE: fewer than 2 generations sampled')
        sys.exit(2)

    print(f'kernel_log_dependency=NONE')
    print(f'writers={w} ops_per_writer={ops} successful_updates={ok}')
    print(f'checked_snapshots={len(rows)} reader_counts={dict(sorted(counts.items()))}')
    print(f'distinct_observed_generations={len(observations)} expected_total_generations={last}')
    print('independent_sha256_allowed_states=PASS')
    print('observed_same_generation_same_digest=PASS')
    print('reader_generation_monotonicity=PASS')
    print('final_generation_and_digest=PASS')
    print('complete_generation_to_state_correctness=NOT_TESTED')
    print('ITERATION2B_STAGE_A: PASS')


if __name__ == '__main__':
    main()

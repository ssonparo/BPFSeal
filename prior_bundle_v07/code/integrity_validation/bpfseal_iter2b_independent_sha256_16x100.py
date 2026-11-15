#!/usr/bin/env python3
"""Fail-closed independent verification of BPFSeal Iteration 2B 16x100 trace.

Requires raw output of bpfseal_iter2b_sha256_16x100.sh and
its kernel's known canonical BPFSeal-array-v1 SHA-256 layout.
"""
import hashlib
import re
import sys
from pathlib import Path

EXPECTED = 1602  # initial + 16*100 + final delete
PREFIX = b'BPFSeal-array-v1'
CANONICAL_LEN = 28 + 64 * 17


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def bpftrace_bytes(s):
    """Decode bpftrace text-format buf: printable bytes and \\xHH escapes.

    Reject ambiguous escaping, truncation, raw Unicode and incorrect lengths.
    """
    out = bytearray()
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == '\\':
            require(i + 1 < len(s), 'dangling backslash in buf')
            if s[i + 1] == 'x':
                require(i + 3 < len(s) and re.fullmatch(r'[0-9a-fA-F]{2}', s[i + 2:i + 4]),
                        'bad \\x escape in buf')
                out.append(int(s[i + 2:i + 4], 16))
                i += 4
            else:
                # bpftrace can escape punctuation; accept literal escaped byte,
                # but disallow C control-character escapes (ambiguous in raw text).
                require(s[i + 1] in r'\\`"\'*?[]{}()$%&|;:,.+-/=<>!@#^~ ',
                        f'unsupported backslash escape: {s[i:i+2]!r}')
                out.append(ord(s[i + 1]))
                i += 2
        else:
            require(32 <= ord(ch) <= 126, 'non-ASCII or control character in buf')
            out.append(ord(ch))
            i += 1
    return bytes(out)


def records(text, name):
    entries = re.findall(r'^@' + name + r'\[(\d+)\]: (.*)$', text, re.M)
    out = {}
    for k, value in entries:
        key = int(k)
        require(key not in out, f'duplicate {name}[{key}]')
        out[key] = value
    require(set(out) == set(range(1, EXPECTED + 1)) - (set([EXPECTED]) if name == 'tag' else set()),
            f'{name}: expected {EXPECTED - (name == "tag")} keys; got {len(out)}; missing={sorted(set(range(1, EXPECTED+1)) - set(out))[:8]}')
    return out


def numeric(records_dict, name):
    out = {}
    for g, s in records_dict.items():
        require(bool(re.fullmatch(r'\d+', s)), f'non-numeric {name}[{g}]')
        out[g] = int(s)
    return out


def main(path):
    text = Path(path).read_text(encoding='utf-8')
    require('CONCURRENT_TEST: PASS' in text, 'harness not PASS')
    summary = re.search(r'^summary writers=(\d+) ops=(\d+) successful_updates=(\d+) failed_updates=(\d+) failed_reads=(\d+) expected_generation=(\d+)$', text, re.M)
    require(summary is not None, 'missing harness summary')
    require(tuple(map(int, summary.groups())) == (16, 100, 1600, 0, 0, 1601), 'unexpected harness counters')
    mapdata = re.search(r'^map_id=(\d+) max_entries=(\d+)$', text, re.M)
    require(mapdata is not None and int(mapdata[2]) == 1, 'missing or incorrect 1-slot map')
    mid = int(mapdata[1])
    snap = re.findall(r'^snapshot reader=\d+ gen=\d+ map=(\d+) cookie=(\d+) digest=[0-9a-f]{64}$', text, re.M)
    require(bool(snap), 'no snapshots to identify map cookie')
    require(all(int(m) == mid for m, _ in snap), 'snapshot map ID mismatch')
    cookies = {int(c) for _, c in snap}
    require(len(cookies) == 1, 'missing/inconsistent map cookie')
    cookie = next(iter(cookies))
    require(0 <= cookie < 1 << 64, 'cookie out of range')

    seen = numeric(records(text, 'seen'), 'seen')
    valid = numeric(records(text, 'valid'), 'valid')
    ids = numeric(records(text, 'program_id'), 'program_id')
    loads = numeric(records(text, 'load_time'), 'load_time')
    digests = {g: bpftrace_bytes(s) for g, s in records(text, 'digest').items()}
    tags = {g: bpftrace_bytes(s) for g, s in records(text, 'tag').items()}
    require(all(x == 1 for x in seen.values()), 'generation seen count not 1')
    require(all(x == 1 for x in valid.values()), 'one or more invalid digests')
    require(all(len(d) == 32 for d in digests.values()), 'digest bytes not 32')
    require(all(len(tag) == 8 for tag in tags.values()), 'tag bytes not 8')
    require(all(ids[g] > 0 and loads[g] > 0 for g in range(1, EXPECTED)), 'missing nonempty program metadata')
    require(ids[EXPECTED] == 0 and loads[EXPECTED] == 0, 'final deletion not empty')
    require(len({ids[g] for g in range(1, EXPECTED)}) == 2, 'did not observe two program identities')
    require(all(0 <= t < (1 << 64) for t in loads.values()), 'load time out of range')

    # Compare trace metadata with independent userspace BPF_OBJ_GET_INFO_BY_FD output.
    progs = {}
    for name, taghex, load, progid in re.findall(
            r'^program=([AB]) tag=([0-9a-f]{16}) load_time=(\d+) id=(\d+)$', text, re.M):
        require(name not in progs, f'duplicate program {name}')
        progs[name] = (int(progid), int(load), bytes.fromhex(taghex))
    require(set(progs) == {'A', 'B'}, 'missing program A/B info')
    by_id = {v[0]: v[1:] for v in progs.values()}
    require(len(by_id) == 2, 'A and B share ID')

    for g in range(1, EXPECTED + 1):
        buf = bytearray(CANONICAL_LEN)
        buf[:16] = PREFIX
        buf[16:24] = cookie.to_bytes(8, 'big')
        buf[24:28] = (1).to_bytes(4, 'big')
        if g < EXPECTED:
            require(ids[g] in by_id, f'unknown program ID gen {g}: {ids[g]}')
            load, tag = by_id[ids[g]]
            require(loads[g] == load and tags[g] == tag,
                    f'trace metadata disagrees with userspace info gen {g}')
            buf[28] = 1
            buf[29:37] = tags[g]
            buf[37:45] = loads[g].to_bytes(8, 'big')
        expected_digest = hashlib.sha256(buf).digest()
        require(digests[g] == expected_digest,
                f'SHA-256 mismatch at gen {g}: observed={digests[g].hex()} expected={expected_digest.hex()}')
    print(f'generation_coverage={EXPECTED}/{EXPECTED} PASS')
    print('trace_metadata_matches_program_info=PASS')
    print(f'independent_sha256_commitments={EXPECTED}/{EXPECTED} PASS')
    print('concurrent_writers=16 updates_per_writer=100')
    print('ITERATION2B_STAGE_B2_16X100_SHA256: PASS')
    print('full_16_writer_SHA256=PASS')


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 2, 'usage: python3 bpfseal_iter2b_independent_sha256_4x10.py TRACE_FILE')
        main(sys.argv[1])
    except (ValueError, OSError, UnicodeError) as error:
        print(f'ITERATION2B_STAGE_B2_16X100_SHA256: FAIL: {error}', file=sys.stderr)
        sys.exit(1)

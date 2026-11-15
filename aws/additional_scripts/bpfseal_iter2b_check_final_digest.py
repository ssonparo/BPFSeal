#!/usr/bin/env python3
"""Read-only forensic comparison of final empty-map digest with raw bpftrace data."""
import hashlib
import importlib.util
import re
from pathlib import Path

root = Path.home() / 'bpfseal'
trace = root / 'results/iteration2b/stage_b2/digest_full_16x100.txt'
validator = root / 'experiments/bpfseal_iter2b_independent_sha256_16x100.py'
spec = importlib.util.spec_from_file_location('bpfseal_validator', validator)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
text = trace.read_text(encoding='utf-8')
cookies = {int(c) for c in re.findall(r'^snapshot reader=\d+ gen=\d+ map=\d+ cookie=(\d+) digest=[0-9a-f]{64}$', text, re.M)}
assert len(cookies) == 1, f'Expected exactly one map cookie; found {len(cookies)}'
cookie = next(iter(cookies))
raw = re.findall(r'^@digest\[1602\]: (.*)$', text, re.M)
assert len(raw) == 1, f'Expected exactly one final digest; found {len(raw)}'
observed = module.bpftrace_bytes(raw[0])
canonical = bytearray(28 + 64 * 17)
canonical[:16] = b'BPFSeal-array-v1'
canonical[16:24] = cookie.to_bytes(8, 'big')
canonical[24:28] = (1).to_bytes(4, 'big')
expected = hashlib.sha256(canonical).digest()
print(f'final_generation=1602 map_cookie={cookie}')
print(f'raw_repr={raw[0]!r}')
print(f'decoded_length={len(observed)} expected_length=32')
print(f'decoded_hex={observed.hex()}')
print(f'independent_empty_state_sha256={expected.hex()}')
print(f'exact_match={observed == expected}')
if len(observed) == 31:
    repairs = [(i, expected[i]) for i in range(32) if observed[:i] == expected[:i] and observed[i:] == expected[i+1:]]
    print(f'single_missing_byte_candidates={[(i, f"{b:02x}") for i,b in repairs]}')
    print('diagnosis=INCOMPLETE_RECORD_OR_ENCODING_UNRESOLVED')
else:
    print('diagnosis=EXACT_MATCH' if observed == expected else 'diagnosis=DIGEST_MISMATCH')
print('trace_modified=NO')

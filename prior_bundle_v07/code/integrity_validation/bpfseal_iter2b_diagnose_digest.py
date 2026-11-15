#!/usr/bin/env python3
"""Read-only diagnosis of bpftrace digest encoding in Stage B2 16x100 output."""
import importlib.util
import re
import sys
from pathlib import Path

TRACE = Path.home() / 'bpfseal/results/iteration2b/stage_b2/digest_full_16x100.txt'
VALIDATOR = Path.home() / 'bpfseal/experiments/bpfseal_iter2b_independent_sha256_16x100.py'

if not TRACE.is_file() or not VALIDATOR.is_file():
    sys.exit(f'MISSING_FILE: trace={TRACE.is_file()} validator={VALIDATOR.is_file()}')

spec = importlib.util.spec_from_file_location('bpfseal_existing_validator', VALIDATOR)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
raw = TRACE.read_text(encoding='utf-8', errors='replace')
records = re.findall(r'^@digest\[(\d+)\]: (.*)$', raw, re.MULTILINE)
print(f'digest_records={len(records)}')
print(f'trace_bytes={TRACE.stat().st_size}')
print(f'replacement_characters={raw.count(chr(0xfffd))}')
problems = []
length_hist = {}
for gstr, value in records:
    g = int(gstr)
    try:
        data = mod.bpftrace_bytes(value)
        length_hist[len(data)] = length_hist.get(len(data), 0) + 1
        if len(data) != 32:
            problems.append((g, f'decoded_length={len(data)}', value))
    except Exception as exc:
        problems.append((g, f'decode_error={exc}', value))
print('decoded_length_histogram=' + str(dict(sorted(length_hist.items()))))
print(f'problem_count={len(problems)}')
for g, reason, value in problems[:12]:
    print(f'bad_gen={g} {reason} raw_length={len(value)} raw_repr={value!r}')
print('diagnostic_only=YES; trace_not_modified=YES')

#!/usr/bin/env python3
"""Independent BPFSeal Iteration 2B B1 sequential state-to-generation check."""
import hashlib
import re
import sys
from pathlib import Path

def fail(message):
    sys.exit('B1_VALIDATION: FAIL: ' + message)

if len(sys.argv) != 2:
    sys.exit('Usage: python3 bpfseal_iter2b_b1_validate.py RUN_OUTPUT')
s = Path(sys.argv[1]).read_text()
progs = {}
for name, tag, load_time, pid in re.findall(r'^program=([AB]) tag=([0-9a-f]{16}) load_time=(\d+) id=(\d+)$', s, re.M):
    if name in progs: fail('duplicate program metadata')
    progs[name] = bytes.fromhex(tag), int(load_time)
if set(progs) != {'A','B'}: fail('missing program metadata')
rows = re.findall(r'^step=(\d+) state=([AB]) gen=(\d+) map=(\d+) cookie=(\d+) digest=([0-9a-f]{64})$',s,re.M)
if len(rows)!=64: fail(f'expected 64 steps; found {len(rows)}')
pattern='AABBABBA'
map_ids=set(); cookies=set(); digests={'A':set(),'B':set()}
for index, (st, state, gen, mapid, cookie, digest) in enumerate(rows,1):
    st,gen,mapid,cookie = map(int,(st,gen,mapid,cookie))
    if st!=index or gen!=index or state!=pattern[(index-1)%8]: fail(f'step/state/generation mismatch at row {index}')
    map_ids.add(mapid); cookies.add(cookie)
    if mapid==0 or cookie==0: fail('invalid map identity')
    if not 0 <= progs[state][1] < (1<<64): fail('invalid load_time')
    canonical=bytearray(28 + 64*17)
    canonical[:16]=b'BPFSeal-array-v1'
    canonical[16:24]=cookie.to_bytes(8,'big')
    canonical[24:28]=(1).to_bytes(4,'big')
    canonical[28]=1
    canonical[29:37]=progs[state][0]
    canonical[37:45]=progs[state][1].to_bytes(8,'big')
    expected=hashlib.sha256(canonical).hexdigest()
    if digest!=expected: fail(f'independent SHA-256 mismatch at generation {gen} state {state}')
    digests[state].add(digest)
if len(map_ids)!=1 or len(cookies)!=1: fail('inconsistent map identity')
if len(digests['A'])!=1 or len(digests['B'])!=1 or digests['A']==digests['B']:
    fail('unexpected state digest equivalence/variation')
summary=re.search(r'^summary steps=(\d+) final_generation=(\d+)$',s,re.M)
if not summary or tuple(map(int,summary.groups()))!=(64,64) or 'B1_HARNESS: PASS' not in s:
    fail('missing or invalid harness summary')
print('steps=64 independent_generation_to_state_sha256=PASS')
print('repeated_A_and_B_updates=TESTED')
print('sequential_reference_validation=PASS')
print('concurrent_commit_order_validation=NOT_TESTED')
print('ITERATION2B_STAGE_B1: PASS')

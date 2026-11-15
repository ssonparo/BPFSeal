#!/usr/bin/env python3
"""Independently reproduce BPFSeal Iteration 1C map-local SHA256 digests."""
import hashlib
import re
import sys
from pathlib import Path

if len(sys.argv) != 3:
    sys.exit('Usage: python3 bpfseal_verify_sha256.py RESTORE_RUN.txt COOKIE_DIGEST_EVENTS.txt')
run = Path(sys.argv[1]).read_text()
logs = Path(sys.argv[2]).read_text()
mapmatch = re.search(r'^map_id=(\d+) max_entries=(\d+)$',run,re.M)
if not mapmatch:
    sys.exit('FAIL: missing map_id/max_entries info')
mapid, nslots = map(int,mapmatch.groups())
if not (1 <= nslots <= 64):
    sys.exit(f'FAIL: unsupported slot count {nslots}')
progs = {}
for name, tag, load_time, prog_id in re.findall(r'^program=(A|B) tag=([0-9a-f]{16}) load_time=(\d+) id=(\d+)$',run,re.M):
    progs[name] = (bytes.fromhex(tag),int(load_time),int(prog_id))
if set(progs) != {'A','B'}:
    sys.exit(f'FAIL: missing program metadata: {set(progs)}')
events = re.findall(r'BPFSEAL_ITER1C (update|delete) map=(\d+) cookie=(\d+) gen=(\d+) digest=([0-9a-f]{64})',logs)
events = [(op,int(mid),int(cookie),int(gen),digest) for op,mid,cookie,gen,digest in events]
events = [e for e in events if e[1]==mapid]
if len(events)!=5 or [e[3] for e in events]!=[1,2,3,4,5]:
    sys.exit(f'FAIL: expected five ordered events, found generations {[e[3] for e in events]}')
if len({e[2] for e in events})!=1:
    sys.exit('FAIL: multiple map cookies')
cookie = events[0][2]
# Exact format from kernel Iteration 1C: 16-byte ASCII domain,
# 8-byte big-endian cookie, 4-byte big-endian max_entries,
# 64 fixed 17-byte slot entries (occupancy + 8-byte tag + 8-byte load_time).
# Only slot 0 is used; the remaining 63 slots remain zero.
base = bytearray(28 + 64*17)
base[:16] = b'BPFSeal-array-v1'
base[16:24] = cookie.to_bytes(8,'big')
base[24:28] = nslots.to_bytes(4,'big')
all_ok = True
for event,state in zip(events,['A','A','B','A',None]):
    data = bytearray(base)
    if state is not None:
        tag, load_time, _ = progs[state]
        data[28] = 1
        data[29:37] = tag
        data[37:45] = load_time.to_bytes(8,'big')
    recomputed = hashlib.sha256(data).hexdigest()
    matched = recomputed == event[4]
    all_ok &= matched
    print(f'gen={event[3]} state={state or "empty"} SHA256={"PASS" if matched else "FAIL"} calculated={recomputed} kernel={event[4]}')
print('INDEPENDENT_VERIFICATION:', 'PASS' if all_ok else 'FAIL')
sys.exit(0 if all_ok else 1)

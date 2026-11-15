#!/usr/bin/env python3
"""Validate exactly one map's five Iteration-1C transitions from dmesg log."""
from pathlib import Path
import re, sys
path=Path(sys.argv[1] if len(sys.argv)>1 else 'results/iteration1c/restore_events.txt')
lines=path.read_text().splitlines()
pat=re.compile(r'BPFSEAL_ITER1C (update|delete) map=(\d+) gen=(\d+) digest=([0-9a-f]{64})')
events=[]
for line in lines:
    m=pat.search(line)
    if m: events.append((m.group(1),int(m.group(2)),int(m.group(3)),m.group(4)))
if len(events)!=5:
    sys.exit(f'FAIL: expected 5 digest events, observed {len(events)}; check log collection')
maps={ev[1] for ev in events}
if len(maps)!=1:
    sys.exit(f'FAIL: expected one map, found {maps}')
events.sort(key=lambda e:e[2])
ops=[e[0] for e in events]
gens=[e[2] for e in events]
h=[e[3] for e in events]
checks={
    'generation_sequence_1_to_5':gens==[1,2,3,4,5],
    'four_updates_then_delete':ops==['update']*4+['delete'],
    'same_object_updated_twice_same_digest':h[0]==h[1],
    'target_B_changes_digest':h[1]!=h[2],
    'same_object_A_restoration':h[0]==h[3],
    'delete_changes_digest':h[3]!=h[4],
}
for name,ok in checks.items(): print(f'{name}: {"PASS" if ok else "FAIL"}')
print('digest_A:',h[0]);print('digest_B:',h[2]);print('digest_restored_A:',h[3]);print('digest_empty:',h[4])
if not all(checks.values()):sys.exit(1)
print('OVERALL: PASS')

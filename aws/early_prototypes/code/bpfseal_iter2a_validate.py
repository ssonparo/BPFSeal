#!/usr/bin/env python3
"""Check synchronized snapshots against canonical SHA256 and per-generation kernel event history."""
import hashlib,re,sys
from pathlib import Path
if len(sys.argv)!=3:sys.exit('Usage: python3 bpfseal_iter2a_validate.py RUN.txt KERNEL_EVENTS.txt')
run=Path(sys.argv[1]).read_text(); logs=Path(sys.argv[2]).read_text()
header=re.search(r'^map_id=(\d+) max_entries=(\d+)$',run,re.M)
if not header:sys.exit('FAIL missing map info')
mid,slots=map(int,header.groups())
if slots!=1:sys.exit('FAIL validator designed for one-slot map')
progs={}
for name,tag,tm,pid in re.findall(r'^program=([AB]) tag=([0-9a-f]{16}) load_time=(\d+) id=(\d+)$',run,re.M):progs[name]=(bytes.fromhex(tag),int(tm),int(pid))
if len(progs)!=2:sys.exit('FAIL missing program metadata')
events={}
for event_mid,cookie,gen,digest in re.findall(r'BPFSEAL_ITER1C update map=(\d+) cookie=(\d+) gen=(\d+) digest=([0-9a-f]{64})',logs):
    if int(event_mid)==mid:
        gen=int(gen)
        if gen in events and events[gen]!=(int(cookie),digest):sys.exit(f'FAIL conflicting event for generation {gen}')
        events[gen]=(int(cookie),digest)
summary=re.search(r'^summary writers=(\d+) ops=(\d+) successful_updates=(\d+) failed_updates=(\d+) failed_reads=(\d+) expected_generation=(\d+)$',run,re.M)
if not summary:sys.exit('FAIL missing summary')
w,ops,ok,bad,readbad,last=map(int,summary.groups())
if ok!=w*ops or bad or readbad or last!=1+ok or 'CONCURRENT_TEST: PASS' not in run:sys.exit('FAIL harness outcome')
if set(events)!=set(range(1,last+1)):sys.exit(f'FAIL missing kernel events: got {len(events)} expected {last}')
cookies={c for c,d in events.values()}
if len(cookies)!=1:sys.exit('FAIL inconsistent map cookie')
cookie=cookies.pop()
def expected(state):
    b=bytearray(28+64*17);b[:16]=b'BPFSeal-array-v1';b[16:24]=cookie.to_bytes(8,'big');b[24:28]=slots.to_bytes(4,'big')
    if state:
        tag,t,_=progs[state];b[28]=1;b[29:37]=tag;b[37:45]=t.to_bytes(8,'big')
    return hashlib.sha256(b).hexdigest()
valid={expected('A'),expected('B')}
if len(valid)!=2:sys.exit('FAIL unable to distinguish program states')
for g,(c,d) in events.items():
    if d not in valid:sys.exit(f'FAIL kernel commitment unknown at gen {g}')
samples=re.findall(r'^snapshot reader=(\d+) gen=(\d+) map=(\d+) cookie=(\d+) digest=([0-9a-f]{64})$',run,re.M)
if not samples:sys.exit('FAIL no reader samples')
readers=set(); observed=set(); last_read={}; checked=0
for reader,gen,smid,scookie,d in samples:
    reader=int(reader);gen=int(gen);readers.add(reader);observed.add(gen)
    if int(smid)!=mid or int(scookie)!=cookie or gen not in events:sys.exit(f'FAIL invalid snapshot identity/gen {gen}')
    if d!=events[gen][1]:sys.exit(f'FAIL mixed generation/digest at gen {gen}')
    if gen<last_read.get(reader,0):sys.exit(f'FAIL reader {reader} generation went backward')
    last_read[reader]=gen;checked+=1
final=re.search(r'^final gen=(\d+) cookie=(\d+) digest=([0-9a-f]{64})$',run,re.M)
if not final or int(final[1])!=last or int(final[2])!=cookie or final[3]!=events[last][1]:sys.exit('FAIL final snapshot mismatch')
if len(readers)!=4:sys.exit(f'FAIL expected 4 readers, got {len(readers)}')
if len(observed)<2:sys.exit('INCONCLUSIVE: readers did not observe multiple generations')
print(f'kernel_events={len(events)} complete_contiguous=PASS')
print(f'independent_sha256_states=2 PASS')
print(f'checked_snapshots={checked} readers={len(readers)} distinct_generations={len(observed)}')
print('snapshot_generation_digest_consistency=PASS')
print('final_snapshot=PASS')
print('ITERATION2A_CONCURRENT_VALIDATION: PASS')

#!/usr/bin/env python3
"""BPFSeal offline replay: SHA-256 provenance, B2 verifier, and performance data.

Usage:
    python3 BPFSeal_replay_archived_results.py /path/to/extracted/BPFSeal_Evidence [output_dir]

No root privilege, network access, kernel build or EC2 instance required.
The 5-trial quartiles use linear percentile interpolation (numpy/Pandas default).
"""
import csv
import hashlib
import math
import pathlib
import statistics
import subprocess
import sys

RUNS = [
    ('2004_logging','full_matrix_20261102T225927Z','7.0.0-2004-aws'),
    ('2005_baseline','full_matrix_20261103T101544Z','7.0.0-2005-aws'),
    ('2006_no_logging','full_matrix_20261103T143835Z','7.0.0-2006-aws'),
    ('2007_no_hash','full_matrix_20261103T161719Z','7.0.0-2007-aws'),
]

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''):h.update(b)
    return h.hexdigest()

def quantile(a,p):
    x=sorted(a)
    n=(len(x)-1)*p
    i=math.floor(n); f=n-i
    return x[i]*(1-f) + x[min(i+1,len(x)-1)]*f

def run(root, out):
    root=pathlib.Path(root).resolve()
    out=pathlib.Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    manifest=root/'exports/collection_20261103T185318Z/original_file_sha256.txt'
    entries=0
    for line in manifest.read_text().splitlines():
        digest, rel=line.split('  ',1)
        target=root/rel
        if not target.is_file() or sha(target)!=digest:raise RuntimeError(f'SHA mismatch: {rel}')
        entries+=1
    print('SHA256_MANIFEST_PASS:', entries, 'files')
    trace=root/'results/iteration2b/final_archive/digest_full_16x100.txt'
    verify=root/'results/iteration2b/final_archive/bpfseal_iter2b_independent_sha256_16x100_v2.py'
    print('B2 raw trace sha256:',sha(trace))
    print('B2 verifier sha256:',sha(verify))
    r=subprocess.run([sys.executable,str(verify),str(trace)],capture_output=True,text=True)
    print(r.stdout,end='')
    if r.returncode:raise RuntimeError(r.stderr)
    (out/'b2_replay.txt').write_text(r.stdout,encoding='utf-8')
    all_rows=[]; medians={}
    for label,run_id,kernel in RUNS:
        rdir=root/'results/performance/p1'/run_id
        with (rdir/'summary.csv').open(newline='') as f:
            summary=list(csv.DictReader(f))
        if len(summary)!=20 or set(int(x['writers']) for x in summary)!={1,4,8,16}:
            raise RuntimeError(f'Missing trial rows: {run_id}')
        batches={}
        for item in summary:
            w=int(item['writers']);tr=int(item['trial']);success=int(item['successful_updates'])
            assert item['kernel']==kernel and int(item['ops_per_writer'])==10000 and success==w*10000
            csvpath=root/item['csv_file']
            # Stream full latency CSVs; validate every trial count, schema and identity.
            n=0
            with csvpath.open(newline='') as f:
                rd=csv.DictReader(f)
                for rec in rd:
                    if int(rec['trial'])!=tr or int(rec['writers'])!=w or int(rec['latency_ns'])<=0:
                        raise RuntimeError(f'Unexpected raw trial record: {csvpath}')
                    n+=1
            if n!=success:raise RuntimeError(f'Raw trial count {n} != {success}: {csvpath}')
            batches.setdefault(w,[]).append(float(item['throughput_ops_s']))
        assert all(len(v)==5 for v in batches.values())
        for w in (1,4,8,16):
            xs=batches[w]
            median=statistics.median(xs)
            all_rows.append(dict(variant=label,kernel=kernel,writers=w,trials=5,
                 operations_total=w*10000*5,
                 median_ops_s=f'{median:.2f}',q1_ops_s=f'{quantile(xs,.25):.2f}',
                 q3_ops_s=f'{quantile(xs,.75):.2f}',min_ops_s=f'{min(xs):.2f}',max_ops_s=f'{max(xs):.2f}'))
            medians[label,w]=median
            print(label,w,f'median={median:,.2f} q1={quantile(xs,.25):,.2f} q3={quantile(xs,.75):,.2f}')
    for w in (1,4,8,16):
        b=medians['2005_baseline',w]; s=medians['2006_no_logging',w];nohash=medians['2007_no_hash',w]
        print(f'COMPARISON writers={w} throughput_reduction_pct={100*(1-s/b):.2f} nohash_speedup_x={nohash/s:.3f}')
    with (out/'performance_replay.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(all_rows[0]));writer.writeheader();writer.writerows(all_rows)
    print('FULL_REPLAY_PASS: 4 kernels × 20 trials, 5,800,000 raw latency records')
    print('output:',out/'performance_replay.csv')

if __name__=='__main__':
    if not 2<=len(sys.argv)<=3:sys.exit('Usage: python3 BPFSeal_replay_archived_results.py EXTRACTED_ROOT [OUT_DIR]')
    run(sys.argv[1],sys.argv[2] if len(sys.argv)==3 else './bpfseal_replay')

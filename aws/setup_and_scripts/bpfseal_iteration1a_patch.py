#!/usr/bin/env python3
"""Strict, source-specific BPFSeal Iteration 1A diagnostic patch for Linux 7.0 AWS.
Run from the ROOT of linux-aws-7.0-bpfseal-patched.
This deliberately does not implement authenticated state or attestation.
"""
from pathlib import Path
import sys

p = Path('kernel/bpf/arraymap.c')
if not p.exists():
    raise SystemExit('ERROR: run from the patched Linux source root')
s = p.read_text()
if 'BPFSEAL_ITER1A' in s:
    raise SystemExit('ERROR: diagnostic patch already applied; refusing duplicate')

# This insertion is intentionally after both xchg paths and before releasing
# the old program reference. It observes the result; it is not an atomic
# authenticated-state publication mechanism.
old_update = '''\tif (old_ptr)
\t\tmap->ops->map_fd_put_ptr(map, old_ptr, true);

\treturn 0;
}'''
new_update = '''\t/* BPFSEAL_ITER1A: diagnostic observation only, not attestation. */
\tif (map->map_type == BPF_MAP_TYPE_PROG_ARRAY) {
\t\tstruct bpf_prog *before = old_ptr;
\t\tstruct bpf_prog *after = new_ptr;

\t\tpr_info("BPFSEAL_ITER1A update map=%u slot=%u old=%u new=%u\\n",
\t\t\tmap->id, index,
\t\t\tbefore ? before->aux->id : 0,
\t\t\tafter ? after->aux->id : 0);
\t}

\tif (old_ptr)
\t\tmap->ops->map_fd_put_ptr(map, old_ptr, true);

\treturn 0;
}'''

old_delete = '''\tif (old_ptr) {
\t\tmap->ops->map_fd_put_ptr(map, old_ptr, need_defer);
\t\treturn 0;
\t} else {
\t\treturn -ENOENT;
\t}
}'''
new_delete = '''\tif (old_ptr) {
\t\t/* BPFSEAL_ITER1A: report only successful removal. */
\t\tif (map->map_type == BPF_MAP_TYPE_PROG_ARRAY) {
\t\t\tstruct bpf_prog *before = old_ptr;

\t\t\tpr_info("BPFSEAL_ITER1A delete map=%u slot=%u old=%u new=0\\n",
\t\t\t\tmap->id, index, before->aux->id);
\t\t}
\t\tmap->ops->map_fd_put_ptr(map, old_ptr, need_defer);
\t\treturn 0;
\t} else {
\t\treturn -ENOENT;
\t}
}'''

for label, before in [('update', old_update), ('delete', old_delete)]:
    hits = s.count(before)
    if hits != 1:
        raise SystemExit(f'ERROR: expected exactly one {label} anchor, found {hits}; no edits performed')

s2 = s.replace(old_update, new_update, 1).replace(old_delete, new_delete, 1)
backup = p.with_suffix('.c.bpfseal-original')
if backup.exists():
    raise SystemExit('ERROR: backup already exists; inspect before rerunning')
backup.write_text(s)
p.write_text(s2)
print('Applied BPFSEAL_ITER1A to kernel/bpf/arraymap.c')
print('Original saved as kernel/bpf/arraymap.c.bpfseal-original')
print('No kernel install, build, or reboot performed')

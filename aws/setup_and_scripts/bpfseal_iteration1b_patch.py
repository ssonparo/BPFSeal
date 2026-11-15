#!/usr/bin/env python3
"""BPFSeal iteration 1B: per-PROG_ARRAY serialized mutation generation.

Run from the root of the Linux kernel source tree containing iteration 1A.
Refuses to edit unexpected sources and backs up both files.
Not a cryptographic integrity or attestation implementation.
"""
from pathlib import Path
import sys

hdr = Path('include/linux/bpf.h')
src = Path('kernel/bpf/arraymap.c')
for p in (hdr, src):
    if not p.is_file():
        sys.exit(f'ERROR: missing {p}; run from kernel source root')

h = hdr.read_text()
s = src.read_text()
if 'BPFSEAL_ITER1B' in h or 'BPFSEAL_ITER1B' in s:
    sys.exit('ERROR: Iteration 1B marker already found; refusing repeat patch')
if 'BPFSEAL_ITER1A' not in s:
    sys.exit('ERROR: Iteration 1A instrumentation is absent')


def replace_once(txt, old, new, label):
    count = txt.count(old)
    if count != 1:
        raise ValueError(f'{label}: expected exactly one anchor, found {count}')
    return txt.replace(old, new, 1)

try:
    h = replace_once(
        h,
        '\tstruct mutex poke_mutex;\n\tstruct work_struct work;\n',
        '\tstruct mutex poke_mutex;\n'
        '\t/* BPFSEAL_ITER1B: serialized PROG_ARRAY mutation generation. */\n'
        '\tu64 bpfseal_generation;\n'
        '\tstruct work_struct work;\n',
        'bpf_array_aux declaration')

    start = s.index('int bpf_fd_array_map_update_elem(')
    mid = s.index('static long __fd_array_map_delete_elem(', start)
    end = s.index('static long fd_array_map_delete_elem(', mid)
    update = s[start:mid]
    delete = s[mid:end]

    update = replace_once(update,
        '\tu32 index = *(u32 *)key, ufd;\n',
        '\tu32 index = *(u32 *)key, ufd;\n'
        '\tu64 bpfseal_gen = 0; /* BPFSEAL_ITER1B */\n',
        'update local variable')
    update = replace_once(update,
        '\t\tmap->ops->map_poke_run(map, index, old_ptr, new_ptr);\n'
        '\t\tmutex_unlock(&array->aux->poke_mutex);',
        '\t\tmap->ops->map_poke_run(map, index, old_ptr, new_ptr);\n'
        '\t\t/* BPFSEAL_ITER1B: ordered within this PROG_ARRAY. */\n'
        '\t\tif (map->map_type == BPF_MAP_TYPE_PROG_ARRAY)\n'
        '\t\t\tbpfseal_gen = ++array->aux->bpfseal_generation;\n'
        '\t\tmutex_unlock(&array->aux->poke_mutex);',
        'update commit')
    update = replace_once(update,
        'pr_info("BPFSEAL_ITER1A update map=%u slot=%u old=%u new=%u\\n",\n'
        '\t\t\tmap->id, index,\n'
        '\t\t\tbefore ? before->aux->id : 0,\n'
        '\t\t\tafter ? after->aux->id : 0);',
        'pr_info("BPFSEAL_ITER1A BPFSEAL_ITER1B update map=%u slot=%u old=%u new=%u gen=%llu\\n",\n'
        '\t\t\tmap->id, index,\n'
        '\t\t\tbefore ? before->aux->id : 0,\n'
        '\t\t\tafter ? after->aux->id : 0,\n'
        '\t\t\t(unsigned long long)bpfseal_gen);',
        'update diagnostic')

    delete = replace_once(delete,
        '\tu32 index = *(u32 *)key;\n',
        '\tu32 index = *(u32 *)key;\n'
        '\tu64 bpfseal_gen = 0; /* BPFSEAL_ITER1B */\n',
        'delete local variable')
    delete = replace_once(delete,
        '\t\tmap->ops->map_poke_run(map, index, old_ptr, NULL);\n'
        '\t\tmutex_unlock(&array->aux->poke_mutex);',
        '\t\tmap->ops->map_poke_run(map, index, old_ptr, NULL);\n'
        '\t\t/* BPFSEAL_ITER1B: failed empty-slot deletes do not advance. */\n'
        '\t\tif (old_ptr && map->map_type == BPF_MAP_TYPE_PROG_ARRAY)\n'
        '\t\t\tbpfseal_gen = ++array->aux->bpfseal_generation;\n'
        '\t\tmutex_unlock(&array->aux->poke_mutex);',
        'delete commit')
    delete = replace_once(delete,
        'pr_info("BPFSEAL_ITER1A delete map=%u slot=%u old=%u new=0\\n",\n'
        '\t\t\t\tmap->id, index, before->aux->id);',
        'pr_info("BPFSEAL_ITER1A BPFSEAL_ITER1B delete map=%u slot=%u old=%u new=0 gen=%llu\\n",\n'
        '\t\t\t\tmap->id, index, before->aux->id,\n'
        '\t\t\t\t(unsigned long long)bpfseal_gen);',
        'delete diagnostic')

    s = s[:start] + update + delete + s[end:]
except (ValueError, IndexError) as exc:
    sys.exit(f'ERROR: {exc}; no files modified')

for p in (hdr, src):
    backup = p.with_name(p.name + '.bpfseal-iter1b-backup')
    if backup.exists():
        sys.exit(f'ERROR: backup already exists: {backup}; no files modified')

try:
    for p in (hdr, src):
        p.with_name(p.name + '.bpfseal-iter1b-backup').write_bytes(p.read_bytes())
    hdr.write_text(h)
    src.write_text(s)
except Exception as exc:
    for p in (hdr, src):
        backup = p.with_name(p.name + '.bpfseal-iter1b-backup')
        if backup.exists():
            p.write_bytes(backup.read_bytes())
    sys.exit(f'ERROR: write failed; backups restored: {exc}')

print('PATCH APPLIED: BPFSEAL_ITER1B')
print('Modified include/linux/bpf.h and kernel/bpf/arraymap.c')
print('Backups: *.bpfseal-iter1b-backup')
print('No build, kernel installation, or reboot performed')

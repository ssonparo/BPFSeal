#!/usr/bin/env python3
"""BPFSeal Iteration 2A: add an internal, mutex-protected evidence snapshot.

Run from any directory on EC2. This does NOT build/install a kernel or expose
an API to userspace. It expects the prior Iteration 1C source tree.
"""
from pathlib import Path
import argparse
import sys

DEFAULT_ROOT = Path.home() / 'bpfseal/kernel/linux-aws-7.0-bpfseal-patched'

HEADER_INSERT = '''/* BPFSeal Iteration 2A: experimental kernel-internal evidence snapshot. */
struct bpfseal_map_evidence {
\tu32 map_id;
\tu32 max_entries;
\tu64 map_cookie;
\tu64 generation;
\tu8 digest[SHA256_DIGEST_SIZE];
\tbool valid;
};

int bpfseal_prog_array_snapshot(struct bpf_map *map,
\t\t\t\tstruct bpfseal_map_evidence *evidence);

'''

SOURCE_INSERT = '''/*
 * BPFSeal Iteration 2A: coherent map-level bookkeeping snapshot.
 * Caller must hold a live reference to map; no copy_to_user under mutex.
 */
int bpfseal_prog_array_snapshot(struct bpf_map *map,
\t\t\t\tstruct bpfseal_map_evidence *evidence)
{
\tstruct bpf_array *array;

\tif (!map || !evidence)
\t\treturn -EINVAL;
\tif (map->map_type != BPF_MAP_TYPE_PROG_ARRAY)
\t\treturn -EOPNOTSUPP;

\tarray = container_of(map, struct bpf_array, map);
\tmutex_lock(&array->aux->poke_mutex);
\tmemset(evidence, 0, sizeof(*evidence));
\tevidence->map_id = map->id;
\tevidence->max_entries = map->max_entries;
\tevidence->map_cookie = map->cookie;
\tevidence->generation = array->aux->bpfseal_generation;
\tevidence->valid = array->aux->bpfseal_digest_valid;
\tif (evidence->valid)
\t\tmemcpy(evidence->digest, array->aux->bpfseal_digest,
\t\t       SHA256_DIGEST_SIZE);
\tmutex_unlock(&array->aux->poke_mutex);
\treturn 0;
}

'''

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT,
                        help='Linux kernel source root')
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    hpath = root / 'include/linux/bpf.h'
    spath = root / 'kernel/bpf/arraymap.c'
    try:
        h = hpath.read_text()
        s = spath.read_text()
    except OSError as exc:
        print(f'ERROR: cannot read kernel sources: {exc}', file=sys.stderr)
        return 1

    hmarker = 'struct bpf_array_aux {'
    smarker = 'int bpf_fd_array_map_update_elem('
    if h.count(hmarker) != 1 or s.count(smarker) != 1:
        print('ERROR: unexpected source layout; no changes made', file=sys.stderr)
        return 1
    if 'struct bpfseal_map_evidence {' in h or 'int bpfseal_prog_array_snapshot(' in s:
        print('ERROR: snapshot patch appears already applied; no changes made', file=sys.stderr)
        return 1
    if 'bpfseal_generation' not in h or 'bpfseal_digest_valid' not in h or 'poke_mutex' not in h:
        print('ERROR: Iteration 1C state fields not found; no changes made', file=sys.stderr)
        return 1
    bh = hpath.with_name('bpf.h.bpfseal-2a-backup')
    bs = spath.with_name('arraymap.c.bpfseal-2a-backup')
    if bh.exists() or bs.exists():
        print('ERROR: a backup already exists; no changes made', file=sys.stderr)
        return 1

    updated_h = h.replace(hmarker, HEADER_INSERT + hmarker, 1)
    updated_s = s.replace(smarker, SOURCE_INSERT + smarker, 1)
    try:
        # Back up both originals before modifying either source file.
        bh.write_text(h)
        bs.write_text(s)
        hpath.write_text(updated_h)
        spath.write_text(updated_s)
    except OSError as exc:
        print(f'ERROR writing files: {exc}. Inspect backups before retrying.', file=sys.stderr)
        return 1
    print('BPFSEAL_ITER2A: SNAPSHOT SOURCE PATCH APPLIED')
    print('Modified: include/linux/bpf.h; kernel/bpf/arraymap.c')
    print('Backups:', bh, bs, sep='\n  ')
    print('No kernel build, installation, or reboot performed.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

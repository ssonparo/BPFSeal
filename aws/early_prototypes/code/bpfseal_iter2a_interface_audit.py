#!/usr/bin/env python3
"""Read-only BPFSeal Iteration 2A audit; writes source excerpts and safety checks.

Run on the EC2 machine with the patched Ubuntu AWS 7.0 source tree.
Does not change kernel sources, packages, boot configuration, or running kernel.
"""
from pathlib import Path
import argparse
import datetime
import platform
import re
import sys

ROOT = Path.home() / 'bpfseal/kernel/linux-aws-7.0-bpfseal-patched'
OUTPUT = Path.home() / 'bpfseal/results/iteration2a/interface_audit.txt'


def excerpt(label, content, pattern, before=15, after=95, max_hits=2):
    matches = list(re.finditer(pattern, content, re.M))
    result = [f'\n===== {label} (matches={len(matches)}) =====']
    lines = content.splitlines()
    for hit in matches[:max_hits]:
        line = content.count('\n', 0, hit.start())
        start = max(0, line - before)
        end = min(len(lines), line + after + 1)
        result.extend(f'{i + 1:6d} {lines[i]}' for i in range(start, end))
        result.append('---')
    if not matches:
        result.append('NOT FOUND — inspect kernel revision before modifying source')
    return '\n'.join(result), bool(matches)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    root = args.root.expanduser()
    output = args.output.expanduser()
    paths = {
        'syscall': 'kernel/bpf/syscall.c',
        'arraymap': 'kernel/bpf/arraymap.c',
        'bpf_header': 'include/linux/bpf.h',
        'uapi': 'include/uapi/linux/bpf.h',
    }
    sources = {}
    try:
        for key, rel in paths.items():
            sources[key] = (root / rel).read_text()
    except OSError as exc:
        print(f'ERROR: unable to read sources: {exc}', file=sys.stderr)
        return 1

    checks = []
    chunks = [f'BPFSeal Iteration 2A read-only interface/cleanup audit',
              f'Generated UTC: {datetime.datetime.now(datetime.timezone.utc).isoformat()}',
              f'Host kernel: {platform.release()}',
              f'Source root: {root}',
              f'Patch present: {"int bpfseal_prog_array_snapshot(" in sources["arraymap"]}',
              f'']
    targets = [
        ('BPF_OBJ_GET_INFO_BY_FD dispatcher', 'syscall', r'^static int bpf_obj_get_info_by_fd\(', 5, 56),
        ('Map information handler', 'syscall', r'^static int bpf_map_get_info_by_fd\(', 6, 115),
        ('Map FD retrieval and lifetime', 'syscall', r'^static int bpf_map_get_fd_by_id\(|^static int bpf_map_new_fd\(|^static int bpf_map_release\(', 8, 70),
        ('Map release/file-ops', 'syscall', r'^static const struct file_operations bpf_map_fops|^const struct file_operations bpf_map_fops', 7, 52),
        ('Map UAPI structure', 'uapi', r'^struct bpf_map_info\s*\{', 4, 42),
        ('BPFSeal evidence type and helper declaration', 'bpf_header', r'^struct bpfseal_map_evidence\s*\{', 5, 24),
        ('BPFSeal synchronized snapshot helper', 'arraymap', r'^int bpfseal_prog_array_snapshot\(', 6, 43),
        ('Program-array allocation', 'arraymap', r'^static struct bpf_map \*prog_array_map_alloc\(', 5, 85),
        ('Program-array teardown and uref cleanup', 'arraymap', r'^static void prog_array_map_(?:free|clear)\(', 5, 90),
        ('FD-array clear operations', 'arraymap', r'^static void bpf_fd_array_map_clear\(', 6, 76),
        ('Update operations', 'arraymap', r'^int bpf_fd_array_map_update_elem\(', 6, 125),
        ('Delete operations', 'arraymap', r'^static long __fd_array_map_delete_elem\(', 6, 100),
        ('PROG_ARRAY map-ops table', 'arraymap', r'^const struct bpf_map_ops prog_array_map_ops\s*=', 5, 33),
    ]
    for label, key, pattern, before, after in targets:
        segment, found = excerpt(label, sources[key], pattern, before, after)
        chunks.append(segment)
        checks.append((label, found))
    chunks.append('\n===== QUICK CHECKS =====')
    chunks.extend(f'{"FOUND" if found else "NOT FOUND"}: {name}' for name, found in checks)
    chunks.append('\nNOTE: This audit reports code locations, NOT evidence of correct lifetime, synchronization or API security.')
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text('\n'.join(chunks) + '\n')
    except OSError as exc:
        print(f'ERROR writing report: {exc}', file=sys.stderr)
        return 1
    print(f'Read-only audit written to: {output}')
    print(f'Located {sum(ok for _, ok in checks)}/{len(checks)} requested source sections.')
    print('No source files modified. No kernel build or reboot performed.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Package the original BPFSeal EC2 research workspace without kernel build artifacts.

Run on Ubuntu EC2: python3 ~/bpfseal_collect_ec2.py
Creates ~/bpfseal/BPFSeal_EC2_Complete_Research_Archive.zip
This is a snapshot; it does not execute experiments or modify kernel source.
"""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from datetime import datetime, timezone
import hashlib, json, os, sys

ROOT = Path.home() / 'bpfseal'
SRC = ROOT / 'kernel/linux-aws-7.0-bpfseal-patched'
OUTPUT = ROOT / 'BPFSeal_EC2_Complete_Research_Archive.zip'
MAX_BYTES = 500 * 1024 * 1024  # avoid including unexpected large files
EXCLUDE_EXT = {'.o','.a','.so','.deb','.ko','.cmd','.d','.pem','.key','.p12','.pfx','.qcow2','.img','.iso','.vmlinux','.bz2','.xz'}
EXCLUDE_NAMES = {'.git','.venv','venv','__pycache__','node_modules','debian','build','dist','.cache'}
# Data retained: code, logs, results, run manifests, tables, config and source diff inputs.
DIRS = ['src','experiments','results','logs']
KERNEL_FILES = [
    'kernel/bpf/arraymap.c', 'kernel/bpf/syscall.c', 'include/linux/bpf.h',
    'include/uapi/linux/bpf.h', 'debian.aws-7.0/changelog',
    'kernel/bpf/arraymap.c.bpfseal-cookie-backup',
    'kernel/bpf/arraymap.c.bpfseal-2a-backup',
    'kernel/bpf/syscall.c.bpfseal-2a-ioctl-backup',
    'include/linux/bpf.h.bpfseal-2a-backup',
]
files = {}
skipped = []
def add(p, dest):
    if not p.is_file() or p.is_symlink(): return
    try:
        size = p.stat().st_size
        if size > MAX_BYTES:
            skipped.append({'path':str(p),'reason':'exceeds 500MiB cap'}); return
        if p.suffix.lower() in EXCLUDE_EXT or p.name.startswith('.env') or 'private' in p.name.lower():
            skipped.append({'path':str(p),'reason':'potential binary/private key'}); return
        files[dest] = p
    except OSError: skipped.append({'path':str(p),'reason':'unreadable'})
for directory in DIRS:
    base = ROOT / directory
    if not base.exists(): continue
    for p in base.rglob('*'):
        rel = p.relative_to(base)
        if any(part in EXCLUDE_NAMES for part in rel.parts): continue
        if p.is_file(): add(p, f'EC2_workspace/{directory}/{rel.as_posix()}')
for relative in KERNEL_FILES:
    add(SRC / relative, f'kernel_patched/{relative}')
# Capture nearby hand-written scripts and top-level notes, without recursing into kernel.
for p in ROOT.iterdir() if ROOT.exists() else []:
    if p.is_file() and p.suffix.lower() in {'.py','.c','.h','.sh','.md','.txt','.json','.csv'}:
        add(p, f'EC2_workspace/top_level/{p.name}')
if not ROOT.is_dir(): sys.exit(f'Workspace not found: {ROOT}')
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
manifest = {
    'created_utc': datetime.now(timezone.utc).isoformat(),
    'workspace': str(ROOT),
    'running_kernel': os.uname().release,
    'description':'BPFSeal experimental artifacts copied from original EC2 workspace; excludes full kernel tree and build outputs',
    'files': [], 'skipped':skipped,
}
with ZipFile(OUTPUT,'w',ZIP_DEFLATED,compresslevel=6,allowZip64=True) as z:
    for dest,p in sorted(files.items()):
        try:
            data = p.read_bytes()
            z.writestr(dest,data)
            manifest['files'].append({'path':dest,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        except OSError:
            skipped.append({'path':str(p),'reason':'read failed'})
    z.writestr('MANIFEST.json',json.dumps(manifest,indent=2))
    z.writestr('README.txt',
        'BPFSeal EC2 workspace research archive.\n'
        'Contains experiments, available logs/results, source scripts, and selected modified kernel files.\n'
        'Does NOT include full 30+ GiB kernel source/build tree, installed kernel binaries, or SSH credentials.\n'
        'MANIFEST.json lists contents and SHA-256 for each file.\n')
print(f'Created: {OUTPUT}')
print(f'Files: {len(manifest["files"])} | Size: {OUTPUT.stat().st_size:,} bytes')
print(f'Skipped: {len(skipped)} (see MANIFEST.json)')

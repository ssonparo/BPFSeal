#!/usr/bin/env python3
"""Verify generated package hashes (independent of original AWS evidence manifest)."""
from pathlib import Path
import hashlib,sys
root=Path(__file__).resolve().parents[1]; n=0; bad=[]
for line in (root/'MANIFEST_SHA256.txt').read_text().splitlines():
    if not line or line.startswith('#'):continue
    digest,path=line.split('  ',1);file=root/path
    if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest()!=digest:bad.append(path)
    n+=1
print(f'Verified {n-len(bad)}/{n} repository files')
if bad:print('Mismatches:',*bad,sep='\n  ');sys.exit(1)

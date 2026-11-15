#!/usr/bin/env python3
"""Safely extract original AWS evidence into the gitignored unpacked directory."""
from pathlib import Path
import tarfile
root=Path(__file__).resolve().parents[1]
archive=root/'evidence/raw/BPFSeal_Evidence_20261103T185318Z.tar.gz'
out=root/'evidence/unpacked'
out.mkdir(exist_ok=True)
with tarfile.open(archive,'r:gz') as t:
    for item in t:
        dest=(out/item.name).resolve()
        if not dest.is_relative_to(out.resolve()) or not (item.isfile() or item.isdir()):
            raise ValueError(f'Unsafe archive entry: {item.name}')
    t.extractall(out,filter='data')
print('Extracted to:',out)

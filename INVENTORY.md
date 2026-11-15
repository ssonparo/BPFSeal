# Inventory and completeness boundaries

- Original AWS evidence archive: **364 regular files**, **180,709,170 uncompressed bytes**, contains kernel snapshots, test harnesses, raw traces, and datasets. The original archive is retained separately and intentionally excluded from this public GitHub repository.
- Offline analysis: five files extracted from the **current user-uploaded** `BPFSeal_Offline_Analysis_Download(1).zip`.
- Exported final comparative patches: 2004, 2006, 2007 versus baseline 2005.
- Source material also merged from the prior research-consolidated ZIP, original v0.7 experiment-code ZIP, and direct project `.py`, `.c`, `.sh` files. Files are organized by source instead of silently de-duplicating variant histories.
- The source archive does **not** contain a fully reconstructible base Ubuntu kernel source tree or definitive current LaTeX project for the newest PDF.
- Raw CSV evidence remains in the untouched `.tar.gz` archive; its 80 performance trial CSVs are **not** copied as individual tracked Git files. `tools/unpack_raw_evidence.py` recovers them on demand.
- The project evidence records previous checksum verification; the new repository-level SHA-256 manifest independently detects repackaging changes.

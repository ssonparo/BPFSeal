BPFSeal original EC2 evidence export.
- experiments/: source/harness files present on original instance
- results/: ALL files, including raw P1 CSV, B2 trace, and perf.data
- kernel/*: selected source files and version metadata from 2004–2007,
  NOT multi-GB kernel build directories
- patches/: per-version unified source differences against 2005 baseline
- boot-configs/: installed kernel configs if available
- original_file_sha256.txt: checksums relative to ~/bpfseal
- collection_report.txt: explicitly reports missing expected artifacts
This archive is NOT a complete kernel source distribution. For reproduction,
retrieve the matching Ubuntu linux-aws-7.0 upstream source separately, then
apply/inspect the version-specific source differences and build metadata.

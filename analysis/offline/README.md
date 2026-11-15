# BPFSeal evidence replay and statistics — 3 November 2026

## What was actually checked

- SHA-256 of original uploaded archive: `f8c97f99dadbc4bac47c1bbe0458be98bae7c92228d79e5184862e43255b6032`.
- Archived SHA-256 manifest: **353 of 353 file checksums match**.
- Original Stage B2 trace: `aa55992340955d268e2870e271bbbea3393782c90ecb7fadf2e0f3dcbbf7cb86`.
- Original independent verifier: `ad11540f2fe95449df1932f85ffa913b68a8372a91dfab149d9bb9a25b460bd9`.
- Offline independent SHA-256 reconstruction: **1,602/1,602 PASS** (1,600 concurrent updates and initial/final events).
- Performance: **80 original per-trial latency CSVs, 5,800,000 valid latency observations**, 20 trials/kernel across four kernel variants.
- Summary statistics regenerated from original summary CSVs, with each trial's raw CSV row count verified.
- Unified source patches for 2004, 2006, and 2007 reconstructed the archived modified kernel files exactly when applied to the corresponding 2005 source-file subset.
- Benchmark source sha256: `123f5061283803f35a52d218a7d476fa4b14c171d9a7085221f02df1d686f0d5`.
- Benchmark executable sha256: `dafce9f9621a5c65eeb74df6ae5a8ce6d85345be58b24e06c56a8cb62ea4e0db`.

## Replaying on a copy of the extracted archive

```
python3 BPFSeal_replay_archived_results.py /path/to/extracted/BPFSeal_Evidence /tmp/bpfseal_replay
```

The script verifies every SHA-256 entry, invokes the original Stage B2 verifier, validates every raw performance CSV's trial identity and successful-update count, and writes `performance_replay.csv`.

`performance_replay.csv` contains five-trial median, Q1, Q3, min, and max update throughput per kernel and writer count. Quartiles are **linear interpolation** of sorted samples (Q1 at 25%, Q3 at 75%). It is *not* a confidence interval.

## Limitations

- Source export includes modified source files, versioned patches, configurations and build metadata, but **not** the upstream multi-GB Ubuntu kernel source tree; a clean-room kernel rebuild was not conducted.
- The historical benchmark campaigns were sequential on one eight-vCPU EC2 host and were not replicated on another host.
- The 2007 no-hash variant has invalid digest evidence, so it is a diagnostic ablation, not a functional integrity system.
- The independent B2 check independently reconstructs digests from *recorded* trace information; it is not remote attestation or adversarial kernel-integrity proof.
- The one-writer perf profile still has 155 CPU samples. All original perf recordings and reports are preserved in the separately uploaded original archive.

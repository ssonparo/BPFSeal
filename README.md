# BPFSeal: AWS kernel experiments, evidence, and offline analysis

Research artifact bundle prepared from existing local project files on **2026-11-14**. It does not represent a fresh EC2 execution or an independently recreated kernel build. The original AWS evidence archive is preserved separately and is not included in this public GitHub working tree.

## Folder map

| Path | Contents |
| --- | --- |
| `aws/experiments/` | C harness sources and Python/bash validation scripts extracted from AWS evidence |
| `aws/kernel_patches/` | Actual exported unified patches for 2004, 2006, 2007 relative to baseline 2005 |
| `aws/kernel_configs/` | Original 2004–2007 boot configuration captures |
| `aws/kernel_source_snapshots/` | Archived **selected modified source files** (not full Linux kernel) |
| `aws/setup_and_scripts/` | Root-level collected AWS experiment and build scripts |
| `aws/early_prototypes/` | Earlier iteration patch generators and tests from prior source bundle |
| `aws/additional_scripts/` | Scripts available as separate project artifacts |
| `analysis/offline/` | Latest user-uploaded replay analysis, outputs, plot, and instructions |
| `evidence/selected_records/` | Readable small experiment logs, traces, and summaries |
| `evidence/raw/` | Not included in this repository; the original AWS evidence archive is retained separately |
| `evidence/original_uploaded/` | Original code/analysis bundles for independent cross-checking |
| `prior_bundle_v07/` | Earlier consolidated scripts, small datasets, and provenance |
| `paper/` | Not included in this repository; manuscript drafts are retained separately pending publication |
| `MANIFEST_SHA256.txt` | SHA-256 hashes of files in the repository (excluding itself) |

## Getting started

1. `git lfs install` (install Git LFS beforehand if not installed). The original 39 MiB archive is marked for LFS in `.gitattributes`.
2. `git init && git add . && git commit -m "Import BPFSeal research artifacts"` (or add to your existing repository).
3. For a smaller public repository, omit `evidence/raw/` and upload that original archive to a durable archival service, with its checksum and link documented. **Never silently replace the original archive with a repack.**
4. `python3 tools/check_manifest.py` verifies this repository's local file hashes.
5. `python3 tools/unpack_raw_evidence.py` unpacks the original evidence archive to `evidence/unpacked/` on demand (ignored by Git).
6. `python3 analysis/offline/BPFSeal_replay_archived_results.py evidence/unpacked/ ./local-build/replay` runs checksum, B2, and performance replay checks after unpacking; see `analysis/offline/README.md`.

## Experiment provenance and caveats

- The evidence archive is an existing AWS capture, not simulated outcomes. It preserves original runtime results and separate baseline/BPFSeal kernel-source subsets.
- The archived `kernel/` entries are **not** a complete, independently buildable Ubuntu kernel tree. Start from the matching Ubuntu `linux-aws-7.0` source if rebuilding.
- Kernel 2005 is the unmodified performance baseline; 2004 has diagnostic logging; 2006 removes active diagnostics; 2007 disables digest generation and marks evidence invalid. **The 2007 no-hash build is not security-functional.**
- Benchmark throughput is from capacity-one synthetic maps on one EC2 host. Do not infer production, multi-map, hardware attestation, or zero-overhead behavior.
- The original full B2 record was independently replayed as 1,602 / 1,602 matching generation-associated digests; offline analysis remains reproducible via the supplied validator and trace.
- Some earlier prototype patch generators represent development stages. Do not automatically combine or reapply those patches to a new kernel. The `aws/kernel_patches/` directory is the final collected patch series.
- Manuscript files are intentionally excluded from this public repository. Refer to the eventual published article for the authoritative manuscript.

## Publishing checklist

Review the public repository for usernames, machine/network information, and any sensitive logs before publishing. Do not commit credentials, SSH keys, private cloud IDs, or confidential data. A coarse redaction may break recorded checksums: keep the original private, publish a separately labeled redacted derivative, and document the difference.

**Original evidence SHA-256:** `f8c97f99dadbc4bac47c1bbe0458be98bae7c92228d79e5184862e43255b6032`

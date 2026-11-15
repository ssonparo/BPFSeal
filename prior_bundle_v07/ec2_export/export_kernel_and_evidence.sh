#!/usr/bin/env bash
# Run only after restarting the original EC2 instance; READ-ONLY export.
# Gathers BPFSeal modified kernel source and summaries, not 34 GB build trees.
set -Eeuo pipefail
cd "$HOME/bpfseal"
DEST="$HOME/bpfseal/BPFSeal_EC2_Kernel_Source_and_Evidence_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DEST/kernel" "$DEST/results" "$DEST/provenance"
for pair in \
  "2004:linux-aws-7.0-bpfseal-patched" \
  "2005:linux-aws-7.0-baseline-2005" \
  "2006:linux-aws-7.0-bpfseal-nolog-2006" \
  "2007:linux-aws-7.0-bpfseal-nohash-2007"; do
  label=${pair%%:*}; dir=${pair#*:}
  src="kernel/$dir"
  target="$DEST/kernel/$label"
  mkdir -p "$target/kernel/bpf" "$target/include/linux"
  for file in kernel/bpf/arraymap.c kernel/bpf/syscall.c include/linux/bpf.h; do
    if [[ -f "$src/$file" ]]; then cp -p "$src/$file" "$target/$file"; fi
  done
  if [[ -f "$src/debian.aws-7.0/changelog" ]]; then cp -p "$src/debian.aws-7.0/changelog" "$target/changelog"; fi
done
for dir in \
  results/iteration2b/final_archive \
  results/iteration2b/stage_b1 \
  results/iteration2b/stage_b2 \
  results/performance/p1/full_matrix_20261102T225927Z \
  results/performance/p1/full_matrix_20261103T101544Z \
  results/performance/p1/full_matrix_20261103T143835Z \
  results/performance/p1/full_matrix_20261103T161719Z \
  results/performance/p2b; do
  [[ -d "$dir" ]] || continue
  mkdir -p "$DEST/$dir"
  # Include digest traces, scripts, summary files, profiler data and logs.
  # Exclude per-operation raw p1 w*.csv to avoid unexpectedly large export.
  find "$dir" -maxdepth 1 -type f ! -name 'w*_t*.csv' \
   -exec cp -p '{}' "$DEST/$dir/" \;
done
cp -p bpfseal_*.sh "$DEST/provenance/" 2>/dev/null || true
printf 'kernel=%s\n' "$(uname -r)" > "$DEST/provenance/kernel_at_export.txt"
(find "$DEST" -type f -print0 | sort -z | xargs -0 sha256sum) > "$DEST/provenance/checksums.txt"
ARCHIVE="${DEST}.tar.gz"
tar -C "$(dirname "$DEST")" -czf "$ARCHIVE" "$(basename "$DEST")"
printf 'EXPORT_SUCCESS %s\n' "$ARCHIVE"

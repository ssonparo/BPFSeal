#!/usr/bin/env bash
# BPFSeal original-evidence collector, 2026-11-03.
# READS existing experiments, results, kernel source files and /boot configs.
# WRITES only to ~/bpfseal/exports/. Does NOT run tests, compile, or change kernels.
set -Eeuo pipefail

ROOT="${BPFSEAL_ROOT:-$HOME/bpfseal}"
cd "$ROOT"
[[ -d experiments && -d results && -d kernel ]] || {
  echo 'ERROR: expected experiments/, results/, and kernel/ under ~/bpfseal' >&2; exit 2;
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="exports/BPFSeal_Evidence_${STAMP}.tar.gz"
META="exports/collection_${STAMP}"
mkdir -p "$META/patches" "$META/boot-configs"
REPORT="$META/collection_report.txt"
: > "$REPORT"

log() { printf '%s\n' "$*" | tee -a "$REPORT"; }
log "BPFSeal read-only artifact collection"
log "UTC: $STAMP"
log "Booted kernel: $(uname -r) (does not need to be the experimental kernel)"
log "Root: $ROOT"
log ""

# Include the exact original experimental directories; no kernel build trees.
INCLUDE=(experiments results)

# Original source trees are deliberately collected as selected individual files.
# 2005 is the unmodified reference for the 2004, 2006, and 2007 variants.
declare -A TREES=(
  [2004]='kernel/linux-aws-7.0-bpfseal-patched'
  [2005]='kernel/linux-aws-7.0-baseline-2005'
  [2006]='kernel/linux-aws-7.0-bpfseal-nolog-2006'
  [2007]='kernel/linux-aws-7.0-bpfseal-nohash-2007'
)
FILES=(kernel/bpf/arraymap.c kernel/bpf/syscall.c include/linux/bpf.h)

for VER in 2004 2005 2006 2007; do
  SRC="${TREES[$VER]}"
  log "SOURCE ${VER}: ${SRC}"
  for F in "${FILES[@]}" debian.aws-7.0/changelog debian/debian.env debian/changelog; do
    if [[ -f "$SRC/$F" ]]; then
      INCLUDE+=("$SRC/$F")
    else
      log "  MISSING: $SRC/$F"
    fi
  done
  CFG="/boot/config-7.0.0-${VER}-aws"
  if [[ -f "$CFG" ]]; then
    cp -p "$CFG" "$META/boot-configs/$(basename "$CFG")"
  else
    log "  MISSING: $CFG"
  fi
done

BASE="${TREES[2005]}"
for VER in 2004 2006 2007; do
  PATCH="$META/patches/bpfseal_vs_baseline_${VER}.patch"
  : > "$PATCH"
  for F in "${FILES[@]}"; do
    if [[ -f "$BASE/$F" && -f "${TREES[$VER]}/$F" ]]; then
      # diff exit code 1 is normal (files differ); other codes are errors.
      STATUS=0
      diff -u --label "a/$F" --label "b/$F" "$BASE/$F" "${TREES[$VER]}/$F" >> "$PATCH" || STATUS=$?
      if [[ "$STATUS" -gt 1 ]]; then
        log "ERROR: diff failed for $VER $F (exit $STATUS)"
        exit "$STATUS"
      fi
    fi
  done
  log "PATCH $VER: $(wc -c < "$PATCH") bytes"
done

for VER in 2003 2004 2005 2006 2007; do
  # Include installed version/config information, not installed images/modules.
  :
done
{
  printf '# Kernel / OS environment at export\n'
  uname -a
  cat /etc/os-release
  printf '\n# Installed image/modules packages\n'
  dpkg-query -W 'linux-image-unsigned-7.0.0-*-aws' 'linux-modules-7.0.0-*-aws' 2>/dev/null || true
  printf '\n# GRUB saved boot choices\n'
  grub-editenv list 2>/dev/null || true
  printf '\n# Toolchain\n'
  gcc --version 2>/dev/null | head -1 || true
  openssl version 2>/dev/null || true
} > "$META/environment.txt"

# Root-level harness runners, validators, scripts, and diagnostic logs.
while IFS= read -r -d '' F; do
  F="${F#./}"
  INCLUDE+=("$F")
done < <(find . -maxdepth 1 -type f \
  \( -name '*.sh' -o -name '*.py' -o -name '*.c' -o -name 'p2*.log' -o -name 'bpfseal_*.log' \) -print0)

# Include every original result, especially the raw 2004–2007 per-operation CSVs.
# No filters exclude w1_t1.csv or perf.data.
log ""
log 'IMPORTANT DATA PATH CHECKS'
for RUN in 20261102T225927Z 20261103T101544Z 20261103T143835Z 20261103T161719Z; do
  FILE="results/performance/p1/full_matrix_${RUN}/summary.csv"
  if [[ -f "$FILE" ]]; then
    log "  FOUND: $FILE"
  else
    log "  MISSING: $FILE"
  fi
done
for F in \
  results/iteration2b/final_archive/digest_full_16x100.txt \
  results/iteration2b/final_archive/bpfseal_iter2b_independent_sha256_16x100_v2.py \
  results/performance/p2b/perf_1writer.data \
  results/performance/p2b/perf_8writers.data; do
  if [[ -f "$F" ]]; then log "  FOUND: $F"; else log "  MISSING: $F"; fi
done

log ""
log 'Input directory sizes (uncompressed):'
du -sh experiments results | tee -a "$REPORT"

# Checksums for each individual original file, plus selected kernel sources.
# Null delimiters handle unusual filenames safely.
: > "$META/original_file_sha256.txt"
for DIR in experiments results; do
  find "$DIR" -type f -print0 | sort -z | xargs -0 -r sha256sum >> "$META/original_file_sha256.txt"
done
for F in "${INCLUDE[@]:2}"; do
  [[ -f "$F" ]] && sha256sum "$F" >> "$META/original_file_sha256.txt"
done
sort -u "$META/original_file_sha256.txt" -o "$META/original_file_sha256.txt"

cat > "$META/README.txt" <<'TXT'
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
TXT

log "Creating archive: $OUT"
tar -czf "$OUT" -- "${INCLUDE[@]}" "$META"
sha256sum "$OUT" | tee "${OUT}.sha256"
log "ARCHIVE_READY: $ROOT/$OUT"
log "SHA256: $(cut -d' ' -f1 "${OUT}.sha256")"
log "SIZE: $(du -h "$OUT" | cut -f1)"
log 'No experiments, builds, kernel changes or reboots were performed.'

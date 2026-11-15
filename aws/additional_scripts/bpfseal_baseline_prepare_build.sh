#!/usr/bin/env bash
# BPFSeal matched-baseline candidate: isolated preparation / explicit build.
# Does not install packages, change bootloader, or reboot.
set -Eeuo pipefail
MODE="${1:---prepare}"
ROOT="${HOME}/bpfseal"
SOURCE="$ROOT/kernel/linux-aws-7.0-7.0.0"
DEST="$ROOT/kernel/linux-aws-7.0-baseline-2005"
PATCHED="$ROOT/kernel/linux-aws-7.0-bpfseal-patched"
LOGDIR="$ROOT/logs/baseline2005"
EXPECTED_RUNNING="7.0.0-2004-aws"
BASEVERSION="7.0.0-2005.14~24.04.1"
ORIGVERSION="7.0.0-1014.14"
fail() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "== $*"; }
[[ "$MODE" == "--prepare" || "$MODE" == "--build" ]] || fail "Usage: $0 --prepare | --build"
[[ "$(uname -r)" == "$EXPECTED_RUNNING" ]] || fail "Running kernel differs: $(uname -r)"
[[ -f "$SOURCE/debian.aws/changelog" && -f "$SOURCE/debian/rules" ]] || fail "Original source missing"
[[ -f "$PATCHED/debian/build/build-aws/.config" ]] || fail "Patched build config missing"
[[ "$(head -1 "$SOURCE/debian.aws/changelog")" == *"($ORIGVERSION)"* ]] || fail "Unexpected original AWS changelog version"
if grep -q 'BPFSEAL_ITER1' "$SOURCE/kernel/bpf/arraymap.c" "$SOURCE/kernel/bpf/syscall.c"; then fail "Original source contains BPFSeal markers"; fi
for cmd in fakeroot make gcc dpkg-deb python3; do command -v "$cmd" >/dev/null || fail "Missing $cmd"; done
AVAIL=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
(( AVAIL >= 45*1024*1024 )) || fail "Less than 45 GiB available in root volume"
mkdir -p "$LOGDIR"
if [[ "$MODE" == "--prepare" ]]; then
  [[ ! -e "$DEST" ]] || fail "Destination already exists; refusing overwrite: $DEST"
  info "Copying pristine source into isolated directory (no existing trees modified)"
  cp -a "$SOURCE" "$DEST"
  info "Changing isolated AWS package version only"
  python3 - "$DEST/debian.aws/changelog" "$ORIGVERSION" "$BASEVERSION" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); old=sys.argv[2]; new=sys.argv[3]
s=p.read_text()
first, sep, rest=s.partition('\n')
assert first.startswith('linux-aws ('+old+') '), repr(first)
p.write_text(first.replace('('+old+')','('+new+')',1)+sep+rest)
PY
  printf 'source=%s\ndest=%s\noriginal_aws_version=%s\nbaseline_aws_version=%s\nrunning_kernel=%s\n' "$SOURCE" "$DEST" "$ORIGVERSION" "$BASEVERSION" "$(uname -r)" > "$LOGDIR/manifest.txt"
  sha256sum "$SOURCE/kernel/bpf/arraymap.c" "$DEST/kernel/bpf/arraymap.c" \
    "$SOURCE/kernel/bpf/syscall.c" "$DEST/kernel/bpf/syscall.c" \
    "$SOURCE/include/linux/bpf.h" "$DEST/include/linux/bpf.h" | tee "$LOGDIR/source_hashes.txt"
  info "PREPARATION_COMPLETE; no build, install, or reboot performed"
  info "Review $DEST and $LOGDIR/manifest.txt before running --build"
else
  [[ -d "$DEST" ]] || fail "Prepare first using --prepare"
  [[ "$(head -1 "$DEST/debian.aws/changelog")" == *"($BASEVERSION)"* ]] || fail "Baseline changelog version mismatch"
  [[ ! -e "$LOGDIR/build_started" ]] || fail "Build previously started; refusing implicit rerun"
  info "Building isolated baseline source using previously successful Ubuntu workflow"
  touch "$LOGDIR/build_started"
  cd "$DEST"
  set -o pipefail
  info "fakeroot debian/rules clean"
  fakeroot debian/rules clean 2>&1 | tee "$LOGDIR/clean.log"
  info "DEB_BUILD_OPTIONS=parallel=6 fakeroot debian/rules binary-aws"
  DEB_BUILD_OPTIONS="parallel=6" fakeroot debian/rules binary-aws 2>&1 | tee "$LOGDIR/binary_aws.log"
  info "DEB_BUILD_OPTIONS=parallel=6 fakeroot debian/rules binary-headers"
  DEB_BUILD_OPTIONS="parallel=6" fakeroot debian/rules binary-headers 2>&1 | tee "$LOGDIR/binary_headers.log"
  info "BUILD_COMPLETE; no package installation or reboot performed"
  find "$ROOT/kernel" -maxdepth 1 -type f -name '*2005*.deb' -printf '%f\n' | sort
  info "Verify resulting UTS_RELEASE and config before any installation"
fi

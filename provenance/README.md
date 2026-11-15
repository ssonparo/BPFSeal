# BPFSeal Kernel Provenance and Reproducibility

## Original kernel source

- Ubuntu release: 24.04 (Noble)
- Source package: linux-aws-7.0
- Source version: 7.0.0-1014.14~24.04.1
- Kernel version: 7.0.14
- Architecture: amd64
- Original source package descriptor: build/*.dsc

The source package archives were verified against the SHA-256
checksums in the Ubuntu source package descriptor.

The original Ubuntu kernel source archives are not redistributed
in this repository.

## Experimental kernel variants

| Build | Configuration |
|---|---|
| 2004 | BPFSeal with verbose logging |
| 2005 | Unmodified experimental baseline |
| 2006 | BPFSeal without verbose logging |
| 2007 | No-hash ablation |

The 2004–2007 package version identifiers were assigned locally
for the experimental builds.

## Patch verification

The three BPFSeal variants modify:

- include/linux/bpf.h
- kernel/bpf/arraymap.c
- kernel/bpf/syscall.c

For builds 2004, 2006, and 2007, each of the three archived
patch sections matched a patch independently reconstructed
from the corresponding experimental source tree and the
2005 baseline.

The ordering of sections differs between the archived and
reconstructed whole-patch files.

## Build information

The baseline build script is preserved in build/.

The recorded build commands include:

    fakeroot debian/rules clean
    DEB_BUILD_OPTIONS="parallel=6" fakeroot debian/rules binary-aws
    DEB_BUILD_OPTIONS="parallel=6" fakeroot debian/rules binary-headers

Recorded tools:

- GCC 13.3.0
- GNU Make 4.3
- dpkg-buildpackage 1.22.6

These commands were recovered from the baseline build script.
A complete independent rebuild of all four experimental
kernels has not been performed as part of this provenance audit.

## Experimental evidence

Public evidence:
https://github.com/ssonparo/BPFSeal/releases/tag/v0.1-artifacts

The original AWS evidence archive is preserved separately.
The public evidence archive contains documented hostname
redactions and excludes three binary perf recordings.

## Limitations

This provenance audit verified the Ubuntu source-package
identity and the three selected modified source files in
each experimental variant. It did not establish that all
remaining kernel-tree files were byte-for-byte identical
or independently reproduce the compiled kernels.

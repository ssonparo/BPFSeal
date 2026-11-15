-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 1.0
Source: linux-aws-7.0
Binary: linux-aws-7.0-headers-7.0.0-1014, linux-aws-7.0-tools-7.0.0-1014, linux-aws-7.0-cloud-tools-7.0.0-1014, linux-image-unsigned-7.0.0-1014-aws, linux-image-unsigned-7.0.0-1014-aws-dbgsym, linux-modules-7.0.0-1014-aws, linux-headers-7.0.0-1014-aws, linux-tools-7.0.0-1014-aws, linux-cloud-tools-7.0.0-1014-aws, linux-udebs-aws, linux-buildinfo-7.0.0-1014-aws, linux-image-unsigned-7.0.0-1014-aws-64k, linux-image-unsigned-7.0.0-1014-aws-64k-dbgsym, linux-modules-7.0.0-1014-aws-64k, linux-headers-7.0.0-1014-aws-64k, linux-tools-7.0.0-1014-aws-64k, linux-cloud-tools-7.0.0-1014-aws-64k, linux-udebs-aws-64k, linux-buildinfo-7.0.0-1014-aws-64k
Architecture: all amd64 arm64
Version: 7.0.0-1014.14~24.04.1
Maintainer: Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>
Standards-Version: 3.9.4.0
Vcs-Git: git://git.launchpad.net/~canonical-kernel/ubuntu/+source/linux-aws/+git/noble -b aws-7.0-next
Build-Depends: gcc-13, gcc-13-aarch64-linux-gnu [arm64] <cross>, gcc-13-arm-linux-gnueabihf [armhf] <cross>, gcc-13-powerpc64le-linux-gnu [ppc64el] <cross>, gcc-13-riscv64-linux-gnu [riscv64] <cross>, gcc-13-s390x-linux-gnu [s390x] <cross>, gcc-13-x86-64-linux-gnu [amd64] <cross>, debhelper-compat (= 10), autoconf <!stage1>, automake <!stage1>, bc <!stage1>, bindgen-0.65 [amd64 arm64 armhf ppc64el riscv64 s390x], bison <!stage1>, clang-19 [amd64 arm64 armhf ppc64el riscv64 s390x], cpio, curl <!stage1>, default-jdk-headless <!stage1>, dkms <!stage1>, flex <!stage1>, gawk <!stage1>, java-common <!stage1>, kmod <!stage1>, libaudit-dev <!stage1>, libcap-dev <!stage1>, libdebuginfod-dev [amd64 arm64 armhf ppc64el s390x riscv64] <!stage1>, libdw-dev <!stage1>, libelf-dev <!stage1>, libiberty-dev <!stage1>, liblzma-dev <!stage1>, libnewt-dev <!stage1>, libnl-3-dev, libnl-genl-3-dev, libnuma-dev [amd64 arm64 ppc64el s390x] <!stage1>, libpci-dev <!stage1>, libssl-dev <!stage1>, libstdc++-dev, libtool <!stage1>, libtraceevent-dev [amd64 arm64 armhf ppc64el s390x riscv64] <!stage1>, libtracefs-dev [amd64 arm64 armhf ppc64el s390x riscv64] <!stage1>, libudev-dev <!stage1>, libunwind8-dev [amd64 arm64 armhf ppc64el] <!stage1>, llvm-19-dev, makedumpfile [amd64] <!stage1>, openssl <!stage1>, pahole (>= 1.29-2ubuntu2) [amd64 arm64 armhf ppc64el s390x riscv64] | dwarves (>= 1.21) [amd64 arm64 armhf ppc64el s390x riscv64] <!stage1>, pkg-config <!stage1>, python3 <!stage1>, python3-dev <!stage1>, python3-setuptools, rsync [!i386] <!stage1>, rust-1.91-src [amd64 arm64 armhf ppc64el riscv64 s390x], rustc-1.91 [amd64 arm64 armhf ppc64el riscv64 s390x], rustfmt-1.91 [amd64 arm64 armhf ppc64el riscv64 s390x], uuid-dev <!stage1>, zstd <!stage1>
Build-Depends-Indep: asciidoc <!stage1>, bzip2 <!stage1>, python3-docutils <!stage1>, sharutils <!stage1>, xmlto <!stage1>
Package-List:
 linux-aws-7.0-cloud-tools-7.0.0-1014 deb devel optional arch=amd64,arm64 profile=!stage1
 linux-aws-7.0-headers-7.0.0-1014 deb devel optional arch=all profile=!stage1
 linux-aws-7.0-tools-7.0.0-1014 deb devel optional arch=amd64,arm64 profile=!stage1
 linux-buildinfo-7.0.0-1014-aws deb kernel optional arch=amd64,arm64 profile=!stage1
 linux-buildinfo-7.0.0-1014-aws-64k deb kernel optional arch=arm64 profile=!stage1
 linux-cloud-tools-7.0.0-1014-aws deb devel optional arch=amd64,arm64 profile=!stage1
 linux-cloud-tools-7.0.0-1014-aws-64k deb devel optional arch=arm64 profile=!stage1
 linux-headers-7.0.0-1014-aws deb devel optional arch=amd64,arm64 profile=!stage1
 linux-headers-7.0.0-1014-aws-64k deb devel optional arch=arm64 profile=!stage1
 linux-image-unsigned-7.0.0-1014-aws deb kernel optional arch=amd64,arm64 profile=!stage1
 linux-image-unsigned-7.0.0-1014-aws-64k deb kernel optional arch=arm64 profile=!stage1
 linux-image-unsigned-7.0.0-1014-aws-64k-dbgsym deb devel optional arch=arm64 profile=!stage1
 linux-image-unsigned-7.0.0-1014-aws-dbgsym deb devel optional arch=amd64,arm64 profile=!stage1
 linux-modules-7.0.0-1014-aws deb kernel optional arch=amd64,arm64 profile=!stage1
 linux-modules-7.0.0-1014-aws-64k deb kernel optional arch=arm64 profile=!stage1
 linux-tools-7.0.0-1014-aws deb devel optional arch=amd64,arm64 profile=!stage1
 linux-tools-7.0.0-1014-aws-64k deb devel optional arch=arm64 profile=!stage1
 linux-udebs-aws udeb debian-installer optional arch=amd64,arm64 profile=!stage1+!noudeb+!cross+!autopkgtest
 linux-udebs-aws-64k udeb debian-installer optional arch=arm64 profile=!stage1+!noudeb+!cross+!autopkgtest
Checksums-Sha1:
 84ccdabedcb5eb28af56989b6070cfa864a325a9 254937830 linux-aws-7.0_7.0.0.orig.tar.gz
 729c65a89e013f0e63c367b98b54b6992de67e70 5011007 linux-aws-7.0_7.0.0-1014.14~24.04.1.diff.gz
Checksums-Sha256:
 c6343795c8c7e4feff55f5b309365c8e0eaf49cd6abcb412e32315313f149536 254937830 linux-aws-7.0_7.0.0.orig.tar.gz
 9742a626b2eb81b9fd8ae9e083b4b4c4c96f161c021bd6f838273ea0a95ef581 5011007 linux-aws-7.0_7.0.0-1014.14~24.04.1.diff.gz
Files:
 415e5d4ee110d9415c2901751e6f9c9d 254937830 linux-aws-7.0_7.0.0.orig.tar.gz
 5fe3a0c2e291665534be9eba7dc5e3f3 5011007 linux-aws-7.0_7.0.0-1014.14~24.04.1.diff.gz
Ubuntu-Compatible-Signing: ubuntu/4 pro/3 livepatch:2025 kmod:2025

-----BEGIN PGP SIGNATURE-----

iQJPBAEBCgA5FiEEkEKyd+ITr7f9rrV6QONvSk9yOMMFAmqtnogbHG1hZ2FsaS5s
ZW1lc0BjYW5vbmljYWwuY29tAAoJEEDjb0pPcjjDNlQP/3ILHqb4YCnERJKX6Fp9
jmUAvxvvkd/EgqDqKT1g2J0YNqVxUzdAKERF2Ekhra/5mDgDX+R5ZEA1QRNr9Ptv
s3Frhuha0eAqaYSSW335KGR+x/lkJ/Ar5FiOCFpBFBqxG8gikwARTHTUJ1YSd3vx
T/H8mtW68uNs5hjWzh3QYWHZI8Ricqp4hX4pCWWpSWyHayvUw/KzYnry6zKrDX24
eW1TfgHTiYRL0KTzS8/tCfI468Fm+9orlSGsZOCNylfA7qlLwQWhqMW1uI3AEOnu
gXMo3nAvQ6OUNX0lORgpswKKsTQCT4rP4517aEuCXVViXW4MV0SqivxE+6sLs04q
dLu9OWE3+Fn84bymHQFjKMYr+GRECkcthE+3V/QcsqqoanlGvlYuZkoCTKsIH9HL
3a3ZK/I1goHrhICFys6p6IQhUHBrOeDZDeIqpk8ZhDHfSMWdz/CK0aT/P81u1bI1
CyO1esw3xAHZq/PZ2Qyi3pH5XiQfOtc4uG/mqPnYS+930yAIcoO3GMsK/E3ezWJM
QBPwqRHX8QquZCIy4Yp6cFYZtbauZkz2fvXl5+frJXjJD9Cd9oMW0FMMn05XHbHc
/MjeUGgzpfWg+7w2+PovJ8CwAJjNs9j8+RNvA4LmwwZH0hVo6sf9ssqJM2waKbqP
RZvrALSOpCVXarjcC30KcPbw
=BoLb
-----END PGP SIGNATURE-----

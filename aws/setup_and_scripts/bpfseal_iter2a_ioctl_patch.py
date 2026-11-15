#!/usr/bin/env python3
"""Apply experimental BPFSeal map-FD ioctl (iteration 2A) to the user's source tree.

Run on the EC2 instance, not on Mac. Does not build/install/reboot.
Deliberately leaves generation-zero digest invalid until first successful mutation.
"""
from pathlib import Path
import sys

root = Path.home() / 'bpfseal/kernel/linux-aws-7.0-bpfseal-patched'
p = root / 'kernel/bpf/syscall.c'
h = root / 'include/linux/bpf.h'
if not p.is_file() or not h.is_file():
    sys.exit('ERROR: expected patched kernel source not found; no changes made')
s = p.read_text()
header = h.read_text()

if 'bpfseal_prog_array_snapshot' not in header or 'struct bpfseal_map_evidence' not in header:
    sys.exit('ERROR: Iteration 2A snapshot declaration missing; no changes made')
if 'BPFSEAL_IOCTL_GET_EVIDENCE' in s:
    sys.exit('ERROR: ioctl implementation already present; no changes made')
if 'const struct file_operations bpf_map_fops = {' not in s:
    sys.exit('ERROR: expected map file operations missing; no changes made')

anchor = 'const struct file_operations bpf_map_fops = {'
if s.count(anchor) != 1:
    sys.exit('ERROR: ambiguous map file operations; no changes made')

newcode = r'''/*
 * BPFSeal Iteration 2A experimental interface, not a Linux UAPI proposal.
 * ABI is private to this test kernel and companion harness.
 * Supported on native x86-64 only (no compat_ioctl implementation).
 */
struct bpfseal_ioctl_evidence {
	__u32 version;
	__u32 map_id;
	__u32 max_entries;
	__u32 valid;
	__u64 map_cookie;
	__u64 generation;
	__u8 digest[SHA256_DIGEST_SIZE];
};

#define BPFSEAL_IOCTL_GET_EVIDENCE _IOR('Q', 0xe1, struct bpfseal_ioctl_evidence)

static long bpfseal_map_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg)
{
	struct bpfseal_ioctl_evidence out = { 0 };
	struct bpfseal_map_evidence snapshot;
	struct bpf_map *map = filp->private_data;
	int err;

	if (cmd != BPFSEAL_IOCTL_GET_EVIDENCE)
		return -ENOTTY;
	/* Only privileged test clients may observe raw map cookie and digest. */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!(filp->f_mode & FMODE_READ))
		return -EBADF;
	if (!arg)
		return -EFAULT;

	/* filp holds a map reference until the ioctl has finished. */
	err = bpfseal_prog_array_snapshot(map, &snapshot);
	if (err)
		return err;

	out.version = 1;
	out.map_id = snapshot.map_id;
	out.max_entries = snapshot.max_entries;
	out.valid = snapshot.valid ? 1 : 0;
	out.map_cookie = snapshot.map_cookie;
	out.generation = snapshot.generation;
	if (snapshot.valid)
		memcpy(out.digest, snapshot.digest, SHA256_DIGEST_SIZE);

	if (copy_to_user((void __user *)arg, &out, sizeof(out)))
		return -EFAULT;
	return 0;
}

'''

# Anchor the insert before the file operations; no changes to the existing BPF syscalls.
s2 = s.replace(anchor, newcode + anchor, 1)
ops_start = s2.index(anchor)
ops_end = s2.find('\n};', ops_start)
if ops_end < 0:
    sys.exit('ERROR: map file operations closing brace missing; no changes made')
ops = s2[ops_start:ops_end]
if '\t.release\t= bpf_map_release,' not in ops:
    sys.exit('ERROR: release anchor missing in map operations; no changes made')
ops2 = ops.replace('\t.release\t= bpf_map_release,',
                   '\t.release\t= bpf_map_release,\n\t.unlocked_ioctl\t= bpfseal_map_ioctl,', 1)
s2 = s2[:ops_start] + ops2 + s2[ops_end:]

# Minimal header for ioctl encoding; required header is expected on this Linux tree.
include = '#include <linux/ioctl.h>\n'
if include not in s2:
    # Include at top before all existing includes, only if a conventional include exists.
    first = s2.find('#include <')
    if first < 0:
        sys.exit('ERROR: no include section found; no changes made')
    s2 = s2[:first] + include + s2[first:]

backup = p.with_name('syscall.c.bpfseal-2a-ioctl-backup')
if backup.exists():
    sys.exit('ERROR: backup already exists; no changes made')
backup.write_text(s)
p.write_text(s2)
print('BPFSEAL_ITER2A_IOCTL: SOURCE PATCH APPLIED')
print(f'Changed: {p}')
print(f'Backup: {backup}')
print('Interface: privileged ioctl on BPF map FD (native x86-64 only)')
print('No kernel build, installation, or reboot performed.')

#!/usr/bin/env python3
"""BPFSeal Iteration 1C: bounded, diagnostic SHA-256 PROG_ARRAY state digest.

Applies to the source tree containing successful Iteration 1B.
This is NOT complete EEI, an authenticated root, or hardware attestation.
The digest is defined only for PROG_ARRAY maps with max_entries <= 64.
"""
from pathlib import Path
import sys

src = Path('kernel/bpf/arraymap.c')
hdr = Path('include/linux/bpf.h')
if not src.is_file() or not hdr.is_file():
    sys.exit('ERROR: run from kernel source tree root')
s, h = src.read_text(), hdr.read_text()
if 'BPFSEAL_ITER1C' in s or 'BPFSEAL_ITER1C' in h:
    sys.exit('ERROR: Iteration 1C already applied')
if 'BPFSEAL_ITER1B' not in s or 'bpfseal_generation' not in h:
    sys.exit('ERROR: Iteration 1B prerequisites missing')


def replace_once(text, old, new, label):
    n = text.count(old)
    if n != 1:
        raise ValueError(f'{label}: found {n} anchors, expected 1')
    return text.replace(old, new, 1)

# Domain-separated canonical representation: 16 ASCII bytes (zero-padded),
# be64 map cookie, be32 slot count, then 64 * (presence byte + 8 program tag
# bytes + be64 load_time). Unused slots are all zero; no padding ambiguity.
# Load time distinguishes different program instances with the same BPF tag
# within the bounded experiment but is not an authoritative object identity.
helper = r'''/* BPFSEAL_ITER1C: experimental per-map content digest, not attestation. */
#define BPFSEAL_ITER1C_MAX_SLOTS 64
#define BPFSEAL_ITER1C_SLOT_BYTES (1 + BPF_TAG_SIZE + 8)
#define BPFSEAL_ITER1C_PREFIX_BYTES (16 + 8 + 4)
#define BPFSEAL_ITER1C_BYTES (BPFSEAL_ITER1C_PREFIX_BYTES + \
                              BPFSEAL_ITER1C_MAX_SLOTS * BPFSEAL_ITER1C_SLOT_BYTES)

static void bpfseal_iter1c_put_be64(u8 *out, u64 val)
{
	int i;

	for (i = 0; i < 8; i++)
		out[i] = (u8)(val >> (56 - 8 * i));
}

static void bpfseal_iter1c_put_be32(u8 *out, u32 val)
{
	int i;

	for (i = 0; i < 4; i++)
		out[i] = (u8)(val >> (24 - 8 * i));
}

/* Caller must hold poke_mutex. This deliberately has bounded O(64) cost. */
static bool bpfseal_iter1c_digest(struct bpf_array *array)
{
	struct bpf_map *map = &array->map;
	u8 canonical[BPFSEAL_ITER1C_BYTES] = { 0 };
	u32 i;

	if (map->max_entries > BPFSEAL_ITER1C_MAX_SLOTS) {
		array->aux->bpfseal_digest_valid = false;
		return false;
	}

	memcpy(canonical, "BPFSeal-array-v1", 16);
	bpfseal_iter1c_put_be64(canonical + 16, map->cookie);
	bpfseal_iter1c_put_be32(canonical + 24, map->max_entries);

	for (i = 0; i < map->max_entries; i++) {
		struct bpf_prog *prog = READ_ONCE(array->ptrs[i]);
		u8 *slot = canonical + BPFSEAL_ITER1C_PREFIX_BYTES +
			i * BPFSEAL_ITER1C_SLOT_BYTES;

		if (!prog)
			continue;
		slot[0] = 1;
		memcpy(slot + 1, prog->tag, BPF_TAG_SIZE);
		bpfseal_iter1c_put_be64(slot + 1 + BPF_TAG_SIZE,
					prog->aux->load_time);
	}
	sha256(canonical, sizeof(canonical), array->aux->bpfseal_digest);
	array->aux->bpfseal_digest_valid = true;
	return true;
}

'''

try:
    h = replace_once(h,
        '\tu64 bpfseal_generation;\n',
        '\tu64 bpfseal_generation;\n'
        '\t/* BPFSEAL_ITER1C: digest is valid only for <=64 slots. */\n'
        '\tu8 bpfseal_digest[SHA256_DIGEST_SIZE];\n'
        '\tbool bpfseal_digest_valid;\n',
        'aux fields')
    # SHA256_DIGEST_SIZE already used elsewhere in bpf.h.
    include_anchor = '#include <linux/bpf.h>\n'
    s = replace_once(s, include_anchor,
                     include_anchor + '#include <crypto/sha2.h> /* BPFSEAL_ITER1C */\n',
                     'sha2 include')
    s = replace_once(s, 'int bpf_fd_array_map_update_elem(',
                     helper + 'int bpf_fd_array_map_update_elem(', 'helper insertion')

    start = s.index('int bpf_fd_array_map_update_elem(')
    mid = s.index('static long __fd_array_map_delete_elem(', start)
    end = s.index('static long fd_array_map_delete_elem(', mid)
    update, delete = s[start:mid], s[mid:end]

    update = replace_once(update,
        '\tu64 bpfseal_gen = 0; /* BPFSEAL_ITER1B */\n',
        '\tu64 bpfseal_gen = 0; /* BPFSEAL_ITER1B */\n'
        '\tu8 bpfseal_digest[SHA256_DIGEST_SIZE]; /* BPFSEAL_ITER1C */\n'
        '\tbool bpfseal_digest_valid = false;\n', 'update locals')
    update = replace_once(update,
        '\t\t\tbpfseal_gen = ++array->aux->bpfseal_generation;\n',
        '\t\t\tbpfseal_gen = ++array->aux->bpfseal_generation;\n'
        '\t\tif (map->map_type == BPF_MAP_TYPE_PROG_ARRAY) {\n'
        '\t\t\tbpfseal_digest_valid = bpfseal_iter1c_digest(array);\n'
        '\t\t\tif (bpfseal_digest_valid)\n'
        '\t\t\t\tmemcpy(bpfseal_digest, array->aux->bpfseal_digest,\n'
        '\t\t\t\t       SHA256_DIGEST_SIZE);\n'
        '\t\t}\n', 'update committed digest')
    update = replace_once(update,
        '\tif (old_ptr)\n\t\tmap->ops->map_fd_put_ptr(map, old_ptr, true);',
        '\t/* BPFSEAL_ITER1C: digest captured while mutex was held. */\n'
        '\tif (map->map_type == BPF_MAP_TYPE_PROG_ARRAY && bpfseal_digest_valid)\n'
        '\t\tpr_info("BPFSEAL_ITER1C update map=%u gen=%llu digest=%*phN\\n",\n'
        '\t\t\tmap->id, (unsigned long long)bpfseal_gen,\n'
        '\t\t\tSHA256_DIGEST_SIZE, bpfseal_digest);\n'
        '\tif (old_ptr)\n\t\tmap->ops->map_fd_put_ptr(map, old_ptr, true);',
        'update digest log')

    delete = replace_once(delete,
        '\tu64 bpfseal_gen = 0; /* BPFSEAL_ITER1B */\n',
        '\tu64 bpfseal_gen = 0; /* BPFSEAL_ITER1B */\n'
        '\tu8 bpfseal_digest[SHA256_DIGEST_SIZE]; /* BPFSEAL_ITER1C */\n'
        '\tbool bpfseal_digest_valid = false;\n', 'delete locals')
    delete = replace_once(delete,
        '\t\t\tbpfseal_gen = ++array->aux->bpfseal_generation;\n',
        '\t\t\tbpfseal_gen = ++array->aux->bpfseal_generation;\n'
        '\t\tif (old_ptr && map->map_type == BPF_MAP_TYPE_PROG_ARRAY) {\n'
        '\t\t\tbpfseal_digest_valid = bpfseal_iter1c_digest(array);\n'
        '\t\t\tif (bpfseal_digest_valid)\n'
        '\t\t\t\tmemcpy(bpfseal_digest, array->aux->bpfseal_digest,\n'
        '\t\t\t\t       SHA256_DIGEST_SIZE);\n'
        '\t\t}\n', 'delete committed digest')
    delete = replace_once(delete,
        '\t\tmap->ops->map_fd_put_ptr(map, old_ptr, need_defer);',
        '\t\t/* BPFSEAL_ITER1C: no digest is published for empty deletes. */\n'
        '\t\tif (map->map_type == BPF_MAP_TYPE_PROG_ARRAY && bpfseal_digest_valid)\n'
        '\t\t\tpr_info("BPFSEAL_ITER1C delete map=%u gen=%llu digest=%*phN\\n",\n'
        '\t\t\t\tmap->id, (unsigned long long)bpfseal_gen,\n'
        '\t\t\t\tSHA256_DIGEST_SIZE, bpfseal_digest);\n'
        '\t\tmap->ops->map_fd_put_ptr(map, old_ptr, need_defer);',
        'delete digest log')
    s = s[:start] + update + delete + s[end:]
except (ValueError, IndexError) as exc:
    sys.exit(f'ERROR: {exc}; no files modified')

for p in (hdr, src):
    if p.with_name(p.name + '.bpfseal-iter1c-backup').exists():
        sys.exit('ERROR: Iteration 1C backup already exists; no files modified')

try:
    for p in (hdr, src):
        p.with_name(p.name + '.bpfseal-iter1c-backup').write_bytes(p.read_bytes())
    hdr.write_text(h)
    src.write_text(s)
except Exception as exc:
    for p in (hdr, src):
        backup = p.with_name(p.name + '.bpfseal-iter1c-backup')
        if backup.exists():
            p.write_bytes(backup.read_bytes())
    sys.exit(f'ERROR: patch write failed; originals restored: {exc}')

print('PATCH APPLIED: BPFSEAL_ITER1C (bounded diagnostic content digest)')
print('Files: kernel/bpf/arraymap.c and include/linux/bpf.h')
print('No compilation, install, or reboot performed.')

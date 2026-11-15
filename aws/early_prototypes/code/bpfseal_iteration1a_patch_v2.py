#!/usr/bin/env python3
"""BPFSeal 1A diagnostic instrumentation, source-checked, not attestation.
Run in the root of the clean Linux AWS 7.0 patched source tree.
"""
from pathlib import Path
import re

p = Path('kernel/bpf/arraymap.c')
if not p.is_file():
    raise SystemExit('ERROR: run from the patched kernel source root')
s = p.read_text()
if 'BPFSEAL_ITER1A' in s:
    raise SystemExit('ERROR: BPFSEAL_ITER1A already present; refusing duplicate')
backup = p.with_name(p.name + '.bpfseal-original')
if backup.exists():
    raise SystemExit('ERROR: existing backup; inspect before retrying')

def function_span(text, declaration):
    matches = list(re.finditer(declaration, text, flags=re.M))
    if len(matches) != 1:
        raise SystemExit(f'ERROR: expected one function, got {len(matches)} for {declaration}')
    start = matches[0].start()
    opening = text.find('{', matches[0].end())
    if opening == -1:
        raise SystemExit('ERROR: no opening brace')
    depth = 0
    for i in range(opening, len(text)):
        if text[i] == '{': depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0: return start, i + 1
    raise SystemExit('ERROR: unterminated function')

update_decl = r'^int bpf_fd_array_map_update_elem\s*\('
delete_decl = r'^static long __fd_array_map_delete_elem\s*\('
ua, ub = function_span(s, update_decl)
da, db = function_span(s, delete_decl)
update = s[ua:ub]
delete = s[da:db]

# Check that both relevant paths commit through xchg, that updates run the
# optional JIT poke before the insertion point, and that old refs are live.
if update.count('xchg(array->ptrs + index, new_ptr)') != 2 or 'map_poke_run(map, index, old_ptr, new_ptr)' not in update:
    raise SystemExit('ERROR: unexpected update commit structure')
if delete.count('xchg(array->ptrs + index, NULL)') != 2 or 'map_poke_run(map, index, old_ptr, NULL)' not in delete:
    raise SystemExit('ERROR: unexpected delete commit structure')

# Match the reference release as an anchor rather than hard-coded whitespace.
# Every event is placed before the reference to the replaced target is dropped.
update_anchor = r'(?m)^(?P<indent>[ \t]*)if\s*\(old_ptr\)\s*\n[ \t]*map->ops->map_fd_put_ptr\(map, old_ptr, true\);'
delete_anchor = r'(?m)^(?P<indent>[ \t]*)map->ops->map_fd_put_ptr\(map, old_ptr, need_defer\);'

if len(list(re.finditer(update_anchor, update))) != 1:
    raise SystemExit('ERROR: update reference-release anchor mismatch; no edits')
if len(list(re.finditer(delete_anchor, delete))) != 1:
    raise SystemExit('ERROR: delete reference-release anchor mismatch; no edits')

update_event = '''\t/* BPFSEAL_ITER1A: diagnostic event only; not atomic attestation. */
\tif (map->map_type == BPF_MAP_TYPE_PROG_ARRAY) {
\t\tstruct bpf_prog *before = old_ptr;
\t\tstruct bpf_prog *after = new_ptr;

\t\tpr_info("BPFSEAL_ITER1A update map=%u slot=%u old=%u new=%u\\n",
\t\t\tmap->id, index,
\t\t\tbefore ? before->aux->id : 0,
\t\t\tafter ? after->aux->id : 0);
\t}

'''
delete_event = '''\t\t/* BPFSEAL_ITER1A: diagnostic event on successful removal. */
\t\tif (map->map_type == BPF_MAP_TYPE_PROG_ARRAY) {
\t\t\tstruct bpf_prog *before = old_ptr;

\t\t\tpr_info("BPFSEAL_ITER1A delete map=%u slot=%u old=%u new=0\\n",
\t\t\t\tmap->id, index, before->aux->id);
\t\t}
'''
update2 = re.sub(update_anchor, lambda m: update_event + m.group(0), update, count=1)
delete2 = re.sub(delete_anchor, lambda m: delete_event + m.group(0), delete, count=1)
# Replace from right to left so source offsets remain valid.
changes = sorted([(ua, ub, update2), (da, db, delete2)], reverse=True)
s2 = s
for a, b, replacement in changes:
    s2 = s2[:a] + replacement + s2[b:]
if s2.count('BPFSEAL_ITER1A') != 4:
    raise SystemExit('ERROR: unexpected instrumentation count; no edits')
backup.write_text(s)
p.write_text(s2)
print('PATCH APPLIED: kernel/bpf/arraymap.c')
print('BACKUP:', backup)
print('Diagnostic logging only; no EEI, root, or hardware attestation')

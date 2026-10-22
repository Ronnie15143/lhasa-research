#!/usr/bin/env python3
"""ko_disasm.py - disassemble a function out of a loadable kernel module (.ko).

A .ko is ET_REL: symbols are section-relative and the section addresses are 0, so
"vaddr" does not exist.  This tool resolves the symbol through its st_shndx,
disassembles inside that section, and annotates every branch target with the
module's own function name.

usage: ko_disasm.py <module.ko> <symbol> [n_insn]
       ko_disasm.py <module.ko> --list      # list functions of .text
"""
import bisect
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    path, name = sys.argv[1], sys.argv[2]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 400

    f = open(path, 'rb')
    e = ELFFile(f)
    symtab = e.get_section_by_name('.symtab')
    sections = list(e.iter_sections())

    # collect functions per section index
    by_sec = {}
    target = None
    for s in symtab.iter_symbols():
        if not s.name or not s['st_value']:
            continue
        if s['st_info']['type'] == 'STT_FUNC' and s['st_shndx'] not in ('SHN_UNDEF', 'SHN_ABS'):
            by_sec.setdefault(s['st_shndx'], []).append((s['st_value'], s.name))
        if s.name == name:
            target = s
    for k in by_sec:
        by_sec[k].sort()

    if name == '--list' or target is None:
        for idx, funs in sorted(by_sec.items()):
            sec = sections[idx] if idx < len(sections) else None
            print(f'--- section {getattr(sec, "name", idx)} ({len(funs)} funcs)')
            for v, n in funs:
                print(f'  {v:#08x}  {n}')
        return 0 if target else 1

    idx = target['st_shndx']
    funcs = by_sec.get(idx, [])
    addrs = [a for a, _ in funcs]
    sec = sections[idx]
    start = target['st_value']
    # function size = gap to the next function in the same section
    nxt = None
    for a, _n in funcs:
        if a > start:
            nxt = a
            break
    size = (nxt - start) if nxt else min(0x400, sec['sh_size'] - start)
    off = sec['sh_offset'] + start
    data = open(path, 'rb').read()[off:off + size]

    print(f'{name}  section={sec.name} vaddr={start:#x} size={size:#x} file_off={off:#x}')

    def ann(t):
        i = bisect.bisect_right(addrs, t) - 1
        if i < 0:
            return None
        b, n = funcs[i]
        return n + (f'+{t-b:#x}' if t != b else '')

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    n = 0
    for ins in md.disasm(data, start):
        extra = ''
        if ins.mnemonic in ('bl', 'b', 'cbz', 'cbnz', 'tbz', 'tbnz'):
            op = ins.op_str.split(',')[-1].strip()
            if op.startswith('#'):
                try:
                    s = ann(int(op[1:], 16))
                    if s:
                        extra = '   ; ' + s
                except ValueError:
                    pass
        print(f'  {ins.address:#08x}  {ins.mnemonic} {ins.op_str}{extra}')
        n += 1
        if n >= limit:
            break
    return 0


if __name__ == '__main__':
    sys.exit(main())

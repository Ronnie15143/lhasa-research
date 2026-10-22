#!/usr/bin/env python3
"""solve_live.py — pair a frozen trace window and solve the KASLR slide against
the symbol table recovered from the device's own kernel Image.

usage: solve_live.py <pair_dir> <vmlinux.elf>
Prints the slide and the runtime address of every interesting global.
"""
import collections
import sys

import pair_records as P
from elftools.elf.elffile import ELFFile

KIMAGE_BASE = 0xFFFFFFC080000000


def load_syms(path):
    syms = {}
    with open(path, 'rb') as f:
        e = ELFFile(f)
        for sec in e.iter_sections():
            if sec.name.startswith('.symtab'):
                for s in sec.iter_symbols():
                    if s.name and s['st_value']:
                        syms.setdefault(s.name, s['st_value'])
    return syms


def live_pairs(d):
    txt = P.text_records(f'{d}/text.txt')
    out = []
    for cpu in sorted(txt):
        try:
            raws = P.raw_records(f'{d}/raw_{cpu}.bin')
        except FileNotFoundError:
            continue
        if not raws:
            continue
        for caller, t in P.align(raws, txt[cpu]):
            if t[5] is False:           # core kernel only, skip modules
                out.append((caller, t[2], t[3]))
    return out


def main(d, elf):
    syms = load_syms(elf)
    pairs = live_pairs(d)
    votes = collections.Counter()
    detail = []
    for caller, sym, off in pairs:
        base = syms.get(sym)
        if base is None:
            continue
        votes[caller - (base + off)] += 1
        detail.append((caller, sym, off))
    print(f'paired core records: {len(pairs)}   usable: {len(detail)}')
    if not votes:
        print('no vote')
        return 1
    top = votes.most_common(4)
    for s, n in top:
        print(f'  slide={s:#x}  votes={n}  ({s % 0x200000:#x} mod 2MiB)')
    slide, n = top[0]
    total = sum(votes.values())
    print(f'\n=> slide = {slide:#x}   confidence {n}/{total}')
    if slide % 0x200000:
        print('   !! not 2MiB aligned — suspicious')
    print(f'   _text    = {KIMAGE_BASE + slide:#x}')
    for k in ('selinux_state', 'init_task', 'init_cred', 'selinux_enforcing'):
        if k in syms:
            print(f'   {k:16s} = {syms[k] + slide:#x}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1], sys.argv[2]))

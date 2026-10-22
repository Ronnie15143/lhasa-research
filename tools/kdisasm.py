#!/usr/bin/env python3
"""kdisasm.py - disassemble a named function out of the device's own kernel
Image, using the symbol table recovered from that same Image.

Image-4.0.21.0.bin is a straight linear dump with text_offset = 0, so
    file_offset == link_addr - 0xffffffc080000000

usage: kdisasm.py <elf> <image> <symbol> [n_insns]
"""
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile

KIMAGE = 0xFFFFFFC080000000


def sym(elf, name):
    with open(elf, 'rb') as f:
        e = ELFFile(f)
        for sec in e.iter_sections():
            if not sec.name.startswith('.symtab'):
                continue
            for s in sec.iter_symbols():
                if s.name == name and s['st_value']:
                    return s['st_value']
    return None


def main():
    elf, img, name = sys.argv[1], sys.argv[2], sys.argv[3]
    n = int(sys.argv[4]) if len(sys.argv) > 4 else 120
    addr = sym(elf, name)
    if addr is None:
        print(f'symbol {name} not found')
        return 1
    off = addr - KIMAGE
    data = open(img, 'rb').read()
    print(f'{name} @ {addr:#x}  file_off={off:#x}')
    code = data[off:off + n * 4]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for ins in md.disasm(code, addr):
        t = f'{ins.mnemonic} {ins.op_str}'
        mark = ''
        low = t.lower()
        if 'invalid argument' in low or '#0x16' in t or '0xffffffffffffffea' in t:
            mark = '   <== -EINVAL'
        print(f'  {ins.address:#014x}  {t}{mark}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

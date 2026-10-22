#!/usr/bin/env python3
"""erofs_carve.py - pull ELF objects (.ko) straight out of an EROFS partition image.

The dlkm partitions are EROFS (magic 0xE0F5E1E2 at offset 1024).  If the file
data happens to be stored uncompressed it sits flat in the image, so we can cut
objects out by scanning for \\x7fELF and computing the object extent from the
section-header table (handling the e_shnum == 0 / SHN_XINDEX case where the real
count lives in shdr[0].sh_size).

usage: erofs_carve.py <image> <outdir> [name-filter]
"""
import os
import re
import struct
import sys

EM_AARCH64 = 0xB7


def elf_extent(d, o):
    """Return (size, shnum) for a candidate ELF at offset o, or None."""
    if o + 0x40 > len(d) or d[o:o + 4] != b'\x7fELF':
        return None
    if d[o + 4] != 2 or d[o + 5] != 1:           # 64-bit, little endian
        return None
    if struct.unpack_from('<H', d, o + 18)[0] != EM_AARCH64:
        return None

    e_shoff = struct.unpack_from('<Q', d, o + 0x28)[0]
    e_shentsize = struct.unpack_from('<H', d, o + 0x3a)[0]
    e_shnum = struct.unpack_from('<H', d, o + 0x3c)[0]
    e_phoff = struct.unpack_from('<Q', d, o + 0x20)[0]
    e_phnum = struct.unpack_from('<H', d, o + 0x38)[0]
    e_phentsize = struct.unpack_from('<H', d, o + 0x36)[0]

    end = 0
    shnum = e_shnum
    if e_shoff and e_shentsize:
        if shnum == 0:                            # extended numbering
            if o + e_shoff + 0x40 <= len(d):
                shnum = struct.unpack_from('<Q', d, o + e_shoff + 0x20)[0]
        if shnum and shnum < 0x10000:
            end = max(end, e_shoff + shnum * e_shentsize)
            for i in range(shnum):
                off = o + e_shoff + i * e_shentsize
                if off + 0x40 > len(d):
                    break
                so = struct.unpack_from('<Q', d, off + 0x18)[0]
                ss = struct.unpack_from('<Q', d, off + 0x20)[0]
                if so + ss <= len(d):
                    end = max(end, so + ss)
    if e_phoff and e_phnum and e_phentsize:
        end = max(end, e_phoff + e_phnum * e_phentsize)
        for i in range(e_phnum):
            off = o + e_phoff + i * e_phentsize
            if off + 0x38 > len(d):
                break
            po = struct.unpack_from('<Q', d, off + 0x08)[0]
            pf = struct.unpack_from('<Q', d, off + 0x20)[0]
            if po + pf <= len(d):
                end = max(end, po + pf)
    if end <= 0x100 or o + end > len(d):
        return None
    return end, shnum


def modinfo(d, o, size):
    blob = d[o:o + size]
    name = None
    m = re.search(rb'name=([\w\-]+)', blob)
    if m:
        name = m.group(1).decode('ascii', 'replace')
    vm = None
    m = re.search(rb'vermagic=([\x20-\x7e]{8,120})', blob)
    if m:
        vm = m.group(1).decode('ascii', 'replace')
    return name, vm


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    img, outdir = sys.argv[1], sys.argv[2]
    filt = sys.argv[3] if len(sys.argv) > 3 else None
    d = open(img, 'rb').read()
    os.makedirs(outdir, exist_ok=True)

    print(f'image={img} size={len(d)}')
    hits = [m.start() for m in re.finditer(b'\x7fELF', d)]
    print(f'ELF magic hits={len(hits)}')
    written = 0
    covered = []                                  # (start, end) already emitted
    for o in hits:
        if any(s <= o < e for s, e in covered):
            continue
        r = elf_extent(d, o)
        if not r:
            continue
        size, shnum = r
        name, vm = modinfo(d, o, size)
        fname = (name or f'obj_{o:#x}') + '.ko'
        covered.append((o, o + size))
        if filt and filt not in fname:
            continue
        with open(os.path.join(outdir, fname), 'wb') as f:
            f.write(d[o:o + size])
        written += 1
        print(f'  + {fname:<32} off={o:#010x} size={size:#09x} shnum={shnum}'
              + (f' vermagic={vm}' if vm else ''))
    print(f'wrote {written} objects into {outdir}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

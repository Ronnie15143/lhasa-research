#!/usr/bin/env python3
"""esp_patch.py - replace EFI/BOOT/BOOTAA64.EFI inside the android_esp FAT image.

The efisp partition (`android_esp`) is an 8 MiB FAT12 image that holds the GBL
bootloader the firmware loads without authenticating it.  We only need to swap
one file, and our replacement (a 2.5 KB UEFI app) is far smaller than the
original 1.58 MB, so the patch is: walk EFI/BOOT, find BOOTAA64.EFI, write the
new body at its first cluster and update the directory entry's size field.

usage: esp_patch.py <in.img> <payload.efi> <out.img>
"""
import struct
import sys


class Fat:
    def __init__(self, data):
        self.d = bytearray(data)
        b = self.d
        self.bps = struct.unpack_from('<H', b, 11)[0]
        self.spc = b[13]
        self.rsvd = struct.unpack_from('<H', b, 14)[0]
        self.nfats = b[16]
        self.root_entries = struct.unpack_from('<H', b, 17)[0]
        self.tot16 = struct.unpack_from('<H', b, 19)[0]
        self.fatsz = struct.unpack_from('<H', b, 22)[0]
        if self.fatsz == 0:                     # FAT32
            self.fatsz = struct.unpack_from('<I', b, 36)[0]
        self.root_start = (self.rsvd + self.nfats * self.fatsz) * self.bps
        self.root_sectors = (self.root_entries * 32 + self.bps - 1) // self.bps
        self.data_start = self.root_start + self.root_sectors * self.bps
        self.cluster_bytes = self.spc * self.bps
        self.type = 'FAT12/16' if self.fatsz and self.tot16 else 'FAT32'

    def cluster_off(self, clus):
        return self.data_start + (clus - 2) * self.cluster_bytes

    def next_cluster(self, clus):
        if self.type == 'FAT32':
            return struct.unpack_from('<I', self.d, self.rsvd * self.bps + clus * 4)[0] & 0x0FFFFFFF
        off = self.rsvd * self.bps + clus * 3 // 2
        v = struct.unpack_from('<H', self.d, off)[0]
        return (v >> 4) if (clus & 1) else (v & 0xFFF)

    def read_dir(self, start_off, count):
        out = []
        for i in range(count):
            e = start_off + i * 32
            if e + 32 > len(self.d):
                break
            name = bytes(self.d[e:e + 11])
            if name[0] == 0x00:
                break
            if name[0] == 0xE5:
                continue
            attr = self.d[e + 11]
            clus = struct.unpack_from('<H', self.d, e + 26)[0]
            size = struct.unpack_from('<I', self.d, e + 28)[0]
            out.append({'off': e, 'name': name, 'attr': attr, 'clus': clus, 'size': size})
        return out

    def dir_entries(self, dir_off, cluster=None):
        if cluster is None:
            return self.read_dir(dir_off, self.root_entries)
        ents = []
        seen = set()
        c = cluster
        while 2 <= c < 0xFFF8 and c not in seen:
            seen.add(c)
            ents += self.read_dir(self.cluster_off(c), self.cluster_bytes // 32)
            c = self.next_cluster(c)
        return ents


def find(ents, short):
    for e in ents:
        if e['name'][:11] == short:
            return e
    return None


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    src, payload_path, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    img = Fat(open(src, 'rb').read())
    payload = open(payload_path, 'rb').read()

    print(f'image {src}: {len(img.d)} bytes  bps={img.bps} spc={img.spc} '
          f'root_ents={img.root_entries} fatsz={img.fatsz} data@{img.data_start:#x}')

    root = img.dir_entries(img.root_start)
    efi = find(root, b'EFI        ')
    if not efi:
        print('no EFI directory')
        return 1
    boot = find(img.dir_entries(None, efi['clus']), b'BOOT       ')
    if not boot:
        print('no EFI/BOOT directory')
        return 1
    ent = find(img.dir_entries(None, boot['clus']), b'BOOTAA64EFI')
    if not ent:
        print('no EFI/BOOT/BOOTAA64.EFI')
        return 1

    print(f'found BOOTAA64.EFI: dir_entry@{ent["off"]:#x} clus={ent["clus"]} size={ent["size"]}')
    if len(payload) > ent['size']:
        # count the clusters we could use
        free = 0
        c = ent['clus']
        while 2 <= c < 0xFFF8:
            free += img.cluster_bytes
            c = img.next_cluster(c)
        if len(payload) > free:
            print(f'payload {len(payload)} > available {free}')
            return 1

    off = img.cluster_off(ent['clus'])
    img.d[off:off + len(payload)] = payload
    struct.pack_into('<I', img.d, ent['off'] + 28, len(payload))

    with open(dst, 'wb') as f:
        f.write(img.d)
    print(f'wrote {dst}: payload {len(payload)} bytes at {off:#x}, size field updated')
    return 0


if __name__ == '__main__':
    sys.exit(main())

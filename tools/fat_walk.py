#!/usr/bin/env python3
"""Recursively walk a FAT12/16/32 image and print the full directory tree."""
import struct
import sys


class Fat:
    def __init__(self, data):
        self.d = data
        bs = data[:512]
        self.bps = struct.unpack_from("<H", bs, 0x0B)[0]
        self.spc = bs[0x0D]
        self.rsv = struct.unpack_from("<H", bs, 0x0E)[0]
        self.nfats = bs[0x10]
        self.root_ent = struct.unpack_from("<H", bs, 0x11)[0]
        self.fatsz16 = struct.unpack_from("<H", bs, 0x16)[0]
        self.fatsz32 = struct.unpack_from("<I", bs, 0x24)[0]
        self.rootcl = struct.unpack_from("<I", bs, 0x2C)[0]
        self.cs = self.spc * self.bps
        self.fat_off = self.rsv * self.bps
        if self.fatsz16:
            self.fatsz = self.fatsz16
            self.root_dir_off = self.fat_off + self.nfats * self.fatsz16 * self.bps
            self.root_is_fixed = True
        else:
            self.fatsz = self.fatsz32
            self.root_is_fixed = False
        self.data_off = self.fat_off + self.nfats * self.fatsz * self.bps
        if self.root_is_fixed:
            self.data_off += self.root_ent * 32

    def cluster_off(self, cl):
        return self.data_off + (cl - 2) * self.cs

    def next_cluster(self, cl):
        if self.fatsz16:
            off = self.fat_off + cl * 2
            v = struct.unpack_from("<H", self.d, off)[0]
            return None if v >= 0xFFF8 else v
        off = self.fat_off + cl * 4
        v = struct.unpack_from("<I", self.d, off)[0] & 0x0FFFFFFF
        return None if v >= 0x0FFFFFF8 else v

    def chain(self, cl, limit=64):
        out = []
        seen = set()
        while cl and cl not in seen and len(out) < limit:
            seen.add(cl)
            out.append(cl)
            cl = self.next_cluster(cl)
        return out

    def ls(self, offset, clusters=None, depth=0):
        pad = "  " * depth
        entries = []
        if clusters is None:
            blob = self.d[offset:offset + self.root_ent * 32] if self.root_is_fixed else b""
        else:
            blob = b"".join(self.d[self.cluster_off(c):self.cluster_off(c) + self.cs] for c in clusters)
        for i in range(len(blob) // 32):
            ent = blob[i * 32:(i + 1) * 32]
            if len(ent) < 32 or ent[0] == 0x00:
                break
            if ent[0] == 0xE5 or ent[0x0B] == 0x0F:
                continue
            attr = ent[0x0B]
            if attr & 0x08:
                continue
            name = ent[0:8].decode("ascii", "replace").rstrip()
            ext = ent[8:11].decode("ascii", "replace").rstrip()
            full = name + ("." + ext if ext else "")
            size = struct.unpack_from("<I", ent, 0x1C)[0]
            clus = struct.unpack_from("<H", ent, 0x1A)[0]
            if not self.fatsz16:
                clus |= struct.unpack_from("<H", ent, 0x14)[0] << 16
            if attr & 0x10:
                print(f"{pad}[DIR] {full}/")
                if depth < 6 and clus >= 2:
                    self.ls(0, self.chain(clus), depth + 1)
            else:
                print(f"{pad}      {full:24s} {size:>9d} bytes  cluster={clus}")
                entries.append((full, size, clus))
        return entries


def main(path):
    with open(path, "rb") as fh:
        f = Fat(fh.read())
    print(f"bps={f.bps} spc={f.spc} fatsz16={f.fatsz16} rootcl={f.rootcl}")
    print("=== tree ===")
    f.ls(f.root_dir_off)


if __name__ == "__main__":
    main(sys.argv[1])

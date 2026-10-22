#!/usr/bin/env python3
"""Parse a FAT image's boot sector and walk the root directory listing."""
import struct
import sys


def main(path):
    with open(path, "rb") as fh:
        data = fh.read()

    bs = data[:512]
    print(f"=== boot sector ({path}) ===")
    print(f"  OEM       : {bs[3:11].decode('ascii', 'replace')}")
    bps = struct.unpack_from("<H", bs, 0x0B)[0]
    spc = bs[0x0D]
    rsv = struct.unpack_from("<H", bs, 0x0E)[0]
    nfats = bs[0x10]
    root_ent = struct.unpack_from("<H", bs, 0x11)[0]
    tot16 = struct.unpack_from("<H", bs, 0x13)[0]
    fatsz16 = struct.unpack_from("<H", bs, 0x16)[0]
    tot32 = struct.unpack_from("<I", bs, 0x20)[0]
    fatsz32 = struct.unpack_from("<I", bs, 0x24)[0]
    rootcl = struct.unpack_from("<I", bs, 0x2C)[0]
    print(f"  bytes/sector={bps} sec/cluster={spc} reserved={rsv} fats={nfats}")
    print(f"  root_entries={root_ent} tot16={tot16} fatsz16={fatsz16}")
    print(f"  tot32={tot32} fatsz32={fatsz32} root_cluster={rootcl}")

    fat_start = rsv * bps
    if fatsz16:
        # FAT12/FAT16: fixed-size root directory right after the FATs
        root_off = fat_start + nfats * fatsz16 * bps
    elif rootcl:
        cluster_size = spc * bps
        root_off = fat_start + nfats * fatsz32 * bps + (rootcl - 2) * cluster_size
    else:
        root_off = fat_start
    print(f"  root_off=0x{root_off:x}")

    print()
    print("=== root directory entries ===")
    off = root_off
    for _ in range(128):
        if off + 32 > len(data):
            break
        ent = data[off:off + 32]
        if ent[0] == 0x00:
            break
        if ent[0] == 0xE5:
            off += 32
            continue
        attr = ent[0x0B]
        if attr == 0x0F:  # long file name
            off += 32
            continue
        name = ent[0:8].decode("ascii", "replace").rstrip()
        ext = ent[8:11].decode("ascii", "replace").rstrip()
        size = struct.unpack_from("<I", ent, 0x1C)[0]
        clus = struct.unpack_from("<H", ent, 0x1A)[0] | (struct.unpack_from("<H", ent, 0x14)[0] << 16)
        flag = "DIR" if attr & 0x10 else "   "
        print(f"  {flag} {name}{('.' + ext) if ext else '':12s} size={size:>9d} cluster={clus}")
        off += 32


if __name__ == "__main__":
    main(sys.argv[1])

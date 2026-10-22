#!/usr/bin/env python3
"""Extract a file from a FAT image by following its cluster chain."""
import struct
import sys

sys.path.insert(0, ".")
from fat_walk import Fat  # noqa: E402


def extract(img_path, out_path, cluster, size):
    with open(img_path, "rb") as fh:
        f = Fat(fh.read())
    blob = bytearray()
    for cl in f.chain(cluster, limit=4096):
        off = f.cluster_off(cl)
        blob += f.d[off:off + f.cs]
    blob = bytes(blob[:size])
    with open(out_path, "wb") as fh:
        fh.write(blob)
    print(f"wrote {out_path}: {len(blob)} bytes (requested {size})")
    print(f"head: {blob[:16].hex()}")
    # PE check
    if blob[:2] == b"MZ":
        pe_off = struct.unpack_from("<I", blob, 0x3C)[0]
        if blob[pe_off:pe_off + 4] == b"PE\0\0":
            machine = struct.unpack_from("<H", blob, pe_off + 4)[0]
            print(f"PE signature OK at 0x{pe_off:x}, machine=0x{machine:04x} "
                  f"({'ARM64' if machine == 0xAA64 else 'other'})")


if __name__ == "__main__":
    extract(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))

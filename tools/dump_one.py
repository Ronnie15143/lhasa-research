#!/usr/bin/env python3
"""dump_one.py - dump selected files out of an EROFS image using erofs_extract.py.

usage: dump_one.py <image> <outdir> <name-substring> [more-substrings...]

Walks the filesystem once, and for every regular file whose path contains one of
the substrings, writes it out.  A failure on one file never aborts the run.
"""
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import erofs_extract as E  # noqa: E402


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    img, outdir = sys.argv[1], sys.argv[2]
    wants = [s.lower() for s in sys.argv[3:]]
    os.makedirs(outdir, exist_ok=True)

    fs = E.Erofs(img)
    print(f'image={img} bs={fs.sb.bs} inos={fs.sb.inos} root_nid={fs.sb.root_nid}')

    hits = 0
    for path, inode in fs.walk():
        if not inode.is_file():
            continue
        low = path.lower()
        if not any(w in low for w in wants):
            continue
        try:
            data = inode.data()
        except Exception as exc:      # noqa: BLE001 - keep walking
            print(f'  !! {path}: {type(exc).__name__}: {exc}')
            traceback.print_exc(limit=2)
            continue
        out = os.path.join(outdir, os.path.basename(path))
        with open(out, 'wb') as f:
            f.write(data)
        magic = data[:4]
        kind = 'ELF' if magic == b'\x7fELF' else magic.hex()
        print(f'  + {path:<44} size={len(data):<9} magic={kind} -> {out}')
        hits += 1
    print(f'dumped {hits} file(s) into {outdir}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

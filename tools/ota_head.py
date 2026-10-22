#!/usr/bin/env python3
"""ota_head.py - fetch only the first N bytes of a partition from a remote OTA.

Why: the system/vendor partitions are 700-900 MiB and the CDN gives ~20 KB/s, so we
cannot pull them whole.  But EROFS keeps its metadata (superblock, inode tables,
directory blocks) at the front of the image, and file data behind it.  Fetching the
front lets us parse the whole tree; individual file bodies can then be fetched by
block range on demand.

usage: ota_head.py <zip_url> <partition> <bytes> <out.img>
"""
import struct
import sys
import time
import urllib.request
import zipfile

from ota_extract import HttpFile, UA, url_size, parse_fields


def read_range(url, off, length, chunk=1 << 20, tries=6):
    """Fetch [off, off+length) with per-chunk retries; the CDN drops long reads."""
    out = bytearray()
    pos = off
    end = off + length
    while pos < end:
        want = min(chunk, end - pos)
        for attempt in range(tries):
            req = urllib.request.Request(
                url, headers={**UA, 'Range': f'bytes={pos}-{pos + want - 1}'})
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    data = r.read()
                if len(data) == want:
                    out += data
                    pos += want
                    break
                out += data
                pos += len(data)
                want -= len(data)
                if want <= 0:
                    break
            except Exception:
                time.sleep(1 + attempt)
        else:
            raise RuntimeError(f'range {pos:#x}+{want:#x} failed after {tries} tries')
    return bytes(out)


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        return 2
    url, part, nbytes, out = sys.argv[1], sys.argv[2], int(sys.argv[3], 0), sys.argv[4]

    size = url_size(url)
    hf = HttpFile(url, size)
    zf = zipfile.ZipFile(hf)
    info = zf.getinfo('payload.bin')
    hf.seek(info.header_offset)
    lh = hf.read(30)
    _sig, _ver, _flag, _method, _t, _d, _crc, _cs, _us, nlen, elen = struct.unpack('<IHHHHHIIIHH', lh)
    pdata = info.header_offset + 30 + nlen + elen
    hf.seek(pdata)
    hdr = hf.read(24)
    magic, _pver, msize, sigsize = struct.unpack('>4sQQI', hdr)
    if magic != b'CrAU':
        print('bad payload magic', magic)
        return 1
    hf.seek(pdata + 24)
    manifest = hf.read(msize)
    dstart = pdata + 24 + msize + sigsize

    block_size = 4096
    target_ops = None
    for fn, wt, val in parse_fields(manifest):
        if fn == 3 and wt == 0:
            block_size = val
        elif fn == 13 and wt == 2:
            pname = None
            ops = []
            for pfn, pwt, pval in parse_fields(val):
                if pfn == 1 and pwt == 2:
                    pname = pval.decode()
                elif pfn == 8 and pwt == 2:
                    op = {'type': 0, 'off': 0, 'len': 0, 'extents': []}
                    for ofn, owt, oval in parse_fields(pval):
                        if ofn == 1 and owt == 0:
                            op['type'] = oval
                        elif ofn == 2 and owt == 0:
                            op['off'] = oval
                        elif ofn == 3 and owt == 0:
                            op['len'] = oval
                        elif ofn == 6 and owt == 2:
                            sb = nb = 0
                            for efn, _ewt, eval_ in parse_fields(oval):
                                if efn == 1:
                                    sb = eval_
                                elif efn == 2:
                                    nb = eval_
                            op['extents'].append((sb, nb))
                    ops.append(op)
            if pname == part:
                target_ops = ops
                break

    if target_ops is None:
        print(f'partition {part} not found')
        return 1

    img = bytearray(nbytes)
    fetched = 0
    for op in target_ops:
        if not op['len']:
            continue
        # stop once every extent of this op starts beyond our window
        if all(sb * block_size >= nbytes for sb, _ in op['extents']):
            continue
        hf.seek(dstart + op['off'])
        blob = hf.read(op['len'])
        if op['type'] == 1:
            import bz2
            blob = bz2.decompress(blob)
        elif op['type'] == 8:
            import lzma
            blob = lzma.decompress(blob)
        elif op['type'] != 0:
            print('unsupported op type', op['type'])
            return 1
        ptr = 0
        for sb, nb in op['extents']:
            length = nb * block_size
            seg = blob[ptr:ptr + length]
            ptr += length
            off = sb * block_size
            if off >= nbytes:
                continue
            take = min(len(seg), nbytes - off)
            img[off:off + take] = seg[:take]
            fetched += take

    with open(out, 'wb') as f:
        f.write(img)
    print(f'wrote {out}: {len(img)} bytes, fetched {fetched} ({hf.nreq} requests, {hf.nbytes} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main())

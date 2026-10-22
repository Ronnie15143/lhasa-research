#!/usr/bin/env python3
"""ota_extract.py — pull a single partition out of a remote Android OTA zip
using HTTP range requests only (no full download).

usage: ota_extract.py <zip_url> [--list] [--part boot --out boot.img]
"""
import bz2
import io
import lzma
import struct
import sys
import urllib.request

import os

# The CDN answers 403 unless it sees both a browser-ish UA *and* a miui.com
# Referer; a plain curl/urllib request is rejected.
UA = {
    'User-Agent': os.environ.get(
        'OTA_UA',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/126.0 Safari/537.36'),
    'Referer': os.environ.get('OTA_REFERER', 'https://www.miui.com/'),
}


class HttpFile(io.RawIOBase):
    """Read-only seekable file over HTTP ranges."""

    def __init__(self, url, size):
        self.url = url
        self.size = size
        self.pos = 0
        self.nreq = 0
        self.nbytes = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=0):
        if whence == 0:
            self.pos = off
        elif whence == 1:
            self.pos += off
        else:
            self.pos = self.size + off
        return self.pos

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        if n <= 0 or self.pos >= self.size:
            return b''
        end = min(self.pos + n, self.size) - 1
        req = urllib.request.Request(
            self.url, headers={**UA, 'Range': f'bytes={self.pos}-{end}'})
        with urllib.request.urlopen(req, timeout=180) as r:
            data = r.read()
        self.nreq += 1
        self.nbytes += len(data)
        self.pos += len(data)
        return data


def url_size(url):
    req = urllib.request.Request(url, headers={**UA}, method='HEAD')
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers['Content-Length'])


def read_varint(buf, i):
    shift = 0
    val = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def parse_fields(buf):
    """yield (field_no, wire_type, value) for a protobuf message buffer."""
    i = 0
    n = len(buf)
    while i < n:
        key, i = read_varint(buf, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = read_varint(buf, i)
            yield fn, wt, v
        elif wt == 1:
            yield fn, wt, buf[i:i + 8]
            i += 8
        elif wt == 2:
            ln, i = read_varint(buf, i)
            yield fn, wt, buf[i:i + ln]
            i += ln
        elif wt == 5:
            yield fn, wt, buf[i:i + 4]
            i += 4
        else:
            raise ValueError(f'wire type {wt}')


def main():
    url = sys.argv[1]
    do_list = '--list' in sys.argv
    want = None
    outp = None
    for i, a in enumerate(sys.argv):
        if a == '--part':
            want = sys.argv[i + 1]
        if a == '--out':
            outp = sys.argv[i + 1]

    size = url_size(url)
    print(f'zip size = {size} bytes ({size/2**30:.2f} GiB)')
    hf = HttpFile(url, size)

    import zipfile
    zf = zipfile.ZipFile(hf)
    names = zf.namelist()
    print(f'zip entries: {len(names)}')
    for nm in names:
        info = zf.getinfo(nm)
        print(f'  {nm:40s} method={info.compress_type} size={info.file_size}')
    if 'payload.bin' not in names:
        print('no payload.bin -> nothing to do')
        return 1

    info = zf.getinfo('payload.bin')
    # locate payload data inside the zip via its local file header
    hf.seek(info.header_offset)
    lh = hf.read(30)
    sig, ver, flag, method, t, d, crc, csize, usize, nlen, elen = struct.unpack(
        '<IHHHHHIIIHH', lh)
    assert sig == 0x04034b50, hex(sig)
    pdata = info.header_offset + 30 + nlen + elen
    print(f'payload.bin: method={method} data_at={pdata} size={info.file_size}')
    hf.seek(pdata)
    hdr = hf.read(24)
    # update_engine writes the payload header big-endian (network order)
    magic, pver, msize, sigsize = struct.unpack('>4sQQI', hdr)
    print(f'payload header: magic={magic!r} ver={pver} manifest={msize} meta_sig={sigsize}')
    if magic != b'CrAU':
        print('unexpected payload magic')
        return 1
    hf.seek(pdata + 24)
    manifest = hf.read(msize)
    print(f'manifest bytes: {len(manifest)}')
    # install-operation data_offset is relative to the blob section, which
    # starts right after header + manifest + metadata signature
    dstart = pdata + 24 + msize + sigsize
    hf.seek(dstart)
    if hf.read(6) != b'\xfd7zXZ\x00':
        print('warning: data section does not start with an XZ magic')

    block_size = 4096
    parts = []
    for fn, wt, val in parse_fields(manifest):
        if fn == 3 and wt == 0:
            block_size = val
        elif fn == 13 and wt == 2:
            parts.append(val)
    print(f'block_size={block_size}  partitions={len(parts)}')

    index = {}
    for p in parts:
        pname = None
        ops = []
        nblocks = 0
        for fn, wt, val in parse_fields(p):
            if fn == 1 and wt == 2:
                pname = val.decode()
            elif fn == 8 and wt == 2:
                op = {'type': 0, 'data_offset': 0, 'data_length': 0, 'extents': []}
                for ofn, owt, oval in parse_fields(val):
                    if ofn == 1 and owt == 0:
                        op['type'] = oval
                    elif ofn == 2 and owt == 0:
                        op['data_offset'] = oval
                    elif ofn == 3 and owt == 0:
                        op['data_length'] = oval
                    elif ofn == 6 and owt == 2:
                        sb = nb = 0
                        for efn, ewt, eval_ in parse_fields(oval):
                            if efn == 1:
                                sb = eval_
                            elif efn == 2:
                                nb = eval_
                        op['extents'].append((sb, nb))
                ops.append(op)
                nblocks += sum(nb for _, nb in op['extents'])
        if pname:
            index[pname] = ops
            sz = nblocks * block_size
            print(f'  {pname:24s} ops={len(ops):4d} size={sz/2**20:8.2f} MiB')

    if do_list or not want:
        return 0
    if want not in index:
        print(f'partition {want} not present')
        return 1

    ops = index[want]
    total = sum(nb for op in ops for _, nb in op['extents']) * block_size
    print(f'\nextracting {want}: {total} bytes, {len(ops)} ops')
    out = bytearray(total)
    done = 0
    for op in ops:
        ln = op['data_length']
        if ln:
            hf.seek(dstart + op['data_offset'])
            blob = hf.read(ln)
            if op['type'] == 1:
                blob = bz2.decompress(blob)
            elif op['type'] == 8:
                blob = lzma.decompress(blob)
            elif op['type'] != 0:
                print(f"  !! unsupported op type {op['type']}")
                return 1
        else:
            blob = b''
        ptr = 0
        for sb, nb in op['extents']:
            L = nb * block_size
            seg = blob[ptr:ptr + L]
            off = sb * block_size
            out[off:off + len(seg)] = seg
            ptr += L
            done += len(seg)
    with open(outp, 'wb') as f:
        f.write(out)
    print(f'wrote {outp}: {len(out)} bytes   (http reqs={hf.nreq}, bytes={hf.nbytes})')
    return 0


if __name__ == '__main__':
    sys.exit(main())

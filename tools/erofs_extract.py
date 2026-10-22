#!/usr/bin/env python3
# -*- coding: ascii -*-
"""erofs_extract.py - read files out of an EROFS image (Android *_dlkm, system, vendor, ...).

usage: erofs_extract.py <image> <outdir> [--list] [--only-ko] [--verbose]

What it implements (all field layouts taken from the Linux on-disk format,
fs/erofs/erofs_fs.h + fs/erofs/zmap.c v6.6):

  superblock      magic 0xE0F5E1E2 @1024, blkszbits, meta_blkaddr, root nid,
                  feature_compat / feature_incompat, per-alg compression configs
                  (COMPR_CFGS records that follow the superblock)
  inodes          32-byte compact and 64-byte extended layout (i_format bit0),
                  inline xattr size = 12 + 4*(icount-1)
  directories     12-byte erofs_dirent, FNAME length rule = next nameoff or the
                  end of the directory block/EOF for the last entry
  data layout 0   FLAT_PLAIN    - raw blocks at startblk
  data layout 2   FLAT_INLINE   - blocks + uncompressed tail inline after
                                  inode+xattr
  data layout 1   COMPRESSED_FULL     - legacy 8-byte z_erofs_lcluster_index
                                        array at align8(meta_end)+16
  data layout 3   COMPRESSED_COMPACT  - packed 4B/2B lcluster index array right
                                        after the 8-byte z_erofs_map_header
  compressed ->   per-extent decode; supports per-inode big pclusters
                  (ADVISE_BIG_PCLUSTER_1/2 + Z_EROFS_LI_D0_CBLKCNT), inline /
                  tail-packing pclusters (ADVISE_INLINE_PCLUSTER, h_idata_size)
                  and fragments stored in the packed inode (ADVISE_FRAGMENT_*)
  algorithms      LZ4(0) / LZ4HC = raw LZ4 block (lz4.block), ZSTD(3) = raw
                  zstd frame, plus best effort DEFLATE(2) and LZMA(1)

Anything the reader cannot handle is reported as ErofsUnsupported with the
exact field values, never silently skipped.
"""

import argparse
import io
import lzma
import mmap
import os
import re
import stat as statmod
import struct
import sys
import zlib

# ---------------------------------------------------------------------------
# on-disk constants
# ---------------------------------------------------------------------------
EROFS_SUPER_OFFSET = 1024
EROFS_MAGIC = 0xE0F5E1E2
EROFS_NAME_LEN = 255

# feature_compat
FC_SB_CHKSUM = 0x1
FC_MTIME = 0x2
FC_XATTR_FILTER = 0x4

# feature_incompat
FI_LZ4_0PADDING = 0x00000001
FI_COMPR_CFGS = 0x00000002
FI_BIG_PCLUSTER = 0x00000002
FI_CHUNKED_FILE = 0x00000004
FI_DEVICE_TABLE = 0x00000008
FI_COMPR_HEAD2 = 0x00000008
FI_ZTAILPACKING = 0x00000010
FI_FRAGMENTS = 0x00000020
FI_XATTR_PREFIXES = 0x00000040
FI_48BIT = 0x00000080
FI_METABOX = 0x00000100
FI_ALL_KNOWN = (FI_METABOX << 1) - 1

FI_NAMES = [
    (0x00000001, "LZ4_0PADDING"),
    (0x00000002, "COMPR_CFGS/BIG_PCLUSTER"),
    (0x00000004, "CHUNKED_FILE"),
    (0x00000008, "DEVICE_TABLE/COMPR_HEAD2"),
    (0x00000010, "ZTAILPACKING"),
    (0x00000020, "FRAGMENTS"),
    (0x00000040, "XATTR_PREFIXES"),
    (0x00000080, "48BIT"),
    (0x00000100, "METABOX"),
]

# inode datalayout (i_format >> 1) & 7
DL_FLAT_PLAIN = 0
DL_COMPRESSED_FULL = 1
DL_FLAT_INLINE = 2
DL_COMPRESSED_COMPACT = 3
DL_CHUNK_BASED = 4

DL_NAMES = {
    DL_FLAT_PLAIN: "flat-plain",
    DL_COMPRESSED_FULL: "compressed-full",
    DL_FLAT_INLINE: "flat-inline",
    DL_COMPRESSED_COMPACT: "compressed-compact",
    DL_CHUNK_BASED: "chunk-based",
}

# lcluster types
LC_PLAIN = 0
LC_HEAD1 = 1
LC_NONHEAD = 2
LC_HEAD2 = 3
LC_TYPE_NAMES = {LC_PLAIN: "PLAIN", LC_HEAD1: "HEAD1", LC_NONHEAD: "NONHEAD", LC_HEAD2: "HEAD2"}

# z_erofs_lcluster_index.di_advise bits
LI_TYPE_MASK = 0x0003
LI_D0_CBLKCNT = 0x0800     # 1 << 11
LI_HOLE = 0x4000           # 1 << 14
LI_PARTIAL_REF = 0x8000    # 1 << 15

# z_erofs_map_header.h_advise bits
ADV_COMPACTED_2B = 0x0001
ADV_BIG_PCLUSTER_1 = 0x0002
ADV_BIG_PCLUSTER_2 = 0x0004
ADV_INLINE_PCLUSTER = 0x0008
ADV_INTERLACED_PCLUSTER = 0x0010
ADV_FRAGMENT_PCLUSTER = 0x0020

# compression algorithms (h_algorithmtype nibble)
ALG_LZ4 = 0
ALG_LZMA = 1
ALG_DEFLATE = 2
ALG_ZSTD = 3
ALG_NAMES = {ALG_LZ4: "lz4", ALG_LZMA: "lzma", ALG_DEFLATE: "deflate", ALG_ZSTD: "zstd",
             ALG_LZ4 + 4: "plain-shifted", ALG_LZ4 + 5: "plain-interlaced"}

# chunk format bits
CHUNK_FORMAT_BLKBITS_MASK = 0x001F
CHUNK_FORMAT_INDEXES = 0x0020
CHUNK_FORMAT_48BIT = 0x0040

EROFS_NULL_ADDR = 0xFFFFFFFF

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000


class ErofsError(Exception):
    pass


class ErofsUnsupported(ErofsError):
    """A feature that this reader knows about but does not implement."""


class ErofsCorrupt(ErofsError):
    """On-disk data does not satisfy the format."""


def align_up(x, a):
    return (x + a - 1) & ~(a - 1)


def round_down(x, a):
    return x & ~(a - 1)


def xattr_ibody_size(icount):
    """fs/erofs/erofs_fs.h: 12 byte header + (icount-1) * 4 bytes inline xattr."""
    if not icount:
        return 0
    return 12 + 4 * (icount - 1)


def mode_to_str(mode):
    m = mode & S_IFMT
    pfx = {S_IFDIR: 'd', S_IFREG: '-', S_IFLNK: 'l'}.get(m, '?')
    bits = ''
    for shift in (6, 3, 0):
        v = (mode >> shift) & 7
        bits += 'r' if v & 4 else '-'
        bits += 'w' if v & 2 else '-'
        bits += 'x' if v & 1 else '-'
    return pfx + bits


# ---------------------------------------------------------------------------
# superblock
# ---------------------------------------------------------------------------
class SuperBlock(object):
    def __init__(self, data):
        if len(data) < EROFS_SUPER_OFFSET + 128:
            raise ErofsCorrupt("image smaller than one EROFS superblock (%d bytes)" % len(data))
        self.raw = bytes(data[EROFS_SUPER_OFFSET:EROFS_SUPER_OFFSET + 128])
        (self.magic, self.checksum, self.feature_compat, self.blkszbits,
         self.sb_extslots) = struct.unpack_from('<IIIBB', self.raw, 0)
        if self.magic != EROFS_MAGIC:
            raise ErofsCorrupt("bad EROFS magic %#010x at offset %d (expected %#010x)"
                               % (self.magic, EROFS_SUPER_OFFSET, EROFS_MAGIC))
        (self.root_nid,) = struct.unpack_from('<H', self.raw, 14)
        (self.inos,) = struct.unpack_from('<Q', self.raw, 16)
        (self.build_time,) = struct.unpack_from('<Q', self.raw, 24)
        (self.build_time_nsec,) = struct.unpack_from('<I', self.raw, 32)
        (self.blocks,) = struct.unpack_from('<I', self.raw, 36)
        (self.meta_blkaddr,) = struct.unpack_from('<I', self.raw, 40)
        (self.xattr_blkaddr,) = struct.unpack_from('<I', self.raw, 44)
        self.uuid = self.raw[48:64]
        self.volume_name = self.raw[64:80].split(b'\x00')[0].decode('utf-8', 'replace')
        (self.feature_incompat,) = struct.unpack_from('<I', self.raw, 80)
        (self.u1,) = struct.unpack_from('<H', self.raw, 84)
        (self.extra_devices,) = struct.unpack_from('<H', self.raw, 86)
        (self.devt_slotoff,) = struct.unpack_from('<H', self.raw, 88)
        # bytes 90..127: dirblkbits / xattr_prefix_count / ... / packed_nid
        self.dirblkbits = self.raw[90] if len(self.raw) > 90 else 0
        self.packed_nid = struct.unpack_from('<Q', self.raw, 100)[0] if len(self.raw) >= 108 else 0

        self.bs = 1 << self.blkszbits
        self.bs_bits = self.blkszbits
        self.sb_size = 128 + self.sb_extslots * 16
        self.lz4_max_distance = self.u1
        self.available_compr_algs = self.u1

        if self.blkszbits < 9 or self.blkszbits > 16:
            raise ErofsUnsupported("blkszbits %d out of range" % self.blkszbits)
        if self.dirblkbits:
            raise ErofsUnsupported("dirblkbits %d (directory block size != block size)" % self.dirblkbits)
        unknown = self.feature_incompat & ~FI_ALL_KNOWN
        if unknown:
            raise ErofsUnsupported("unknown feature_incompat bits %#x (kernel would refuse too)" % unknown)
        if self.feature_incompat & FI_48BIT:
            raise ErofsUnsupported("FILENAME feature_incompat 48BIT (blocks/startblk > 32 bit)")
        if self.feature_incompat & FI_METABOX:
            raise ErofsUnsupported("feature_incompat METABOX")

        self.compr_cfgs = {}

    def has(self, bit):
        return bool(self.feature_incompat & bit)

    def feature_names(self):
        out = []
        for bit, name in FI_NAMES:
            if self.feature_incompat & bit:
                out.append(name)
        return out


# ---------------------------------------------------------------------------
# compression configs (follow the superblock when COMPR_CFGS is set)
# ---------------------------------------------------------------------------
def load_compr_cfgs(sb, data):
    """fs/erofs/super.c:erofs_load_compr_cfgs()

    Each record is  <u16 len><len bytes>, 4-byte aligned, one per set bit of
    available_compr_algs in increasing algorithm order.
    """
    offset = EROFS_SUPER_OFFSET + sb.sb_size
    algs = sb.available_compr_algs
    if algs & ~0xF:
        raise ErofsUnsupported("available_compr_algs %#x has unknown bits" % algs)
    alg = 0
    while algs:
        if algs & 1:
            offset = align_up(offset, 4)
            if offset + 2 > len(data):
                raise ErofsCorrupt("compression cfg record for alg %d runs past EOF" % alg)
            (length,) = struct.unpack_from('<H', data, offset)
            if length == 0:
                length = 0x10000
            body = bytes(data[offset + 2:offset + 2 + length])
            if len(body) != length:
                raise ErofsCorrupt("compression cfg record for alg %d truncated" % alg)
            offset += 2 + length
            sb.compr_cfgs[alg] = body
        algs >>= 1
        alg += 1
    return sb.compr_cfgs


def cfg_dict_size(sb, alg):
    """Return algorithm specific parameters as a dict (best effort)."""
    body = sb.compr_cfgs.get(alg)
    if body is None:
        return {}
    if alg == ALG_LZ4:
        d = {}
        if len(body) >= 2:
            d['max_distance'] = struct.unpack_from('<H', body, 0)[0]
        if len(body) >= 4:
            d['max_pclusterblks'] = struct.unpack_from('<H', body, 2)[0]
        return d
    if alg == ALG_ZSTD:
        d = {}
        if len(body) >= 1:
            d['format'] = body[0]
        if len(body) >= 2:
            d['windowlog'] = body[1] + 10
        return d
    if alg == ALG_DEFLATE:
        return {'windowbits': body[0]} if body else {}
    if alg == ALG_LZMA:
        d = {}
        if len(body) >= 4:
            d['dict_size'] = struct.unpack_from('<I', body, 0)[0]
        if len(body) >= 6:
            d['format'] = struct.unpack_from('<H', body, 4)[0]
        return d
    return {}


# ---------------------------------------------------------------------------
# lcluster index entry
# ---------------------------------------------------------------------------
class LCluster(object):
    __slots__ = ('type', 'clusterofs', 'delta0', 'delta1', 'blkaddr', 'cblkcnt', 'nextpackoff')

    def __init__(self):
        self.type = LC_NONHEAD
        self.clusterofs = 0
        self.delta0 = 0
        self.delta1 = 0
        self.blkaddr = 0
        self.cblkcnt = 0
        self.nextpackoff = 0

    def __repr__(self):
        return '<LC %s cofs=%d d0=%d d1=%d blk=%d cblk=%d>' % (
            LC_TYPE_NAMES.get(self.type, self.type), self.clusterofs,
            self.delta0, self.delta1, self.blkaddr, self.cblkcnt)


class Extent(object):
    __slots__ = ('la', 'llen', 'pa', 'plen', 'kind', 'alg', 'head_lcn', 'note')

    def __init__(self, la, llen, pa, plen, kind, alg=None, head_lcn=0, note=''):
        self.la = la
        self.llen = llen      # decoded length in bytes
        self.pa = pa          # absolute byte offset in the image
        self.plen = plen      # encoded length in bytes
        self.kind = kind      # 'plain' | 'comp' | 'inline' | 'fragment'
        self.alg = alg
        self.head_lcn = head_lcn
        self.note = note

    def __repr__(self):
        return '<Extent la=%d llen=%d pa=%#x plen=%d %s alg=%s>' % (
            self.la, self.llen, self.pa, self.plen, self.kind,
            ALG_NAMES.get(self.alg, self.alg))


# ---------------------------------------------------------------------------
# inode
# ---------------------------------------------------------------------------
class Inode(object):
    def __init__(self, fs, nid):
        self.fs = fs
        self.nid = nid
        self.iloc = fs.sb.meta_blkaddr * fs.sb.bs + nid * 32
        d = fs.data
        if self.iloc + 32 > fs.size:
            raise ErofsCorrupt("nid %d -> offset %#x beyond EOF" % (nid, self.iloc))
        (self.i_format, self.i_xattr_icount, self.i_mode, self.i_nb) = struct.unpack_from('<HHHH', d, self.iloc)
        self.version = self.i_format & 0x01
        self.datalayout = (self.i_format >> 1) & 0x07
        self.nlink_1bit = bool(self.i_format & 0x10)
        if self.version == 0:      # compact, 32 bytes
            (self.size,) = struct.unpack_from('<I', d, self.iloc + 8)
            (self.i_mtime,) = struct.unpack_from('<I', d, self.iloc + 12)
            (self.i_u,) = struct.unpack_from('<I', d, self.iloc + 16)
            (self.i_ino,) = struct.unpack_from('<I', d, self.iloc + 20)
            self.i_uid, self.i_gid = struct.unpack_from('<HH', d, self.iloc + 24)
            self.inode_size = 32
            self.nlink = 1 if self.nlink_1bit else self.i_nb
        elif self.version == 1:    # extended, 64 bytes
            (self.size,) = struct.unpack_from('<Q', d, self.iloc + 8)
            (self.i_u,) = struct.unpack_from('<I', d, self.iloc + 16)
            (self.i_ino,) = struct.unpack_from('<I', d, self.iloc + 20)
            self.i_uid, self.i_gid = struct.unpack_from('<II', d, self.iloc + 24)
            (self.i_mtime,) = struct.unpack_from('<Q', d, self.iloc + 32)
            (self.i_mtime_nsec,) = struct.unpack_from('<I', d, self.iloc + 40)
            (self.nlink,) = struct.unpack_from('<I', d, self.iloc + 44)
            self.inode_size = 64
        else:
            raise ErofsCorrupt("nid %d: i_format version %d" % (nid, self.version))

        self.xattr_size = xattr_ibody_size(self.i_xattr_icount)
        self.meta_end = self.iloc + self.inode_size + self.xattr_size
        self.type = self.i_mode & S_IFMT

        if self.datalayout == DL_COMPRESSED_FULL or self.datalayout == DL_COMPRESSED_COMPACT:
            self.startblk = None
            self.nr_blocks = self.i_u          # total physical blocks of the file
        elif self.datalayout == DL_CHUNK_BASED:
            self.startblk = None
            self.nr_blocks = 0
        else:
            self.startblk = self.i_u
            self.nr_blocks = (self.size + fs.sb.bs - 1) // fs.sb.bs

        self._data = None

    # -- helpers ---------------------------------------------------------
    def is_dir(self):
        return self.type == S_IFDIR

    def is_file(self):
        return self.type == S_IFREG

    def is_symlink(self):
        return self.type == S_IFLNK

    def describe(self):
        return "nid=%d iloc=%#x %s size=%d layout=%s" % (
            self.nid, self.iloc, mode_to_str(self.i_mode), self.size,
            DL_NAMES.get(self.datalayout, self.datalayout))

    def data(self):
        if self._data is None:
            self._data = self.fs.read_inode_data(self)
        return self._data


# ---------------------------------------------------------------------------
# filesystem
# ---------------------------------------------------------------------------
class Erofs(object):
    def __init__(self, path, verbose=False):
        self.path = path
        self.verbose = verbose
        self.f = open(path, 'rb')
        self.size = os.fstat(self.f.fileno()).st_size
        if self.size == 0:
            raise ErofsCorrupt("empty image")
        self.data = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        self.sb = SuperBlock(self.data)
        if self.sb.has(FI_COMPR_CFGS):
            load_compr_cfgs(self.sb, self.data)
        self.warnings = []
        self.stats = {'files': 0, 'dirs': 0, 'symlinks': 0, 'compressed': 0,
                      'bytes': 0, 'errors': 0}
        self._packed_inode = None
        self._lz4 = None
        self._zstd = None
        self._lz4_warned = False
        self.pad_hits = {}

    def close(self):
        try:
            self.data.close()
        except Exception:
            pass
        self.f.close()

    def warn(self, msg):
        self.warnings.append(msg)
        print("  [warn] " + msg, file=sys.stderr)

    # -- compression backends --------------------------------------------
    def _lz4_mod(self):
        if self._lz4 is None:
            try:
                import lz4.block as _lb
                self._lz4 = _lb
            except ImportError:
                raise ErofsUnsupported("python module 'lz4' is required to decode LZ4 pclusters")
        return self._lz4

    def _zstd_mod(self):
        if self._zstd is None:
            try:
                import zstandard as _zs
                self._zstd = _zs
            except ImportError:
                raise ErofsUnsupported("python module 'zstandard' is required to decode ZSTD pclusters")
        return self._zstd

    def decompress(self, alg, blob, llen, hint=''):
        """Decode one pcluster.  `blob` is the encoded bytes, `llen` the exact
        number of decoded bytes the index promises."""
        if llen < 0:
            raise ErofsCorrupt("negative decoded length %d" % llen)
        if llen == 0:
            return b''
        tried = []

        def attempt(name, fn):
            try:
                out = fn()
            except Exception as exc:                     # noqa: BLE001 - want the message
                tried.append("%s: %s" % (name, exc))
                return None
            if out is None or len(out) != llen:
                tried.append("%s: produced %s bytes, expected %d"
                             % (name, 'None' if out is None else len(out), llen))
                return None
            return out

        if alg in (ALG_LZ4,):
            lb = self._lz4_mod()
            # EROFS_FEATURE_INCOMPAT_LZ4_0PADDING: a pcluster is zero padded to
            # the physical cluster size.  Normally the padding is at the *end*,
            # but plenty of vendor images (Xiaomi lhasa odm/vendor dlkm) store
            # the stream right aligned, i.e. with the zero padding at the
            # front - a self contained LZ4 block can never start with 0x00
            # (token 0x00 = empty literal run + match with offset 0), so
            # skipping the leading zeros is unambiguous.
            cands = [('as-is', blob)]
            lstripped = blob.lstrip(b'\x00')
            if lstripped and lstripped != blob:
                cands.append(('lead0', lstripped))
            rstripped = blob.rstrip(b'\x00')
            if rstripped and rstripped != blob:
                cands.append(('trail0', rstripped))
            stripped = blob.strip(b'\x00')
            if stripped and stripped != blob:
                cands.append(('strip0', stripped))
            for tag, src in cands:
                out = attempt('lz4[%s](%d)' % (tag, llen),
                              lambda src=src: lb.decompress(src, uncompressed_size=llen))
                if out is not None:
                    if tag != 'as-is':
                        self.pad_hits[tag] = self.pad_hits.get(tag, 0) + 1
                    return out
            # last resort: locate the stream start inside the padded cluster
            for off in range(1, len(blob)):
                if blob[off] == 0:
                    continue
                try:
                    out = lb.decompress(blob[off:], uncompressed_size=llen)
                except Exception:
                    continue
                if len(out) == llen:
                    self.pad_hits['scan@%d' % off] = self.pad_hits.get('scan@%d' % off, 0) + 1
                    return out
        elif alg == ALG_ZSTD:
            zs = self._zstd_mod()
            out = attempt('zstd(%d)' % llen,
                          lambda: zs.ZstdDecompressor().decompress(blob, max_output_size=llen))
            if out is not None:
                return out
            off = blob.find(b'\x28\xb5\x2f\xfd')
            if off > 0:
                out = attempt('zstd@%d(%d)' % (off, llen),
                              lambda: zs.ZstdDecompressor().decompress(blob[off:],
                                                                      max_output_size=llen))
                if out is not None:
                    self.pad_hits['zstd@%d' % off] = self.pad_hits.get('zstd@%d' % off, 0) + 1
                    return out
            out = attempt('zstd-stream(%d)' % llen,
                          lambda: zs.ZstdDecompressor().stream_reader(io.BytesIO(blob)).read())
            if out is not None:
                return out
        elif alg == ALG_DEFLATE:
            windowbits = cfg_dict_size(self.sb, ALG_DEFLATE).get('windowbits', 15)
            for wb in (-windowbits, -15, windowbits, 15):
                out = attempt('deflate(%d,wb=%d)' % (llen, wb),
                              lambda wb=wb: zlib.decompressobj(wb).decompress(blob))
                if out is not None:
                    return out
        elif alg == ALG_LZMA:
            dict_size = cfg_dict_size(self.sb, ALG_LZMA).get('dict_size', 1 << 16)
            out = attempt('lzma(raw,dict=%d)' % dict_size,
                          lambda: lzma.LZMADecompressor(
                              format=lzma.FORMAT_RAW,
                              filters=[{'id': lzma.FILTER_LZMA1, 'dict_size': dict_size}]
                          ).decompress(blob))
            if out is not None:
                return out
        else:
            raise ErofsUnsupported("unknown compression algorithm id %d %s" % (alg, hint))

        # Last resort: sniff the container and try every decoder we have.
        if blob[:4] == b'\x28\xb5\x2f\xfd':
            out = attempt('sniff zstd', lambda: self._zstd_mod().ZstdDecompressor().decompress(
                blob, max_output_size=llen))
            if out is not None:
                return out
        raise ErofsCorrupt("cannot decode pcluster alg=%s llen=%d plen=%d %s; tried: %s"
                           % (ALG_NAMES.get(alg, alg), llen, len(blob), hint, ' | '.join(tried)))

    # -- inode data ------------------------------------------------------
    def read_inode_data(self, inode):
        dl = inode.datalayout
        if dl == DL_FLAT_PLAIN:
            return self._read_flat(inode)
        if dl == DL_FLAT_INLINE:
            return self._read_flat(inode, inline=True)
        if dl in (DL_COMPRESSED_FULL, DL_COMPRESSED_COMPACT):
            return self._read_compressed(inode)
        if dl == DL_CHUNK_BASED:
            return self._read_chunked(inode)
        raise ErofsUnsupported("inode %d (nid %d): datalayout %d" % (inode.i_ino, inode.nid, dl))

    def _read_flat(self, inode, inline=False):
        size = inode.size
        if size == 0:
            return b''
        bs = self.sb.bs
        nblk = size // bs if inline else (size + bs - 1) // bs
        tail = size - nblk * bs
        out = bytearray()
        if inode.startblk == EROFS_NULL_ADDR:
            nblk = 0
            tail = size
        if nblk:
            start = inode.startblk * bs
            end = start + nblk * bs
            if end > self.size:
                raise ErofsCorrupt("nid %d: data [%#x,%#x) beyond EOF (%#x)"
                                   % (inode.nid, start, end, self.size))
            out += self.data[start:end]
        if inline and tail:
            start = inode.meta_end
            if start + tail > self.size:
                raise ErofsCorrupt("nid %d: inline data beyond EOF" % inode.nid)
            out += self.data[start:start + tail]
        return bytes(out[:size])

    def _read_chunked(self, inode):
        bs = self.sb.bs
        fmt = inode.i_u & 0xFFFF
        chunkbits = fmt & CHUNK_FORMAT_BLKBITS_MASK
        has_idx = bool(fmt & CHUNK_FORMAT_INDEXES)
        if fmt & CHUNK_FORMAT_48BIT:
            raise ErofsUnsupported("chunk-based inode %d uses 48BIT chunk indexes" % inode.nid)
        chunk_size = bs << chunkbits
        nchunks = (inode.size + chunk_size - 1) // chunk_size
        base = align_up(inode.meta_end, 8)
        out = bytearray()
        for i in range(nchunks):
            if has_idx:
                off = base + i * 8
                startblk_hi, device_id, startblk_lo = struct.unpack_from('<HHI', self.data, off)
                if device_id:
                    raise ErofsUnsupported("chunk index %d of nid %d refers to device_id %d"
                                           % (i, inode.nid, device_id))
                startblk = (startblk_lo & 0xFFFFFFFF)
                if startblk == EROFS_NULL_ADDR:
                    out += b'\x00' * chunk_size
                    continue
            else:
                off = base + i * 4
                (startblk,) = struct.unpack_from('<I', self.data, off)
                if startblk == EROFS_NULL_ADDR:
                    out += b'\x00' * chunk_size
                    continue
            start = startblk * bs
            out += self.data[start:start + chunk_size]
        return bytes(out[:inode.size])

    # -- compression -----------------------------------------------------
    def _map_header(self, inode):
        hpos = align_up(inode.meta_end, 8)
        if hpos + 8 > self.size:
            raise ErofsCorrupt("nid %d: map header beyond EOF" % inode.nid)
        raw = bytes(self.data[hpos:hpos + 8])
        h_lo = struct.unpack_from('<I', raw, 0)[0]
        h_advise = struct.unpack_from('<H', raw, 4)[0]
        h_algtype = raw[6]
        h_clusterbits = raw[7]
        return hpos, raw, h_lo, h_advise, h_algtype, h_clusterbits

    def _packed_inode(self):
        if self._packed_inode is None:
            nid = self.sb.packed_nid
            if not nid:
                # older layouts store packed_nid at offset 96
                nid = struct.unpack_from('<Q', self.sb.raw, 96)[0] if len(self.sb.raw) >= 104 else 0
            if not nid:
                raise ErofsUnsupported("file uses fragments but superblock has no packed_nid")
            self._packed_inode = Inode(self, nid)
        return self._packed_inode

    def read_fragment(self, off, length, llen):
        packed = self._packed_inode()
        blob = packed.data()
        if off + length > len(blob):
            raise ErofsCorrupt("fragment [%d,+%d) beyond packed inode size %d"
                               % (off, length, len(blob)))
        return self.decompress(ALG_LZ4, blob[off:off + length], llen,
                               hint='(fragment from packed inode nid %d)' % packed.nid)

    def _read_compressed(self, inode):
        bs = self.sb.bs
        size = inode.size
        if size == 0:
            return b''
        hpos, hraw, h_lo, h_advise, h_algtype, h_clusterbits = self._map_header(inode)

        # whole file inside the packed inode (fragments feature)
        if h_clusterbits >> 7:
            frag_off = (struct.unpack_from('<Q', hraw, 0)[0] & ~(1 << 63))
            return self.read_fragment(frag_off, size, size)

        alg1 = h_algtype & 0x0F
        alg2 = h_algtype >> 4
        lcb = self.sb.bs_bits + (h_clusterbits & 7)
        lcsize = 1 << lcb
        totalidx = (size + lcsize - 1) // lcsize
        self.stats['compressed'] += 1

        if self.verbose:
            print("  [z] nid=%d size=%d advise=%#06x alg1=%s alg2=%s lcb=%d totalidx=%d"
                  % (inode.nid, size, h_advise, ALG_NAMES.get(alg1, alg1),
                     ALG_NAMES.get(alg2, alg2), lcb, totalidx))

        if inode.datalayout == DL_COMPRESSED_FULL:
            base = align_up(inode.meta_end, 8) + 16      # map header(8) + legacy pad(8)
            entries = self._load_full_index(inode, base, totalidx, lcb, h_advise)
        else:
            base = align_up(inode.meta_end, 8) + 8       # map header(8)
            if lcb != self.sb.bs_bits and lcb != 14:
                raise ErofsUnsupported("compact lcluster index with logical cluster "
                                       "bits %d (kernel supports 12 only)" % lcb)
            entries = self._load_compact_index(inode, base, totalidx, lcb, h_advise)

        # ---- inline (tail-packing) pcluster: data lives in the metadata area
        # kernel: m.nextpackoff of the tail lcluster == vi->z_idataoff
        idata_off = None
        idata_size = struct.unpack_from('<H', hraw, 2)[0]
        tail_head = self._tail_head_lcn(entries, size, lcb)
        if h_advise & ADV_INLINE_PCLUSTER:
            tail_lcn = (size - 1) >> lcb
            if tail_lcn >= len(entries):
                tail_lcn = len(entries) - 1
            idata_off = entries[tail_lcn].nextpackoff

        # ---- group lclusters into extents
        extents = []
        i = 0
        while i < totalidx:
            e = entries[i]
            if e.type == LC_NONHEAD:
                # orphan NONHEAD (previous extent missing) - report, do not crash
                self.warn("nid %d: lcn %d is NONHEAD without a preceding head" % (inode.nid, i))
                i += 1
                continue
            la = (i << lcb) | e.clusterofs
            j = i + 1
            while j < totalidx and entries[j].type == LC_NONHEAD:
                j += 1
            if j < totalidx:
                end_la = (j << lcb) | entries[j].clusterofs
            else:
                end_la = size
            llen = min(end_la, size) - la
            if llen <= 0:
                # normal at EOF: the trailing lcluster(s) may be stale leftovers
                # whose logical position is already past the end of the file.
                if self.verbose:
                    print("  [z] nid %d: skipping stale lcn %d (la=%d size=%d)"
                          % (inode.nid, i, la, size))
                i = j
                continue

            if e.type == LC_PLAIN:
                if e.blkaddr == EROFS_NULL_ADDR:
                    ext = Extent(la, llen, 0, 0, 'hole', head_lcn=i)
                else:
                    # a PLAIN ("shifted") pcluster stores at most one lcluster
                    # worth of decoded data; the kernel only requires
                    # m_llen <= m_plen (1 << lclusterbits), it is *not* bounded
                    # by lcsize - clusterofs (data is shifted by clusterofs).
                    if llen > lcsize:
                        self.warn("nid %d: PLAIN extent at lcn %d spans %d > %d (plen)"
                                  % (inode.nid, i, llen, lcsize))
                        llen = lcsize
                    ext = Extent(la, llen, e.blkaddr * bs, lcsize, 'plain',
                                 alg=ALG_LZ4 + 4, head_lcn=i)
            else:
                alg = alg2 if e.type == LC_HEAD2 else alg1
                plen_blk = self._extent_blocks(entries, i, totalidx, lcb, h_advise)
                # inline / tail-packing pcluster?
                if (h_advise & ADV_INLINE_PCLUSTER) and idata_off is not None and i == tail_head:
                    ext = Extent(la, llen, idata_off, idata_size, 'inline', alg, i,
                                 note='tail-packing')
                elif (h_advise & ADV_FRAGMENT_PCLUSTER) and i == tail_head:
                    frag_off = h_lo
                    ext = Extent(la, llen, frag_off, plen_blk * bs, 'fragment', alg, i,
                                 note='packed inode nid %d' % self.sb.packed_nid)
                else:
                    if e.blkaddr == EROFS_NULL_ADDR:
                        ext = Extent(la, llen, 0, 0, 'hole', alg, i)
                    else:
                        ext = Extent(la, llen, e.blkaddr * bs, plen_blk * bs, 'comp', alg, i)
            extents.append(ext)
            i = j

        # ---- decode
        out = bytearray(size)
        for ext in extents:
            if ext.kind == 'hole':
                continue
            if ext.kind == 'plain':
                chunk = self.data[ext.pa:ext.pa + ext.llen]
                if len(chunk) != ext.llen:
                    raise ErofsCorrupt("nid %d: plain extent [%#x,+%d) beyond EOF"
                                       % (inode.nid, ext.pa, ext.llen))
            elif ext.kind == 'fragment':
                chunk = self.read_fragment(ext.pa, ext.plen, ext.llen)
            else:
                if ext.pa + ext.plen > self.size:
                    raise ErofsCorrupt("nid %d: extent [%#x,+%d) beyond EOF (%#x)"
                                       % (inode.nid, ext.pa, ext.plen, self.size))
                blob = self.data[ext.pa:ext.pa + ext.plen]
                if ext.kind == 'inline':
                    # inline pclusters are stored un-padded, plen is exact
                    chunk = self.decompress(ext.alg, blob, ext.llen, hint='(inline)')
                else:
                    chunk = self.decompress(ext.alg, blob, ext.llen,
                                            hint='@%#x' % ext.pa)
            out[ext.la:ext.la + ext.llen] = chunk[:ext.llen]
        return bytes(out)

    @staticmethod
    def _tail_head_lcn(entries, size, lcb):
        """Head lcluster of the extent that contains the last byte of the file."""
        tail = (size - 1) >> lcb
        if tail >= len(entries):
            tail = len(entries) - 1
        k = tail
        guard = 0
        while k > 0 and entries[k].type == LC_NONHEAD and guard < len(entries):
            k -= 1 if entries[k].delta0 <= 1 else entries[k].delta0
            guard += 1
        return k

    def _extent_blocks(self, entries, i, totalidx, lcb, advise):
        """z_erofs_get_extent_compressedlen() -> encoded size in blocks."""
        e = entries[i]
        one = 1 << (lcb - self.sb.bs_bits)
        if e.type == LC_PLAIN:
            return one
        if e.type == LC_HEAD1 and not (advise & ADV_BIG_PCLUSTER_1):
            return one
        if e.type == LC_HEAD2 and not (advise & ADV_BIG_PCLUSTER_2):
            return one
        # the compressed block count of a big pcluster lives in the *first
        # NONHEAD lcluster after the head* (delta[0] | Z_EROFS_LI_D0_CBLKCNT)
        nxt = entries[i + 1] if i + 1 < totalidx else None
        if nxt is not None and nxt.type == LC_NONHEAD and nxt.cblkcnt:
            return nxt.cblkcnt
        if nxt is None or nxt.type != LC_NONHEAD:
            return one
        if nxt.delta0 != 1:
            self.warn("lcn %d: bogus CBLKCNT layout, assuming 1 block" % i)
            return one
        self.warn("lcn %d: big pcluster head without CBLKCNT, assuming 1 block" % i)
        return one

    # -- index decoders --------------------------------------------------
    def _load_full_index(self, inode, base, totalidx, lcb, advise):
        """legacy 8-byte z_erofs_lcluster_index array (datalayout 1)."""
        if advise & ADV_COMPACTED_2B:
            # bit 0 means ADVISE_EXTENTS for COMPRESSED_FULL in >=6.8, which is a
            # completely different table; verify the first entry looks sane.
            pass
        need = totalidx * 8
        if base + need > self.size:
            raise ErofsCorrupt("nid %d: lcluster index array [%#x,+%d) beyond EOF"
                               % (inode.nid, base, need))
        blob = self.data[base:base + need]
        entries = []
        for k in range(totalidx):
            di_advise, di_clusterofs, u32 = struct.unpack_from('<HHI', blob, k * 8)
            e = LCluster()
            e.type = di_advise & LI_TYPE_MASK
            e.nextpackoff = base + k * 8 + 8
            if e.type == LC_NONHEAD:
                e.clusterofs = 1 << lcb
                e.delta0 = u32 & 0xFFFF
                e.delta1 = (u32 >> 16) & 0xFFFF
                if e.delta0 & LI_D0_CBLKCNT:
                    if not (advise & (ADV_BIG_PCLUSTER_1 | ADV_BIG_PCLUSTER_2)):
                        self.warn("nid %d: lcn %d has CBLKCNT but no BIG_PCLUSTER advise"
                                  % (inode.nid, k))
                        e.cblkcnt = e.delta0 & ~LI_D0_CBLKCNT
                        e.delta0 = 1
                    else:
                        e.cblkcnt = e.delta0 & ~LI_D0_CBLKCNT
                        e.delta0 = 1
            else:
                e.clusterofs = di_clusterofs
                if e.clusterofs >= (1 << lcb):
                    raise ErofsCorrupt("nid %d: lcn %d clusterofs %d >= %d"
                                       % (inode.nid, k, e.clusterofs, 1 << lcb))
                e.blkaddr = u32
            entries.append(e)
        # structural sanity: entry 0 must be a head/plain with clusterofs 0
        if entries and entries[0].type == LC_NONHEAD:
            raise ErofsUnsupported(
                "nid %d: first lcluster is NONHEAD - this looks like the post-6.8 "
                "extent table (ADVISE_EXTENTS, h_advise=%#06x), not the legacy "
                "lcluster index; unsupported" % (inode.nid, advise))
        if entries and entries[0].clusterofs != 0:
            raise ErofsUnsupported(
                "nid %d: first lcluster clusterofs=%d != 0 - extent table layout "
                "suspected (h_advise=%#06x)" % (inode.nid, entries[0].clusterofs, advise))
        return entries

    def _load_compact_index(self, inode, ebase, totalidx, lcb, advise):
        """packed 4B/2B z_erofs_lcluster_index array (datalayout 3)."""
        compacted_4b_initial = (32 - ebase % 32) // 4
        if compacted_4b_initial == 32 // 4:
            compacted_4b_initial = 0
        if (advise & ADV_COMPACTED_2B) and compacted_4b_initial < totalidx:
            compacted_2b = round_down(totalidx - compacted_4b_initial, 16)
        else:
            compacted_2b = 0

        big = advise & ADV_BIG_PCLUSTER_1

        def pos_of(lcn):
            pos = ebase
            if lcn < compacted_4b_initial:
                return pos + lcn * 4, 2
            pos += compacted_4b_initial * 4
            lcn -= compacted_4b_initial
            if lcn < compacted_2b:
                return pos + lcn * 2, 1
            pos += compacted_2b * 2
            lcn -= compacted_2b
            return pos + lcn * 4, 2

        bs = self.sb.bs

        def pack_bytes(pos, amortizedshift):
            vcnt = 2 if (1 << amortizedshift) == 4 else 16
            eofs = pos & (bs - 1)
            base = round_down(eofs, vcnt << amortizedshift)
            blk = pos - eofs
            start = blk + base
            blob = self.data[start:start + (vcnt << amortizedshift)]
            if len(blob) != vcnt << amortizedshift:
                raise ErofsCorrupt("nid %d: compact index pack [%#x] beyond EOF"
                                   % (inode.nid, start))
            return blob, base, eofs, vcnt

        def decode_bits(blob, encodebits, i):
            bitpos = encodebits * i
            v = struct.unpack_from('<I', blob, bitpos // 8)[0] >> (bitpos & 7)
            lomask = (1 << lcb) - 1
            return v & lomask, (v >> lcb) & 3

        entries = []
        for lcn in range(totalidx):
            pos, shift = pos_of(lcn)
            blob, base, eofs, vcnt = pack_bytes(pos, shift)
            if (1 << shift) == 4:
                if lcb > 14:
                    raise ErofsUnsupported("compact 4B pack with lclusterbits %d" % lcb)
            elif (1 << shift) == 2 and lcb != 12:
                raise ErofsUnsupported("compact 2B pack with lclusterbits %d" % lcb)
            encodebits = ((vcnt << shift) - 4) * 8 // vcnt
            i = (eofs - base) >> shift
            lo, dtype = decode_bits(blob, encodebits, i)
            e = LCluster()
            e.type = dtype
            e.nextpackoff = round_down(pos, vcnt << shift) + (vcnt << shift)
            if dtype == LC_NONHEAD:
                e.clusterofs = 1 << lcb
                # delta[1] = distance to next head (lookahead), inside this pack
                j = i
                d1 = 0
                while True:
                    lo2, t2 = decode_bits(blob, encodebits, j)
                    if t2 != LC_NONHEAD:
                        break
                    d1 += 1
                    j += 1
                    if j >= vcnt:
                        if not (lo2 & LI_D0_CBLKCNT):
                            d1 += lo2 - 1
                        break
                e.delta1 = d1
                if lo & LI_D0_CBLKCNT:
                    if not big:
                        self.warn("nid %d: lcn %d CBLKCNT without BIG_PCLUSTER_1" % (inode.nid, lcn))
                    e.cblkcnt = lo & ~LI_D0_CBLKCNT
                    e.delta0 = 1
                elif i + 1 != vcnt:
                    e.delta0 = lo
                else:
                    lo2, t2 = decode_bits(blob, encodebits, i - 1) if i > 0 else (0, 0)
                    if t2 != LC_NONHEAD:
                        lo2 = 0
                    elif lo2 & LI_D0_CBLKCNT:
                        lo2 = 1
                    e.delta0 = lo2 + 1
            else:
                e.clusterofs = lo
                # pblk: base of the pack plus the number of blocks preceding it
                if not big:
                    nblk = 1
                    j = i
                    while j > 0:
                        j -= 1
                        lo2, t2 = decode_bits(blob, encodebits, j)
                        if t2 == LC_NONHEAD:
                            j -= lo2
                        if j >= 0:
                            nblk += 1
                else:
                    nblk = 0
                    j = i
                    while j > 0:
                        j -= 1
                        lo2, t2 = decode_bits(blob, encodebits, j)
                        if t2 == LC_NONHEAD:
                            if lo2 & LI_D0_CBLKCNT:
                                j -= 1
                                nblk += lo2 & ~LI_D0_CBLKCNT
                                continue
                            if lo2 <= 1:
                                raise ErofsCorrupt("nid %d: compact big-pcluster delta0=%d"
                                                   % (inode.nid, lo2))
                            j -= lo2 - 2
                            continue
                        nblk += 1
                base_u32 = struct.unpack_from('<I', blob, (vcnt << shift) - 4)[0]
                e.blkaddr = (base_u32 + nblk) & 0xFFFFFFFF
            entries.append(e)
        return entries

    # -- directory walk --------------------------------------------------
    def read_dir(self, inode):
        """Yield (name, nid, file_type) for a directory inode."""
        data = inode.data()
        bs = self.sb.bs
        total = len(data)
        pos = 0
        while pos < total:
            limit = min(bs, total - pos)
            block = data[pos:pos + limit]
            if limit < 12:
                break
            (first_nameoff,) = struct.unpack_from('<H', block, 8)
            if first_nameoff < 12 or first_nameoff % 12 or first_nameoff > limit:
                raise ErofsCorrupt("dir nid %d: bad first nameoff %d (limit %d)"
                                   % (inode.nid, first_nameoff, limit))
            count = first_nameoff // 12
            offs = []
            for k in range(count):
                nid, nameoff, ftype = struct.unpack_from('<QHB', block, k * 12)
                offs.append((nid, nameoff, ftype))
            for k, (nid, nameoff, ftype) in enumerate(offs):
                end = offs[k + 1][1] if k + 1 < len(offs) else limit
                if nameoff > len(block) or end < nameoff:
                    raise ErofsCorrupt("dir nid %d: bad nameoff %d/%d" % (inode.nid, nameoff, end))
                name = bytes(block[nameoff:end]).split(b'\x00')[0]
                try:
                    name = name.decode('utf-8')
                except UnicodeDecodeError:
                    name = name.decode('utf-8', 'replace')
                yield name, nid, ftype
            pos += limit
            if limit < bs:
                break

    def walk(self):
        """Yield (path, inode) for every node, depth first."""
        root = Inode(self, self.sb.root_nid)
        if not root.is_dir():
            raise ErofsCorrupt("root nid %d is not a directory (mode %#o)"
                               % (self.sb.root_nid, root.i_mode))
        stack = [('', root)]
        while stack:
            prefix, dir_inode = stack.pop()
            self.stats['dirs'] += 1
            yield (prefix or '/'), dir_inode
            children = []
            for name, nid, ftype in self.read_dir(dir_inode):
                if name in ('.', '..'):
                    continue
                if not name:
                    continue
                child = Inode(self, nid)
                path = (prefix + '/' + name) if prefix else name
                children.append((path, child))
            for path, child in reversed(children):
                if child.is_dir():
                    stack.append((path, child))
                else:
                    if child.is_file():
                        self.stats['files'] += 1
                    elif child.is_symlink():
                        self.stats['symlinks'] += 1
                    yield path, child


# ---------------------------------------------------------------------------
# .ko helpers
# ---------------------------------------------------------------------------
def elf_info(data):
    """Return (machine, vermagic, modname) for an ELF module body.

    Never raises: pyelftools chokes on some stripped/repacked vendor modules, and
    one bad .ko must not abort a whole extraction run.  When the section table
    cannot be walked we fall back to scanning for the .modinfo strings.
    """
    machine = None
    vermagic = None
    modname = None
    if len(data) >= 20 and data[:4] == b'\x7fELF':
        machine = struct.unpack_from('<H', data, 18)[0]
    try:
        from elftools.elf.elffile import ELFFile
        elf = ELFFile(io.BytesIO(data))
        sec = elf.get_section_by_name('.modinfo')
        if sec is not None:
            blob = sec.data()
            for entry in blob.split(b'\x00'):
                if entry.startswith(b'vermagic='):
                    vermagic = entry[9:].decode('ascii', 'replace').strip()
                elif entry.startswith(b'name='):
                    modname = entry[5:].decode('ascii', 'replace').strip()
    except Exception:
        pass
    if vermagic is None:
        m = re.search(rb'vermagic=([\x20-\x7e]{4,200})', data)
        if m:
            vermagic = m.group(1).decode('ascii', 'replace').strip()
    if modname is None:
        m = re.search(rb'(?<![\w])name=([A-Za-z0-9_\-]{2,64})\x00', data)
        if m:
            modname = m.group(1).decode('ascii', 'replace')
    return machine, vermagic, modname


def elf_verify(data):
    """Strict check: pyelftools can open it and e_machine is what Android uses."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return None, 'pyelftools not installed'
    try:
        elf = ELFFile(io.BytesIO(data))
        machine = elf['e_machine']
        # touch the section table so a broken sh_link shows up as a failure
        _ = [s.name for s in elf.iter_sections()]
        return machine, None
    except Exception as exc:
        return None, '%s: %s' % (type(exc).__name__, exc)


def looks_like_elf(data):
    return data[:4] == b'\x7fELF'


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="List / extract files from an EROFS image (Android *_dlkm etc.)")
    ap.add_argument('image')
    ap.add_argument('outdir', nargs='?', default=None,
                    help="output directory (created if missing)")
    ap.add_argument('--list', action='store_true', help="only list the tree")
    ap.add_argument('--only-ko', '--only-modules', dest='only_ko', action='store_true',
                    help="extract only *.ko / module files")
    ap.add_argument('--no-read', dest='no_read', action='store_true',
                    help="with --list: do not decode file data (skips vermagic)")
    ap.add_argument('--verbose', '-v', action='store_true')
    args = ap.parse_args(argv)

    if not args.list and not args.outdir:
        ap.error("outdir is required unless --list is given")

    try:
        fs = Erofs(args.image, verbose=args.verbose)
    except ErofsUnsupported as exc:
        print("UNSUPPORTED: %s" % exc, file=sys.stderr)
        return 3
    except ErofsError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2

    sb = fs.sb
    print("image        : %s (%d bytes, %d blocks)" % (args.image, fs.size, fs.size // sb.bs + (1 if fs.size % sb.bs else 0)))
    print("superblock   : magic=%#010x blkszbits=%d (bs=%d) inos=%d root_nid=%d meta_blkaddr=%d"
          % (sb.magic, sb.blkszbits, sb.bs, sb.inos, sb.root_nid, sb.meta_blkaddr))
    print("sb blocks    : %d (filesystem claims %d bytes)" % (sb.blocks, sb.blocks * sb.bs))
    print("feature_compat   : %#010x" % sb.feature_compat)
    print("feature_incompat : %#010x  [%s]" % (sb.feature_incompat, ', '.join(sb.feature_names())))
    if sb.has(FI_COMPR_CFGS):
        algs = [i for i in range(4) if sb.available_compr_algs & (1 << i)]
        print("compr cfgs   : available_compr_algs=%#06x -> %s"
              % (sb.available_compr_algs, [ALG_NAMES.get(a, a) for a in algs]))
        for a in algs:
            print("               %-8s cfg=%s %s" % (ALG_NAMES.get(a, a),
                                                    sb.compr_cfgs.get(a, b'').hex(),
                                                    cfg_dict_size(sb, a)))
    else:
        print("compr cfgs   : none (legacy layout, lz4_max_distance=%d)" % sb.lz4_max_distance)
    print("")

    has_pyelftools = True
    try:
        import elftools  # noqa: F401
    except ImportError:
        has_pyelftools = False

    nodes = []
    for path, inode in fs.walk():
        nodes.append((path, inode))

    n_ko = 0
    ko_rows = []
    exported = []
    errors = 0
    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)

    for path, inode in nodes:
        kind = 'd' if inode.is_dir() else ('l' if inode.is_symlink() else '-')
        comp = ''
        if inode.datalayout in (DL_COMPRESSED_FULL, DL_COMPRESSED_COMPACT):
            comp = ' [compressed]'
        elif inode.datalayout == DL_FLAT_INLINE:
            comp = ' [inline]'
        elif inode.datalayout == DL_CHUNK_BASED:
            comp = ' [chunked]'
        extra = ''
        data = None
        vermagic = None
        if kind == '-' and not args.no_read and path.endswith('.ko'):
            try:
                data = inode.data()
            except Exception as exc:                     # noqa: BLE001
                errors += 1
                print("  [error] %s: %s: %s" % (path, type(exc).__name__, exc),
                      file=sys.stderr)
                data = None
            if data is not None:
                try:
                    if looks_like_elf(data):
                        machine, vermagic, modname = elf_info(data)
                        extra = ' ELF machine=%s' % ('%#x' % machine if machine is not None else '?')
                        modinfo = b'vermagic=' in data or b'.modinfo\x00' in data
                        extra += ' modinfo=%s' % ('yes' if modinfo else 'no')
                        if vermagic:
                            extra += ' vermagic=%s' % vermagic
                        elif modinfo:
                            extra += ' vermagic=<?>'
                    else:
                        extra = ' not-ELF(magic=%s)' % data[:4].hex()
                except Exception as exc:                 # noqa: BLE001
                    extra = ' probe-failed(%s)' % type(exc).__name__
                n_ko += 1
                ko_rows.append((path, inode.size, vermagic, extra))

        if args.list:
            print("%s %8d %-24s %s%s%s" % (
                mode_to_str(inode.i_mode), inode.size,
                DL_NAMES.get(inode.datalayout, '?'), path, comp, extra))

        # extraction
        if args.outdir and kind != 'd':
            name = os.path.basename(path)
            if args.only_ko and not name.endswith('.ko'):
                continue
            try:
                if data is None:
                    data = inode.data()
            except Exception as exc:                     # noqa: BLE001
                errors += 1
                print("  [error] %s: %s: %s" % (path, type(exc).__name__, exc),
                      file=sys.stderr)
                continue
            outpath = os.path.join(args.outdir, *path.split('/'))
            os.makedirs(os.path.dirname(outpath) or '.', exist_ok=True)
            with open(outpath, 'wb') as fh:
                fh.write(data)
            fs.stats['bytes'] += len(data)
            exported.append((path, len(data)))

    print("")
    s = fs.stats
    print("nodes: %d dirs, %d files, %d symlinks; compressed inodes: %d"
          % (s['dirs'], s['files'], s['symlinks'], s['compressed']))
    if args.outdir:
        print("exported %d files (%d bytes) into %s"
              % (len(exported), s['bytes'], args.outdir))
    if n_ko:
        print("modules found: %d" % n_ko)
        for row in ko_rows:
            print("  %-50s %8d %s" % (row[0], row[1], row[3]))
    if errors:
        print("%d file(s) failed to decode - see [error] lines above" % errors)
        return 1
    if fs.warnings:
        print("%d warning(s) - see [warn] lines above" % len(fs.warnings))
    return 0


if __name__ == '__main__':
    sys.exit(main())

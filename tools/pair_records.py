#!/usr/bin/env python3
"""pair_records.py — pair trace_pipe_raw records with the text trace of the SAME
frozen window, using (cpu, common_pid, event_pid) as the join key.

raw record: 4-byte ring_buffer_event header + 32-byte payload
  payload+0  u16 trace type (109 = sched_blocked_reason)
  payload+2  u8  flags
  payload+3  u8  preempt_count
  payload+4  s32 common_pid      (task that was running)
  payload+8  s32 event pid       (task that blocked)
  payload+16 u64 caller          (raw kernel text / module address)
  payload+24 u32 io_wait

text line: "  comm-pid   [cpu] flags timestamp: sched_blocked_reason: pid=N iowait=N caller=sym+0xoff/0xsize [mod]"
"""
import collections
import re
import struct
import sys

TYPE_SBR = 109
REC = 36

LINE = re.compile(
    r'^\s*(?P<comm>.*?)-(?P<cpid>\d+)\s+\[(?P<cpu>\d+)\]\s+\S+\s+'
    r'(?P<ts>\d+\.\d+):\s+sched_blocked_reason:\s+pid=(?P<epid>-?\d+)\s+'
    r'iowait=(?P<iow>\d+)\s+caller=(?P<sym>[A-Za-z0-9_.$]+)\+0x(?P<off>[0-9a-fA-F]+)'
    r'(?:/0x(?P<size>[0-9a-fA-F]+))?'
    r'(?P<mod>\s+\[[^\]]+\])?'
)


def text_records(path):
    out = collections.defaultdict(list)
    for line in open(path, encoding='utf-8', errors='replace'):
        m = LINE.match(line)
        if not m:
            continue
        out[int(m.group('cpu'))].append((
            int(m.group('cpid')), int(m.group('epid')),
            m.group('sym'), int(m.group('off'), 16),
            int(m.group('size'), 16) if m.group('size') else 0,
            m.group('mod') is not None,
        ))
    return out


def raw_records(path):
    d = open(path, 'rb').read()
    out = []
    i = 0
    while i + REC <= len(d):
        hdr = struct.unpack_from('<I', d, i)[0]
        pl = i + 4
        if struct.unpack_from('<H', d, pl)[0] != TYPE_SBR:
            # resync on the next ring header that declares an 8-word payload
            i += 4
            continue
        wlen = hdr & 0x1F
        cpid = struct.unpack_from('<i', d, pl + 4)[0]
        epid = struct.unpack_from('<i', d, pl + 8)[0]
        caller = struct.unpack_from('<Q', d, pl + 16)[0]
        iow = struct.unpack_from('<I', d, pl + 24)[0]
        out.append((cpid, epid, caller, iow, wlen))
        i += 4 + wlen * 4
    return out


def align(raws, txt):
    """Greedy LCS-style alignment on (common_pid, event_pid) sequences."""
    pairs = []
    j = 0
    for r in raws:
        cpid, epid, caller, iow, _ = r
        # look ahead a little in the text stream for a match
        for k in range(j, min(j + 12, len(txt))):
            if txt[k][0] == cpid and txt[k][1] == epid:
                pairs.append((caller, txt[k]))
                j = k + 1
                break
    return pairs


def main():
    txt = text_records('pair/text.txt')
    print('text lines per cpu:', {c: len(v) for c, v in sorted(txt.items())})

    total_raw = total_pairs = 0
    caller_sym = collections.Counter()
    for cpu in sorted(txt):
        try:
            raws = raw_records(f'pair/raw_{cpu}.bin')
        except FileNotFoundError:
            continue
        if not raws:
            continue
        pairs = align(raws, txt[cpu])
        total_raw += len(raws)
        total_pairs += len(pairs)
        for caller, t in pairs:
            caller_sym[(caller, t[2], t[3], t[4], t[5])] += 1

    print(f'raw records total: {total_raw}   aligned pairs: {total_pairs}')
    print()
    print('=== caller address -> symbol (EXACT, from paired window) ===')
    rows = sorted(caller_sym.items(), key=lambda kv: -kv[1])
    for (caller, sym, off, size, ismod), n in rows:
        tag = ' [MODULE]' if ismod else ''
        print(f'{caller:#018x}  {sym}+{off:#x}/{size:#x}  x{n}{tag}')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""solve_slide.py — compute KASLR slide from paired runtime callers + a System.map.

For each (runtime_addr, symbol) pair:
    slide_i = runtime_addr - (map_sym_addr - map_text_addr)
slide is the same for all i iff the reference map's layout matches the device.
The spread of slide_i is exactly the layout drift of the reference build.
"""
import collections
import re
import sys

KIMAGE_LINK = None        # filled from the map's _text

# runtime addr -> symbol+off, exactly paired from the frozen trace window
PAIRS = [
    (0xffffffe9f13d6710, 'worker_thread',              0x248),
    (0xffffffe9f13d8d50, 'rcu_gp_fqs_loop',            0x154),
    (0xffffffe9f13ed088, 'kthread_flush_worker',       0xa8),
    (0xffffffe9f13ed23c, 'submit_bio_wait',            0x74),
    (0xffffffe9f144bcf4, 'folio_wait_bit_common',      0x188),
    (0xffffffe9f1488164, 'spi_transfer_wait',          0x84),
    (0xffffffe9f148b29c, '__flush_work',               0x268),
    (0xffffffe9f148f17c, 'rcu_gp_kthread',             0xc8),
    (0xffffffe9f149fc94, 'msleep',                     0x18),
    (0xffffffe9f152613c, 'regmap_lock_mutex',          0x10),
    (0xffffffe9f160aa34, 'dma_fence_default_wait',     0xec),
]


def load_map(path):
    syms = {}
    for line in open(path, encoding='utf-8', errors='replace'):
        p = line.split()
        if len(p) < 3:
            continue
        try:
            a = int(p[0], 16)
        except ValueError:
            continue
        syms.setdefault(p[2], a)
    return syms


def main(path):
    syms = load_map(path)
    text = syms.get('_text')
    if text is None:
        # arm64 maps put _text after _stext; fall back to the lowest text symbol
        cands = [v for k, v in syms.items() if k in ('_stext', '_text')]
        text = min(cands) if cands else None
    print(f'_text (link) = {text:#018x}')
    for k in ('_stext', '_etext', '_sdata', '_edata', '_end', 'selinux_state',
              'init_task', 'init_cred'):
        if k in syms:
            print(f'  {k:24s} {syms[k]:#018x}   (+{syms[k]-text:#x})')
    print()

    slides = []
    print(f'{"symbol":28s} {"+off":>8s} {"map_link":>18s} {"runtime":>18s} {"slide":>14s}')
    missing = []
    for addr, sym, off in PAIRS:
        base = syms.get(sym)
        if base is None:
            missing.append(sym)
            continue
        link = base - text + off          # offset from _text, plus in-function offset
        slide = addr - (text + link)
        slides.append((sym, slide))
        print(f'{sym:28s} {off:#8x} {base+off:#18x} {addr:#18x} {slide:#14x}')

    if missing:
        print('\nmissing symbols:', missing)
    if not slides:
        return 1

    print('\n=== slide statistics ===')
    vals = sorted(s for _, s in slides)
    print(f'  n={len(vals)}  min={vals[0]:#x}  max={vals[-1]:#x}  spread={vals[-1]-vals[0]:#x} ({(vals[-1]-vals[0])/1024:.1f} KiB)')
    mode = collections.Counter(slides).most_common(4)
    for s, n in mode:
        print(f'  slide={s[1]:#x}  hits={n}')
    import statistics
    med = int(statistics.median(vals))
    print(f'  median = {med:#x}   ({med/2**30:.6f} GiB)')
    print(f'  median % 2MiB = {med % 0x200000:#x}')
    print(f'  median aligned down to 2MiB = {med & ~0x200000 if False else med - med % 0x200000:#x}')
    for _, s in slides:
        d = s - med
        print(f'    {(_):28s} drift {d:+#x} ({d/1024:+.1f} KiB)')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else 'System.map.61816-4k'))

# An English journal: trying to unlock an XRing O3 device

This is the narrative version of `docs/journal/*` (which are in Chinese). It records what we did,
what we believed, and — more importantly — **what we falsified**. Every claim below has a
corresponding report with instruction-level citations.

---

## Round 0 — the device and the ground truth

Xiaomi 18 Fold (`lhasa`), Xiaomi's own **XRing O3** SoC, Android 17 / HyperOS `OS4.0.21.0.XPNCNXM`,
kernel `6.18.21-android17-5-g284297031c53`, SPL 2026-08-01, bootloader **locked**, AVB green.
Attacker perspective: `adb shell` — uid 2000, no capabilities, Seccomp 0, SELinux enforcing.

The interesting part is not the phone, it is the boot chain: XRing is new enough that almost nothing
about it is public, and the firmware loads its bootloader (`GBL`) from a partition named
`android_esp` — the SoC vendor's name for what Qualcomm devices call `efisp`.

Two facts decided the whole project:

1. `android_esp.img` is a plain **FAT12** volume containing `EFI/BOOT/BOOTAA64.EFI` (1.58 MB), and
   that PE has **no Authenticode** (data directory 4 is empty). The partition carries no AVB footer.
2. The GBL protocol is documented in AOSP (`platform/bootable/libbootloader`, branch `gbl-android17`):
   `gbl_efi_avb` exposes `WriteLockState(Self, Type, State)` at vtable `+0x48`, and in the GBL source
   `fastboot flashing unlock` never consults the lock for `LockType::Device` — `WriteLockState` is the
   only arbiter.

So the unlock chain is:

```
write android_esp  →  BL loads our GBL (no signature check)  →  our GBL calls
WriteLockState(DEVICE, UNLOCKED)  →  permanently unlocked  →  Magisk
```

Everything collapses into "get one write to a block device".

## Round 1 — the last mile, built early

We built the payload before the exploit, on purpose: if the payload is ready, the moment a write
primitive appears the device is unlocked in a minute.

`payload/esp_unlock.c` compiles with `zig cc -target aarch64-uefi` into a **2,560-byte** PE32+
(machine `0xAA64`, subsystem 10, `ImageBase = 0`, no `.reloc` — treated as position independent).
`tools/esp_patch.py` inserts it in place of the original `BOOTAA64.EFI` inside the FAT12 image by
rewriting the file body and the directory-entry size only (verified byte-for-byte).

KASLR was solved for the *target* side too: `selinux_state` lives at `_text + 0x2959630`, and the slide
can be recovered on every boot from the raw trace ring (`tools/cap_pair.sh` + `tools/solve_live.py`,
11 independent symbols agree, spread = 0).

## Round 2 — CVE-2026-64560, and how it died

A posix-cpu-timers UAF in this kernel version looked like the obvious candidate. The reference
implementation (a different Xiaomi build) reported a hit rate of 1/1000–1/5000 execs and panics at
~7000 execs.

Our port produced **zero** hits in 28,000 execs. The temptation was to call it bad luck. Instead we
disassembled `begin_new_exec` on the device kernel and read the order of operations:

```
+0x698  bl exchange_tids                 ; pid is moved to the new leader first
+0x6a8  bl transfer_pid (PIDTYPE_TGID)
+0x75c  bl _raw_write_unlock_irq
+0x76c  bl release_task(leader)          ; only now is sighand cleared
```

`posix_cpu_timer_del()` looks the target up with `PIDTYPE_TGID`. By the time `sighand` is cleared the
tgid already points at the exec'ing thread, so **the `!sh` branch has no reachable instant**. The bug
is "not backported" on paper, yet mechanically unreachable on this build. We rebuilt the harness with
the reference structure (parent-owned timers, parent-side delete storm, non-leader exec) and ran
three timing shapes for another 17,600 execs: still nothing, as predicted.

The same round produced the **order-1 reclaim primitives** we still use:
`/dev/uhid` + `UHID_CREATE2` gives `kmemdup(rd_data, 256)` — an order-1 kmalloc-256 slab full of
attacker bytes, unprivileged; and `send(AF_UNIX, 11872)` yields an order-1 page with all 8192 bytes
under our control (that constant is device-specific: `data_len = size - 0xe80`).

## Round 3 — mapping the surface instead of guessing

We stopped guessing and started measuring.

- **538 device nodes** on the system, exactly **14** openable by uid 2000; of the **73 misc devices**
  only **8** are usable.
- `mali0` opens but every ioctl returns **EPERM** (the `gpu_device` allow set does not contain shell) —
  the 1.9 MB kbase driver is out of reach.
- `xr_fbt`'s provider is not in `vendor_dlkm`; the module that references it (`os_cpu_qi.ko`) only
  imports `register_xr_fbt`. Dead end without the vendor partition.
- `tango32` turned out to be a 32-bit translator shim, not a device: no objects, no OOB, and its
  `compat_ioctl` forwarding does **not** change the SELinux verdict for any device we tested.
- `uinput`'s force-feedback path has a real UAF, but `/dev/input/event*` is EACCES for shell, so it
  cannot be triggered.
- binder: the page allocator has a genuine freelist bug (DoS only), the transaction path is
  structurally clean, and fd transfer has no double-close or OOB. Along the way we discovered that a
  previous conclusion — "binder write requires the buffer inside its own VMA" — was a **measurement
  artefact**: the probe sent the bare command word `0x0c` instead of the ioctl-encoded `0x0000630c`.
  With the correct encoding `BC_TRANSACTION` reports `write_consumed=68`.
- pty/tty: ring-buffer writes all carry `and 0xfff`, ldisc switching takes the write lock, and
  `tty_struct` lives in a dedicated cache.

We also turned the OTA into a working module pipeline: fetch a single partition over HTTP ranges
(the CDN needs a browser UA **and** a `miui.com` referer), parse EROFS (legacy LZ4, with the zero
padding at the *front* of each stream), and export **486/486** vendor `.ko` files, verified by
`e_shoff + e_shnum*shentsize == file size`.

## Round 3.5 — the patch-level audit

The most useful artefact came from a change of method: instead of hunting bugs, compare the device
binary against upstream stable fixes.

```
38 ChangeLogs (6.18.23 … 6.18.58, 12,142 subjects)
  → filter: uid-2000-reachable subsystem AND memory-corruption shape
  → resolve the commit sha locally → pull the unified diff from git.kernel.org
  → derive an assembly fingerprint (a cmp immediate, a new bounds branch, a field offset)
  → check it instruction-by-instruction in vmlinux-4.0.21.0.elf
  → verdict: fixed / MISSING / code absent
```

Result: the device's effective stable level is **≈ 6.18.44**; everything from **6.18.45 on is missing**
(21 checked: 14 missing, 1 equivalent, 6 not compiled). Two of the missing ones are UAFs reachable
with plain syscalls — the futex private-hash ref race and the futex/pi `exec()` race.

We then built and ran triggers for the PI/exec race: a fixed-phase owner/waiter harness, a randomized
pre-exec delay, a phase-swept single-attempt variant (166,000 iterations at 1253/s), and finally a
variant that tears the old mm down *before* the exec'ing task exits so the stale `pi_state` is
dereferenced by `exit_pi_state_list()` — 50,000 iterations. **No crash.**

The reason matters more than the result: `mm_struct` comes from a dedicated cache (`mm_cachep`), and
with `kasan=off`, no `dmesg`, and `panic_on_warn=0`, a silent UAF is indistinguishable from no UAF.
Turning it into anything useful needs controlled reclaim of that cache plus observability we do not
have. The remaining interesting target is the *other* futex bug, whose freed object is a `kvzalloc`
hash array — a normal kmalloc/vmalloc bucket our existing primitives can actually reach.

## What this repository is for

It documents a chain that is one primitive short, and a pile of **evidence-backed negative results**:
11 surfaces excluded with instruction-level citations, a stable patch-level audit that pins the device
at 6.18.44, and a reproducible toolchain (OTA → EROFS → modules, kernel disassembly, BTF, ESP
packaging, KASLR recovery). Negative results in this field are expensive to obtain and rarely
published; they are the main reason this is public.

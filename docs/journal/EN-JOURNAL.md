# Journal: boot-chain and kernel research on the XRing O3

This is the narrative counterpart of the reports in `docs/journal/` and `docs/audits/`
(which are in Chinese). It records what was tried, in what order, and what was falsified.
Every claim has a corresponding report with instruction-level citations.

## The device

Xiaomi 18 Fold (`lhasa`), XRing O3 SoC, Android 17 / HyperOS `OS4.0.21.0.XPNCNXM`,
kernel `6.18.21-android17-5-g284297031c53`, SPL 2026-08-01, bootloader locked, AVB green.
The research position is `adb shell`: uid 2000, no capabilities, Seccomp 0, SELinux enforcing.

XRing is Xiaomi's in-house SoC and essentially undocumented publicly. Two properties of its boot
chain shaped the project from the start:

1. The bootloader (GBL) is loaded from `android_esp`, the XRing equivalent of Qualcomm's `efisp` —
   an 8 MiB FAT12 volume. Its `EFI/BOOT/BOOTAA64.EFI` has no Authenticode signature (data directory
   4 is empty) and the partition carries no AVB footer.
2. The GBL protocol is documented in AOSP (`platform/bootable/libbootloader`, branch
   `gbl-android17`): `gbl_efi_avb` exposes `WriteLockState(Self, Type, State)` at vtable `+0x48`,
   and in the GBL source `fastboot flashing unlock` performs no lock check for `LockType::Device`.
   `WriteLockState` is the only arbiter.

That gives an unlock chain: write the ESP → the bootloader loads an unsigned GBL → that GBL calls
`WriteLockState(DEVICE, UNLOCKED)` → permanently unlocked. The entire problem reduces to one block
device write.

## Building the payload first

The payload was built before any exploit work, so that the moment a write primitive appears, the
unlock is a one-minute operation.

`payload/esp_unlock.c` compiles with `zig cc -target aarch64-uefi` into a 2,560-byte PE32+ binary
(machine 0xAA64, subsystem 10, `ImageBase = 0`, no `.reloc`; treated as position independent).
`tools/esp_patch.py` swaps it into the FAT12 image in place of the original `BOOTAA64.EFI`,
rewriting only the file body and the directory-entry size (verified byte-for-byte).

The address side was solved too: `selinux_state` sits at `_text + 0x2959630`, and the KASLR slide
can be recovered every boot from the raw trace ring buffer (`tools/cap_pair.sh` +
`tools/solve_live.py`; 11 independent symbols agree, spread = 0).

## CVE-2026-64560, and why it does not apply here

A posix-cpu-timers UAF present in this kernel version looked like the obvious candidate. A
reference implementation on a different Xiaomi build reported hit rates of 1/1000–1/5000 execs and
panics by ~7000 execs. The ported harness produced zero hits in 28,000 execs.

Instead of attributing this to luck, `begin_new_exec` was disassembled on the device kernel:

```
+0x698  bl exchange_tids               ; pid moved to the new leader first
+0x6a8  bl transfer_pid (PIDTYPE_TGID)
+0x75c  bl _raw_write_unlock_irq
+0x76c  bl release_task(leader)        ; sighand cleared only here
```

`posix_cpu_timer_del()` looks the target up with `PIDTYPE_TGID`. By the time `sighand` is cleared,
the tgid already points at the exec'ing thread, so the `!sh` branch has no reachable instant. The
bug exists in the source but is mechanically unreachable on this build. The harness was then rebuilt
to the reference structure (parent-owned timers, parent-side delete storm, non-leader exec) and run
in three timing shapes for another 17,600 execs: still zero, as the code predicts.

The same round produced the order-1 reclaim primitives used throughout: `/dev/uhid` +
`UHID_CREATE2` gives `kmemdup(rd_data, 256)` — an order-1 kmalloc-256 slab of attacker bytes,
unprivileged; `send(AF_UNIX, 11872)` yields an order-1 page with all 8192 bytes controlled
(the constant is device-specific: `data_len = size - 0xe80`).

## Mapping the surface

The next phase replaced guessing with measurement:

- 538 device nodes on the system; exactly 14 are openable by uid 2000. Of 73 misc devices, 8 are
  usable.
- `mali0` opens, but every ioctl returns EPERM — the `gpu_device` allow set does not include
  shell. The 1.9 MB kbase driver is out of reach.
- `xr_fbt`'s provider is not in `vendor_dlkm`; the module that references it (`os_cpu_qi.ko`) only
  imports `register_xr_fbt`.
- `tango32` is a 32-bit translator shim, not a device: no objects, no OOB, and its `compat_ioctl`
  forwarding does not change the SELinux verdict for any tested device.
- The uinput force-feedback path has a real UAF, but `/dev/input/event*` is EACCES for shell.
- Binder: the page allocator has a genuine freelist bug (DoS only — the write target is a constant
  unmapped address, so a hit always panics); the transaction path is structurally clean; fd
  transfer has no double-close or OOB.
- pty/tty: all ring-buffer writes carry `and 0xfff`, ldisc switching holds the write lock, and
  `tty_struct` lives in a dedicated cache.

One earlier conclusion had to be retracted. `HANDOVER_2` claimed the binder write path requires the
buffer to lie inside its own VMA; that was a measurement artefact — the probe sent the bare command
word `0x0c` instead of the ioctl-encoded `0x0000630c`. With the correct encoding, `BC_TRANSACTION`
reports `write_consumed=68`, and the write path is fully reachable by uid 2000
(`docs/audits/BINDER_REOPENED.md`).

A working module pipeline was built in parallel: fetch a single OTA partition over HTTP ranges
(the CDN requires a browser UA and a `miui.com` referer), parse EROFS (legacy LZ4, with zero
padding at the front of each stream), and export 486/486 vendor `.ko` files, verified by
`e_shoff + e_shnum * e_shentsize == file size`.

## The patch-level audit

The most productive phase came from inverting the approach: instead of hunting for bugs, check the
device kernel against upstream stable fixes.

```
38 ChangeLogs (6.18.23 … 6.18.58, 12,142 subjects)
  → filter: uid-2000-reachable subsystem AND memory-corruption shape
  → resolve the commit sha → pull the unified diff from git.kernel.org
  → derive an assembly fingerprint (a cmp immediate, a new bounds branch, a field offset)
  → check it instruction-by-instruction in vmlinux-4.0.21.0.elf
  → verdict: fixed / missing / code absent
```

The device's effective stable level is **≈ 6.18.44**: the 6.18.39 binder `tmp_ref` pin and the
6.18.44 hid-logitech-dj `report_count` check are both present, while everything checked from
6.18.45 onward is absent (21 checked: 14 missing, 1 equivalent, 6 not compiled), with no
out-of-order backports.

Two of the missing fixes are UAFs reachable with plain syscalls: the futex private-hash refcount
race and the futex/pi `exec()` race. For the second, four trigger generations were built: a
fixed-phase owner/waiter harness (20,000 iterations), a randomized pre-exec delay (20,000), a
phase-swept single-attempt variant (166,000 iterations at 1,253/s), and a variant that tears the
old mm down before the exec'ing task exits, so the stale `pi_state` is dereferenced in
`exit_pi_state_list()` (50,000). Total: 256,000 iterations, no observable effect.

The limiting factor is observability, not reachability. `mm_struct` comes from a dedicated cache
(`mm_cachep`), and with `kasan=off`, no readable kernel log, and `panic_on_warn=0`, a silent UAF is
indistinguishable from no UAF. The remaining target of interest is the other futex bug: its freed
object is a `kvzalloc` hash array — an ordinary kmalloc/vmalloc bucket whose size is
attacker-selected via the slot count, so the existing reclaim primitives can cover it. That
analysis is in `docs/patch-level/FUTEX_CANDIDATES.md` §5.2.

## Current state

- Unlock chain: complete except one kernel write primitive; payload and ESP patcher ready.
- Patch-level audit: device pinned at 6.18.44; 14 reachable fixes missing, with instruction-level
  verdicts for every checked entry.
- Attack surface: 11 candidate surfaces ruled out with evidence; 538 device nodes and 73 misc
  devices fully enumerated.

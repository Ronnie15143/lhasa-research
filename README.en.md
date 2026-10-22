# lhasa-research — unlocking an XRing O3 device

A reverse-engineering journal: **Xiaomi 18 Fold (`lhasa`)**, Xiaomi's own **XRing O3** SoC,
Android 17 / HyperOS, kernel `6.18.21-android17-5`, SPL 2026-08-01, bootloader locked,
attacker = `adb shell` (uid 2000, no capabilities, SELinux enforcing).

The device is interesting because its boot chain has a link that, once touched, means permanent
unlock — and almost nothing about this SoC is public.

## The chain we proved

```
① write android_esp (XRing's efisp, 8 MiB FAT12, holds EFI/BOOT/BOOTAA64.EFI = GBL)
        ↓
② bootloader loads GBL from efisp: "is it a UEFI app?" — no authenticity check
        ↓
③ our GBL calls gbl_efi_avb vtable +0x48 = WriteLockState(Self, DEVICE, UNLOCKED)
        ↓
④ permanent unlock → Magisk
```

Evidence for every link: the GBL protocol is documented in AOSP
(`platform/bootable/libbootloader`, branch `gbl-android17`), the firmware image is a plain FAT12
volume with an unsigned PE (`BOOTAA64.EFI` has no Authenticode), and `fastboot flashing unlock`
never consults the lock for `LockType::Device` — `WriteLockState` is the only arbiter.

**The last mile is already built**: `payload/esp_unlock.c` compiles to a **2,560-byte** UEFI app
(`zig cc -target aarch64-uefi`, PE32+ / machine 0xAA64 / subsystem 10), and `tools/esp_patch.py`
swaps it into the stock ESP image in place (only the directory-entry size changes; verified
byte-for-byte).

## The blocker: one kernel write

`selinux_state` lives at `_text + 0x2959630`; the KASLR slide is resolved every boot from the
raw trace ring buffer (`tools/cap_pair.sh` + `tools/solve_live.py`, 11 independent symbols agree,
spread = 0).

So everything reduces to: **get one kernel write as uid 2000.**

## What we ruled out (11 surfaces, each with evidence)

CVE-2026-64560 (mechanically unreachable on this build), hid-multitouch, uinput FF, uinput
non-FF ioctls, Xiaomi's ashmem variants, the `tango32` vendor driver, `mali0` (ioctl EPERM),
`xr_fbt`, the binder page allocator (DoS only), the binder transaction path and fd transfer,
and pty/tty. Each report is in `docs/audits/` with instruction-level citations.

We also corrected an earlier conclusion: the "binder write path requires the buffer inside its own
VMA" claim was a measurement artefact — the probe sent the bare command word instead of the
ioctl-encoded one. With the correct encoding `BC_TRANSACTION` reports `write_consumed=68`.

## The most useful artefact: a patch-level audit

Instead of guessing which subsystem has a bug, we compared the device binary against upstream
stable fixes:

```
38 ChangeLogs (6.18.23 – 6.18.58, 12,142 subjects)
  → filter by "uid-2000 reachable subsystem + memory-corruption shape"
  → resolve commit sha locally → pull the unified diff from git.kernel.org
  → derive an assembly-level fingerprint (a cmp immediate, a new bounds branch, a field offset)
  → check it instruction-by-instruction in vmlinux-4.0.21.0.elf
  → verdict: fixed / MISSING / code absent
```

Result: **the device's effective stable level is ≈ 6.18.44; everything from 6.18.45 on is missing**
(14 missing, 1 equivalent, 6 not-compiled out of 21 checked). Two of the missing ones are UAFs
reachable with plain syscalls (the futex private-hash ref race and the futex/pi `exec()` race).
Details: `docs/patch-level/PATCH_LEVEL_6.18.45_58.md` and `FUTEX_CANDIDATES.md`.

## Negative results are results

- ~256,000 race/phase iterations (17.6k for CVE-2026-64560, 20k+20k+166k+50k for the futex races) —
  zero crashes;
- all **538** device nodes scanned: only **14** are openable by uid 2000;
- **73** misc devices: only **8** usable;
- the three generic escape hatches (userns / io_uring / bpf) are all closed.

## Layout

```
docs/journal/      handovers and stage reports
docs/audits/       the 11 surface audits
docs/patch-level/  patch-level audit, futex candidates, module pipeline, one-page status
tools/             reproducible analysis and packaging tools
probes/            40+ on-device probes (surface map, ioctl oracles, race triggers, sanity checks)
payload/           the unlock payload source
patches/           upstream fix patches (GPL-2.0, from kernel.org, for reference only)
```

## Notice

All work was done on a device we own (full backup taken first). No third-party devices, accounts
or data are involved. The repository contains **no vendor firmware, module binaries, OTA payloads,
signing keys or device dumps** — only self-written source, analysis, and public upstream patches
(GPL-2.0, in `patches/`). There is **no working exploit** here: the unlock payload needs a kernel
write primitive that we did not obtain, and the race triggers exist only to prove whether a fix is
missing.

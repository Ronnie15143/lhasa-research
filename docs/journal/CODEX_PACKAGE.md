# 交给外部模型的技术包 —— 小米 18 Fold（lhasa）解锁 / 内核提权现状

> 用途：向外部模型（Codex / GPT / Claude 等）求解**新思路**。本文件自包含：
> 环境硬事实、已打通的链、已用证据关闭的路、可达面实测、手上的原语、工具与产物、以及具体问题。
> 一切结论都有本机证据；不确定的地方明确标注。

---

## 0. 目标与现状（一句话）

目标：**拿到 root / 永久解锁 BL**。唯一可行的技术链是
「写 `android_esp`(efisp) → bootloader 未验签加载自造 GBL → 调 `gbl_efi_avb.write_lock_state` 解锁」。
现在**只差一次"能写该分区"的能力**：SELinux 下唯一能写 `android_esp_block_device` 的域是 `update_engine`，
而 uid 2000 能触到的内核内存破坏面已被逐个审计排除（见 §3）。**需要一个我们没想到的角度。**

## 1. 设备与环境（全部实测）

| 项 | 值 |
|---|---|
| 机型 | Xiaomi 18 Fold，codename `lhasa`，model 2608BPX34C |
| SoC | XRing O3（小米自研） |
| 系统 | Android 17 / HyperOS `OS4.0.21.0.XPNCNXM` |
| 内核 | `6.18.21-android17-5-g284297031c53-abogki553682993-4k`，SPL 2026-08-01 |
| BL | **locked**（`ro.boot.flash.locked=1`、AVB green、`slot-unbootable:b=yes`） |
| 攻击者身份 | `adb shell` = uid 2000，**无任何 capability**，Seccomp 0，SELinux Enforcing |
| 页/CPU | 4K 页 / 10 核 / `CONFIG_ARM64_VA_BITS_39` |
| 加固 | `HARDENED_USERCOPY_DEFAULT_ON`、`FORTIFY_SOURCE`、`CONFIG_CFI`、`BUG_ON_DATA_CORRUPTION`、`PANIC_ON_OOPS`、`INIT_ON_ALLOC_DEFAULT_ON`、`ARM64_PAN/MTE`、`SLUB_CPU_PARTIAL`、`SHUFFLE_PAGE_ALLOCATOR`；`KASAN=y` 但 **cmdline `kasan=off`**；`RANDOM_KMALLOC_CACHES` **未设** |
| 关掉的通用面 | 无 `CONFIG_USER_NS`、无 `IO_URING`（SELinux EACCES）、`bpf()` EACCES、`keyctl/add_key` EACCES、`userfaultfd` EPERM、`AF_PACKET`/`AF_VSOCK` EACCES、无 `SYSVIPC`/`POSIX_MQUEUE`、`CONFIG_STATIC_USERMODEHELPER_PATH=""`（core_pattern/modprobe 死路） |

## 2. 已打通的解锁链（每一环有证据）

```
① 写 android_esp（8 MiB FAT12，含 EFI/BOOT/BOOTAA64.EFI，即 GBL）
     ↓  ② bootloader 从 efisp 加载 GBL，只检查"是 UEFI 应用"，不验真实性
     ↓  ③ 我们的 GBL 调 gbl_efi_avb 协议 vtable +0x48 WriteLockState(Self, 0=DEVICE, 0=UNLOCKED)
     ↓  ④ 永久解锁 → 刷 Magisk
```

- `gbl_efi_avb` GUID `{6bc66b9a-d5c9-4c02-9da9-50af198d912c}`；vtable 布局已在 AOSP
  `platform/bootable/libbootloader`（分支 `gbl-android17`）的 `gbl/docs/gbl_efi_avb_protocol.md` 原件核对：
  `Revision, ReadPartitionAttributes, ReadDeviceStatus, ValidateVbmetaPublicKey, Read/WriteRollbackIndex,
   Read/WritePersistentValue, HandleVerificationResult, WriteLockState, FactoryDataReset`。
- GBL 源码证实 `fastboot flashing unlock` 对 `LockType::Device` 不查锁，唯一裁决者就是 `WriteLockState`。
- `BOOTAA64.EFI` 明文 1.58 MB，PE 数据目录无 SECURITY（无 Authenticode）；`android_esp.img` 无 AVB footer。
- **我们已经做好载荷**：`BOOTAA64_unlock.EFI`（2,560 B，zig `-target aarch64-uefi`，
  PE32+/machine 0xAA64/subsystem 10/ImageBase 0），并用 FAT12 patch 工具换进 `android_esp_unlock.img`
  （目录项 size 1,585,152 → 2,560，首簇 2 @0x7000，已逐字节验证）。

## 3. 已用证据关闭的道路（11 项，别重复）

| 面 | 结论 | 证据 |
|---|---|---|
| CVE-2026-64560（posix-cpu-timers 非 leader exec UAF） | **机制级不可达**：本机 de_thread 先 `exchange_tids`+`transfer_pid(TGID)` 再 `release_task(leader)`，`!sh` 窗口不存在；修正触发结构 17,600 exec 零命中 | `64560_DEAD_ON_LHASA.md` |
| HID multitouch（6.18.22 #267 缺 report-ID 校验） | 被 core 的 `-EINVAL` 守卫吃掉，只到 dev_warn | `HID_MT_C1_RECHECK.md` |
| uinput FF 上传/擦除 UAF | 候选真实，但 `/dev/input/event*` 对 shell **EACCES**，触发不了 | `UINPUT_FF_AUDIT.md` |
| `/dev/uinput` 非 FF ioctl（UI_DEV_SETUP/ABS_SETUP/SET_*BIT/SET_PHYS） | 无 OOB/UAF（kstrndup(name,0x50)、`_IOC_SIZE≤0x1c`、`code≤0x3f`、11 条 `*_MAX` 界全在） | `UINPUT_ASHMEM_AUDIT.md` |
| tango32 厂商 ioctl | 无 OOB/UAF/泄露（fops 只挂 unlocked_ioctl，无对象；栈拷贝终点=canary 前沿） | `TANGO32_AUDIT.md` |
| tango32 `0x400c74a3` compat 转发 | 实测**不改变** SELinux 判决（mali 仍 EPERM / binder 仍 EACCES / uhid 仍 ENOTTY） | `l74_tango_compat.c` |
| `/dev/mali0`（kbase 1.9MB） | ioctl 全 **EPERM**（`gpu_device` 的 allow 域不含 shell） | `l71/l72` |
| `/dev/xr_fbt` | 提供者模块不在可取分区（`os_cpu_qi.ko` 只是 import `register_xr_fbt`） | `MODULE_PIPELINE.md` |
| binder 页面分配器（全局 freelist LRU 不对称） | 真缺陷但**只值 DoS**（写落点常量非映射、必 panic、shrinker 放回 order-0） | `BINDER_ALLOC_AUDIT.md` |
| binder 事务路径（offsets/flat_binder_object/释放/读回） | **结构性干净**（offsets 无 TOCTOU、四道界、零化 40B 栈缓冲、failed_at 截断、读路径不回吐 buffer） | `BINDER_TXN_AUDIT.md` |
| pty/tty（`/dev/ptmx`） | 无 UAF/OOB（环缓冲三处写点全 `and 0xfff`；ldisc 切换持写锁；tty_struct 是专用 slub cache） | `TTY_AUDIT.md` |
| 6.18.22 缺补丁扫描（277 条） | **死路**：清单里没有 tty/pty、AF_UNIX、epoll/futex/pidfd/memfd、f2fs/ext4；能碰到的都要 `CAP_NET_ADMIN` 或 `bpf()` | `HUNT_STATUS.md` |

## 4. 本机可达面（逐条实测，不是推测）

- **可 open 的设备**（538 个 device node 全扫）：`/dev/binder`、`/dev/uhid`、`/dev/uinput`、
  `/dev/tango32`、`/dev/xr_fbt`(ioctl 部分 EACCES)、`/dev/mali0`(ioctl EPERM)、
  `/dev/ashmem_{unpinning_enable,ignore_unset_prot_read,ignore_unset_prot_exec}`、`/dev/ashmemb8fc85c4-…`、
  `/dev/ptmx`、`/dev/zero|null|random|urandom`。
- **系统调用可达**：`AF_UNIX`、`AF_INET/DGRAM`、`AF_NETLINK`（仅 proto 0=ROUTE 与 7=SELINUX 能开）、
  `epoll`、`timerfd`、`eventfd`、`memfd_create`、`pidfd_open`、`open_tree`、`/proc/slabinfo` 可读。
- **全拒**：块设备、`/dev/ufs-bsg0`、`/dev/device-mapper`、`/dev/fuse`、`/dev/dma_heap/*`、`/dev/kvm`、
  `/dev/udmabuf`、`/dev/vhost-vsock`、`/dev/net/tun`、`/proc/kallsyms`、`dmesg`、`pstore`、perf tracepoint。
- **SELinux**：能写 `android_esp_block_device` 的域**只有 `update_engine`**；`init` 只有 open+ioctl 没有 write；
  `shell` 对 ESP 连 open 都没有。
- **shell 可启动任意 init 服务**（实测）：`/vendor/etc/init/mtk_thinmd.rc` 有
  `on property:debug.modem.triggerexception=* → start ${debug.modem.triggerexception}`，
  而 `debug.` 属 `debug_prop`、shell 有 `set` 权限 ⇒ `setprop debug.modem.triggerexception <服务名>` 即可拉起任何服务。
- **hypsys / `miui.mqsas.IMQSNative`（uid 0）**：`code 1` = root 读文件、`code 7` = **root 任意文件写（字符串载荷）**、
  `code 8` = root 读；对 `misc_block_device`/`android_esp_block_device` 的写被 SELinux 拒（其域只有 `blk_file` 读）。

## 5. 手上的原语（现成可用）

- **可控回收**：`/dev/uhid` + `UHID_CREATE2`（走 write）→ `kmemdup(rd_data, rd_size)`，
  `rd_size=1..4096`，256 → **order-1 kmalloc-256（32 对象/8K slab，内容 100% 任意字节）**，非特权；
  `send(AF_UNIX, 11872)` → `data_len=8192` → **order-1 整页 8192 B 全可控**；
  `UI_SET_PHYS`（`strndup_user(arg,0x400)`）→ kmalloc-1k。
- **布局稳定**：tango32 `0x74a2` 可把本进程 `mm->mmap_base` 写到 `[0x10000001, 2^39)` 内任意值 ⇒ mmap ASLR 归零。
- **可执行匿名内存**：`write "1"` 到 `/dev/ashmem_ignore_unset_prot_exec` 后
  `ASHMEM_SET_PROT_MASK(PROT_READ|PROT_EXEC)` 从 -EINVAL 变 0，`mmap(PROT_READ|PROT_EXEC)` 成功（实测）。
- **KASLR 已解**：每次 boot 用 `cap_pair.sh` + `solve_live.py` 从 trace 原始环形缓冲解 slide
  （11 个符号独立算出同一 2 MiB 对齐值，spread=0）。`selinux_state = _text + 0x2959630`。
- **大对象载体**：`n_tty_data = kzalloc(8920)` → kmalloc-16k/order-2，其中 8K 内容攻击者可控
  （现有原语够不到这一档，但也许对某个 bug 有用）。

## 6. 工具与产物（都能复跑）

- `rom/ota_extract.py`：按 HTTP Range 从 9.6 GB OTA 抠单分区（CDN 需浏览器 UA + `Referer: https://www.miui.com/`）。
- `rom/erofs_extract.py`：完整 EROFS 读取器（legacy/compact、LZ4/ZSTD、datalayout1/3、big-pcluster、tail-packing），
  已把 `vendor_dlkm` 的 **486/486 个 `.ko`** 全量导出并逐字节校验（`e_shoff+e_shnum*e_shentsize == 文件长度`）。
- `rom/ko_disasm.py`：ET_REL 模块按符号反汇编 + 分支标注；`rom/kdisasm.py`：按符号反汇编整内核；
  `rom/btf_dump.py`：从 Image `.BTF` 取结构布局。
- `rom/esp_patch.py`：向 FAT12 镜像里换 `EFI/BOOT/BOOTAA64.EFI`。
- `research/l65.c`（64560 触发/回收/夺页）、`l70_surface.c`（可达面扫描）、`l72_ioctl.c`（ioctl 可达性判据）、
  `l73_binder.c`、`l74_tango_compat.c`、`l75_ashmem_exec.c`、`l76_netlink.c`。
- 文档：`HANDOVER.md`（第 1 轮）、`HANDOVER_2.md`（第 2 轮）、`HUNT_STATUS.md`（单页状态）、
  `MODULE_PIPELINE.md`、各审计报告（见 §3 表右列）。

---

## 7. 我们要问的问题（请只回答这些，不要泛泛而谈）

**Q1（最想要）**：在上述"无 userns / 无 io_uring / 无 bpf / 无 keyring / 无 perf / 无 SYSVIPC / 无 POSIX_MQUEUE、
HARDENED_USERCOPY + BUG_ON_DATA_CORRUPTION + CFI + INIT_ON_ALLOC + PAN/MTE、KASAN 关闭"的 Android 17 / 6.18 内核上，
**uid 2000 还剩哪些类别的内存破坏面是我们没列的？** 请给具体子系统 + 触发 syscall/设备 + 对象所在 slab，
并说明为什么它能绕开上述加固。特别注意：我们没审过的 `flip buffer（tty_buffer）`、
`procfs/sysfs 写入路径`、`shmem/tmpfs`、`dma-buf` 与 `mali fd 传递`、`binder fd 传递`、
`pidfd_getfd`、`process_vm_writev`、`epoll/timerfd 的 fd 生命周期`。

**Q2（绕开内核）**：我们只有一个 **uid 0 的"文本文件写"** 原语（`IMQSNative code 7`，写一个字符串到任意路径）。
有没有办法用它写出一个**能被 bootloader 的 FAT 驱动接受、且包含任意 ELF 内容**的 ESP 镜像？
关键难点：FAT 引导扇区与 FAT 表必然含 0x00 字节，而该原语只能写字符串。
是否存在"全字段可打印 ASCII 的 FAT12/FAT16 变体"、或者 `LBA/簇大小/根目录项` 可被选到让关键字段避开 0x00 的构造？
或者反过来：有没有办法让该原语做**追加写/按偏移写**（例如写到 `/proc/self/fd/N`、写到 device 的某个 offset 文件、
写到 loop 设备的 backing file）？

**Q3（目标域正确）**：`update_engine` 是本机唯一有 `android_esp_block_device:blk_file write` 的域。
在"shell 能 `start` 任意 init 服务"的前提下，**有没有不依赖 payload 签名的办法让 update_engine 写我们给的内容**？
我们想到的方向：`IUpdateEngine` AIDL 里 merge/cleanup/suspend/resume 类不碰 payload 的方法、
`--payload_path` 的路径是否可由属性/文件注入、`/data/ota_package` 的可写性、
以及 update_engine 是否 dlopen 任何 `/data` 下的库（`LD_PRELOAD`/`/etc/ld.so.preload` 类注入）。

**Q4（能不能把已有原语组合起来）**：我们已经有 (a) `mm->mmap_base` 任意写（本进程）、
(b) 可执行 ashmem、 (c) uhid 的 order-1 全控对象、 (d) AF_UNIX 的 order-1 全控页。
在**没有**任何 UAF/OOB 的前提下，这四样能不能组合出"让内核替我们写一块块设备"的效果？
（我们判断 PAN/PXN 让"内核执行用户页"不成立，请指出这个判断是否有漏洞。）

**Q5（如果都不行）**：以你的经验，这类"BL 锁定 + 无 userns + 厂商加固"的设备，
**实际被攻破时走的通常是什么路**？（例如：厂商服务的 binder 接口、OTA 客户端、
`fastbootd` 用户态、`vold`、`gsid`、`keystore`、`gatekeeper`…）请按"最可能先出成果"排序，并给出第一步该查什么。

**约束**：不要建议"官方解锁/找售后/换设备"；不要建议需要 `CAP_NET_ADMIN`、`CAP_SYS_ADMIN`、userns 的方案
（我们没有）；不要重复我们已经关闭的 11 条（§3）。

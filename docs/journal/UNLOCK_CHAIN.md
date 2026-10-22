# 解锁链全图（每一环都已实测/证实）

> 2026-10-22。本文是本轮所有侦察的收口：**整条链已经打通到"只差一次 permissive/root"**。

```
┌─ 终极解锁链 ────────────────────────────────────────────────────────┐
│                                                                     │
│  ① 写 android_esp（= XRing 的 efisp，FAT12，内含 EFI/BOOT/BOOTAA64.EFI）│
│         ↓                                                           │
│  ② bootloader 从 efisp 加载 GBL，**只检查是不是 UEFI 应用、不验真实性**   │
│     （公开研究已证：小米17 / Redmi K90PM 同源，ShadowBlade Lab，2026-03）│
│         ↓                                                           │
│  ③ 我们的 GBL 调 gbl_efi_avb 协议 slot 8 = write_lock_state(+0x48)     │
│     ——源码证实 `flashing unlock` 对 LockType::Device **不查锁**，        │
│       唯一裁决者就是这个 provider 方法                                │
│         ↓                                                           │
│  ④ 永久解锁 → 刷 Magisk → 持久 root                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                              ↑
        唯一阻塞：① 需要写块设备 → 需要 SELinux permissive 或 root
                              ↑
        唯一可达手段：一次内核任意写（zero `selinux_state`，地址每次 boot 可算）
```

## 一、每一环的证据

| 环节 | 结论 | 证据 |
|---|---|---|
| `android_esp` = efisp | 是 | `rom/fw/android_esp.img` 是 8 MiB **FAT12** 卷（头 `mkfs.fat`），含 `EFI`/`BOOTAA64` 目录项；`rom/fw/*` 全量搜 `efisp` 零命中（XRing 用 android_esp 这个名字） |
| GBL 不验真实性 | 公开研究已证 | 高通平台 GBL 漏洞：`ABL 从 efisp 加载 GBL 后仅检查其是否为 UEFI 应用，未验证真实性`；同族仓库 `kasnria001/qualcomm_gbl_exploit_poc`（977★，含 `gbl_efi_unlock.efi`/`gbl_efi_relock.efi`/`VbRwStateApp.c`）、`SuperTurtleDev/gbl_root_canoe`（`FakelockOverlay.c`/`VerifiedBootHook.c`）、`1vivy/gbl-chainload` |
| BOOTAA64.EFI 无 Authenticode | 实测 | PE 数据目录只有 dir 0/3/5/6，**无 dir 4 (SECURITY)** → 无 PKCS#7 → UEFI Secure Boot 覆盖不到 |
| `flashing unlock` 不查锁 | 源码 | `libgbl/src/fastboot/mod.rs:1734-1768`，只有 `LockType::Critical` 走 `check_unlocked()`；`Device` 直接调 provider |
| provider vtable | 实测 | 明文 BOOTAA64.EFI 里 `0x11E14C..0x11E7A0` 9 个方法：`read_partitions_to_verify` / **`read_device_status`** / `validate_vbmeta_public_key` / `read_rollback_index` / `write_rollback_index` / `read_persistent_value` / `write_persistent_value` / `handle_verification_result` / **`write_lock_state`** |

## 二、阻塞点的三条独立实测（avc oracle）

本轮建立了**权限判定的实测 oracle**：SELinux 拒绝会出现在 `logcat -d -b all | grep avc:` 中。

```
hypsys(uid 0) 写 misc
  → avc: denied { write } ... tcontext=u:object_r:misc_block_device:s0 tclass=blk_file permissive=0
hypsys(uid 0) 写 android_esp_b
  → avc: denied { write } ... tcontext=u:object_r:android_esp_block_device:s0 tclass=blk_file permissive=0
hypsys(uid 0) 写 /data/local/tmp
  → avc: denied { search } ... tcontext=u:object_r:shell_data_file:s0 tclass=dir
hypsys(uid 0) 写 /data/anr → 无拒绝、文件生成（oracle 有效性已验证）
```

**顺带解决了历史悬案**：之前那次"写 misc 后重启仍 locked"的实验——**写入根本没落地**，一直是 SELinux 在挡。旧文档从判据到写权限两处都不成立。

CIL 策略交叉验证（本地 `plat/vendor/system_ext_sepolicy.cil` 全量）：

```
boot_block_device（含 bcp_a=sda1、boot_a）的写规则只有一条：
  update_engine_common -> boot_block_device : ioctl read write getattr lock append map open watch watch_reads
hypsys_ssi_default -> boot_block_device：零规则
```

⇒ **bcp 注入内核 cmdline 的路也不通**（update_engine 只吃 MIUI releasekey 签名的 payload）。

## 三、固件侧：证毕，别再挖

| 证据 | 数据 |
|---|---|
| 逐镜像 crypt flag | `header+0x110 == 1` ⟺ body 熵≈8.0；`==0` ⟺ 明文。**22 个签名镜像 100% 吻合，零例外** |
| 明文对照组 | `ddr_param0/1/3/5` flag=0，body 是自描述头 `a5a55a5a17072620 + len`，熵 5.15–5.66 |
| ECB 检测 | uefi body 131072 个 16B 块 **distinct=131072，重复 0** → 链式/流密码，非 ECB |
| 签名覆盖密文 | `SHA-384(body_as_stored)` 命中 `header+0x1EC` → encrypt-then-sign |
| 解压穷举 | LZMA(全 lc·lp·pb·dict)、XZ、zlib/deflate/gzip(逐字节 skip)、zstd、brotli、lz4、bzip2、7z、**EDK2 Tiano/LZ77** 全失败；`_FVH`=0、压缩魔数=0、UTF-16 串=0 |
| 密钥位置 | **bl2/xloader 的 body 也加密，而 BL2 由 ROM 加载 → ROM 不可能软件解密 ⇒ key 在 efuse/inline crypto，软件里永远没有** |

⇒ provider 实现体不可读、不可改。**唯一能碰它的是"在它被加载后调用它"，也就是上面链条的 ③。**

## 四、内核侧：现在只剩这一个缺口

目标已收窄成一句话：**拿到一次任意内核写，把 `selinux_state` 清零**（每 boot 的地址都能精确算出，本轮已验证 spread=0 的两独立抓取）。

现状：

| 路径 | 状态 |
|---|---|
| CVE-2026-64560 | 存在，但缺 order-1 回收原语（已穷尽：SYSVIPC/POSIX_MQUEUE 未编译；add_key/BPF/io_uring 被 SELinux 拒；setxattr 非持久；ANON_NAME 是 C 字符串；BTF 逐字段核对余下 order-1 cache 无可控窗口；8KB frag 是 order-3） |
| 通用 LPE | 全被 config 关闭（无 AF_ALG user API、无 userns、binderfs 不可达） |
| 上游 6.18.22 | 277 条补丁，shell 可达 ∩ 安全 = 9 条，全需 CAP_NET_ADMIN 或未编译 |
| `/dev/binder` | 读侧通（BR_NOOP）；**写侧要求命令缓冲落在 binder 自己的 VMA 内**（错误码差分已证），而 VMA 页由内核按需填充 → 形成一个调用环 |
| `/dev/uhid` | ioctl 到达驱动，未深挖 |
| `/dev/ptmx`、perf(self) | 可达，未深挖 |

## 五、手上现在有的工具（都已验证）

- `research/cap_pair.sh` + `pair_records.py` + `solve_live.py` → **每次 boot 精确解 slide**（spread=0）
- `rom/vmlinux-4.0.21.0.elf`（139,213 符号）+ `Image-4.0.21.0.bin`（含 `.BTF`）→ 精确反汇编与结构布局
- `rom/kdisasm.py` → 按符号反汇编设备真实内核
- `avc_probe.sh` → **权限判定 oracle**（logcat avc 拒绝）
- `fb3.py` → 自定义 libusb fastboot 客户端（标准 fastboot 枚举不到本机）
- `%TEMP%\gbl_repo` → **GBL 全量源码**（`gbl-android17`，HEAD `bdf1b55`）

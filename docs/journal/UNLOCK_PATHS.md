# UNLOCK_PATHS — 不依赖内核 root 的解锁/绕过路径穷尽（lhasa / XRing O3）

> 设备：Xiaomi 18 Fold `lhasa` / 2608BPX34C / XRing O3 / Android 17 / HyperOS OS4.0.21.0.XPNCNXM
> 内核 `6.18.21-android17-5-...-4k`，SPL 2026-08-01，BL 锁定（`ro.boot.flash.locked=1`）
> adb serial `038BB41049983540`，shell uid 2000
> 本轮时间窗：2026-10-22 09:00 – 09:45（**09:27 设备重启过一次，见 §8**）
> 约束：只读探测 + 静态分析；未写任何分区、未 flash。

---

## 0. ★ 本轮最重要的结论：GBL「判锁判据 = misc[0:4] == 0x4B」这条证据链有硬伤

交接文档（`HANDOVER.md` / `REPORT_GBL_LOCK.md`）把整套作战计划压在
「`misc[0:4]`（小端 u32）== `0x4B` → unlocked」上。我用 PE 段表 + capstone 重新反汇编后
**无法复现这个结论**，而且拿到了反证。

### 0.1 正确的 PE 映射（原报告用的是 file offset 当 RVA，会看错位置）

`BOOTAA64.EFI` 的段表（`gbl_judge.py` 实测，raw ≠ virtual）：

```
image_base = 0x140000000   image_size = 0x166000
  .text    va=0x00001000 vsize=0x00119b9c raw=0x00000400 rawsize=0x00119c00
  .rdata   va=0x0011b000 vsize=0x0003d6e8 raw=0x0011a000 rawsize=0x0003d800
  .data    va=0x00159000 vsize=0x00003580 raw=0x00157800 rawsize=0x00001a00
  .pdata   va=0x0015d000 vsize=0x000044c8 raw=0x00159200 rawsize=0x00004600
```

函数边界用 `.pdata`（**ARM64 是 8 字节记录**，不是 12 字节）解析，得到 **2201 个函数**，
与 `gbl_functions.txt` 的条数一致。

字符串真实位置（`gbl_xref.py` 实测）：

| 内容 | RVA | 文件偏移 |
|---|---|---|
| `"miscDevice is not unlocked"` | `0x139780` | `0x138780` |
| 分区名 `"misc"`（独立 NUL 结尾） | `0x12c3c8` | `0x12b3c8` |

### 0.2 全程序 xref：判锁语句只有一处，但它比的不是分区内容

对 `.text` 做线性扫描（79,728 条 xref）：

```
=== xrefs to miscDevice is not unlocked @0x139780 ===
  add  @rva 0x000a8afc  func 0xa8a40-0xa8cb0          ← 唯一一处
=== xrefs to misc(partition name) @0x12c3c8 ===
  add  @rva 0x000889b8  func 0x88804-0x8bb68
  add  @rva 0x000a8ac0  func 0xa8a40-0xa8cb0
```

`read_partition_by_name` 辅助函数（RVA `0x6c90`）的调用点只有 6 处：

```
  bl @0x00071cb4  func 0x71b74-0x71cb8
  bl @0x000889d0  func 0x88804-0x8bb68
  bl @0x0009c294  func 0x9c0f0-0x9c2f0
  bl @0x0009c488  func 0x9c2f0-0x9c4e4
  bl @0x0009cd0c  func 0x9cb54-0x9cd80
  bl @0x000a8ad8  func 0xa8a40-0xa8cb0        ← 判锁函数
```

### 0.3 判锁函数的真实数据流（`gbl_fn.py 0xa8a40 0xa8cb0`）

```asm
0x000a8a64  mov  x19, x8                 ; x8 = 结构体返回指针（AAPCS64 sret；本函数返回 0x118 字节的 Result）
0x000a8a84  ldr  x25, [x0, #0xe0]        ; 分区访问接口 (ptr, vtable)
0x000a8a88  add  x0, x0, #0x48
0x000a8a8c  bl   0xb4170                 ; 取输出缓冲区 -> x0=ptr, x1=len
0x000a8a90  cmp  x1, #0x800
0x000a8a94  b.hs 0xa8aa8                 ; len < 0x800 -> 错误 tag 0x1c
0x000a8aa8  mov  w1, wzr
0x000a8aac  mov  w2, #0x800
0x000a8ab0  mov  x21, x0                 ; ★ x21 = 真正的数据缓冲区（堆块）
0x000a8ab4  bl   0x20d5c                 ; memset(x21, 0, 0x800)
0x000a8ab8  ldp  x0, x1, [x25]           ; 接口
0x000a8abc  adrp x2, #0x14012c000
0x000a8ac0  add  x2, x2, #0x3c8          ; "misc"
0x000a8ac4  add  x8, sp, #0x48           ; ★ x8 = sret 输出结构（不是缓冲区！）
0x000a8ac8  mov  w3, #4                  ; strlen("misc")
0x000a8acc  mov  x4, xzr
0x000a8ad0  mov  x5, x21                 ; ★ 数据写进 x21
0x000a8ad4  mov  w6, #0x800
0x000a8ad8  bl   0x6c90                  ; 按名字找/读分区
0x000a8adc  ldr  w8, [sp, #0x48]         ; ★ 读的是 sret 结构第 1 个字段（tag/判别式）
0x000a8ae0  cmp  w8, #0x4b
0x000a8ae4  b.ne 0xa8b38
```

**关键点：`sp+0x48` 是 `bl 0x6c90` / `bl 0x7060` 的结构体返回地址（x8 = sret），
不是 misc 的内容；misc 内容落在 `x21`，而代码从未比较过 `x21[0:4]`。**

辅证：`0x6c90` 自己的序言就是 `mov x19, x8` → 末尾 `stp q0,q1,[x19] / str q2,[x19,#0x20] / str x8,[x19,#0x30]`，
它往 `x19`（= 调用者的 `sp+0x48`）拷贝 **0x38 字节**的结构体，首字段是 tag。
这是 Rust `Result<_, E>`（E 较大、走 sret）的标准布局。

### 0.4 `0x4b` 在同一程序里是「状态/判别式」常量，而不是「分区内容魔数」

在同样引用 `"misc"` 的大函数 `0x88804-0x8bb68`（13 KB）里扫立即数 `0x4b`：

```
  共 48 处 cmp wN, #0x4b
  0x000894e4  mov  x8, #0x4b
  0x000894f0  bfxil x10, x8, #0, #0x20
  0x000894f4  cmp  w10, #0x4b
  0x00089504  adrp x8, #0x140134000 / add x8, x8, #0x3f0   ; "preloaded..."
  0x00089518  csel x8, x9, x8, ne                          ; "preloaded" vs "designated load"
```

即 `0x4b` 在这段代码里是被**写进寄存器再比较**的状态值（紧邻 "preloaded" / "designated load"
这类 slot/load 状态字符串），属于枚举/状态码，而不是从分区读出来的内容。

补充统计（`cmp #0x4b` 之后紧邻的分支类型）：

```
func 0x88804:  b.ne=24  b.eq=7   csel=1   str(被调度)=15      ← 全部是"相等/不等"，没有 b.hi/b.ls
func 0xa8a40:  b.ne=2
```

⇒ `0x4b` 不是 jump-table 的边界值（那样会跟 `b.hi`/`b.ls`），而是**被反复用作相等比较的常量/枚举 tag**。
在 13 KB 的 fastboot 命令处理函数里出现 30+ 次相等比较，最自然的解释是**命令/状态枚举的 arm 分发**，
而不是"分区内容魔数"。

### 0.6 同一模式在另一个函数里比的是别的东西

`0x88804` 里同样的「读 misc → 比 0x4b」：

```asm
0x000889b0  add  x8, sp, #1, lsl #12    ; sret = sp+0x1000
0x000889b8  add  x2, x2, #0x3c8         ; "misc"
0x000889c8  mov  x5, x23                ; 数据缓冲区
0x000889d0  bl   0x6c90
0x000889d4  ldr  w8, [x21, #0x250]      ; ★ 读的是上下文结构体 +0x250 字段
0x000889d8  cmp  w8, #0x4b
0x000889dc  b.eq 0x88a08
```

两处「读 misc 后比 0x4b」比的分别是 `sret.tag` 和 `[ctx+0x250]`，
**没有一处是在比 `misc[0:4]`**。这让「0x4B = misc 内容魔数」的假设进一步变弱。

### 0.5 结论（对自己人的警告）

- 「唯一判锁处」定位是**可靠的**：`"miscDevice is not unlocked"` 全程序只有 1 个 xref，
  落在 `0xa8a40-0xa8cb0`。
- 「判据 = `misc[0:4] == 0x4B`」**没有被证明**，现有反汇编更像是
  `if (sret_tag == 0x4b)`，而 `0x4b` 是程序内部的状态码。
- **风险**：若判据其实是状态码，那么把 `4B 00 00 00` 写进 `misc[0:4]` 不会解锁，
  只会把 BCB 的 `command[32]` 破坏成非法值（可恢复，但白干）。
- 建议在真机上花内核写之前，先用**只读**手段把这个判据钉死，例如：
  ① 从 OTA 里抠 `system_ext`/`boot` 无关——需要的是 GBL 的**符号**
  （`BOOTAA64.EFI` 带 `.note`，可查 build id / 是否能在 GBL 源码 `external/gbl+` 里对上
  `get_unlock_status` 的真实实现）；
  ② 直接读 `misc[0:0x800]` 看当前 command 是不是 `"bootonce-bootloader"` / 空，
     再对照 `0x4b` 的语义（需要任意一次读 block device 的能力）；
  ③ 让 GBL 自己说话：`fastboot oem get_unlock_status` 之类（需进 bootloader，本轮禁止 reboot）。

---

## 1. misc 及其「兄弟分区」的 SELinux 标签与可写性（任务点 1）

### 1.1 `ls -lZ /dev/block/by-name/` 全量（节选与本任务相关的全部条目）

命令：`adb shell "ls -lZ /dev/block/by-name/"`（`/proc/partitions` 被拒，by-name 可列）

| 分区 | 设备节点 | SELinux 标签 |
|---|---|---|
| **misc** | `/dev/block/sdc79` | **`misc_block_device`** |
| backup1..5 | sdc95..sdc99 | `block_device`（泛型！） |
| boot_reserve_a / _b | sda6 / sdb6 | `block_device` |
| mipatch | sdc102 | `block_device` |
| mem | sdc84 | `block_device` |
| metadata | sdc82 | `block_device` |
| pfg | sdc87 | `block_device` |
| secinfo | sdc93 | `block_device` |
| countrycode | sdc88 | `block_device` |
| charger | sdc90 | `block_device` |
| exaid_a / exaid_b | sdc39 / sdc78 | `recovery_block_device` |
| ffu | sdc83 | `ffu_partition` |
| rescue | sdc80 | `rescue_block_device` |
| blackbox | sdc86 | **`blackbox_block_device`** |
| logfs | sdc100 | `logfs_block_device` |
| oops | sdc101 | `oops_block_device` |
| dfx | sdc81 | `dfx_block_device` |
| ebuff | sdc85 | `block_device` |
| opconfig | sdc89 | `miupdate_block_device` |
| userdata | sdc103 | `userdata_block_device` |
| super | sdc94 | `super_block_device` |
| android_esp_a/b | sdc38 / sdc77 | `android_esp_block_device` |
| uefi_a/b | sdc3 / sdc42 | `uefi_block_device` |
| vbmeta* | sdc25..sdc27, sdc64..sdc66 | `vbmeta_block_device` |
| boot_a/b, vendor_boot_a/b | sdc22/61, sdc24/63 | `boot_block_device` |
| init_boot_a/b | sdc23 / sdc62 | `init_boot_block_device` |

### 1.2 全策略里能写 `misc_block_device` 的域（穷举，`plat_sepolicy.cil`）

```
(allow hal_bootctl_default    misc_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))   ← vendor_sepolicy.cil:3418
(allow init                   misc_block_device (blk_file (write lock append map open)))
(allow kcmdlinectrl           misc_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
(allow misctrl                misc_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
(allow mtectrl                misc_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
(allow uncrypt                misc_block_device (blk_file (write lock append map open)))
(allow update_engine_common   misc_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
(allow vendor_init            misc_block_device (blk_file (write lock append map open)))
(allow vendor_misc_writer     misc_block_device (blk_file (write lock append map open)))   ← 二进制不存在
(allow vold                   misc_block_device (blk_file (write lock append map open)))
(neverallow base_typeattr_493 misc_block_device (blk_file (ioctl read write lock relabelfrom append link rename open)))  ← shell / app 类被禁死
```

**`shell` 与 `hypsys_ssi_default` 都不在其中，且 `neverallow` 挡住了任意"给它加权限"的做法：**

```
(typeattributeset base_typeattr_493
  (and (domain )
       (not (hal_bootctl_server hal_fastboot_server fastbootd init recovery ueventd uncrypt
             update_engine vendor_init vendor_misc_writer vold kcmdlinectrl misctrl mtectrl ))))
(neverallow base_typeattr_493 misc_block_device (blk_file (ioctl read write lock relabelfrom append link rename open)))
```

即：**除上表列出的 12 个域之外，任何域都永远不许 open/write `misc_block_device`** ——
`shell`、`hypsys_ssi_default`、`system_server`、所有 app 域都被这条 neverallow 钉死，
连"改策略放开"这条路都不成立（neverallow 在编译期就拒绝）。

### 1.3 `hypsys_ssi_default`（= `miui.mqsas.IMQSNative` 的宿主域，uid 0）的**全部**规则

`research/hypsys_rules.txt`（266 条，`analyze_sepolicy` 直接 grep `^\(allow hypsys_ssi_...`）。

**唯一可写的块设备只有 `blackbox`：**

```
(allow hypsys_ssi_default blackbox_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
(allow hypsys_ssi_default userdata_block_device (blk_file (ioctl read getattr open)))       ← 只读
(allow hypsys_ssi_default dm_device             (blk_file (ioctl read getattr open)))       ← 只读 + ioctl
(allow hypsys_ssi_default block_device          (dir (search)))                             ← 只能 ls
```

**对 `misc_block_device` 一条规则都没有 ⇒ code 7 写 misc 必被拒（与交接文档实测一致）。**

它可写的文件类型（全部）：`data_log_file`、`bsp_data_log_file`、`mqsas_data_file`、`anr_data_file`、
`offlinedb_data_file`、`data_log_camera_file`、`data_log_misight_file`、`miui_coredump_file`、
`miui_native_file`、`data_log_stability_file`、`bootlog_data_file`、`ota_exception_data_file`、
`offlinelog_file`、`cache_file`、`cache_recovery_file`、`fuse`、`vfat`、`sdcardfs`、`media_rw_data_file`、
`system_optimize_data_file`、`update_engine_log_data_file`，以及对 `system_server`/`priv_app`/
`platform_app`/`untrusted_app`/`system_app` 类型的 `file (write)`。

### 1.4 分区用途与「能不能帮上忙」

| 分区 | 用途判断 | 对解锁有无用 |
|---|---|---|
| `backup1..5`（泛型 `block_device`） | Xiaomi 分区备份/恢复用 | 无：无人读它判断锁；shell/hypsys 对它只有 `dir search` |
| `boot_reserve_a/b`（泛型） | 预留 boot 空间 | 无 |
| `exaid_a/b`（`recovery_block_device`） | MIUI 的 OTA/exaid 恢复分区 | 无：GBL 不读 |
| `ffu`（`ffu_partition`） | FFU 整包刷机用 | 无：GBL 只在 fastboot 模式写它（且 locked 下拒绝） |
| `rescue`（`rescue_block_device`） | **`/mnt/rescue` 以 ext4 rw 挂载**（实测 `/proc/mounts`） | 无：挂载点在 shell 下 `Permission denied`，实测 `touch /mnt/rescue/shell_probe` → 拒绝 |
| `blackbox` | 崩溃黑匣子 | 无：hypsys 可写，但 GBL 不读 |
| `mipatch`/`mem`/`metadata`/`pfg`/`secinfo`/`countrycode`/`charger` | 杂项（泛型 `block_device`） | 无 |

---

## 2. `miui.mqsas.IMQSNative` 完整接口地图（任务点 2，实测）

服务：`service list` → slot `274 miui.mqsas.IMQSNative: [miui.mqsas.IMQSNative]`
SELinux：`system_ext_service_contexts:14  miui.mqsas.IMQSNative u:object_r:mqsasd_service:s0`
宿主：`ps -A -Z` → `u:r:hypsys_ssi_default:s0 root 1369 1 ... hypsys_system`（`/system_ext/bin/hypsys_system`）

### 2.1 探测方法（可重复）

```bash
# 客户端（宽限）：
adb shell "CLASSPATH=/data/local/tmp/caplog.jar app_process64 /system/bin CapLog miui.mqsas.IMQSNative <code> [args...]"
# 更强：service call 会打印完整 reply parcel（含 Java 异常文本）
adb shell "service call miui.mqsas.IMQSNative <code> [s16 <str>]..."
```

**`service call` 是 Java/AIDL 服务的强证据**：参数不匹配时回包是
`fffffffe <len> "Parcel data not fully consumed, unread size: 8"` —— 这是
`android.os.Parcel.enforceNoDataAvail()` 的原文，说明服务端是 Java AIDL stub。

### 2.2 Code 表（本轮实测，`transact=true` = 该 code 存在）

| code | 实测结果 | 判读 |
|---|---|---|
| 0 | `transact=false` | 不存在 |
| 1 | 已知 captureLog（交接文档） | 日志抓取，参数 9 个 |
| 2 | 已知返回 PFD（交接文档） | socket 抓包 |
| 3 | **调用者被 SIGKILL（"Killed"）** | 存在且危险 |
| 4 | 已知 action/params/timeout | 有返回 int |
| 5 | `transact=true` 3×int，全 0 | 存在，无文件副作用 |
| 6 | `transact=true` 1×String → 2×int；**在指定路径创建 0 字节 `root:system 0600` 文件** | **= 建/截断文件（root）** |
| 7 | 已知：root 任意文件写（path,data） | 受 SELinux 目标标签限制 |
| 8 | 已知：root 任意文件读（path）→ String | 同上 |
| 9 | `transact=true` 3×int | 存在 |
| 10 | `transact=true` 1×int | 存在 |
| 11 | `transact=true` 1×int | 存在 |
| 12 | **调用者被 SIGKILL** | 存在且危险 |
| 13 | `transact=true`，带 1 个 String 时回 `fffffffc`（异常，无消息） | 存在 |
| 14 | **调用者被 SIGKILL** | 存在且危险 |
| 15 | `transact=true` 1×int | 存在 |
| 16 | **调用者被 SIGKILL** | 存在且危险 |
| 99 | `transact=false` | 不存在（用作否定对照） |

code 6 的证据：

```
$ adb shell service call miui.mqsas.IMQSNative 6 s16 /data/anr/zz
Result: Parcel( 00000000 00000000   '........')
$ adb shell ls -lZ /data/anr/
-rw------- 1 root   system u:object_r:anr_data_file:s0        0 2026-10-22 09:25 zz
-rw------- 1 root   system u:object_r:anr_data_file:s0        0 2026-10-22 09:25 probe_6
```

### 2.3 有没有「执行命令 / 拷文件 / 写块设备」的方法？

- **没有找到命令执行**：对 5/6/9/10/11/13/15 逐个灌 shell payload
  （`s16 "touch /data/anr/probe3_<code>"`）→ **`/data/anr` 下没有出现任何 `probe3_*`**。
- **没有找到第二个「写任意文件」**（code 6 是建/截断空文件，写内容仍是 code 7）。
- **没找到写块设备的方法**；即便有，域规则（§1.3）里 misc 不可写。
- code 6/7/8 全部落在 `hypsys_ssi_default` 的同一张 allow 表里，**无法突破 §1.3 的标签限制**。

### 2.4 意外发现：某个 code 会真的重启设备

见 §8。这也是「这个接口不只是文件读写，还有特权系统动作」的间接证据。
**不要盲扫 code**：3/12/14/16 会杀掉调用者，5/6/9/10/11/13/15 里至少一个会 reboot。

---

## 3. 其它 uid 0 的 binder 服务（任务点 3）

`service list` 共 **544** 个服务（`research/svclist.txt`）。逐个按名字筛
`write/exec/copy/flash/misc/block/ota/update/power/reboot` 的结果里，只有这几条与本任务相关：

```
53   android.hardware.boot.IBootControl/default : []          ← ★ 交接文档说「does not exist」，但它在
128  android.system.vold.IVold/default : []
321  persistent_data_block : [android.service.persistentdata.IPersistentDataBlockService]
326  power : [android.os.IPowerManager]
335  reboot_readiness : [...]
383  system_update : [...]
405  updatelock : [...]
521  vold : []
```

### 3.1 可达性判定（策略推演）

```
# shell 能 find 的服务集合
(allow shell base_typeattr_1030 (service_manager (find)))
base_typeattr_1030 = and(service_manager_type,
    not(apex_service default_android_service dnsresolver_service gatekeeper_service
        incident_service installd_service mdns_service netd_service
        system_suspend_control_internal_service system_suspend_control_service
        virtualization_service virtual_touchpad_service **vold_service**
        hal_frp_service hal_keymint_service hal_secretkeeper_service
        hal_secureclock_service hal_sharedsecret_service virtualization_maintenance_service))
```

- **`vold_service` 在排除名单里** ⇒ shell 连 `find` 都不允许 ⇒ vold 这条路彻底关门
  （解释了交接文档「binder 接口有权限检查」）。
- **`hal_bootctl_service` 不在排除名单里** ⇒ `shell` 理论上能 `find`
  `android.hardware.boot.IBootControl/default`。**交接文档里「→ does not exist」的结论可疑**
  （可能是服务名写错，`service call ...IBootControl/default` 的省略号）。
  但**即便可达也不改变结论**：IBootControl 的 AIDL 面只有
  `getBootSlot / markBootSuccessful / setActiveBootSlot / setSlotAsUnbootable / getBootFlashLocked`，
  它写的是 `bootloader_message_ab`（BCB + **misc+2048** 的 `slot_suffix`），
  **永远写不到 misc+0**；而且 `setActiveBootSlot` 会先 `ReadBootloaderMessage` 再回写，
  `command[]` 原样保留。
  **为避免误改 slot_suffix 导致不可启动，本轮没有对它做实测调用。**
- `update_engine` / `persistent_data_block` / `power`：无写 misc+0 的能力
  （update_engine 需 payload 签名；persistent_data_block 需要 `MANAGE_DEVICE_LOCK_STATE` 签名权限，
  且写的是 frp/persistent 分区而不是锁判据；power 只能 reboot）。

### 3.2 一个「潜伏」的原语：`/dev/device-mapper` 是 `dm_device`

```
$ adb shell ls -lZ /dev/device-mapper
crw------- 1 root root u:object_r:dm_device:s0  10, 236  /dev/device-mapper

(allow hypsys_ssi_default dm_device (blk_file (ioctl read getattr open)))
```

`hypsys_system` 是 uid 0，DAC 上 `crw------- root root` 放行；SELinux 上它有 `dm_device` 的 **ioctl**。
也就是说**只要能在 `hypsys_ssi_default` 域里执行代码**（目前 code 表里没有 exec），
就可以 `DM_DEV_CREATE` + `DM_TABLE_LOAD` 做一条 `dm-linear` 映射盖住 `misc` 的
major:minor（dm 内核对底层设备的打开**不再过 SELinux**）。
但它**不能**成为解锁路径：新建的 `/dev/block/dm-N` 同样标 `dm_device`，而
`hypsys_ssi_default` 对 `dm_device` **没有 `write`**（只有 ioctl/read/getattr/open）。
要落地还得再找一个「能写 dm-N」的域（`vold`/`init`/`uncrypt` 都行，但都不可达）。

---

## 4. fastboot / fastbootd 的 `oem` 命令族（任务点 4）——本轮**无法实测**

设备当前在 Android 里（`adb` 在线），要进 bootloader/fastbootd 必须 `adb reboot bootloader`，
**本轮硬约束禁止 reboot**（而且 §8 已经意外重启过一次）。因此：

- 现有证据仍是交接文档第四节：`unlocked: no`、`oem` → `fb lock: true`、
  `fetch` → `Command not allowed`、fastbootd `flash/erase/download` → `not allowed on locked devices`、
  `oem` → `EX_UNSUPPORTED_OPERATION`、`reboot/continue` → `Command not found`。
- 客户端脚本 `fb3.py`（bootloader）/ `fbd.py`（fastbootd）已就绪，**下次带 reboot 授权时**建议按这个顺序补测：
  1. `fbd.py oem`（空参数）→ 看是否回显子命令列表（很多实现会 dump usage）；
  2. `oem help` / `oem ?` / `oem list`；
  3. 小米常见私有子命令：`oem lock`、`oem unlock`、`oem unlock-go`、`oem device-info`、
     `oem getvar`、`oem read`、`oem write`、`oem edl`、`oem reboot-edl`、`oem fus`、`oem fus-unlock`；
  4. **重点**：`fbd.py oem fus` / `oem fus-unlock`（小米 "FUS" = 工厂解锁流程，历史上有过绕过）；
  5. `fastboot getvar all` 已存 `research/fastboot_getvar_all.txt`（23,808 B），可先离线把
     `unlocked`/`secure`/`partition-type:*` 全过一遍，看有没有 `oem-*` 变量。

**结论：这一面既没被证伪也没被穷尽，属于「本轮不可测」而不是「已排除」。**

---

## 5. Xiaomi 特有机制（任务点 5）

### 5.1 `uncrypt` 有 4 个 root 服务变体（`/system/etc/init/uncrypt.rc` 实测）

```
service uncrypt          /system/bin/uncrypt                    class main  socket uncrypt  disabled oneshot user root
service cust_data_keeper /system/bin/uncrypt --cust-data-keeper  class main                  disabled oneshot user root   ← MIUI 私有
service setup-bcb        /system/bin/uncrypt --setup-bcb         class main  socket uncrypt  disabled oneshot user root
service clear-bcb        /system/bin/uncrypt --clear-bcb         class main  socket uncrypt  disabled oneshot user root
```

- `uncrypt` 是 `misc_block_device` 的写者之一（`(allow uncrypt misc_block_device (blk_file (write...)))`），
  且带 `sys_rawio`。
- 但它是 `disabled` + `oneshot`，**只能被 `init` 启动**（`ctl.start=...`）。而
  `shell` **没有** `ctl_start_prop` 的写权限（见 §5.3），所以 shell 拉不起来。
- `hypsys_ssi_default` 反而**有** `ctl_start_prop` + `ctl_stop_prop` + `sys.powerctl` 的写权限，
  但没有任何"设属性"的 code，只能干看。
- 即使拉起来，`--setup-bcb`/`--clear-bcb` 写的是**固定内容**（`boot-recovery` / 清空），
  不可能是 `4B 00 00 00`。

### 5.2 三个 misc 写者的触发条件（实测 rc）

```
# /system/etc/init/kcmdlinectrl.rc
on property:kcmdline.binder=*                 ← ★ shell 有 kcmdline_prop 写权限
  wait_for_prop kcmdline.loaded 1
  exec -- /system/bin/kcmdlinectrl store binder ${kcmdline.binder:-c}
# 只写 misc 的 kcmdline 消息区（misc+32896），碰不到 offset 0

# /system/etc/init/mtectrl.rc
on property:arm64.memtag.bootctl=*            ← ★ shell 有 arm64_memtag_prop 写权限
  trigger mtectrl_update
on mtectrl_update && property:ro.arm64.memtag.bootctl_supported=1
  exec -- /system/bin/mtectrl ${arm64.memtag.bootctl:-none} ... 
# 只写 misc+32832（memtag message）

# /system/etc/init/misctrl.rc
service misctrl /system/bin/misctrl
    user root # for misc partition access
    class core
    oneshot
# 开机由 init 直接拉起，无属性触发口
```

**这三个都只能写 misc 的「system space」（offset ≥ 32768），物理上够不到 offset 0。**

### 5.3 `shell` 能设的属性全集（穷举，决定「能不能拉服务 / 能不能改启动参数」）

```
adb_debug / adb_timeout / arm64_memtag / bionic_linker_16kb_app_compat / casefolding_override /
ctl_bugreport / ctl_dumpstate / ctl_gsid / ctl_prefetch / ctl_snapuserd / debug / dumpstate_last_id /
dumpstate / dynamic_system / exported_dumpstate / gwp_asan / heapprofd_enabled / hsum_boot_strategy /
kcmdline / log_tag / logd_auditrate / lpdumpd / mock_ota / pcc_audit_mode(_client) / perf_drop_caches /
perfobserve / permissive_mte / pm_16kb_app_compat / power_debug / powerctl / remote_prov /
rollback_test / shell / sqlite_log / traced_enabled / traced_perf_enabled /
userspace_reboot_test / vendor_turbosched / wifi_log
```

**没有 `ctl.start` / `ctl.stop` / `ctl.restart`** ⇒ shell 无法启动任何 `disabled` 的 root 服务。
`sys.powerctl` 只能 reboot（不能写 misc 内容）。

### 5.4 MiAssistant / MiFlash 认证通道

- 外部接口只有 USB adb（`/dev/` 下无 `miusb`/`miassistant` 类节点；`ls -l /dev | grep -i -e dm- -e mapper -e misc -e block -e loop` 只出
  `block/`、`device-mapper`、`dio_dma_mapper_misc`、`dm-user/`、`loop-control`）。
- `/mnt/rescue`（rescue 分区，ext4 rw）是 MiAssistant 侧的落点，但 shell 完全不可达
  （`ls: /mnt/rescue: Permission denied`，`touch /mnt/rescue/shell_probe` → `Permission denied`）。
- 结论：**在本机上没有可用的、绕过 adb 的认证通道。**

---

## 6. GBL 里的「其它判锁入口」（任务点 6）

除了 §0 的判锁函数，本轮把 GBL 的 misc 访问面收敛成了：

- 引用 `"misc"` 字符串的函数：**2 个**（`0xa8a40` 判锁、`0x88804` 13KB 的 BCB/分区读写栈）。
- 调用 `read_partition_by_name(0x6c90)` 的地方：**6 处**（见 §0.2）。
- `"miscDevice is not unlocked"` 的 xref：**1 处**。
- 另外两个相关字符串存在但本轮未展开：`"Failed to read bootloader message from misc: "`、
  `"Boot mode from BCB: "`，以及 fastboot 变量表里成对出现的 `"unlocked"` / `"unlocked-critical"`
  （`0x127bb4` 附近，与 `partition-type`、`partition-guid`、`block-device`、`gbl-default-block` 同表）
  和 AVB 日志 `"AVB verification passed. Device is unlocked: "` /
  `"AVB verification failed with . Device is unlocked: ... Continue current boot attempt."`。

**判断**：
- 没有发现「第二套独立的判锁数据源」（efuse / RPMB / UEFI variable）——GBL 里与锁相关的
  输入只有 misc 一处读取 + `androidboot.*` 这类 kernel cmdline（后者由 bootloader 自己产生，
  userspace 改不了）。
- `android_esp` 分支：ESP 里放的是 `BOOTAA64.EFI` 本身，而它是**明文签名 PE**（三级证书链，
  只有小米私钥能签，见 `REPORT.md`）。虽然 `(allow ... android_esp_block_device ...)` 存在，
  但**改 ESP 需要 block 写权限 + 签名私钥**，两条都没有。
- **仍未证伪的**：`0x4b` 的真实语义（§0）。这是唯一一处「可能推翻整个判锁模型」的空白。

---

## 7. 结论：还存在不依赖内核 root 的解锁路径吗？

### 7.1 逐条排除表（本轮新增/加强的证据）

| # | 路径 | 结论 | 证据 |
|---|---|---|---|
| 1 | code 7 (hypsys root 任意写) → misc | **不可行（策略级死）** | `hypsys_ssi_default` 的 266 条规则里**没有** `misc_block_device`；只有 `blackbox_block_device` 可写 |
| 2 | code 6（新建/截断文件） | 不增加能力 | 实测只能建 0 字节文件，写内容还是 code 7 |
| 3 | mqsas 其它 code（exec / copy / block） | **未发现** | 5/6/9/10/11/13/15 灌 shell payload 无任何文件产出；3/12/14/16 会杀调用者 |
| 4 | 其它 uid 0 服务 | 无写 misc+0 的面 | IBootControl 只写 misc+2048；vold 被 `base_typeattr_1030` 排除；update_engine 需签名 |
| 5 | `/dev/device-mapper` dm-linear 覆盖 misc | **原语存在但缺最后一步** | 域有 `dm_device ioctl`，但**没有 `dm_device write`**；需要域内代码执行 |
| 6 | `ctl.start` 拉起 uncrypt/setup-bcb | **不可行** | shell 无 `ctl_start_prop`；且写的内容固定 |
| 7 | kcmdlinectrl / mtectrl / misctrl | **物理够不到** | rc 实测：只写 misc+32896 / +32832；`misctrl` 无属性触发口 |
| 8 | backup1..5 / boot_reserve / exaid / ffu / rescue / blackbox | **无判锁语义** | 标签与用途逐条核对（§1.1/§1.4）；rescue 挂载点 shell 不可写 |
| 9 | fastboot `oem` 族 | **本轮不可测（未排除）** | 需 reboot 进 bootloader，硬约束禁止 |
| 10 | GBL 第二判据 / ESP 分支 | **未发现**；ESP 需签名私钥 | §6 |

### 7.2 明确回答

> **在本轮可测的范围内，不存在「不依赖内核 root 就能改锁状态」的路径。**
> 所有 userspace 可达的 root 写原语，其 SELinux 目标标签集合里都不含 `misc_block_device`，
> 而 `neverallow base_typeattr_493 misc_block_device` 把「靠策略改动放开」这条路也堵死了。

**最有希望的那一条，以及它缺什么：**

1. **（最强）内核写原语 → `misc[0:4]`** —— 这是唯一逻辑闭合的路径，但它缺**两样**东西：
   - 前提 A：CVE-2026-64560 的整页 reclaim（当前唯一阻塞点，见 `STATUS_2026-10-22.md`）；
   - 前提 B：**确认 `0x4b` 的语义**（§0）。如果判据不是 `misc[0:4]==0x4B`，
     这一步做完也不会解锁，必须先把这个判据钉死。
2. **（次强）hypsys 域内的代码执行** —— 如果将来在 code 表里找到 exec 类方法，
   可以：`DM_TABLE_LOAD` 建一条盖住 misc 的 dm-linear，再想办法让一个「有 `dm_device write` 的域」
   去写它（`vold`/`init`/`uncrypt` 都有 write，但都不可达），**仍然差最后一步**。
   或者更直接：域内有 `ctl_start_prop`，可以 `setprop ctl.start setup-bcb` —— 但写的内容固定。
3. **（唯一没被穷尽的）fastboot `oem` 族** —— 缺的只是**一次带 reboot 授权的窗口**。

---

## 8. 事故记录：09:27 设备重启（必须写进交接）

```
$ adb shell cat /proc/uptime
8.73 59.09                      ← 刚起
$ adb shell getprop sys.boot.reason
reboot,shell
$ adb shell getprop ro.boot.bootreason
AP_S_COLDBOOT,NA                ← 硬件冷启动，不是 kernel panic
```

**时间线**：

```
09:23  CapLog 扫 code 0/3/5/6/9/10/11/12/13/14/15/16 → 3/12/14/16 返回 "Killed"
09:24  CapLog 扫 0/5/6/9/10/11/13/15（带 path+data）→ 无副作用
09:25  service call 扫 6/9/10/11/13/15（s16 单参）→ 全部正常回包
09:26  service call 扫 5/6/9/10/11/13/15（每个 3 次，含 shell payload）→ 正常回包，无文件产出
09:27  adb: no devices/emulators found → 设备在重启；uptime 归零
```

**结论**：`sys.boot.reason=reboot,shell` 是**主动 reboot 请求**（不是崩溃）。
高度怀疑是 `IMQSNative` 里某个 code（首要嫌疑 13 / 15，其次 5/6/9/10/11）
执行了 root 侧重启。**已停止该方向的任何重试。**

**影响**：
- KASLR slide 变了。`KASLR_SOLVED.md` 里的 `0x2971200000` 已失效，
  下一次内核写之前必须重跑 `research/cap_pair.sh` + `research/solve_live.py`。
- 未写任何分区、未 flash；`misc` 内容未被我改动。

---

## 9. 本轮新产物

| 文件 | 用途 |
|---|---|
| `gbl_judge.py` | PE 段表 + `.pdata`（ARM64 8 字节记录）函数边界 + 指定函数反汇编 |
| `gbl_xref.py` | 全 `.text` 线性扫描，ADRP/ADD/LDR/STR/BL xref，按函数归并 |
| `gbl_fn.py` | 反汇编单个 GBL 函数，自动把立即数标注成 `.rdata` 字符串 |
| `research/hypsys_rules.txt` | `hypsys_ssi_default` / `_server` / `_client` 的全部 266 条 allow |
| `research/svclist.txt` | 设备全量 `service list`（544 条） |
| 本文 | 不依赖内核 root 的解锁路径穷尽结论 |

---

# 10. ★★ 追加（第二轮）：GBL 真正的判锁逻辑已逆出 —— 判据**不在任何分区里**

> 2026-10-22 09:40–10:05，纯静态，未动机器。

## 10.1 结论先写

```
GBL 的锁状态 = GblAvbProtocol::read_device_status() 的返回值
                （一个 EFI protocol 调用，实现方在 BOOTAA64.EFI 之外）
```

**不是 misc 内容、不是 efuse、不是 RPMB、不是签名派生。**
GBL 只是这个状态的**消费者**：它把状态反射成 `androidboot.vbmeta.device_state`（cmdline）
和 `host.vbmeta.device_state`（device tree），自己从不决定它。

⇒ **任何对 `misc` / `backup*` / `exaid` / `ffu` / `rescue` 的写入都不可能改变锁状态。**
「写 `4B 00 00 00` 到 misc[0:4] 解锁」这条路被**独立地第二次证伪**（第一次是 §0 的判据反汇编）。

## 10.2 完整数据流（每一跳都实测）

### (1) 入口：`0xa8cb0`（wrapper，返回 2 = unlocked）

```asm
0x000a8ce8  ldr  x0, [x0, #0xe0]      ; 平台接口对象
0x000a8cec  bl   0x84650              ; ★ 取 device status（sret = sp+0xc0）
0x000a8cf0  ldr  x8, [x20, #0x40]     ; tag
0x000a8cf4  cmp  x8, #8               ; 变体 8 = "拿到 status"
0x000a8cf8  b.ne 0xa8d10
0x000a8cfc  ldrb w8, [sp, #0xc8]      ; status 的 flags 字节
0x000a8d00  tbz  w8, #0, 0xa8d2c      ; ★ bit0 == 0 → 错误
0x000a8d04  mov  w8, #2
0x000a8d08  str  x8, [x19]            ; 返回 2（unlocked）
...
0x000a8d30  adrp x8, #0x140139000
0x000a8d34  add  x8, x8, #0x784       ; "Device is not unlocked"（+0x784 起，len 0x16）
```

> 注意：`"miscDevice is not unlocked"` 其实是字符串池把 **`"misc"` + `"Device is not unlocked"`**
> 拼在一起造成的假象。真正的错误串是 **`"Device is not unlocked"`**（22 字节，`mov w9,#0x16`）。
> 交接文档把它当成一条完整的锁错误信息，属于被字符串池误导。

### (2) `0x84650`：把 protocol 返回的 status 位重排成 flags

```asm
0x00084674  ldr  x0, [x0, #0x20]
0x00084678  bl   0xb368                ; 取 protocol 接口
0x00084684  bl   0xb8c8
0x00084694  bl   0x7b1b8               ; 真正发 protocol 请求
0x00084698  ldr  w8, [sp, #8]
0x0008469c  cmp  w8, #0x4b             ; Ok?
0x000846c0  ldur w8, [x29, #-0x48]     ; 内层 tag
0x000846c8  cmp  w8, #0x4b             ; Ok?
0x000846d0  lsr  w8, w9, #1
0x000846d4  and  w10, w9, #1           ; ★ bit0 = unlocked
0x000846d8  lsr  w11, w9, #3
0x000846dc  bfi  w10, w8, #0x10, #1    ; 重排 bit0..3 → 0x0000/0x0100/0x10000/0x1000000
0x000846e0  lsr  w8, w9, #2
0x000846e4  bfi  w10, w11, #0x18, #1
0x000846e8  bfi  w10, w8, #8, #1
0x000846ec  mov  w8, #8
0x000846f0  str  x8, [x19]             ; tag = 8
0x000846f4  str  w10, [x19, #8]        ; flags
```

### (3) `0xf0d4`：**这里暴露了真正的数据源**

```asm
0x0000f0fc  ldr  x0, [x0]              ; 接口对象
0x0000f104  ldr  x8, [x0, #0x10]       ; ★ protocol 函数指针
0x0000f10c  add  x1, sp, #8
0x0000f110  blr  x8                    ; ★★ 间接调用：读 device status
0x0000f118  bl   0x18214
0x0000f130  cmp  w8, #0x4b             ; Ok?
```

`blr x8` 失败（`[x0+0x10]` 为空）时的 panic 串直接把调用点写了出来：

```
0x0000f184  add x0, x0, #0x299   ; "self.interface().read_device_status"
0x0000f190  add x8, x8, #0x20b   ; "efi::protocol::gbl_efi_avb::<impl efi::protocol::Protocol<
                                      efi::protocol::gbl_efi_avb::GblAvbProtocol>>::read_device_status::
                                      {{closure}}::thunk"
```

（字符串原文，`pe.read(0x11f200,180)`：
`efi::protocol::gbl_efi_avb::<impl efi::protocol::Protocol<efi::protocol::gbl_efi_avb::GblAvbProtocol>>::read_device_status::{{closure}}::thunk`
`self.interface().read_device_status`）

### (4) 下游消费者

| 消费者 | RVA | 输出 |
|---|---|---|
| dt fixup | `0x69b18` | `ldrb w25,[x21,#9]`（status 结构 +9 = unlock bool）→ `host.vbmeta.device_state` = `unlocked`/`locked`；`ldrb w8,[x21,#8]` → `host.verifiedbootstate`（green/orange 表 @0x12d154/0x12d164）|
| cmdline builder | `0xca1a8` | `ldrb w8,[sp,#0xa0]` → `csel x2,"unlocked","locked",ne` → `androidboot.vbmeta.device_state=` |
| fastboot getvar | `0x35e28` / `0x3b100` / `0x58ee4` | 变量名表 `0x128af0` 含 `unlocked`(+0xc4) / `unlocked-critical`(+0xcc)，答案取自 ctx+0x60 |

## 10.3 为什么可以断定「不是 efuse / RPMB / 分区内容」

| 检验 | 结果 |
|---|---|
| 全 `.text` 扫 `smc` / `hvc` | **0 条**（只有 `brk` 用作 panic）。⇒ GBL 不直接问安全世界要 efuse/RPMB |
| 扫字符串 `flash.locked` | **不存在**。⇒ `ro.boot.flash.locked=1` 不是 GBL 产生的 |
| 扫字符串 `rpmb` / `efuse` / `otp` | 无 rpmb/efuse/otp 相关；只有 libavb 的 rollback-index 文案（rollback 走 `avb_ops` 回调，不是锁状态） |
| 锁状态取值路径 | 唯一路径是 `blr [iface+0x10]`（protocol），返回一个 status 字，bit0 = unlocked |
| 签名相关 | 同一个 protocol 还提供 `validate_vbmeta_public_key`（字符串 `0x11f200` 附近），**与 read_device_status 是两个不同方法** ⇒ 锁状态不从签名派生 |

## 10.4 `0x4b` 的语义已确定 = `Ok` 判别式（不是魔数）

`0x4b` 出现在 30+ 处「调用返回后立即 `cmp wN,#0x4b`」，且错误路径用 `0x1c/0x36/0x3b/0x13/0x3d`
等其它 tag。例如 dt fixup 里每个 `bl`（`0x7e30c`/`b138c`/`b265c`）后面都跟一次 `cmp #0x4b`。
⇒ **`cmp w8,#0x4b` 一律是「这次调用成功了吗」，与 misc 内容无关**。
交接文档里的「`misc[0:4] == 0x4B` ⇒ unlocked」是由此误读而来。

## 10.5 那 `misc` 在 GBL 里到底干什么用

只有两处，**都与锁状态无关**：

1. `0xa8a40`：读 BCB → 用 `0xc5270` 把枚举翻译成 BCB 命令串写进缓冲区 →
   再写回 misc。`0xc5270` 的命令表实测：

   ```
   w1==1 -> "bootonce-bootloader"(len 0x13)   w1==2 -> "boot-recovery"(0xd)
   w1==3 -> "boot-fastboot"(0xd)              else  -> "boot-rescue"(0xb)
   ```
   ⇒ 这是 **set boot command / BCB 写入**，不是判锁。
2. `0x88804`：13 KB 的 fastboot 分区读写/分区表栈（`partition-type`/`partition-guid`/`block-device`）。

## 10.6 提供方在哪个镜像里？——不在我们手上任何一个

`gbl_efi_avb` / `read_device_status` / `GblAvbProtocol` 字符串出现次数：

```
android_esp.img       read_device_status=2  gbl_efi_avb=19  GblAvbProtocol=10  gbl_efi_fastboot=27
BOOTAA64.EFI          read_device_status=2  gbl_efi_avb=19  GblAvbProtocol=10  gbl_efi_fastboot=27   ← 同一份
uefi.img / bl2 / bl31 / xloader / tee / xrse / xsps / xspm / pvmfw / sap* / adsp / modem / ...  全部 0
```

`fat_walk.py rom/fw/android_esp.img` 证明 ESP 里**只有一个文件**：

```
[DIR] EFI/BOOT/BOOTAA64.EFI   1585152 bytes
```

⇒ `gbl_efi_avb` 的**服务端实现**不在 ESP 里，也不在任何明文镜像里。
它只能在 `uefi.img`/`uefi_a|b` 那个**高熵（压缩/加密）UEFI 固件卷**里，
或者在安全世界组件（tee/xrse）里。

## 10.7 由此得出的新攻击面（排序）

1. **逆 `uefi.img`**：2.1 MB，HANDOVER 判定为「明文签名头 + 高熵体」。
   需要先解决解压/解密（XRing 的 UEFI FV 压缩算法未知）。
   一旦拿到，就能定位安装 `gbl_efi_avb` GUID 的 DXE driver —— **那才是锁状态的真主人**。
2. **`pvmfw.img`（1 MB，明文可读）**：pVM firmware，AVB 链的一环，值得单独看。
3. **fastboot `oem` 族**（仍需一次 reboot 窗口）：如果存在
   `oem unlock`/`oem fus` 之类入口，它走的是 protocol 的另一条方法（不是 read_device_status），
   可能根本没被 locked 检查覆盖。
4. **`misc`/分区写入**：**正式作废**（§10.1）。

## 10.8 对上一轮「事故记录」的更正

09:27 那次重启的 `sys.boot.reason = reboot,shell`，与父会话自述的
「写完 misc 后我重启验证」在时间上完全吻合 ⇒ **大概率是父会话自己的 `adb reboot`，不是 mqsas code 触发的**。
本轮不再改动该结论的严重性判断，但把「mqsas 某 code 会 reboot」降级为**未证实**。

## 10.9 新工具

| 文件 | 用途 |
|---|---|
| `gbl_unlock_logic.py` | 按正则列 `.rdata` 字符串 + 直接 xref + 所在函数 |
| `gbl_str_xref.py` | **解析指向字符串 blob 内部偏移的 xref**（`"misc"` 这类合并串必需） |

## 10.10 你要的「hypsys 能否写 misc」实验事实：本轮**没做成**，但方法已备好

设备在 10:05 前后 adb 掉线（`no devices`，连续 30 s 未恢复，疑似父会话正在跑内核侧操作），
所以实测没跑。**注意：这个实验已经不改变任何结论**——§10.1 已证明锁状态不由 misc 决定。

如果仍想把「能/不能」钉成实验事实，最干净的做法**不是**去写（写坏了没法回滚），而是：

```bash
# 1) 看 SELinux 审计记录（这是唯一能"看见"拒绝的方式，logcat 里 shell 可读）
adb shell "logcat -d -b all | grep -i -e avc -e hypsys | grep -i misc"
#    期望：avc: denied { write } ... scontext=u:r:hypsys_ssi_default:s0
#          tcontext=u:object_r:misc_block_device:s0 tclass=blk_file
#    —— 若是这个，父会话那次 code 7 写 misc 就是"从未落地"，
#       旧的「写 4B 没解锁」实验也因此是**混淆**的（既可能没写进去，也可能判据不对）。

# 2) 正向对照（证明 code 8 能读 block device，前提是标签允许）
#    hypsys 对 userdata_block_device 有 read/open —— 但**不要**真读，
#    因为 code 8 是"读到 EOF 转 String"，userdata 是 500+ GB，会 OOM/卡死。
#    ⇒ 正向对照只能用文本文件（/data/anr/mq_probe.txt → "code7_works" 已验证）。

# 3) 反向对照：code 8 读 /data/local/tmp/caplog.jar（shell_data_file，已知被拒）→ 返回空
```

**结论口径**：`hypsys → misc` 的"不能写"目前是 **sepolicy 级证明**（§1.3：266 条 allow 里没有
`misc_block_device`，且有 `neverallow` 兜底），不是实测；实测只能作为佐证，且需要审计日志配合。


# GBL（Generic Bootloader）情报档案 — Android 17 / XRing O3 / lhasa

> 追加式档案。每条结论附来源。未找到的明确写「未找到」。
> 采集时间：2026-10-2x（会话时间）。采集者：research 子智能体。
> 本地静态分析对象：`runs/android/rom/fw/BOOTAA64.EFI`（PE32+ ARM64，1,585,152 B）

---

## 0. 网络可达性（影响情报获取路径，记录备查）

| 主机 | 结果 |
| --- | --- |
| `android.googlesource.com` / `android.git.googlesource.com` / `android.googleid.googlesource.com` | **全部超时**（TCP 443 不可达） |
| `cs.android.com` / `aospxref.com`（DNS 解析失败）/ `chromium.googlesource.com` | 不可达 |
| `github.com` / `api.github.com` / `codeload.github.com` | **可达 200** |
| `raw.githubusercontent.com` | 超时（改用 `api.github.com/repos/.../contents` 取 base64） |
| `source.android.google.cn` | **可达 200**（AOSP 文档镜像，只有文档没有源码） |
| `grep.app` / `sourcegraph.com` / `gitee.com` | 429 / 403 / 超时 |

结论：**拿 AOSP 源码只能走 GitHub 镜像 + `git clone`**（API 匿名限流 60 req/h，实际用 `git ls-remote` / `git fetch --depth 1` 绕开）。

---

## 1. GBL 是什么、在哪（问题 1）

### 1.1 权威结论：GBL 不是 `external/gbl`，git 仓是 `platform/bootable/libbootloader`

Googlesource 的原始文档路径在搜索结果里直接暴露：

- <https://android.googleid.googlesource.com/platform/bootable/libbootloader/+show/d6e72ae78741d9fc8f814189bfccba6ac7ac39a4/gbl/docs/gbl_efi_avb_protocol.md>
- <https://android.googleid.googlesource.com/platform/bootable/libbootloader/+/7b5f3f16c4fb1132c5a238295c6bce2bebee1d78%5E%21/gbl/docs/efi_protocols.md>

即：**仓库 = `platform/bootable/libbootloader`，GBL 子树 = 仓库内的 `gbl/` 目录**。
设备树里看到的 `external/gbl+/...` 是 SoC 厂商（高通/小米）把该仓 checkout 到 `external/gbl` 并用 Bazel external repo 规则（`gbl_repositories_ext`）拼出来的路径前缀，`+` 是 Bazel 标签分隔符，**不是仓库名**。

镜像里同类路径能自证（`strings BOOTAA64.EFI`）：

```
external/gbl+/libgbl/src/gbl_avb/mod.rs
external/gbl+/libgbl/src/gbl_avb/ops.rs
external/gbl+/libgbl/src/fastboot/buffer_pool.rs
external/gbl+/libgbl/src/android_boot/{mod,load,device_tree}.rs
external/gbl+/libgbl/src/{constants,device_tree,ops,partition}.rs
external/gbl+/libefi/src/protocol/{gbl_efi_boot_memory,erase_block,block_io2,device_path,gbl_efi_fastboot_transport}.rs
external/gbl+/libfastboot/src/lib.rs
external/gbl+/libbootparams/src/entry.rs
external/gbl+/libstorage/src/lib.rs , libfdt , libasync , libdttable
external/gbl+/efi/src/{lib,utils,android_boot}.rs
external/gbl++_repo_rules2+avb/libavb/avb_cmdline.c      ← libavb 是 external repo
external/gbl++_repo_rules2+boringssl/...                ← BoringSSL
external/gbl++gbl_repositories_ext+rust_prebuilts/...    ← Rust core/std
符号: gbl_aarch64_prod.pdb                                ← 生产版构建产物名
```

### 1.2 已落地到本机的源码副本（可直接引用/继续挖）

- 仓库：`aosp-mirror-neo/platform_bootable_libbootloader`（GitHub 镜像）
- **分支：`gbl-android17`，HEAD `bdf1b559146ce220ae18c7544c86180d99a7127b`，2026-08-13，"Mark next RC for GBL Android 17"**
- 本地路径：`%TEMP%\gbl_repo`（shallow clone，749 文件，含 `gbl/` 全量源码 + `gbl/docs/`）
- 其它镜像分支的时间线（供确认版本）：
  - `main` = `86fee5d5` 2025-03-24（旧，**不要用**）
  - `android17-release` = `b8c945e5` 2025-07-17
  - CodeLinaro `la_platform_bootable_libbootloader` @ `aosp-new/master` = 同 `86fee5d5`（旧）

**已知局限**：设备固件是 2026-10 的 HyperOS（OS4.0.21.0），比我们能拿到的 2026-08-13 分支更新。镜像里有两个字符串在当前分支源码中查不到（见 §2.5），说明**设备上的 GBL 比公开镜像新 1~2 个 RC**，或小米对 `libgbl` 有本地补丁。

### 1.3 `gbl/` 目录结构（模块划分）

```
gbl/
├── docs/                 ← 协议规范（最重要，见下）
├── libgbl/               ← GBL 主逻辑（Rust）
│   ├── src/gbl_avb/      mod.rs, ops.rs, state.rs   ← AVB 策略层
│   ├── src/fastboot/     mod.rs(282KB), vars.rs, boot_items.rs, sparse.rs, buffer_pool.rs
│   ├── src/android_boot/ mod.rs(143KB), load.rs, vboot.rs, avf.rs, device_tree.rs, hasher.rs
│   ├── src/slots/        android.rs, fuchsia.rs, partition.rs
│   ├── src/{ops.rs(87KB), partition.rs, device_tree.rs, misc.rs, metrics.rs, constants.rs}
│   └── src/fuchsia_boot/
├── libfastboot/          src/lib.rs(99KB)  ← 命令分派 / Transport 抽象 / TCP fastboot
├── libefi/               src/lib.rs, src/protocol/*.rs  ← EFI 协议 Rust 封装
│   └── protocol/gbl_efi_avb.rs (41KB)  ← 本任务核心文件
├── libefi_types/         include/uefi/protocols/gbl_efi_avb_protocol.h  ← C 头（权威结构体）
├── efi/                  src/ops.rs, src/android_boot.rs, src/fastboot.rs  ← EFI 应用入口（BOOTAA64.EFI 本体）
├── libavb/ libboot/ libbootimg/ libbootparams/ libmisc/ liblp/ libabr/
├── libstorage/ libfit/ libfdt/ libdttable/ libasync/ libc/ libutils/ liberror/
├── libopendice/ libprofile/ libsafemath/ libsemihosting/ libstack/ libtrace/ signtool/
└── tests/ integration/ protocol_integration/ tools/ fake_modules/
```

### 1.4 `gbl/docs/` 规范清单（全部已读，可直接引用）

| 文件 | 大小 | 内容 |
| --- | --- | --- |
| `gbl_efi_avb_protocol.md` | 46 KB | **AVB 协议全文**（GUID、10 个方法、lock 语义） |
| `gbl_fastboot.md` | 15 KB | fastboot 命令面 + **Lock Policy** |
| `gbl_efi_fastboot_protocol.md` | 20 KB | 厂商 fastboot 扩展协议（oem 命令挂钩点） |
| `gbl_efi_boot_control_protocol.md` | 15 KB | slot 控制 |
| `gbl_efi_boot_memory_protocol.md` | 11 KB | |
| `gbl_efi_avf_protocol.md` | 9 KB | pVM |
| `gbl_efi_os_configuration_protocol.md` | 16 KB | |
| `gbl_efi_debug_protocol.md` / `gbl_efi_fastboot_transport_protocol.md` | 5/12 KB | |
| `efi_integration.md` | 15 KB | 厂商集成方式（ABL 如何拉起 GBL） |
| `partitions.md` / `gbl_ab_boot_flow.md` / `gbl_fit.md` / `gbl_buffer_usage.md` | | |

---

## 2. `GBL_EFI_AVB_PROTOCOL` 完整定义（问题 2）

来源：`gbl/libefi_types/include/uefi/protocols/gbl_efi_avb_protocol.h`（本地 `%TEMP%\gbl_repo`）+ `gbl/docs/gbl_efi_avb_protocol.md`
镜像 URL 形如 `https://github.com/aosp-mirror-neo/platform_bootable_libbootloader/blob/gbl-android17/gbl/libefi_types/include/uefi/protocols/gbl_efi_avb_protocol.h`

### 2.1 GUID

```c
// {6bc66b9a-d5c9-4c02-9da9-50af198d912c}
#define GBL_EFI_AVB_PROTOCOL_GUID                    \
  {                                                  \
    0x6bc66b9a, 0xd5c9, 0x4c02, {                    \
      0x9d, 0xa9, 0x50, 0xaf, 0x19, 0x8d, 0x91, 0x2c \
    }                                                \
  }
```

Rust 侧一致（`gbl/libefi/src/protocol/gbl_efi_avb.rs:40`）：

```rust
const GUID: EfiGuid =
    EfiGuid::new(0x6bc66b9a, 0xd5c9, 0x4c02, [0x9d, 0xa9, 0x50, 0xaf, 0x19, 0x8d, 0x91, 0x2c]);
const METRICS_TAG: Option<&'static str> = Some("gbl_avb");
```

Revision：`GBL_PROTOCOL_REVISION(1, 0)`（`gbl_efi_avb_protocol.h:34`）。

以字节序落盘的 GUID（EFI 原生混端序）：`9A 6B C6 6B C9 D5 02 4C 9D A9 50 AF 19 8D 91 2C`
—— **可拿这 16 字节在整个 fw 里搜 provider**。

### 2.2 结构体（vtable，权威，注意偏移）

```c
typedef struct GblEfiAvbProtocol {
  uint64_t revision;                                              // +0x00
  EfiStatus (*read_partition_attributes)(...);                    // +0x08
  EfiStatus (*read_device_status)(self, GblEfiAvbDeviceStatus*);  // +0x10  ★
  EfiStatus (*validate_vbmeta_public_key)(...);                   // +0x18
  EfiStatus (*read_rollback_index)(...);                          // +0x20
  EfiStatus (*write_rollback_index)(...);                         // +0x28
  EfiStatus (*read_persistent_value)(...);                        // +0x30
  EfiStatus (*write_persistent_value)(...);                       // +0x38
  EfiStatus (*handle_verification_result)(...);                   // +0x40
  EfiStatus (*write_lock_state)(self, LockType, LockState);       // +0x48  ★
  EfiStatus (*factory_data_reset)(self);                          // +0x50
} GblEfiAvbProtocol;
```

**10 个方法**（不含 revision）：

1. `ReadPartitionAttributes` — 分区特殊属性（VERIFY / VERIFY_IF_EXISTS / FLASH_CRITICAL / FDR）
2. **`ReadDeviceStatus`** — 锁状态 + dm-verity 状态
3. **`ValidateVbmetaPublicKey`** — 厂商验 vbmeta 公钥
4. `ReadRollbackIndex`
5. `WriteRollbackIndex`
6. `ReadPersistentValue`
7. `WritePersistentValue`
8. `HandleVerificationResult` — 厂商处理 AVB 结果（更新 RoT / 设 device state / 打 UI 警告 / 反篡改）
9. **`WriteLockState`** — 改 DEVICE / CRITICAL 锁
10. `FactoryDataReset` — 安全擦除

### 2.3 `ReadDeviceStatus` 返回值 bit 语义（问题 2 关键）

```c
typedef uint64_t GblEfiAvbDeviceStatus;
GBL_EFI_AVB_DEVICE_STATUS_UNLOCKED          = 0x1 << 0;   // bit0 = 已解锁（orange）
GBL_EFI_AVB_DEVICE_STATUS_DM_VERITY_FAILED  = 0x1 << 1;   // bit1 = 因 dm-verity 错误重启
GBL_EFI_AVB_DEVICE_STATUS_UNLOCKED_CRITICAL = 0x1 << 2;   // bit2 = critical 已解锁
GBL_EFI_AVB_DEVICE_STATUS_UNLOCKABLE        = 0x1 << 3;   // bit3 = 允许解锁（对应"OEM unlocking"开关）
```

规范原文（`gbl_efi_avb_protocol.md:378-404`）：

> `StatusFlags`: An output parameter to be updated by firmware with ORed flags detailing the AVB
> device status. **All bits not explicitly defined must be set to zero.**
> …`GBL_EFI_AVB_DEVICE_STATUS_UNLOCKED` - Indicates the device is unlocked. GBL treats unlocked
> devices as being in the `orange` boot state, skipping certain verification enforcements…
> `GBL_EFI_AVB_DEVICE_STATUS_UNLOCKABLE` - …**If the device is not unlockable, calls to
> `WriteLockState()` with a _State_ parameter of value `GBL_EFI_AVB_LOCK_STATE_UNLOCKED` will fail.**
> GBL may call this method multiple times within a single boot session. **If the method returns an
> error, GBL rejects the boot attempt.**

### 2.4 `ValidateVbmetaPublicKey` 判定语义

```c
enum {
  GBL_EFI_AVB_KEY_VALIDATION_STATUS_INVALID,           // 0 → locked 设备 RED + 重启
  GBL_EFI_AVB_KEY_VALIDATION_STATUS_VALID_CUSTOM_KEY,  // 1 → locked:YELLOW / unlocked:ORANGE
  GBL_EFI_AVB_KEY_VALIDATION_STATUS_VALID,             // 2 → 全绿
};
```

> `ValidateVbmetaPublicKey` must set `ValidationStatus` and return `EFI_SUCCESS`. **Any return value
> other than `EFI_SUCCESS` is treated as a fatal verification error, resulting in a `RED` state**
> being reported and GBL failing to boot, even if the device is unlocked. (doc:508-511)

→ 注意：`VALID_CUSTOM_KEY` 在 lock 设备上是**允许启动**的（YELLOW），只是打警告。
这就是「自定义 Root of Trust」路径：只要能骗过 `ValidateVbmetaPublicKey` 返回 1，locked 设备就能带自定义 key 启动。

### 2.5 `WriteLockState` 语义（解锁的唯一闸门）

```c
enum { GBL_EFI_AVB_LOCK_TYPE_DEVICE, GBL_EFI_AVB_LOCK_TYPE_CRITICAL };  // uint8
enum { GBL_EFI_AVB_LOCK_STATE_UNLOCKED, GBL_EFI_AVB_LOCK_STATE_LOCKED }; // uint8
```

返回码表（doc:1087-1094）：

| 返回 | 语义 |
| --- | --- |
| `EFI_SUCCESS` | 锁状态已设置 |
| `EFI_INVALID_PARAMETER` | Type/State 非法 |
| **`EFI_ACCESS_DENIED`** | **设备不可解锁（not unlockable）** ← 我们实测被拒就是这个 |
| `EFI_UNSUPPORTED` | CRITICAL 锁未实现 |

GBL 侧对 DEVICE 锁改动的**强制序列**（doc:1015-1022）：

1. 用 Block I/O 擦除所有带 `GBL_EFI_AVB_PARTITION_FLAG_FDR` 的分区
2. 调 `FactoryDataReset()`
3. 调 `WriteLockState()`

> It is **security-critical** that no user data is allowed to leak across lock state modifications in
> either direction. … they will be called from `TPL_APPLICATION` so are **not guaranteed to be atomic**.

### 2.6 设备 BL 与源码的交叉验证（本地实测）

`python verify_misc_claim.py rom/fw/BOOTAA64.EFI 0xf0a0 0xf110`：

```
0x014000f0d4  paciasp
...
0x014000f0fc  ldr x0, [x0]           ; 取 Protocol 包装里的 interface 指针
0x014000f104  ldr x8, [x0, #0x10]    ; ★ vtable +0x10 = read_device_status（与 §2.2 完全一致）
0x014000f108  cbz x8, #0x14000f154   ; 空指针检查
0x014000f10c  add x1, sp, #8         ; out 参数 &status_flags（u64，栈上）
0x014000f110  blr x8                 ; 间接调用 provider
0x014000f114  add x8, sp, #0x48
0x014000f118  bl #0x140018214        ; EfiStatus -> liberror::Error 转换
0x014000f11c  ldr w8, [sp, #0x48]
0x014000f130  cmp w8, #0x4b          ; Error 判别值比较（Ok 分支）
0x014000f144  ldr x8, [sp, #8]       ; 读回 status_flags
0x014000f148  str x8, [x19, #8]      ; 存进调用者的结构体 +8
```

同一函数在 `0xf154` 的空指针分支里走 `[x8,#0x40]`（= `handle_verification_result` 偏移），
并引用 `.rodata` 的 `0x14011f299` / `0x14011f20b` 两串（作者 panic 字符串）。

> **结论：设备 BL 的锁判定 100% 依赖 provider；GBL 自身不存储、不缓存、不二次校验锁状态。**
> 与源码 `libgbl/src/fastboot/mod.rs:1143` `check_unlocked()` 一一对应。

未在 `gbl-android17` 分支源码中命中的镜像字符串（说明设备 GBL 更新）：

```
misc | Device is not unlocked | Fail to get unlock status        (0x138784 附近连续排列)
```

`"Device is locked"`（源码 `ERR_DEVICE_LOCKED`，fastboot/mod.rs:62）在镜像里**没有**出现，
而出现了 `"Device is not unlocked"` + `"Fail to get unlock status "`。推断：新版本把
`check_unlocked()` 改成了先读 `misc` 的 boot params 拿 unlock status，失败时 `Fail to get unlock status {e}`。
**这条路径值得单独挖**（`libbootparams` + `misc` 分区，可写 → 可能伪造 unlock status）。

---

## 3. locked 设备命令白名单：到底在哪（问题 3 前半）

**先纠正一个前提**：GBL 里**没有**「locked 命令白名单表」这种东西。它用的是**逐命令 `check_unlocked()` 门禁**，
外加一个长得像白名单、但用途完全不同的常量表。三处必须分清：

### 3.1 `PROTECTED_FASTBOOT_COMMANDS` —— 不是锁白名单

`gbl/libfastboot/src/lib.rs:134-156`

```rust
// Check if command is protected from overriding
fn is_protected_command<'a>(mut args: impl Iterator<Item = &'a CStr> + Clone) -> bool {
    const PROTECTED_FASTBOOT_COMMANDS: &[&CStr] = &[
        // LINT.IfChange
        c"continue", c"download", c"fetch", c"getvar",
        c"reboot", c"reboot-bootloader", c"reboot-fastboot", c"reboot-recovery",
        c"set_active", c"upload",
        // LINT.ThenChange(/gbl/docs/gbl_efi_fastboot_protocol.md)
    ];
    ...
}
```

用途：这些是**核心命令，禁止厂商/OEM 通过 `command_exec()` 覆盖**（`command_exec()` 一进来就先
`if is_protected_command(...) { return Ok(DefaultImpl) }`，lib.rs:1321）。**与锁状态无关。**
→ 如果之前观察到「`oem unlock` 在白名单里」，那是厂商侧的实现，不是这张表。

### 3.2 真正的锁门禁：`check_unlocked()` 系列

`gbl/libgbl/src/fastboot/mod.rs:1142-1173`

```rust
/// Returns `Ok` if the device lock is unlocked.
fn check_unlocked(&mut self) -> CommandResult<()> {
    match self.gbl_ops.avb_read_device_status() {
        Err(e) => Err(format_args!("Failed to read lock state: {e}").into()),
        Ok(status) if status.is_unlocked => Ok(()),
        _ => Err(ERR_DEVICE_LOCKED.into()),
    }
}
fn check_critical_unlocked(&mut self) -> CommandResult<()> { /* -> is_unlocked_critical */ }
fn check_full_disk_critical_unlocked(&mut self) -> CommandResult<()> {
    // 先看 ReadPartitionAttributes 有没有 critical 分区；有才查锁
}
```

调用点（`grep -n 'check_unlocked()?' libgbl/src/fastboot/mod.rs`）：

| 行 | 命令 | 门禁 |
| --- | --- | --- |
| 593 | `flash-gpt`（整盘 GPT） | full_disk_critical |
| 768 | 分区读写解析（critical 分区） | critical |
| 780 | 裸整盘访问 | full_disk_critical |
| **1377** | `flash` | **unlocked** |
| **1407** | `erase` | **unlocked** |
| **1507** | `upload` | **unlocked** |
| **1529** | `fetch` | **unlocked** |
| **1572** | `set_active` | **unlocked** |
| **1675** | `stream`（flash/fill 流式） | **unlocked** |
| **1721** | `boot`（`fastboot boot`） | **unlocked** |
| 1629/1636/1641/1646/1652/1656 | `oem add-staged-bootloader-file` / `gbl-add-cmdline` / `gbl-add-bootconfig` / `gbl-add-staged-data` / `gbl-stage` / `gbl-pause-fastboot-after-load` | unlocked |
| 1744 | `flashing lock_critical/unlock_critical` | unlocked |

**未加门禁（locked 下也放行）**：`getvar` / `getvar all` / `reboot*` / `continue` / `download` /
`flashing lock` / **`flashing unlock`** / `flashing get_unlock_ability` /
`oem gbl-sync-tasks` / `gbl-set|unset-default-block` / `gbl-set|unset-download-crc` /
`gbl-partition-info` / `gbl-enable|disable-async-task`。

→ **`oem gbl-partition-info` 在 locked 下可用 → 可以枚举全部分区（含隐藏分区、FDR 标记、critical 标记）。**
这是当前 locked 状态下**信息量最大的免费命令**。

### 3.3 策略文档（人读版本）

`gbl/docs/gbl_fastboot.md:39-51`

> ## Lock Policy
> To ensure device security, GBL Fastboot enforces that most data modification and extraction
> commands are only available when the device is **unlocked**:
> - `fastboot flash` / `fastboot erase` / `fastboot fetch` / `fastboot boot`
> - `fastboot flashing lock_critical` / `fastboot flashing unlock_critical`
> Attempts to run these commands on a locked device will result in a Fastboot failure.

### 3.4 ★ `flashing unlock` 为什么"在白名单里但被 provider 拒"——源码级解释

`gbl/libgbl/src/fastboot/mod.rs:1734-1768`

```rust
async fn flashing_write_lock_state(
    &mut self, lock_type: LockType, lock_state: LockState, mut responder: impl InfoSender,
) -> CommandResult<()> {
    // NOTE: This creates a usability edge case: if a user has unlocked both DEVICE and
    // CRITICAL locks, and then locks DEVICE first, they will be unable to lock CRITICAL
    // because `check_unlocked()` enforces that the DEVICE lock must be unlocked.
    if lock_type == LockType::Critical {
        self.check_unlocked()?;          // ← 只有 CRITICAL 才查锁
    }
    if lock_type == LockType::Device {
        self.wipe_fdr_partitions(&mut responder).await;   // 1. 擦 FDR 分区
        self.sync_tasks_and_fdr(&mut responder).await?;   // 2. FactoryDataReset
    }
    Ok(self.gbl_ops.avb_write_lock_state(lock_type, lock_state)?)   // 3. protocol +0x48
}
```

**`LockType::Device` 走 unlock 时 GBL 完全不做锁检查**——它把「能不能解锁」这一唯一裁决权
整个交给 `WriteLockState` 的 `EFI_ACCESS_DENIED`。**这就是我们被拒的确切原因，也是唯一需要攻的点。**

---

## 4. 已知漏洞 / 绕过研究（问题 3 后半 + 问题 4），按可信度排序

### 4.1 ★★★★★ Qualcomm「GBL 漏洞」解锁链（真实、已被厂商确认、已修）

**这是与本任务最相关、且已被官方确认的 GBL 弱点。**

- 发现方：**小米 ShadowBlade Security Lab**（一说与社区研究者 Gus / @realMlgmXyysd / @LittlenineEnna 一系有交叉）
- 时间线：2026-01 发现 → 2026-03 公开 → **2026-03 上旬高通把修复提供给 OEM**
- 影响：骁龙 8 Elite Gen 5 机型：**小米 17 系列、Redmi K90 Pro Max**，一加 15 可能受影响；三星 S26 Ultra 不受影响（自有 S-Boot，不接受高通公版调试指令）

来源：
- 安兔兔 2026-03-16：<https://antutu.com/doc/136434> —《高通确认已向安卓厂商提供GBL漏洞修复 小米17系列等骁龙8Elite Gen5机型非官方解锁路径被封堵》
- 凤凰网：<https://tech.ifeng.com/c/8rSHeeTgBaP> —《无视答题与时间锁！新漏洞让小米 17 系列成功解锁 Bootloader》
- gizchina EN：<https://en.gizchina.it/2026/03/vulnerabilita-qualcomm-gbl-lazienda-risponde/>
- shiftdelete：<https://en.shiftdelete.net/major-vulnerability-in-qualcomm-powered-devices-update-now/>

**机制（原文摘录，来自本地已存的 `runs/android/ifeng_xiaomi17_unlock.txt` 第 9-10 行）**：

> 在安卓 16 系统中，ABL 从"efisp"分区加载通用引导加载程序（GBL）后，**仅检查其是否为 UEFI 应用，
> 却未验证其真实性**。因此，用户可以直接向该分区写入并执行未签名代码，这构成了整个漏洞利用链的基础。
> 为了向"efisp"分区写入数据，用户必须先将系统安全模块 SELinux 的状态从默认的"强制（Enforcing）"
> 降级为"宽容（Permissive）"。

完整链：
```
SELinux Enforcing -> Permissive（内核缺陷/指令缺陷）
  -> 写 efisp 分区（未签名 EFI 应用）
  -> 重启，ABL 只校验"是 UEFI 应用"就加载并执行  ← 根因
  -> BL 上下文任意代码执行
  -> 覆写 RPMB 里的 lock state / 绕过锁检查
  -> bootloader 解锁
```

**修复**：`gbl_root_canoe` 的 wiki 记录「Xiaomi 在 ABL 版本 **300** 修了这个 GBL 漏洞，但到 306 版
XBL 仍保留引导旧版 ABL 的能力，可间接加载 EFISP」——
<https://github.com/SuperTurtleDev/gbl_root_canoe/blob/main/wiki/docs/ota.md>

**未找到**：该链的 CVE / CNVD 编号。高通-小米这条线没有公开编号（询问式检索 "Qualcomm GBL CVE" 只命中
泛指文章）。**不要编 CVE 号。**

> ⚠️ 与本地已有研究的衔接：`runs/android/research/CVE-2026-64560-public/` 那条链（posix-cpu-timers UAF
> → SELinux permissive → KernelSU）**正好是上面第 1 步**。也就是说，**我们已经有 efisp 写入所需的前置条件**，
> 缺的是第 2-4 步在本机型（XRing O3）上是否成立。

### 4.2 ★★★★★ Xiaomi 18 Fold（本机型）已被非官方解锁 —— 2026-10

- <https://ximitime.com/xiaomi-18-pro-and-fold-get-unofficial-bootloader-unlock-101065/>（2026-10-06）
- <https://en.gizchina.it/2026/10/xiaomi-18-pro-fold-bootloader-sbloccato/>（403，只能读标题）

原文要点：

> The Xiaomi 18 Pro unlock was shared by **@realMlgmXyysd**, while the **Xiaomi 18 Fold was
> reportedly unlocked by LittlenineEnna**.
> …The Xiaomi 18 Fold is powered by Xiaomi's own **XRING O3** chipset. … LittlenineEnna has now
> reportedly achieved a bootloader unlock on the 18 Fold as well. The result is notable because the
> XRING O3 platform uses Xiaomi's own silicon, adding another security layer…
> 评论（DR8701）："this 18 Pro exploit won't become public and the creator has submitted it to Xiaomi
> for them to fix."

**判定**：本机型（lhasa / XRing O3 / HyperOS 4 / Android 17）**确实存在可用的解锁链**，公开时间 2026-10-06，
**没有公开细节**（作者报给小米了）。方法未公开 → 只能自己复现同类思路。

**交叉证据（人名闭环）**：`kasnria001/qualcomm_gbl_exploit_poc` 的 README 里点名的
"Littlenine"、"Mlgm" 与这里的 `@LittlenineEnna`、`@realMlgmXyysd` 是同一批人。
即：**18 Fold 的解锁大概率就是 GBL/efisp 这一系的延续**（XRing 版）。

### 4.3 ★★★★☆ `kasnria001/qualcomm_gbl_exploit_poc`（977★，2026-06-29）

<https://github.com/kasnria001/qualcomm_gbl_exploit_poc>
文件：`README.md` / `VbRwStateApp.c` / `VbRwStateApp.inf` / `gbl_efi_unlock.efi` / `gbl_efi_relock.efi`（各 40 KB PE）

README 原文（关键技术陈述，逐句）：

> Qualcomm adds a gbl boot stage in its ABL because it wants to limit OEM's ability.
> **gbl is loaded as an uefi app. it stores in efisp partition. you need to flash the efi file into
> the partition.**
> **Qualcomm uses its own verification instead of UEFI secure boot. But GBL is unsigned.**
> **So we can load unsigned uefi app. This way, we can achieve arbitary code execution.**
> **So we can overwrite the lock state storing in RPMB.**
> Because the ABL it self reads/writes devinfo via a special function.
> Before milestone, we can call the function to overwrite the lock state.

→ **这是「GBL 信任判定弱点」的最直接表述**：
GBL 阶段不受 UEFI Secure Boot 覆盖，ABL 用自家校验（且按 4.1 的报道，只校验"是不是 UEFI 应用"），
因此 efisp 里的未签名 EFI 应用能拿到 **BL 上下文代码执行**，进而用 ABL 自己的 devinfo
读写函数改 RPMB 里的锁状态。

README 里还有一大段作者与 Littlenine/Mlgm 的**首发权争议**（可忽略，但确认了人物来源）。

`VbRwStateApp.c`（2.6 KB）名字即 `VB Read/Write State App` —— 就是那个改锁状态的 EFI 应用。

### 4.4 ★★★★☆ `SuperTurtleDev/gbl_root_canoe` / `1vivy/gbl-chainload`（同一系，含完整 EFI 源码）

- <https://github.com/SuperTurtleDev/gbl_root_canoe>（`README.md` 5.8 KB，wiki 有安装/OTA 细节）
- <https://github.com/1vivy/gbl-chainload>（**GBL chainloader，含 EDK2 包 + Rust crates**，可直接读源码）
- 派生：`koaaN/x9u-gbl-chainload-app`（OPPO Find X9 Ultra 安装器）、`infiniti-labs/android_external_gbl`

`gbl_root_canoe` README 原文：

> `gbl_root_canoe` is an EDK2-based workspace for patching the EFI applications within Qualcomm ABL
> images. It leverages a **GBL (Generic Bootloader Loader) vulnerability** so the real ABL loads an
> embedded **superfastboot BDS** off the raw **`efisp`** partition. …
> primarily to achieve a **Fake Locked Bootloader** state on Snapdragon 8 Gen 5 / 8 Elite (Gen 5)
> devices to bypass bootloader unlock detection.
> `BDS.efi` is written raw to the `efisp` partition; the cracked ABL (`boot.efi`) and the boot entry
> list (`BOOTENTRIES`) live on the `persist` partition under its `efisp/` directory.
> Requirements: … **The ABL on the `abl` partition must contain the GBL vulnerability. If it does
> not, flash an older ABL with the vulnerability first.**

`1vivy/gbl-chainload` 值得直接读的文件（已确认存在，大小已核）：

| 文件 | 大小 | 为什么重要 |
| --- | --- | --- |
| `GblChainloadPkg/Library/ProtocolHookLib/VerifiedBootHook.c` | 16.9 KB | **hook 掉 VerifiedBoot / AVB 协议**，直接把"Fake Locked"做在协议层 |
| `GblChainloadPkg/Library/ProtocolHookLib/FakelockOverlay.c` | 4.0 KB | 伪造锁状态的 overlay |
| `GblChainloadPkg/Library/ProtocolHookLib/InstallAll.c` | 5.0 KB | 协议安装/劫持总入口 |
| `GblChainloadPkg/Library/ProtocolHookLib/{ScmHook,QseecomHook,SpssHook}.c` | 23/22/5 KB | 劫持 SCM / QSEECom / SPSS（TEE 通道） |
| `GblChainloadPkg/Library/GblPayloadLib/{GblPayload.c,EfispBlockIo.c,LocateOverlay.c}` | 6.2/3.7/1.4 KB | GBL payload 容器 + efisp BlockIo + overlay 定位 |
| `crates/gblp1/src/lib.rs` | 23 KB | **GBLP1 = GBL payload 容器格式**解析 |
| `crates/patch-engine/src/abl_permissive/fastboot_lock_gates.rs` | 3.7 KB | patch ABL 的 fastboot 锁门禁 |
| `docs/project/re-findings.md` | 8.1 KB | **逆向发现汇总**（值得整篇读） |

### 4.5 ★★★☆☆ `infiniti-labs/android_external_gbl`（`seventeen` 分支，2026-10-18）—— 补丁工程

<https://github.com/infiniti-labs/android_external_gbl>（本地未 clone，但关键文件已取）

`submodules/patcher` 的补丁集：

| 补丁 | 作用 |
| --- | --- |
| `fastboot_lock_gates.c/h` | **把 ABL 里 locked 状态下的 flash/erase/slot-change/snapshot-cancel 拒绝逻辑 NOP 掉** |
| `libavb_force_success.c/h` | 强制 libavb 校验返回成功 |
| `dice_mode.c/h` | DICE 模式 |
| `oplus/forceenablefastboot.c/h` | OPPO 强制允许 fastboot |
| `oplus/bypass_warning.c` | 绕过"已解锁"警告 UI |

`fastboot_lock_gates.c` 的注释把 ABL 侧的锁门禁讲得很透（原文，`libfastboot` 之外的**另一半**）：

> The loader presents a locked VerifiedBoot view to the ABL; the ABL's in-fastboot command dispatcher
> then honours that view and refuses flash, erase, slot change and snapshot cancel. Each refusal has
> its own message, and each message is loaded by an ADRP+ADD pair immediately governed by the gate
> that decides whether the refusal runs.

它锚定的 4 条 ABL 字符串（**可以用来判断我们的 BOOTAA64/ABL 里有没有对应门禁**）：

```
"Flashing is not allowed in Lock State"
"Erase is not allowed in Lock State"
"Slot Change is not allowed in Lock State\n"
"Snapshot Cancel is not allowed in Lock State"
```

> 注意：这 4 条是**厂商 ABL（Qualcomm edk2 `FastBootLib`）**的字符串，不是 GBL 的。
> 我们镜像里 GBL 用的是 `"Device is locked"` / `"Device is not unlocked"`。
> **两套 fastboot 实现并存**：GBL 的 fastboot（`libgbl/src/fastboot`）与厂商 ABL 的 fastboot。

其它值得读：`docs/b5-image-primitives.md`、`docs/bds-escape-todo.md`、`docs/boot-volume-lifecycle-audit.md`、
`docs/super-fastboot-diagnostics.md`、`sepolicy/efisp.te`。

### 4.6 ★★☆☆☆ `chkndrp/fastboot-oem-extractor`（60★）

<https://github.com/chkndrp/fastboot-oem-extractor> — "Extract hidden `fastboot oem` commands from firmware blobs"。
纯工具，可用于从我们的 BOOTAA64.EFI / uefi.img 里抠 `oem` 命令表（当前 locked 状态下值得跑一遍）。

### 4.7 未找到的部分（明确声明）

- **没有**任何 GBL 相关的 CVE / CNVD / Android Security Bulletin 编号公开可查。
  （检索 "gbl fastboot vulnerability"、"libgbl CVE"、"external/gbl exploit"、"Android GBL unlock bypass" 全部无编号命中。）
- **没有**官方的 GBL 安全公告页。
- **没有** Google Project Zero / DEF CON / Black Hat 关于 GBL 的议题。
- 上述全部是**社区研究 + 厂商确认的媒体报道**，无正式漏洞编号。

---

## 5. XRing / lhasa 专项（问题 5）

| 结论 | 来源 |
| --- | --- |
| Xiaomi 18 Fold（lhasa，XRing O3，HyperOS 4 / Android 17）**已被非官方解锁**，作者 **@LittlenineEnna**，2026-10-06 | <https://ximitime.com/xiaomi-18-pro-and-fold-get-unofficial-bootloader-unlock-101065/> |
| Xiaomi 18 Pro（SM8950 / SD 8 Elite Gen 6）同批被 **@realMlgmXyysd** 解锁，且**该 exp 不会公开、已提交给小米修** | 同上（评论区 + 正文） |
| 该解锁「appears to rely on a security vulnerability rather than Xiaomi granting an official unlock request」，且 XRing 平台「adding another security layer」 | 同上 |
| 无 XRing O3 专属的 bootloader 漏洞公开分析 | 检索 "XRing O3 bootloader" 无技术内容命中 |
| 无 "Mi Unlock 18 Fold" 官方工具变化记录 | 未找到 |

补充检索（均**未找到**技术细节）：`"XRing O3 bootloader"`、`"lhasa fastboot unlock"`、
`"Xiaomi 18 Fold unlock"`、`"Mi Unlock 18 Fold"`、`"玄戒 O3 bootloader 解锁"`。

---

## 6. 本地静态分析新增证据（本次会话产出）

### 6.1 ★ BOOTAA64.EFI **没有 Authenticode / UEFI Secure Boot 签名**

`PE32+` 数据目录实测（`runs/android`）：

```
dir 0  rva 0x14ec9d size 0x2536   Export
dir 3  rva 0x15d000 size 0x44c8   Exception (.pdata)
dir 5  rva 0x164000 size 0x16a8   Base Relocation
dir 6  rva 0x14ec54 size 0x1c     Debug (gbl_aarch64_prod.pdb)
—— 没有 dir 4 (IMAGE_DIRECTORY_ENTRY_SECURITY) ——
```

→ **GBL 的 EFI 映像里没有任何 PKCS#7 / WIN_CERTIFICATE**，无法被 UEFI Secure Boot 校验。
这与 `kasnria001` README 的 "GBL is unsigned" 完全吻合，也是整条解锁链的物理基础。

### 6.2 ★ `android_esp.img` 就是本机型的 `efisp`

`rom/fw/android_esp.img`（8,388,608 B）：

```
头 64B: eb 3c 90 6d 6b 66 73 2e 66 61 74 00 ...   "mkfs.fat"  "FAT12"   ← FAT12 卷
offset 0x3000  含 "EFI"
offset 0x18A000 含 "BOOTAA64"   （目录项名，非文件内容）
```

→ `android_esp` = FAT12 EFI System Partition，里面装 `EFI/BOOT/BOOTAA64.EFI`（即 GBL）。
**这就是 XRing 平台上的 `efisp` 等价物**，是 4.1 那条链的第 2 步落点。

（已在 `rom/fw/*` 全量搜 `efisp` 字符串：**无命中**。说明 XRing 用 `android_esp` 这个名字，
不是高通的 `efisp`。`rom/fw/BOOTAA64.EFI` 内也没有 `efisp` 字符串。）

### 6.3 其它已确认（沿用，不重复验证）

- `gbl_efi_avb` / `write_lock_state` / `validate_vbmeta` 符号串在镜像中：
  `gbl_efi_avb`@0x11e15b.., `validate_vbmeta`@0x11e324/0x11e363, `write_lock_state`@0x11e77e/0x11e7b3
- BCB 命令串 `bootonce`@0x142170 / `boot-fastboot`@0x142190 / `boot-rescue`@0x14219d
- `misc` + `Device is not unlocked` + `Fail to get unlock status ` @ **0x138784**（三者连续，见 §2.6）

---

## 7. 建议的攻击面排序（供指挥部决策）

见交给 parent 的最终答复 §(e)。核心三条：

1. **`android_esp` 写入 + 未签名 GBL 执行**（4.1/4.3/6.1/6.2 合力）——唯一有「已被验证过同族成功」背书的路线
2. **`WriteLockState` 是唯一闸门**（3.4）——不必攻 GBL，直接攻 provider；provider 在 `uefi.img` 高熵卷 / `xrse.img` / TEE
3. **`misc` 里的 unlock status 新路径**（2.6）——`libbootparams` + `misc` 可写，可能是最省事的一条

---

## 8. 复现脚本 / 数据落点

- 源码副本：`%TEMP%\gbl_repo`（branch `gbl-android17`）
- 其它 clone：`%TEMP%\gblroot`（gbl_root_canoe）、`%TEMP%\gbl_cl`（CodeLinaro，旧）
- 反汇编：`python runs/android/verify_misc_claim.py rom/fw/BOOTAA64.EFI <lo> <hi>`（cwd=runs/android）
- PE 数据目录检查：见 §6.1 命令

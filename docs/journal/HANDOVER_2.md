# 交接文档 · 2026-10-22 第二轮

> 承接 `HANDOVER.md`（第一轮）。**第一轮的若干"核心结论"已被推翻，务必先读第 7 节再动手。**
> 本轮真正的成果：**解锁链全线打通到"只差一次 selinux permissive"**，并且
> **找到了那个缺失的 order-1 可控回收原语（/dev/uhid）**。卡住的地方只剩竞态命中率。

---

## 1. 设备与环境

| 项 | 值 |
|---|---|
| 机型 | Xiaomi 18 Fold，codename **lhasa**，model 2608BPX34C |
| SoC | **XRing O3**（小米自研，非骁龙、非 MTK） |
| 系统 | Android 17 / HyperOS **OS4.0.21.0.XPNCNXM** |
| 内核 | `6.18.21-android17-5-g284297031c53-abogki553682993-4k` |
| SPL | 2026-08-01 |
| adb serial | `<device-serial>` |
| 当前状态 | BL **locked**（`ro.boot.flash.locked=1`、`vbmeta.device_state=locked`、AVB green） |
| slot | `_a` 活动；`slot-unbootable:b = yes`；`android_esp_b` 可随意破坏 |
| shell | uid 2000，Seccomp 0，groups 含 `uhid(3011)`、`readtracefs(3012)` |

**工具链**

- 交叉编译：`tools/zig/zig-windows-x86_64-0.13.0/zig.exe cc -target aarch64-linux-musl -static -O2 [-pthread] -o X.exe X.c`
- 本机 Python：`C:\Users\user\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe`
  （已装 capstone / pyelftools / peewee / pyusb / libusb-package / brotli / lz4 / zstandard）
- jadx：`tools\jadx\bin\jadx.bat`

---

## 2. ★ 解锁链全图（每一环都有实测或源码证据）

```
① 写 android_esp（XRing 的 efisp，8 MiB FAT12，内含 EFI/BOOT/BOOTAA64.EFI）
        ↓
② bootloader 从 efisp 加载 GBL，只检查"是不是 UEFI 应用"、不验真实性
   （公开研究已证；同族 PoC 含现成 gbl_efi_unlock.efi）
        ↓
③ 我们的 GBL 调 gbl_efi_avb 协议 slot 8 = write_lock_state(+0x48)
   ——源码证实 `flashing unlock` 对 LockType::Device 根本不查锁，唯一裁决者就是这个方法
        ↓
④ 永久解锁 → 刷 Magisk → 持久 root
        ↑
   唯一阻塞：① 需要写块设备 → 需要 SELinux permissive 或 root
        ↑
   唯一可达手段：一次内核任意写（把 selinux_state 清零，地址每次 boot 可算）
```

### 2.1 每一环的证据

| 环节 | 证据 |
|---|---|
| `android_esp` = efisp | `rom/fw/android_esp.img` 8 MiB **FAT12**（头 `mkfs.fat`），含 `EFI`/`BOOTAA64` 目录项；`rom/fw/*` 全量搜 `efisp` 零命中（XRing 用 android_esp 这个名字） |
| GBL 不验真实性 | 高通平台 GBL 漏洞公开研究（ShadowBlade Lab，2026-03）；`kasnria001/qualcomm_gbl_exploit_poc`（977★，含 `gbl_efi_unlock.efi`/`gbl_efi_relock.efi`/`VbRwStateApp.c`）、`SuperTurtleDev/gbl_root_canoe`、`1vivy/gbl-chainload` |
| BOOTAA64.EFI 无 Authenticode | **实测**：PE 数据目录只有 0/3/5/6，**无 dir 4 (SECURITY)** → 无 PKCS#7 → UEFI Secure Boot 覆盖不到 |
| `android_esp.img` 无 AVB footer | 实测（`pvmfw.img` 有）⇒ ESP 不是自带签名分区 |
| `flashing unlock` 不查锁 | 源码 `libgbl/src/fastboot/mod.rs:1734-1768`，只有 `LockType::Critical` 走 `check_unlocked()` |
| provider vtable | 明文 BOOTAA64.EFI 内 `0x11E14C..0x11E7A0` 9 方法（见 §2.2） |
| GBL 源码 | 仓是 **`platform/bootable/libbootloader`**，GBL 在 `gbl/` 子树；镜像 `aosp-mirror-neo/platform_bootable_libbootloader` 分支 **`gbl-android17`**（HEAD `bdf1b55`, 2026-08-13）。已 clone 到 `%TEMP%\gbl_repo`（749 文件） |

### 2.2 `gbl_efi_avb` 协议（GUID + vtable）

```c
// {6bc66b9a-d5c9-4c02-9da9-50af198d912c}
// 落盘字节序: 9A 6B C6 6B C9 D5 02 4C 9D A9 50 AF 19 8D 91 2C
```
| 偏移 | 方法 |
|---|---|
| +0x00 | revision |
| +0x08 | read_partition_attributes |
| **+0x10** | **read_device_status** ← GBL 的锁判定点（`0xf0d4` 处 `blr [x0+0x10]`） |
| +0x18 | validate_vbmeta_public_key |
| +0x20 / +0x28 | read/write_rollback_index |
| +0x30 / +0x38 | read/write_persistent_value |
| +0x40 | handle_verification_result |
| **+0x48** | **write_lock_state** ← 我们的目标 |
| +0x50 | factory_data_reset |

status bits：bit0 UNLOCKED / bit1 DM_VERITY_FAILED / bit2 UNLOCKED_CRITICAL / **bit3 UNLOCKABLE**

---

## 3. ★ 本轮最重要的技术突破：order-1 可控回收原语

**`/dev/uhid` 的 `UHID_CREATE2`（走 `write()`，不是 ioctl）是这台机上唯一满足全部要求的喷洒原语。**

内核会 `kmemdup(rd_data, rd_size)` **持久**保留我们送进去的 HID 报告描述符：

| 要求 | 实测结果 |
|---|---|
| 非特权可用 | ✅ shell 直接 open+write |
| **order-1**（8 KB / 32 对象） | ✅ `rd_size=256` → `kmalloc-256`（objperslab=32, pagesperslab=2） |
| 内容 100% 原始字节可控 | ✅ 原样拷贝，任意字节含 `\0` |
| 持久 | ✅ 活到 UHID_DESTROY/close |
| 高密度 | ✅ 实测 2000 设备 → kmalloc-256 从 10376/10688 → 12352/12352（+1976 对象/+52 slab） |

**关键：全零描述符 + 只放两个指针也能被接受**（实测），不需要它是合法 HID 描述符。

**精确结构**（BTF 实测）：

```
uhid_event         = 4380 字节，union 在偏移 4（packed！不是 8）
uhid_create2_req   = 4372 字节（name[128] phys[64] uniq[64] rd_size@256 bus@258 vendor@260 product@264 version@268 country@272 rd_data@276）
uhid_input2_req    = 4098 字节
事件号：DESTROY=1  START=2  OPEN=4  CREATE2=11  INPUT2=12
```

其它已验证可达但**没有**给出 order-1 原语的面：`/dev/binder`（写路径要求缓冲在自己的 VMA 内，形成环）、`/dev/ptmx`、`perf(self)`。

---

## 4. 内核漏洞：CVE-2026-64560 现状

### 4.1 已确认成立的部分

**写入原语（反汇编确认，不是推测）**

```asm
posix_cpu_timers_exit_group:
  x19 = [sig + 0x128]              ; timerqueue_getnext(&sig->cputimer)
  cbz x19, next
  timerqueue_del(sig + 0x120, x19) ; 内部 rb_erase
  str xzr, [x19, #0x20]            ; it.cpu.task = NULL
  b loop
```

`__rb_erase_augmented` 在「只有左孩子」分支（伪造 `parent_color=0, rb_right=0, rb_left=TARGET`）：

```c
tmp->__rb_parent_color = pc;             // ★ *(TARGET) = 0
__rb_change_child(node, tmp, 0, root);   // 无害副作用
```

⇒ **`*(任意地址) = 0`**。伪造节点在 256 字节对象里的落点：**对象偏移 112**（页内 96）和 **240**（页内 224）。

**KASLR 已解决且可重复**：见 `KASLR_SOLVED.md`；每次 boot 用 `research/cap_pair.sh` + `pair_records.py` + `solve_live.py` 解 slide（spread=0 验证过两次）。
`selinux_state = _text + 0x2959630`（`KIMAGE_VADDR = 0xffffffc080000000`，`CONFIG_ARM64_VA_BITS=39`）。

### 4.2 卡住的部分：竞态本身

**结构性障碍（本轮新发现，很重要）**：

```
de_thread() 顺序：
  zap_other_threads(tsk)   ← 兄弟线程（含 victim 内的删除线程）在 ~1-10µs 内全部死掉
  wait thread_group_empty
  release_task(old_leader) ← sighand 在这里才置 NULL —— 真正的竞态窗口
```

⇒ **victim 内部的删除线程根本不可能命中 `release_task`**（它们死得更早）。
第一轮 probe3 观察到的 `+84` 泄漏，现在可以确认只是"没删掉的 timer"，**不是悬空节点**。
能命中 `release_task` 的只有**父进程的删除线程**（不会被 zap），但命中率极低。

**实测数据**

| 结构 | execs | 结果 |
|---|---|---|
| v33 / l60（父进程删除） | 8,000 | 0 fault |
| l62（父进程删除 + uhid order-1 喷洒） | 3,200 | 0 fault |
| l63/l64（victim 内删除 + uhid 喷洒） | 17,000+ | 0 fault |

按 45 execs/s：100 万次 = 6 小时，1000 万次 = 2.5 天。若真实命中率 1e-6 需 ~25 小时。

**已测过的正向事实**（为下一轮省时间）
- `freetest`：exec 之后父进程补删 **会真正释放对象**（ok=1000，cache 61 slabs → 30 slabs）
- `l64` 诊断：`del_fail` 的 errno 全是 **22 EINVAL = 已删完**，不是失败；排空实测 `1197/1197 → 664/966`
- 排空延迟 ~3 s（`714 → 1030 @t+1s → 489/693 @t+3s`）

---

## 5. 本轮新建的两个判据工具（下一轮直接复用）

### 5.1 SELinux 拒绝 oracle（极其有用）

```sh
logcat -d -b all 2>/dev/null | grep "avc:"
```

任何被拒的操作都会留下 `avc: denied { write } ... tcontext=u:object_r:<label>:s0 tclass=blk_file permissive=0`。
**以前"写了但不知道有没有生效"的问题从此可判。**

本轮用它一次性关掉三条路：

```
hypsys(uid 0) 写 misc            → denied  tcontext=misc_block_device
hypsys(uid 0) 写 android_esp_b   → denied  tcontext=android_esp_block_device
hypsys(uid 0) 写 /data/local/tmp → denied  tcontext=shell_data_file (search)
hypsys(uid 0) 写 /data/anr       → 成功（oracle 有效性验证）
```

### 5.2 CIL 策略直查（本地全量）

`plat_sepolicy.cil`(3.3 MB) / `vendor_sepolicy.cil`(2 MB) / `system_ext_sepolicy.cil` / `odm_sepolicy.cil` 都在工作区。
例：`boot_block_device`（含 `bcp_a=sda1`、`boot_a`）的写规则只有一条 `update_engine_common`。

---

## 6. 已封死的路（附证据，别再走）

| 路径 | 结论 | 证据 |
|---|---|---|
| **官方解锁 / token / 账号** | 数学死路 | token = 36B 含芯片序列号，XBL 内 RSA 验签；原作者结论"除非 bootloader 自身有漏洞" |
| **写 misc 改锁状态** | 双重不成立 | ①GBL 里 misc 只做 BCB，与锁状态无关；②`hypsys` 写 misc 实测 avc denied |
| **固件逆向（uefi/tee/xrse）** | 密码学边界 | `header+0x110 == 1 ⟺ body 熵 8.0`，22 个签名镜像 100% 吻合；`ddr_param*` flag=0 是明文对照组；bl2/xloader 也加密 ⇒ **key 在 efuse，软件里永远没有** |
| **固件解压** | 已穷举 | LZMA(全 lc·lp·pb·dict)/XZ/zlib/deflate/gzip/zstd/brotli/lz4/bz2/7z/**EDK2 Tiano** 全失败；`_FVH`=0 |
| **oem 命令注入** | 白名单极小 | 通：`device-info`、`poweroff`、`unlock`(被 provider 拒)；封：`dm-verity-enforcing`、`set-gpu-preemption`、`gbl-partition-info`、`reboot*`、`continue`、`powerdown`、`set_active` |
| **bcp/bootconfig 注入 cmdline** | 策略封锁 | `boot_block_device` 写规则只有 `update_engine_common` |
| **mqsas 服务后门** | 无命令执行 | `code 1` 的 actionsCSV 不进 shell；`code 2` 塞 `;`/`$()` 只杀调用者；MiSight 里 `RuntimeUtil.exeCommand` 是**死代码**（零调用点） |
| **属性触发 init 动作** | 无可控参数 | 354 个 `on property:` 块、16 个含 exec；shell 只能设 4 个，它们的 exec 参数全固定 |
| **通用 LPE** | config 全关 | 无 `CONFIG_USER_NS`、无 `CONFIG_CRYPTO_USER_API_AEAD`（Copy Fail 不可用）、`/dev/binderfs` 不可达（binderfs UAF 不可用） |
| **上游 6.18.22 补丁** | 无产出 | 277 条，shell 可达 ∩ 安全 = 9 条，全需 CAP_NET_ADMIN 或未编译 |
| **`--flags 2` / 摘 descriptor / dtbo 降级** | 不成立 | 只关 hastree；`allow_verification_error` locked 必须 false；删 descriptor 需重签顶层 vbmeta |

---

## 7. ⚠️ 第一轮 `HANDOVER.md` 需要修正的地方

1. **`0x4b` 不是 magic** —— 是 Rust `Ok` 判别值；`"miscDevice is not unlocked"` 是字符串池错觉（`"misc"` + `"Device is not unlocked"` 两串相邻）。
2. **锁状态判据不是 misc** —— 真判据是 EFI protocol `read_device_status`(+0x10)，provider 在加密固件里。
3. **"写 misc 后重启仍 locked" 这个实验无效** —— 写入被 SELinux 挡掉从未落地（avc 实证）。
4. **符号配对**：`0xffffffe9f09aa2a8` 是 `i2c_dw_xfer+0x1c8`（模块 `xring_i2c`），不是 `worker_thread`。
5. **`bootstrap_slide.py` 的 "33 candidates"** 是恒等式（64MB/2MB），无效。
6. **uhid 走 `write()` 不走 ioctl**；`uhid_event` 是 packed，union 在偏移 **4**。
7. **`xrse.img` 的 body 在 0x8000**，`bl2/npu` 在 0xCB0，`npu` 是唯一 `total > body_end` 的。

---

## 8. 资产清单

### 8.1 内核侧（`rom/`）

| 文件 | 说明 |
|---|---|
| `Image-4.0.21.0.bin` | 42,940,928 B，`text_offset=0`，`image_size=0x29a0000`；含 `.BTF` @0x1aed000（4.27 MB） |
| `vmlinux-4.0.21.0.elf` | 139,213 符号，可直接给 capstone 用 |
| `boot-4.0.21.0.img` | 解出的 boot 分区（100 MB） |
| `btf_dump.py` / `btf_screen.py` | BTF 结构 dump / order-1 窗口筛查 |
| `kdisasm.py` | **按符号反汇编设备真实内核**（`python kdisasm.py <elf> <image> <sym> [n]`） |
| `ota_extract.py` | HTTP Range 从 9 GiB OTA 提单个分区的工具 |
| `lhasa-OS4.0.{6,18,21}.0.zip` | 三个版本的整包 OTA |
| `fw/` | 30 个分区镜像：`BOOTAA64.EFI`(明文 1.58 MB)、`android_esp.img`(8 MB FAT12)、`uefi.img`(加密 2 MB)、`tee.img`、`xrse.img`、`pvmfw.img`(ANDROID! 明文)、`bl2/bl31/xloader`、各 `ddr_param*` 等 |

### 8.2 利用代码（`research/`）

| 文件 | 用途 |
|---|---|
| `cap_pair.sh` + `pair_records.py` + `solve_live.py` | **每次 boot 解 KASLR slide**（spread=0） |
| `uhid_probe.c` | uhid 可用性验证（packed 布局，4380 字节事件） |
| `uhid_spray.c` | order-1 喷洒验证（含全零+指针模式） |
| `freetest.c` | 证明 exec 后父进程补删会真正释放 |
| `l62.c` | 父进程删除 + uhid 喷洒（3,200 execs，0 fault） |
| `l63.c` / `l64.c` | victim 内删除 + 父进程补删 + uhid 喷洒；**l64 是解耦架构，45 execs/s** |
| `l64_loop.sh` | 持续战役脚本 |
| `avc_probe.sh` | **SELinux 拒绝 oracle** |
| `binder_step.c` / `binder_step2.c` / `binder_dev.c` / `binder_where.c` | binder 写路径边界标定 |
| `hypsys_rules.txt` / `prop_triggers.txt` | mqsas 策略 / 354 个属性触发块 |
| `GBL_INTEL.md` | GBL 源码结构、协议定义、已知漏洞（带 URL） |
| `XIAOMI_UNLOCK_INTEL.md` | 小米解锁史（带 URL 与可信度评级） |
| `UEFI_UNPACK.md` | 固件加密证明（含 22 镜像 crypt flag 表） |

### 8.3 其它

- `fb3.py` —— 自定义 libusb fastboot 客户端。**支持 `FB_VID`/`FB_PID` 环境变量**：
  bootloader 是 `0x18d1:0xd00d`，**fastbootd 是 `0x18d1:0x4e11`**。标准 `fastboot.exe` 枚举不到本机（驱动绑定问题）。
- `jars/` + `jadx_mqs/`(2133 java) + `jadx_c1/`(1891 java) + `jadx_misight/`(2251 java) —— MIUI 服务反编译
- `%TEMP%\gbl_repo` —— GBL 全量源码（`gbl-android17`）

### 8.4 设备侧当前状态

- `l64_loop.sh` 后台战役在跑（日志 `/data/local/tmp/l64c.log`），约 45 execs/s
- 设备健康：uptime 连续、`enforce=1`
- **注意**：设备停在 bootloader 时 XRing 的 GBL **没有** `reboot`/`continue`/`powerdown` 命令，
  只有 `oem poweroff` 可用；恢复方式 = 长按电源键 ~15 s（正常会先短暂进 fastbootd 再进系统）

---

## 9. 下一轮建议优先级

1. **先判 64560 竞态是否值得继续**（推荐做法）
   在 l64 架构上做**时序扫描**：把 exec 释放点相对删除风暴的相位参数化（0/10/20/…/90%），
   每个相位跑固定量，看是否有相位能出 fault。这比盲目堆量有信息量。
2. **把 uhid 原语用到别的内核 bug 上**（用户已选的方向）
   现在有了"全内容可控、持久、order-1、非特权"的 256 字节对象，
   任何需要 reclaim 的 UAF/OOB 都可以从这里起。重点复查：
   - binder 写路径那个"缓冲必须在自己 VMA 内"的环（扫 `binder_update_page_range` 全部调用点）
   - `posix_cpu_timer` 之外的时间子系统路径
3. **一旦拿到 permissive/root**，立刻按 §2 执行：`hypsys code 7` 写 `android_esp_a`
   → 自造 EFI/GBL 调 `write_lock_state`(+0x48) → 永久解锁。
   写 ESP 前记得：`android_esp_b` 是不活跃槽，可以先在它上面验证写入。

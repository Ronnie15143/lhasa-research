# Xiaomi 18 Fold (lhasa / XRing O3) — BL 解锁与 Root 可行性实测报告

生成时间：2026-10-22
设备：Xiaomi 18 Fold，`2608BPX34C`，codename `lhasa`，国行
内核：`6.18.21-android17-5-g284297031c53-abogki553682993-4k`
系统：Android 17 (SDK 37)，HyperOS `OS4.0.21.0.XPNCNXM`，SPL **2026-08-01**

---

## 一、结论摘要

| 目标 | 结论 | 依据 |
|---|---|---|
| **BL 解锁** | **设备侧已封死，无可行路径** | fastboot 实测：`unlocked: no`、`unlocked-critical: no`、`fb lock: true`、`fetch`/`oem` 全拒、不实现 `flashing` 协议 |
| **内核 root** | **理论可行，需自研漏洞利用** | 无 CAP、`USER_NS` 禁用、BTF 不可读、SPL 2026-08；公开 CVE 基本已修 |
| **SELinux 提权** | **唯一域转换（shell→mcd）无产出** | mcd 域孤立，`fd use` 被拒，stdout 无法回传 |

---

## 二、启动链架构（从固件镜像实测还原）

```
xloader.img  (BL1)              加密 entropy 8.00
  → bl2 / bl31 (TF-A)           加密
    → uefi.img (UEFI firmware)  加密 entropy 8.00   ← 锁逻辑实现在此层
      → android_esp.img / EFI/BOOT/BOOTAA64.EFI
            = GBL (Generic Bootloader) 明文 PE32+ ARM64, 1,585,152 B
        → fastboot / AVB / 加载 Android
```

**关键**：`BOOTAA64.EFI` 是 Google 开源 GBL 的协议客户端，**不含解锁命令**。
其 EFI 协议面（符号未 strip）：

```
gbl_efi_avb::GblAvbProtocol::read_device_status
gbl_efi_avb::GblAvbProtocol::write_lock_state      ← 写锁状态唯一入口
gbl_efi_avb::GblAvbProtocol::read_persistent_value / write_persistent_value  ← RPMB
gbl_efi_avb::GblAvbProtocol::read_rollback_index
gbl_efi_fastboot::GblFastbootProtocol::command_exec / get_var / get_var_all
gbl_efi_boot_control::GblBootControlProtocol::set_active_slot
```

真正的校验和落盘在 **加密的 uefi.img** 里，离线逆向成本极高。

---

## 三、fastboot 实测数据（自制客户端采集）

因 `fastboot.exe` 只枚举 `AndroidUsbDeviceClass`，而设备被 Zadig 绑为通用 `USBDevice`，
故自研 `fb3.py` 通过 libusb/WinUSB 直接实现 fastboot 协议（响应按 USB short-packet 界定，非 NUL）。

### 3.1 bootloader 身份

```
version          : EDK2-XRING 1.0 user
kernel           : uefi-gbl
variant          : XR_UFS
is-userspace     : no
unlocked         : no
unlocked-critical: no
current-slot     : a   (b 槽 unbootable)
max-download-size: 0x20000000
parallel-download-flash: yes
```

### 3.2 解锁 token（设备侧明文交出）

```
base64url: VQEHKwEQU5y9IG-QlB5TL7CKVTQesAMFbGhhc2ECEHB1EpDx2llTE_nToP5R_mc
raw (47B) : 5501072b | 0110 <16B> | 0305 "lhasa" | 0210 <16B>
```

结构为 TLV：magic `55 01`、两段 128-bit 随机数、设备代号 `lhasa`。
**token 内不含签名** → 必须由小米服务器 RSA 私钥补签。

### 3.3 命令面实测

| 命令 | 结果 |
|---|---|
| `getvar:all` | ✅ 完整 484 行变量表（已存 `fastboot_getvar_all.txt`） |
| `oem help` | ❌ `fb lock: true, operation not permitted` |
| `fetch:secinfo:0:512` | ❌ `Command not allowed.` |
| `flashing get_unlock_ability` | ❌ `Invalid flashing arg`（不实现 flashing 协议） |
| `reboot` / `continue` / `powerdown` | ❌ `Command not found` |
| `getvar:secure` / `lock-state` / `unlock_ability` / `at-vboot-state` | ❌ `NotFound` |

**结论**：除 `getvar` 读变量外，无任何可用写/读分区入口。`fb lock: true` 是统一闸门。

---

## 四、SELinux 攻击面测绘

策略文件全部可读（`/sys/fs/selinux/policy` + 5 份 CIL），已解析（`analyze_sepolicy2.py`）。

- shell 域 `service_manager find` 仅 **20 个**标签，**无任何小米/XRing 服务**
- shell 对 OEM 域仅 3 条规则，其中唯一"活路"是域转换：

```cil
(allow shell mcd      (process (transition)))
(allow shell mcd_exec (file (read getattr map execute open)))
(allow mcd   mcd_exec (file (read getattr map execute open entrypoint)))
```

`/system_ext/bin/mcd`（84,648 B，`root:shell`，shell 可执行）执行后进入 `u:r:mcd:s0`。

**实测结果：域转换成功但无产出** —— mcd 域被禁止使用 adbd 的 fd：
```
avc: denied { use } for path="socket:[...]" scontext=u:r:mcd:s0 tcontext=u:r:adbd:s0 tclass=fd
avc: denied { read } for name="u:object_r:vendor_default_prop:s0" scontext=u:r:mcd:s0
octvm: setgroups to readproc failed
```
且 `/dev/xiaomi_memsw_state` 设备节点在当前配置下**不存在**。
→ mcd 域孤立，无法作为提权或信息回传通道。

---

## 五、内核攻击面评估

```
CapEff: 0000000000000000     ← shell 无任何有效 capability
CapBnd: 0000000000008000c0
CONFIG_USER_NS is not set    ← 绝大多数现代 LPE 链前置条件失效
CONFIG_NF_TABLES is not set  ← netfilter LPE 面不存在
CONFIG_INIT_ON_FREE_DEFAULT_ON 未开   ← UAF 可利用（有利）
CONFIG_RANDSTRUCT_NONE                ← 无结构体随机化（有利）
CONFIG_MODULE_SIG_PROTECT=y 但 SIG_FORCE 未开 → root 后可 insmod 未签名模块
CONFIG_IO_URING=y (+ZCRX, FUSE_IOURING)
CONFIG_XDP_SOCKETS=y 但需 CAP_NET_RAW → shell 够不着
CONFIG_NFC=m, CONFIG_NFC_NCI is not set
/sys/kernel/btf/vmlinux → Permission denied
```

### 已核实的候选 CVE

| CVE | 内容 | 影响范围 | 对本机 |
|---|---|---|---|
| CVE-2026-31629 | nfc: llcp 缺 return（CVSS 8.8） | 6.13–6.18.24 | 公布于 **2026-04-24**，SPL 2026-08 极可能已修 |
| CVE-2026-90086 | xsk_tx_metadata_request 提权 | ≤ 6.18.51 | 需 `CAP_NET_RAW`，shell 无 CAP → 不可用 |
| CVE-2026-98471 | KVM 提权 | 未确认 | pKVM 环境，需先有内核执行权 |

---

## 六、已排除的路径

1. **改 bootloader 绕过校验** — uefi/xloader/tee 全为 entropy 8.00 密文；GBL 明文层只是协议客户端
2. **fastboot 免锁命令** — `fb lock: true` 封锁 oem，`fetch` 被拒，无 reboot 类命令
3. **RPMB 魔数擦除（Jz8Root 思路）** — 该方案依赖 MTK Kamakiri BROM；XRing O3 为自研 AP，无 BROM
4. **高通 GBL/efisp 漏洞** — 本机无高通 ABL
5. **官方 token 通道** — 国行 2026 年无答题场次；token 绑定设备代号，不可跨机复用
6. **SELinux 域转换** — 唯一转换（mcd）为孤立域，无输出、无设备节点
7. **`mi-factory-tool`** — 实测为 XML 驱动的硬件产测工具（作者 taojun@xiaomi.com），零解锁能力

---

## 七、仍可推进的方向（按性价比）

1. **等新 CVE**：关注 2026-09 / 2026-10 之后公布的 Android 内核 EoP（本机 SPL 停在 2026-08）
2. **自研内核漏洞**：可用面收窄至 `io_uring`、`binder`、`f2fs`、`erofs`、`Mali (mali_kbase.ko)`、`dmabuf`
   - 有利条件：`RANDSTRUCT_NONE`、`INIT_ON_FREE` 关闭
   - 不利条件：无 CAP、无 USER_NS、BTF 不可读
3. **硬件路径**：devicetree 暴露 `mi_t2_jtag`（Mi T2 安全芯片 JTAG）、`xrse`、`sec_log_bl31/hyp`
4. **`mipatch` 分区机制**（32MB，小米专有补丁通道）—— 未深入研究

---

## 七bis、系统服务攻击面测绘（第二轮，2026-10-22 追加）

### 关键修正：原先"shell 只能触达 20 个服务"的结论是错的

```cil
(allow shell base_typeattr_1030 (service_manager (find)))
(typeattributeset base_typeattr_1030
  (and (service_manager_type) (not (apex_service default_android_service ...))))
```

`base_typeattr_1030` 是**集合运算属性**（`service_manager_type` 减黑名单）。
解析 CIL 时必须处理 `and` / `not` 表达式，否则会把整片攻击面漏掉。
**实际结论：shell 可 find 几乎全部服务**，实测 `cmd -l` 列出 **527 个**可调用服务，
`am start` / `settings get` 均成功。

### root 进程的 binder 接口测绘（`service call` 盲枚举 + AIDL 反编译）

| 服务 | uid / 域 | 可达 code | 结论 |
|---|---|---|---|
| `misight` (`android.MiSight.IMiSightNativeService`) | **root** / `u:r:misight:s0` | **1-8 全部** | 8 个方法**零权限检查**，但全部是 `notify*` 通知类，无危险操作 |
| `hypsys_ssi` (`IHypSysSsi`) | **root** / `u:r:hypsys_ssi_default:s0` | 9 返回 true；10+ 需复杂参数 | `service call` 的简单类型喂不进 parcelable |
| `security` (`miui.security.ISecurityManager`) | system_server | 7/8/9/11/18/20/21/22/23 通过；20 接受 String | 方法面是应用锁/访问控制，不通向 root |
| `miui.mqsas.*` | root | `onShellCommand` 拒绝 | `Failed transaction` / 无实现 |

`misight` AIDL 完整接口（`MiSightService.apk` 反编译所得）：

```java
TRANSACTION_notifyPackLog        = 1   int  无参
TRANSACTION_setRunMode           = 2   void (String, String)
TRANSACTION_notifyUploadSwitch   = 3   void (boolean)
TRANSACTION_notifyConfigUpdate   = 4   void (String)
TRANSACTION_notifyUserActivated  = 5   void 无参
TRANSACTION_notifyNoCatchLog     = 6   void (String, String)
TRANSACTION_notifyPackLogByCycle = 7   int  (int)
TRANSACTION_getVersion           = 8   String
```

调用实测（全部成功，无权限拒绝）：
```
service call misight 4 s16 'selftest'                  → void OK
service call misight 2 s16 'selftest' s16 'selftest'   → void OK
service call misight 6 s16 'selftest' s16 'selftest'   → void OK
service call misight 8                                 → "1.0"
```
但调用后 `/data/system`、`/data/miuilog`、`/data/mqsas` 无任何文件时间戳变化，
无 logcat 输出 → 功能为内部状态通知，不构成文件写/命令执行入口。

### 已排除的一个可疑广播面

`MiSightReceiver` 无 permission 保护，注册了：
```
com.misight.intent.action.updateEvent            → setRunMode(testName, filePath)
com.misightserviceability.intent.action.rebootdevice
com.misightserviceability.intent.action.detection
```
`am broadcast` 实测可达（`Broadcast completed: result=0`），但：
- `updateEvent` 分支被 `Constant.DEBUG = Build.IS_DEBUGGABLE` 挡住，本机 `ro.debuggable=0` → **死代码**
- `detection` 分支可执行，但走的是 `com.miui.misightservice`（普通 app）的检测引擎，非 root 路径

### `/data/local/tmp` 中的既有文件（非我创建）

```
k2daemon     4.7MB  ELF aarch64, NDK r25b, 含 "com.k2tap.core.Portal" / "k2tap_core exited..."
k2reader.so  380KB  ELF aarch64, NDK r28c
```
时间戳 2026-09-13，属主 shell。导入 `system`/`fork`/`execvp`/`setenv`，
是某个自动化点击工具（k2tap）的守护进程，**以 shell 权限运行，与 root 无关**。排除。

---

## 八、设备侧改动清单（全部可逆/已还原）

| 操作 | 状态 |
|---|---|
| `/data/local/tmp/.probe_write_test`（验证可写可执行） | 已删除 |
| `/data/local/tmp/.mcd_copy`（复制 mcd 供分析） | 已删除 |
| `adb reboot bootloader` | 已重启回系统 |
| 分区写入 / 刷机 / 解锁尝试 | **零次** |

---

## 九、工具与产物

| 文件 | 说明 |
|---|---|
| `fb3.py` | 自制 fastboot 客户端（libusb/WinUSB，绕过 fastboot.exe 的 ClassGUID 限制） |
| `fb_diag.py` | USB 底层诊断 |
| `analyze_sepolicy2.py` | SELinux 策略 S-expression 解析器（typeattribute 递归展开） |
| `triage_fw.py` / `scan_fw_strings.py` / `dump_strings.py` | 固件镜像与二进制字符串分析 |
| `fat_walk.py` / `fat_list.py` / `fat_extract.py` | FAT/ESP 镜像解析（含被混淆 FAT 表的连续读取兜底） |
| `fastboot_getvar_all.txt` | 484 行完整 bootloader 变量表 |
| `rom/fw/BOOTAA64.EFI` | 从 android_esp.img 提取的 GBL（明文 PE32+ ARM64） |
| `rom/fw/*.img` | 26 个固件镜像（OTA `OS4.0.21.0.XPNCNXM`） |

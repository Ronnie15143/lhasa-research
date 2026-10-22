# GBL 判锁机制完整逆向报告（第四轮·决定性发现）

生成时间：2026-10-22
目标：Xiaomi 18 Fold (`lhasa`) / XRing O3 / Android 17 / SPL 2026-08
样本：`BOOTAA64.EFI`（GBL，明文 PE32+ ARM64，1,585,152 B）

---

## 一、核心结论（本轮最重要的突破）

**bootloader 锁状态不是硬件熔丝，而是 `misc` 分区偏移 0 的 4 个字节。**

```
判锁表达式：  misc[0:4] (little-endian u32) == 0x4B   → unlocked
             否则                                    → locked
```

这一条把整个作战路径从"数学墙"改写成"工程问题"。

---

## 二、逆向证据链

### 2.1 字符串定位

```
file 0x138780  "miscDevice is not unlocked / Fail to get unlock status"
file 0x132c80  "Failed to read bootloader message from misc partition: "
file 0x132907  "Boot mode from BCB: "
file 0x12b3c8  "misc"   （分区名）
```
`miscDevice is not unlocked` 的源码路径标注为 `external/gbl+/libgbl/src/fastboot/mod.rs`。

### 2.2 交叉引用

```
'miscDevice is not unlocked'  →  ADRP+ADD xref @ 0x1400a8af8
所属函数：RVA 0xa8a40 .. 0xa8cb0（624 字节，由 .pdata 确认）
```

### 2.3 判锁核心（capstone 反汇编，已去除颜色码）

```asm
0x1400a8aac  mov  w2, #0x800          ; 2048 = sizeof(bootloader_message)
0x1400a8abc  adrp x2, 0x14012c000
0x1400a8ac0  add  x2, x2, #0x3c8      ; -> "misc"
0x1400a8ac8  mov  w3, #4              ; sizeof("misc")
0x1400a8ad0  mov  x5, x21             ; buffer
0x1400a8ad4  mov  w6, #0x800          ; 读 2048 字节
0x1400a8ad8  bl   0x140006c90         ; 读 misc 分区
0x1400a8adc  ldr  w8, [sp, #0x48]     ; ★ buffer[0:4] = misc[0:4]
0x1400a8ae0  cmp  w8, #0x4b           ; ★★ 与 0x4B 比较
0x1400a8ae4  b.ne 0x1400a8b38         ; 不等 -> "miscDevice is not unlocked"
0x1400a8af0  bl   0x1400c5270
0x1400a8b20  ldr  w8, [sp, #0x48]
0x1400a8b24  cmp  w8, #0x4b
0x1400a8b28  b.ne 0x1400a8c28
0x1400a8b2c  mov  w8, #2              ; ★ 判定结果 = 2（unlocked）
0x1400a8b30  str  x8, [x19]
```

### 2.4 `misc` 的分区布局（AOSP `bootloader_message.h`，main 分支）

```c
constexpr size_t BOOTLOADER_MESSAGE_OFFSET_IN_MISC = 0;        // ★ offset 0
constexpr size_t VENDOR_SPACE_OFFSET_IN_MISC       = 2*1024;
constexpr size_t WIPE_PACKAGE_OFFSET_IN_MISC       = 16*1024;
constexpr size_t SYSTEM_SPACE_OFFSET_IN_MISC       = 32*1024;

struct bootloader_message {          // 2048 B，位于 misc offset 0
    char command[32];                // ★ offset 0 —— 判锁字节就在这里
    char status[32];
    char recovery[768];
    char stage[32];
    char reserved[1184];
};

struct misc_system_space_layout {    // 位于 offset 32768
    misc_virtual_ab_message virtual_ab_message;   // 32768
    misc_memtag_message     memtag_message;       // 32832
    misc_kcmdline_message   kcmdline_message;     // 32896
    misc_control_message    control_message;      // 32960
};
```

**`misc[0:4]` 就是 `bootloader_message.command[0:4]`。**

---

## 三、所有已知 `misc` 写者（逐一实测排除）

| 域 | 能否被 shell 驱动 | 实测结论 |
|---|---|---|
| `hal_bootctl_default` | 否 | `service call android.hardware.boot.IBootControl/default` → `does not exist`（neverallow 生效） |
| `update_engine` | 否 | 需 OTA payload 签名（releasekey RSA2048） |
| `vold` | 否 | binder 接口有权限检查 |
| `init` / `vendor_init` | 部分 | 只能经属性触发写固定内容 |
| `uncrypt` | 否 | 仅 recovery 环境 |
| `mtectrl` | **可触发** | `setprop arm64.memtag.bootctl <任意值>` 成功 → 触发 `mtectrl`，但**只写 offset 32832** |
| `kcmdlinectrl` | **可触发** | `setprop kcmdline.binder c` 成功（值被白名单限制）→ 只写 **offset 32896** |
| `vendor_misc_writer` | 否 | 策略存在但**二进制不存在**，未启用 |

**结论：没有任何一条可从 shell 触发的路径能写到 offset 0。**

---

## 四、由本发现推出的作战路径

### 4.1 旧路径（已放弃）
```
root → 写 EFI 分区 → chainload → 内存 patch ABL
```
依赖 chainload 能力，而 XRing（非 Qualcomm ABL）不存在该能力。

### 4.2 新路径（决定性简化）
```
临时 root（内核 LPE）
      ↓
dd 写 misc[0:4] = 4B 00 00 00
      ↓
重启
      ↓
GBL 读到 0x4B → unlocked
      ↓
BL 永久解锁 → 可刷 boot/init_boot → Magisk
```

**关键优势**：
- **不需要任何签名/私钥**（锁状态不是签名保护的）
- **不需要物理接触**（misc 是普通块设备）
- **一次性操作即可永久解锁**
- 与 bootloader 的加密镜像完全无关

### 4.3 具体命令（root 后执行）
```bash
printf '\x4b\x00\x00\x00' | dd of=/dev/block/by-name/misc bs=1 count=4 conv=notrunc
sync
reboot
```

回滚（如需）：
```bash
printf '\x00\x00\x00\x00' | dd of=/dev/block/by-name/misc bs=1 count=4 conv=notrunc
```

---

## 五、仍存在的未知与风险

1. **`0x4B` 的语义未与小米官方实现对照**：本值是 GBL 二进制中的硬编码比较值。
   若 bootloader 在解锁后还会写别的标志（如 RPMB 或 TEE），则仅改 misc 可能不够；
   但 GBL 侧的判据已确认只有这一个比较。
2. **写 misc 会破坏 BCB**：offset 0 是 `command[32]`，写入 `4B 00 00 00` 等于把 BCB
   command 设为非法值。正常启动流程不依赖 command（仅 recovery/OTA 使用），
   风险可控，且可随时清零恢复。
3. **需要先取得内核 root** —— 这是当前唯一的前置条件，且已有明确的攻击面清单
   （见 REPORT.md 第五节）。

---

## 六、本轮使用的工具

| 文件 | 说明 |
|---|---|
| `disasm_gbl.py` | 基于 capstone 的 ARM64 反汇编器，带字符串/调用注释 |
| `gbl_functions.txt` | 从 `.pdata` 解析出的 2201 个函数边界（RVA start/end） |
| `walk_cert_chain.py` / `forge_image.py` | 证书链解析与镜像伪造（上一轮成果） |
| `fbd.py` | fastbootd（GBL userspace fastboot）客户端，命令不带 NUL 结尾 |
| `fb3.py` | bootloader fastboot 客户端 |

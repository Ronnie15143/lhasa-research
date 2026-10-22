# 小米 BL 解锁 / 信任链 历史绕过手法与工具 —— 情报汇总（lhasa / XRing O3 定向）

> 2026-10-22，研究型子智能体产出。**纯资料 + 本地静态**，未触碰设备。
> 每条结论带来源；可信度分级：**A** = 一手代码/官方文档，**B** = 多源一致的二手报道，**C** = 单一二手/社区传闻，**D** = 未找到。
> 本地静态结论均标注「本地实测（静态）」，可复现命令写在条目里。

---

## 0. 结论先行：按可行性排序

| # | 路径 | 现状判定 | 关键前提 | 可信度 |
|---|---|---|---|---|
| **1** | **GBL / efisp（ESP）类代码执行链**：往「被 bootloader 当 EFI 应用加载、但未做真实性校验」的分区里塞自定义 EFI app，由它调用 AVB/verified-boot 协议把设备状态写成 unlocked | **本机结构上最可能活着的一条**。GBL 侧（BOOTAA64.EFI）本地已证明**没有 PE 签名**；`android_esp` **没有 AVB footer**。缺的只是「(a) 该分区是否在 vbmeta 哈希链里 + (b) 一个能写块设备的原语」 | 见 §6.4 两个判定实验 | A（机制/代码）+ 本地实测 |
| **2** | **EDL(9008) + 签名 programmer（firehose）直写分区** | 对骁龙新机已有「免鉴权 firehose」生态；**XRing O3 无任何公开 programmer / 工具链**，且自研 SoC 的 EDL 鉴权逻辑无公开材料 | 需要 XRing 的 firehose loader（当前 D） | B/C |
| **3** | **小米 `oem` 私有子命令**（`oem unlock` / `unlock-go` / `fus` / `selinux` …） | `oem unlock` 在 locked 下**真正执行了**但被 provider 拒绝（本机已实测）。命令表已从骁龙 ABL 抽出（§2），但 XRing 侧的命令实现在加密的 `uefi.img` 里，无法静态枚举 | 需要 provider 侧另一条未加锁检查的方法 | A（命令表）+ 本地实测 |
| **4** | **Mi Unlock Token 伪造** | **数学上死路**：token 由 XBL/TEE 内 RSA 验签，无私钥无法伪造；所有社区工具（MiUnlockTool/termux-miunlock）都是「取 token → 送小米服务器换签名」的客户端，不是绕过 | — | A |
| **5** | **账号绑定/资格绕过**（HyperOS 社区限制） | 只是绕「小米服务器的绑定门槛」，**仍然必须走官方 `oem unlock`**；且 HyperOS 2.0.203.0 起已修 | — | A |
| **6** | **misc/BCB、dtbo/vbmeta 降级、slot B、boot_reserve/bcp、工厂模式** | 逐条判定见 §7，**对 Android 17 + AVB2 + GBL 基本全灭** | — | A/本地实测 |

---

## 1. 已实测设备事实（不重复验证，仅对齐）

- BL 锁定：`getvar unlocked → no`、`oem device-info → "Device unlocked: false"`、`ro.boot.flash.locked=1`、`vbmeta.device_state=locked`、AVB green。
- `oem unlock` → **`FAIL Set unlock mode failed`**（指令被接受并执行，provider 拒绝）；`oem unlock-go` → 设备从 USB 消失（reboot）。
- `oem` 白名单：`device-info` 允许；`help/?/info/get-hwid/read-persist/selinux/check-token/get-boot-info` → `fb lock: true, operation not permitted`；裸 `oem` → `Command not found`。
- 锁状态在 TEE/UEFI 的 AVB provider 内（`gbl_efi_avb`），不在任何 Android 可写分区。
- 现有静态基础（父会话）：`rom/fw/uefi.img` 格式 100% 复现（brainpoolP384r1、`F3 Devices Cert`、签名覆盖 `[0,0x570)`、body 摘要 @0x1EC、可自签出 `uefi_FORGED.img` 且 5/5 自验证通过）；`uefi.img`/`xloader.img` 本体是**加密体**，信任根是否内置无法静态判定。

---

## 2. 小米 `oem` 命令族：社区可查的完整表 + locked 行为

### 2.1 骁龙 ABL 侧（可抽，权威）

`chkndrp/fastboot-oem-extractor` 直接对 ABL 做 UEFI PE 解析 + `oem *` 字符串匹配，README 给出的实机样例（Redmi Note 14 Pro+ 5G / amethyst）：

```
fastboot oem allow-wipe-userdata    oem audio-framework      oem device-info
oem disable-charger-screen          oem dm-verity-enforcing  oem edl
oem enable-charger-screen           oem fbreason             oem getguid
oem hwid                            oem lkmsg                oem lock
oem lpmsg                           oem off-mode-charge      oem poweroff
oem ramdump fat                     oem select-display-panel oem set-gpu-preemption
oem set-hw-fence-value              oem uart-enable          oem uefilog
oem unlock
```

来源：<https://github.com/chkndrp/fastboot-oem-extractor>（A，一手工具 + 实机输出）
用法：`python -m fastboot_oem_extractor ./abl.elf`（可直接对本机 `rom/fw/*.img` 里任何含 UEFI PE 的镜像跑）

> 注意两条对我们特别有意义：
> - **`oem set-gpu-preemption`** —— 就是 2026 年骁龙 8EG5 解锁链里那个 **cmdline 注入 / SELinux permissive** 的入口（§6.1）。
> - **`oem dm-verity-enforcing`** —— 语义上直接动 dm-verity 强制状态，值得在 XRing 上试（本机白名单未含此名，需先确认是否 404 还是 403）。

### 2.2 通用小米 fastboot 表（社区 wiki，含 MTK/高通差异）

Uotan Wiki《Fastboot 命令》（2025-04-15 版）明确列出：

```
fastboot oem device-info      # 输出 BL 锁状态(非 MTK)
fastboot oem lks              # 输出 BL 锁状态(MTK)
fastboot oem reboot-recovery  # 重启进 recovery
fastboot oem poweroff
fastboot oem lock             # 重新上锁并清空数据
fastboot oem unlock           # 解锁并清空数据（小米须绑账号+申请+等 7 天+用工具）
fastboot oem edl              # 进入高通 9008，无需工程线/短接，"可无视 BL 锁线刷"
```

来源：<https://wiki.uotan.cn/index.php?title=Fastboot_命令&oldid=937>（B）

**`oem edl` 是这批命令里唯一被社区标为「可无视 BL 锁」的**——它是骁龙平台进 9008 的便捷口。本机实测该名在 `fb lock: true` 白名单内但 `operation not permitted`（即：命令存在、被锁态拦），这本身就说明 XRing 的 fastboot 扩展沿用了小米那套「命令族同名 + 锁态门控」的结构。

### 2.3 XRing 侧的实际命令名（本机实测 + 本地字符串）

- 本机白名单实测存在的名字：`device-info`、`help`、`?`、`info`、`get-hwid`、`read-persist`、`selinux`、`check-token`、`get-boot-info`。
- GBL（`rom/fw/BOOTAA64.EFI`）**自身**带的 oem 命令（本地字符串，A）：

```
"An async task is launched. To sync manually, run \"oem gbl-sync-tasks\"."
"Images not loaded. Run \"oem gbl-pause-fastboot-after-load\""
```

  ⇒ GBL 有一族 `oem gbl-*` 自管理命令。GBL 源码在 AOSP `platform/bootable/libbootloader`（`gbl/`，含 `docs/efi_protocols.md`、`docs/gbl_efi_avb_protocol.md`），**能直接读源码枚举命令**（本次网络到 `android.googlesource.com` 超时，需在能出网的环境补取）。

### 2.4 `Set unlock mode failed` 到底是什么

| 检验 | 结果 |
|---|---|
| 该串是否在 GBL（`BOOTAA64.EFI`，2121 条字符串全扫）里 | **不存在**（本地实测，A） |
| 该串在 GBL 里的近邻语义串 | 只有 `Device is not unlocked` / `Fail to get unlock status` / `miscDevice is not unlocked` / `AVB verification failed … Device is unlocked: … Continue current boot attempt.` |
| 社区对该串的整理 | **未找到**（D）——搜 `"Set unlock mode failed" fastboot xiaomi` 无任何技术贴/issue 命中 |

**结论（本地实测 + 推理）**：这条错误串来自 **Xiaomi 的 provider / fastboot 扩展实现（`uefi.img` 密文体或 TEE）**，不是 GBL、也不是「缺 token」类错误。
对照 lrh2000 的 token 路径（§3），「token 缺失/验签失败」在 AOSP 风格 ABL 上会走另一条错误串；这里返回的是「**模式设置失败**」＝ 请求已经进到「我要改解锁模式」这一步，被更底层的状态机/授权拒绝。也就是：**不是少一个参数，而是这条路本身被 provider 关了**。
→ 与父会话 §10.7 的第 3 条推测（`oem unlock` 可能走 protocol 另一条方法、未被 locked 检查覆盖）**已被这条实测否掉一半**：它确实走了另一条方法，但那条方法内部也校验锁/授权。

---

## 3. Mi Unlock / MiFlashUnlock 协议：token 结构与验签（一手逆向）

`lrh2000/Xiaomi-bootloader` 是对小米 ABL/XBL 的完整逆向（Redmi Note 8T / ginkgo，MIUI V11.0.4.0），**这是全网唯一把 token 结构和验签代码都写出来的资料**：

- 解锁流程：`fastboot getvar token` → 把 token 送小米服务器换签名 → `fastboot download:<sig>` → `fastboot oem unlock`。
  代码：`fastboot/unlock.py`（23 行，就是这三步）、`fastboot/fake_fastboot.c`（伪 fastboot 抓包）。
- **token = 36 字节结构的 base64url（`+`→`-`、`/`→`_`，48 字符）**：

```
55 01 01 20 01 10 <16B RNG> 03 06 "ginkgo"(codename) 02 04 <serial, LE>
                 ^^ 0x24-4=0x20 总长
```

- **验签：RSA（非对称），验签在 XBL 的 Mi-Token UEFI protocol 里**（GUID `068AAE46-BDC6-4073-85D5-31C5EEF19A15`），ABL 的 fastboot server 只是它的 wrapper；`verify/verify.S` 是原始汇编、`verify/verify.c` 是等价 C 重写。
- 作者原话（README 首行）：

> **"TL;DR: It is impossible to bypass Xiaomi's server to unlock the boot loader, unless the boot loader itself contains vulnerabilities."**

来源：<https://github.com/lrh2000/Xiaomi-bootloader>（A，一手逆向 + 二进制 blob + 可编译的验签复现）

### 3.1 社区工具的真相（都是「客户端」，不是绕过）

| 工具 | 干什么 | 结论 |
|---|---|---|
| `MiForge/MiUnlockTool` | "retrieve encryptData(token) for Xiaomi devices" —— 取 token/加密数据交给官方流程 | 服务器依赖，非绕过（A：README） |
| `RohitVerma882/termux-miunlock` | 同上，Termux 版 | 同上 |
| `MiForge/MiAssistantTool` | 用 **MiAssistant 模式**刷官方 recovery ROM（**无需解锁**） | 只能刷**官方签名**包，不能改 boot（A） |
| `MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass` | 绕 HyperOS「社区解锁资格绑定」限制（PHP + php-adb 驱动官方绑定流程） | **仍需官方 `oem unlock`**；HyperOS 2.0.203.0 起已修（A） |
| `TheAirBlow/HyperSploit` | 同上类（绑定/资格），已修 | 同上 |

### 3.2 「离线/本地 token 伪造」评估

**不可能**，理由是可判定的：
1. 签名是 RSA，公钥在 XBL/Xsps 内，私钥在小米服务器；
2. token 含 **16 字节 RNG + codename + 芯片序列号**，即使截获某台机器的有效签名也绑死那台（换设备即失效）；
3. 本机实测 `oem check-token` 存在但被锁态拦——说明 XRing 上这套 token 机制**还在**，只是入口门控。
→ **不要把预算放在这条线上**（A）。

---

## 4. EDL(9008) / firehose：小米新机的现实边界

| 事实 | 来源/可信度 |
|---|---|
| `bkerler/edl` README：「Secure loader with SDM660 on Xiaomi not yet supported (**EDL authentification**)」——即小米在 660 一代就上了 EDL 鉴权 | <https://github.com/bkerler/edl>（A） |
| `Giovix92/EDLUnlock`（"Bootloader Unlock from EDL"）只能覆盖 **MSM89xx / 2018 年前**（利用 alephsecurity 2018 的 firehose 漏洞 + 直接改 `devinfo` 分区） | <https://github.com/Giovix92/EDLUnlock>（A：README 明确写 "every device manufactured before 2018"） |
| 骁龙新机生态里确实存在「**Auth-Free EDL Firehose**」（解锁/救砖），但那是**针对具体骁龙平台签名 loader 的泄露/改造**，不是通用能力 | XDA 帖标题：<https://xdaforums.com/t/unlock-bootloader-unbrick-xiaomi-8-elite-high-versions-auth-free-edl-firehose.4787466/>（B；正文被 Cloudflare 拦，未取到全文） |
| 小米 8EG5 一键解锁工具（`Linuxoid-cn/Mi8E-Unlocker`）**不依赖 EDL**：走 ADB + fastboot + 每机型 factory images / **工程 ABL** + `8750-Ennea.img`，README 写明「安全补丁 ≤ 2026-02-01」且「该补丁之后 **SELinux 提权路径**已被修复」 | <https://github.com/Linuxoid-cn/Mi8E-Unlocker>（A：README/Release 结构） |
| **XRing O3 的 programmer / firehose / bootrom 研究** | **未找到任何公开资料**（D）。搜 `"XRing O3" bootloader EDL`、`xring bootrom` 全部无技术命中 |

**结论**：EDL 这条对 XRing **目前等于零**——不是「被鉴权挡住」，而是连可用的 programmer 都不存在于公开面。要推动只能自研（需要 SoC 文档 / 硬件 / 极高投入），性价比最低。

---

## 5. XRing（玄戒）专研现状：公开面的真实进度

这段是本次研究里**最影响决策**的一块，来源是 2026-09-09 的一篇长文（含 B 站/知乎原始链接与作者原话引用）：

- **XRing O1（小米 15S Pro / Pad 7 Ultra）发布一年多，从不在小米官方解锁支持范围内**。社区到 **2026-08-12** 才由「宵宵狸猫」做出**临时 root**（不接 BL：装 Zygisk 跑 LSPosed，不用解锁 bootloader），**重启即失效**。
- 该临时 root **只撑到 HyperOS 3；作者明确说 OS4 玩不了这套**。
- **XRing O3 的两台首发机（小米 18 Fold、Pad 9 Pro Max）出厂就是 HyperOS 4**。
- 首发日 B 站那些「O3 越狱/解 BL」视频是 **12 秒 AI 引流**；有人问 O3 会不会有方案，O1 方案作者的回答是五个字：**「o3 不会有了」**。
- 该文对 XRing 的三条结构性判断：安全架构无公开文档、底层刷机面是黑盒（变砖有没有救砖口没人测过）、工具生态为零（MiFlash 最后版本已是 6 年前）。

来源：<https://post.smzdm.com/p/a3m0e33d/>（B；引用了 B 站 BV 号与知乎问题）

### 5.1 但 2026-10 出现了「18 Pro / 18 Fold 已被解锁」的报道——必须区分开

| 报道 | 机型/平台 | 关键信息 | 可信度 |
|---|---|---|---|
| hyperdroid 2026-10-09 | 18 Pro（骁龙 8 Elite Gen 6）+ 18 Fold（XRing O3） | 18 Pro 由 **realMlgmXyysd** 解锁；18 Fold 由 **LittlenineEnna** 解锁；「方法与常规流程不同，**看起来基于安全漏洞**」；原 Mi Community 帖被删，Telegram 尚存 | B |
| mundoxiaomi 2026-10-07 | 同上 | 明确 18 Pro = **Snapdragon 8 Elite Gen 6**；给出 X 原帖 <https://x.com/realMlgmXyysd/status/2106995910173688319>；强调「两种架构都被绕过」 | B |
| gizchina / xiaomi-miui.gr 多语种 | 同上 | 同源转载，无新增技术细节 | C |

**判读**：
- 18 Pro 是**高通平台**，用 GBL/efisp 链（§6）解释得通（Qualcomm 侧 2026-03 那条链的后续/变种）。
- 18 Fold 是 **XRing O3**，若报道为真，则说明 **GBL→efisp 这一类「加载未验签 EFI 应用」的缺陷不是高通独有**，而是 GBL 架构本身在 XRing 上的移植缺陷；这与本文 §6.4 的两个判定实验高度吻合。
- 但截至本次检索，**没有任何一条公开资料给出 18 Fold 的技术细节/代码/复现步骤**（D）。所有报道都停在「社区有人做到」。
- ⚠ 与 §5 的「o3 不会有了」（9 月）直接冲突。可能是：(a) 10 月确实出现了新突破；(b) 报道把「18 Pro 的方法」外推到 Fold；(c) 一次性、未公开的私货。**在你拿到可复现材料前，按 (b)/(c) 处理，别当成已解决问题。**

---

## 6. 核心：GBL / efisp（ESP）代码执行链 —— 2026 年唯一被公开验证的「非官方解锁」

### 6.1 三段式漏洞链（骁龙 8EG5，2026-03 公开）

中文侧最完整的一段总结（2026-03-16，含补丁时间线）：

> 「8EG5 机型实现绕过 Bootloader 解锁利用了 3 个漏洞：其一是高通骁龙 8 Elite Gen5 的 **cmdline（OEM）漏洞**，允许 SELinux 被临时设成宽容模式，**在谷歌的 2026 年 2 月安全补丁中修复**。其二是**小米独有的系统服务权限漏洞**，严格来说是小米留的后门，**可以用 root 身份来执行任何命令**。其三是**通用引导程序（GBL）的 efisp 分区校验漏洞**，由于该分区权限极高，**甚至能向 RPMB 写入数据**，使其成为绕过限制、解锁 Bootloader 的关键通道。这三个漏洞里，利用前两个，可以实现临时 Root；利用第三个，可以实现解 BL；三个放在一起，就可以实现绕过 BL 解锁并 Root。」

来源：<https://www.cnblogs.com/coldjelly/p/19726799>（B，作者为实操者，给了脚本/顺序/降级细节）

同事件的媒体版（IT之家/凤凰，2026-03-13）：

> 「在安卓 16 系统中，ABL 从 **efisp** 分区加载通用引导程序（GBL）后，**仅检查其是否为 UEFI 应用，却未验证其真实性**。因此，用户可以直接向该分区写入并执行未签名代码……研究人员发现，高通的 `fastboot oem set-gpu-preemption` 命令**缺乏输入参数校验**，只需追加 `androidboot.selinux=permissive` 即可篡改 SELinux 权限……重启后 ABL 直接加载用户植入的自定义 UEFI 应用，该应用随后把 `is_unlocked` 改为 1，完成解锁……小米可能在 HyperOS 3.0.304.0（中国区）封堵；高通也已修复该 fastboot 命令的参数校验。」

来源：<https://tech.ifeng.com/c/8rSHeeTgBaP>（B，转 Android Authority）

### 6.2 原始 PoC 代码（一手，A）

`kasnria001/qualcomm_gbl_exploit_poc`（977★，2026-03 发布，作者自述 1 月中发现、2 月与 Littlenine 合作、3 月公开）：

README 原话：

> "Qualcomm adds a gbl boot stage in its ABL because it wants to limit OEM's ability. gbl is loaded as an uefi app. it stores in **efisp** partition. you need to flash the efi file into the partition. Qualcomm uses its own verification instead of UEFI secure boot. **But GBL is unsigned.** So we can load unsigned uefi app. This way, we can achieve **arbitrary code execution**. So we can overwrite the **lock state storing in RPMB**. Because the ABL itself reads/writes **devinfo** via a special function. Before milestone, we can call the function to overwrite the lock state."

仓库内容：`VbRwStateApp.c`、`VbRwStateApp.inf`、**`gbl_efi_unlock.efi`**、`gbl_efi_relock.efi`（各 40960 B）。
来源：<https://github.com/kasnria001/qualcomm_gbl_exploit_poc>（A）

**核心 12 行（对父会话最有价值的可复用模板）**：

```c
#define VB_RW_BUF_SIZE 3344
UINT8 Buf[3344];
gBS->LocateProtocol(&gEfiQcomVerifiedBootProtocolGuid, NULL, (VOID**)&VbProtocol);
VbProtocol->VBRwDeviceState(VbProtocol, READ_CONFIG,  Buf, BufLen);  // 先读整块状态
Buf[13] = 0; Buf[14] = 0;                                            // 只改目标字段
VbProtocol->VBRwDeviceState(VbProtocol, WRITE_CONFIG, Buf, BufLen);  // 再整块写回
```

（原始 GUID 注释：`{0x8e5eff91,0x21b6,0x47d3,{0xaf,0x2b,0xc1,0x5a,0x01,0xe0,0x20,0xec}}`）

### 6.3 为什么这条链在架构上成立（第三方深度分析，A/B）

`alephgsm.com` 的《Qualcomm GBL Boot Chain Research on Snapdragon 8 Gen 5》（2026-03-09）把机制拆到可复用的方法论级别：

1. **GBL 被无条件尝试加载**：`LinuxLoader.efi` 不查开关，直接 `GetBlkIOHandles` 按**分区标签**（`efisp` / `efisp_a` / `efisp_b`）找块设备 → `DevicePathToGbl` → `gBS->LoadImage(FALSE, …)` → `StartImage()`。`StartImage` 返回后仍回到 LinuxLoader，所以「多跑一个 EFI 应用」是这条链的**设计内行为**。
2. **UEFI Secure Boot 在该路径上未被强制**：没有 PK/KEK/db 的完整enrollment、构建里也未见 `DxeImageVerificationLib`/`AuthVariableLib` 的引用 ⇒ `LoadImage()` 不等于验签。
3. **解锁状态已服务化**：现代机型上「锁状态」不是可写分区里的布尔位，而是 **RPMB/TEE 背后的结构化对象**，只能通过 `QCOM_VERIFIEDBOOT_PROTOCOL->VBRwDeviceState()` 这类**官方状态机接口**读写；且状态块 **≈3344 字节、带 magic/header**，不能只翻一个 bit。
4. **结论（原文）**：「一旦自定义 EFI payload 能通过 GBL 路径执行，就**不必再逐级击败更早的启动阶段**；只要够得着『合法固件本来就在用的那套 verified-boot 状态机』，就已经足够。」

来源：<https://alephgsm.com/2026/03/09/gbl-boot-chain-research/>（A，逐函数/逐字符串级；本次已抓全文存档 `research/xm_src/aleph_gbl_chain.txt`）

同族工程化项目（把该原语做成「伪 locked」产品，反向证明原语可靠）：`SuperTurtleDev/gbl_root_canoe` —— 把 `BDS.efi` 裸写进 `efisp`，让真 ABL 加载一个**自带 fastboot（superfastboot）** 的 BDS，从而获得 `fastboot flashing unlock/lock`、`fastboot flash <任意分区>`、`fastboot boot xxx.efi` 的能力；其 `boot.efi`（改过的 ABL）与 `BOOTENTRIES` 放在 `persist` 的 `efisp/` 目录。
来源：<https://github.com/SuperTurtleDev/gbl_root_canoe>（A：README + 完整源码树）

### 6.4 映射到 lhasa / XRing O3：本机静态证据（本次新做）

| # | 检验 | 命令/方法 | 结果 | 意义 |
|---|---|---|---|---|
| 1 | `android_esp.img` 是否有 AVB footer | 读末 64 B 判 `AVBf` | **无**（`pvmfw.img` 有） | ESP 不是「自带签名的 AVB 分区」；是否被 vbmeta 的 hash descriptor 覆盖**待查** |
| 2 | `BOOTAA64.EFI`（= GBL）是否有 PE 内嵌签名 | 解析 PE DataDirectory[4] | **`size = 0`**（无 Authenticode/证书表） | **GBL 本体未签名** —— 与 §6.2「GBL is unsigned」完全同构 |
| 3 | `Set unlock mode failed` 是否 GBL 产生 | 2121 条字符串全扫 | **不在** | 拒绝来自 Xiaomi provider，不是 GBL |
| 4 | GBL 是否有 `efisp` 字样 | 字符串扫描 | **0 命中**；但 ESP 里唯一文件就是 `EFI/BOOT/BOOTAA64.EFI` | XRing 上「efisp 的等价物」**就是 ESP（`android_esp_a/b`）**，不是独立 efisp 分区（本机分区表无 `efisp`，共 123 个分区） |
| 5 | GBL 里 AVB protocol 的方法名 | 字符串扫描 | `gbl_efi_avb` / `GblAvbProtocol` / `read_device_status` / `validate_vbmeta_public_key` / `GblEfiAvbKeyValidationStatus`；**未见任何 write/ set 方法** | 读写方法表需从 **AOSP GBL 源码**确认（`gbl/docs/gbl_efi_avb_protocol.md`），本地二进制只暴露了被 GBL 调用的那两个 |

**由此得到两个「一锤定音」的判定实验（都不需要刷机、不需要 reboot）**：

**(A) `android_esp_a` 是否在 AVB 链里**
从完整包取 `vbmeta.img`（父会话手上 OTA 里应有；`runs/android/rom/lhasa-OS4.0.2x.0.zip`），然后：

```bash
avbtool info_image --image vbmeta.img | grep -i -A3 'android_esp'
# 或 python3 -c "…" 直接解析 descriptors，看有没有 hash descriptor 指向 android_esp
```

- 有 hash descriptor ⇒ ESP 内容被顶层 vbmeta 的签名保护 ⇒ 改 ESP 会被 AVB 拦（但注意：**GBL 的 AVB 校验与「谁验 GBL」是两件事**，见下）。
- 无 descriptor ⇒ **ESP 完全不在信任链里** ⇒ 结构与 efisp 同构，链路成立，只剩写原语。

**(B) XRing 的 AVB provider 是否提供「写」方法**
读 AOSP `platform/bootable/libbootloader` 的 `gbl/docs/gbl_efi_avb_protocol.md` + `gbl/` 源码（本次网络到 googlesource 超时，需换环境）。要看两件事：
1. protocol 方法表里除 `read_device_status` / `validate_vbmeta_public_key` 外，**是否有 `write_device_status` / `set_device_state` 之类**；
2. GBL/loader 是否要求「调用方必须是 GBL 自己」（有的实现用 image handle 白名单，有的不校验）。

> 若 (A) 无 descriptor 且 (B) 有写方法 ⇒ 只要能把自定义 EFI app 放进 ESP，就能解锁。而**写 ESP 的原语**正是父会话 §2 那条被低估的线：`hypsys`/`IMQSNative` 的 **uid-0 文件写**。它当时只在 **52 个目录**上测过；**应该改测块设备路径**（`/dev/block/by-name/android_esp`、`/dev/block/by-name/uefi`、`/dev/block/by-name/persist`）——efisp 链只需要**一次块设备写**，不需要执行语义。

---

## 7. 历史经典招式：逐条判定（对 Android 17 + AVB2 + GBL）

| 招式 | 机制 | 对 lhasa 的判定 | 依据 |
|---|---|---|---|
| `fastboot oem unlock` 变体 / 竞态 | token 验签 / provider 状态机 | **死**。本机 `oem unlock` 真执行→provider 拒；token 需小米私钥 | 本机实测 + §3 |
| `oem unlock-go` | 高通工厂式「免 token 解锁」分支 | **未定论，只有 1 个动作值得做**：父会话记录「设备立即从 USB 消失（reboot）」。这类实现的典型行为是**解锁+清数据+立即重启**，fastboot 端看不到返回值。→ 若**还没在重启后读过状态**，应做一次：`getvar unlocked` / `oem device-info`。若仍 `no`，此路关闭 | 本机实测（半） + 高通 ABL 行为常识（C） |
| BCB / misc 注入（`bootonce-bootloader` / `boot-fastboot`） | 改 misc 让 bootloader 换模式/命令集 | **死**。GBL 里 misc 只有两处用途（BCB 命令写入 `0xc5270` 表：`bootonce-bootloader`/`boot-recovery`/`boot-fastboot`/`boot-rescue`；13 KB 分区读写栈），**与锁状态无关**；且 `misc` 对 shell `EACCES` | 父会话 §10.1/§10.5（A）+ 本机实测 |
| `dtbo` / `vbmeta` 降级 | 刷旧镜像触发 anti-rollback 边界 bug | **死**。AVB rollback index 由 `avb_ops` 回调读 RPMB/TEE，`antirollback=1`；且 locked 下根本刷不进 | AOSP libavb + 本机实测 |
| slot B 上「未验证分区」 | 备用槽校验缺失 | **死**。本机 `vbmeta`/`vbmeta_system`/`vbmeta_vendor`/`boot`/`dtbo`/`sec_dtbo`/`pvmfw` 全都有 `_a/_b` 双槽，各自成对签名；GBL 对两槽走同一 `avb` 路径 | 本机 `getvar all`（123 分区，A） |
| `boot_reserve`（1 MB）/`bcp`（16 KB）被读但未签名 | bootloader 读裸分区当配置 | **低概率**。两者都存在（`boot_reserve_a/b` 0x100000、`bcp_a/b` 0x4000），但本机在 GBL 里**没有任何字符串引用**它们；被谁读需看 `xloader`（加密）。列为「若做静态穷举，可查 xloader 解密后引用」 | 本机静态（B） |
| 工厂/售后模式（`*#*#6484#*#*`、MiAssistant） | 售后刷机通道 | **不通向解锁**。MiAssistant 只能刷**官方签名** recovery ROM；diag 入口改不了 AVB 状态 | `MiForge/MiAssistantTool`（A） |
| AVB `--flags 2`（disable verification） | 让 vbmeta 声明不校验 | **死，且有双重理由**：① `--flags` 的两位是 `HASHTREE_DISABLED(1<<0)`=2 与 `VERIFICATION_DISABLED(1<<1)`；`flags=2` 只关 dm-verity hashtree，**不解除对 vbmeta/boot 的签名要求**；② libavb 里 `VERIFICATION_DISABLED` 分支的采纳取决于 bootloader 传入的 `allow_verification_error`，AOSP 要求 **locked 时必须为 false**；③ 最要命的是**你改不了 vbmeta 也刷不进去**（locked） | AOSP `external/avb`：`avb_vbmeta_image.h`（flags 定义）、`avb_slot_verify.c`（`VERIFICATION_DISABLED`/`HASHTREE_DISABLED` 处理）；签名问题见父会话 |
| 把 `boot` 从验证链摘掉 | 删 vbmeta 里的 descriptor | **死**：删 descriptor 要重签顶层 vbmeta（小米发布密钥）；且 GBL 报错文案已写明「GBL requires the vbmeta partition as the top-level verification structure」+「`X` is required but isn't loaded by avb. The partition may be missing or **not included in the vbmeta**」——**缺 descriptor 也是失败**，不是放行 | 本机 GBL 字符串（A） |
| MTK 那套 `seccfg` + RPMB magic（`Jz8PNRUF`） | 擦 RPMB magic 让 LK 回落 seccfg | **平台不适用**，但**架构启示极大**：小米确实会用「**RPMB 里的 milock 记录覆盖 seccfg**」做双层锁。XRing 上等价物就是 provider 的状态块（§6.3 的 3344 B 结构） | `Jz8Root/xiaomi-hyperos-bootloader-unlock`（A，MTK only） |

---

## 8. 建议的下一步（按性价比，全部可静态/只读完成）

1. **（最高）把 `android_esp` 是否在 vbmeta 链里钉死**：取 `vbmeta.img` → `avbtool info_image` 或自写 descriptor 解析，找 `android_esp`。这一步决定 §6 这条链是「结构成立」还是「已封」。
2. **读 AOSP GBL 源码**（`platform/bootable/libbootloader/gbl/`）：`docs/gbl_efi_avb_protocol.md` 看 provider 方法表有无写方法；`gbl_efi_fastboot` 源码枚举全部 fastboot/flashing 命令（比在二进制里猜快 100 倍）。
3. **把 `hypsys`/`IMQSNative` 的 uid-0 写原语改测块设备**：目标路径 `/dev/block/by-name/android_esp`、`uefi`、`persist`、`misc`（只读 open 即可判定 SELinux 是否放行；不要写）。父会话 §2 已证明它在**目录**上能 root 写/读/建，块设备是**没测过的一块**。
4. **`oem unlock-go` 后的状态复读**（若尚未做）：`fastboot getvar unlocked` + `oem device-info`，确认那次「USB 消失」是不是真解锁+清数据+重启。
5. **在 XRing 白名单里补测两个已知危险命令**：`oem dm-verity-enforcing`、`oem set-gpu-preemption`（骁龙链的第一环就是后者）。只观测返回码，不做写操作。
6. **追 18 Fold 的 10 月解锁**：Telegram（realMlgmXyysd / LittlenineEnna 频道）+ X 原帖；目前公开面无技术细节，价值在「有没有人放出方法」。

---

## 9. 来源清单

| 编号 | URL | 类型 | 可信度 |
|---|---|---|---|
| S1 | <https://github.com/kasnria001/qualcomm_gbl_exploit_poc> | 原始 PoC + 源码（`VbRwStateApp.c`、`gbl_efi_unlock.efi`） | A |
| S2 | <https://alephgsm.com/2026/03/09/gbl-boot-chain-research/> | GBL 启动链逐层分析（LoadImage / Secure Boot / VBRwDeviceState） | A |
| S3 | <https://github.com/SuperTurtleDev/gbl_root_canoe> | 把 efisp 原语工程化（superfastboot） | A |
| S4 | <https://www.cnblogs.com/coldjelly/p/19726799> | 8EG5 三漏洞链 + 实操注意事项 + 补丁时间 | B |
| S5 | <https://tech.ifeng.com/c/8rSHeeTgBaP> | 媒体版（Android Authority 转述）：efisp 未验签 + `set-gpu-preemption` 注入 + 3.0.304.0 封堵 | B |
| S6 | <https://github.com/lrh2000/Xiaomi-bootloader> | Mi Token 结构 + RSA 验签逆向（含汇编/C 复现） | A |
| S7 | <https://github.com/chkndrp/fastboot-oem-extractor> | 小米 ABL `oem *` 命令抽取工具 + 实机命令表 | A |
| S8 | <https://wiki.uotan.cn/index.php?title=Fastboot_命令&oldid=937> | 小米 fastboot/oem 通用表（含 `oem edl` 可无视 BL 锁） | B |
| S9 | <https://github.com/MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass> | HyperOS 绑定资格绕过（已修） | A |
| S10 | <https://github.com/Linuxoid-cn/Mi8E-Unlocker> | 8E 一键解锁工具（工程 ABL + factory images，补丁 ≤2026-02-01） | A |
| S11 | <https://github.com/bkerler/edl> | 小米 EDL 鉴权说明 | A |
| S12 | <https://github.com/Giovix92/EDLUnlock> | EDL 改 devinfo 解锁（仅 2018 前 MSM89xx） | A |
| S13 | <https://github.com/Jz8Root/xiaomi-hyperos-bootloader-unlock> | MTK seccfg + RPMB magic 双层锁（平台不适用，架构有启示） | A |
| S14 | <https://post.smzdm.com/p/a3m0e33d/> | XRing O1/O3 解锁现状（O1 仅临时 root、OS4 封死、「o3不会有了」） | B |
| S15 | <https://hyperdroid.ru/xiaomi-18-pro-and-xiaomi-18-fold-bootloaders-unlocked/> | 2026-10-09：18 Pro（Mlgm）/18 Fold（Littlenine）被解锁，疑基于漏洞 | B |
| S16 | <https://www.mundoxiaomi.com/noticias/xiaomi-cerro-bootloader-casi-completo-china-este-desarrollador-ha-tirado-puerta-abajo-xiaomi-18-pro-18-fold> | 同事件 + 18 Pro = SD 8 Elite Gen 6 + X 原帖链接 | B |
| S17 | <https://c.mi.com/> 原帖 | 已被删 | D |
| S18 | AOSP `platform/external/avb`（`avb_vbmeta_image.h` / `avb_slot_verify.c`） | flags=2 语义与 `allow_verification_error` | A |
| S19 | AOSP `platform/bootable/libbootloader`（`gbl/`、`docs/gbl_efi_avb_protocol.md`） | GBL 源码/协议文档 —— **本次网络不可达，待补取** | A（待取） |

### 未找到（明确记为 D，避免后人重复挖）
- `"Set unlock mode failed"` 的任何社区解释/issue/技术贴。
- `oem fus` / `oem fus-unlock` 的**任何**一手资料（父会话旧笔记称「小米 FUS = 工厂解锁流程，历史上有过绕过」，本次检索**无法证实**，暂按 D 处理）。
- XRing O3 / xring / `xring_o3_asic` 的 bootrom、EDL、programmer、设备树、固件解包研究。
- 18 Fold（XRing O3）10 月解锁的**方法/代码/复现步骤**。

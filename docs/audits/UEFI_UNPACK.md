# `uefi.img` 解包与 `gbl_efi_avb` provider 追踪

设备：Xiaomi 18 Fold（lhasa，XRing O3，ARM64）。目标：解开 `runs/android/rom/fw/uefi.img`，拿到实现
`gbl_efi_avb` EFI protocol 的 DXE driver（`read_device_status()` 的真实现）。

**结论先行：`uefi.img` 的 body 是加密的（不是压缩、不是明文），没有密钥解不开；但 provider 的
完整 ABI（9 个方法的 vtable 顺序）和消费者侧代码都拿到了，能不读 DXE 直接调它。**

---

## 0. TL;DR（四问四答）

| 问题 | 答案 |
|---|---|
| **(a) uefi.img 是压缩/加密/明文？** | **加密**。逐镜像的 `crypt flag`（header+0x110）= 1；body 熵 7.99990、256 值均匀（χ²=278，df=255）、2 MiB 内 **131072 个 16 字节块无一重复**（排除 ECB）；所有主流压缩流在最全参数空间下解压全部失败；签名摘要 `SHA-384` 存的是**密文的哈希**（encrypt-then-sign）。 |
| **(b) 是否解开？** | **没有**。解出 **0 个 DXE 模块**（body 全密文）。 |
| **(c) 找到 `gbl_efi_avb` 的 provider 了吗？** | **没找到实现体**，但定位到**消费者**并逆出**完整 9 方法 vtable**（见 §4）。provider 只可能在加密 body 内。 |
| **(d) 下一步去哪找？** | **不要再往 `tee.img`/`xrse.img` 挖**（同容器、同 flag=1、同熵 8.0，一样是密文）。改走：① 动态 hook `LocateProtocol` 取 GUID → 直接调 protocol（推荐）；② patch 明文 `BOOTAA64.EFI` 里的消费者；③ 运行态内存 dump；④ 找工程版/未加密固件。详见 §6。 |

---

## 1. 容器格式（实测，逐字段验证过）

所有 `fw/*.img`（除 `android_esp.img`/`pvmfw.img`/`mcf_ota.img`/`modem.img`/`sap*.img`）都是同一种签名容器：

```
0x000  u64  magic = 0x123456789ABCDEF0        (字节 f0 de bc 9a 78 56 34 12)
0x008  u32  version = 2
0x00C  u32  total   = header_end + body_len
0x010..0x060  ( offset, size ) 描述符表
0x060  u32  body_offset       ← 权威：不用再靠 4 KiB 对齐猜
0x064  u32  body_len
0x110  u32  crypt flag        ← 1 = body 已加密，0 = body 明文（见 §3 表）
0x1EC  48B  SHA-384(body as stored)   ← 逐字节核对命中，签署覆盖的是密文
0x570  ...  4 段 ECDSA 签名
0x5F0  ...  3 张 DER X.509 证书，各 0x239 字节（0x5F0 / 0x830 / 0xA70，末尾 0xCA9）
0xCA9 → 0xCB0 (16 字节对齐填充)
0xCB0  body ...
```

**body 起点不是猜的，有三重证据互相印证：**
1. 第三张证书的 DER `SEQUENCE`（`30 82 02 35`）长度算出结尾 = `0xA70 + 4 + 0x235 = 0xCA9`，对齐到 **0xCB0**；
2. header 自己的描述符 `+0x60` 写着 `(0xCB0, 0x200000)`；
3. 文件尾 `[total, EOF)` 是 **848 字节全零** padding，`total = 0xCB0 + 0x200000 = 0x200CB0`。

于是 `uefi.img` 的 body = **`[0xCB0, 0x200CB0)`，正好 0x200000（2 MiB）**。

> 附注：`total == body_off + body_len` 对 22 个签名镜像里的 21 个成立，唯一例外 `npu.img`
> （`body_end=0x67030`，`total=0xab6b0`，body 之后还有 0x44680 字节附加区）。不影响 `uefi.img`。

证书内容（明文可读，说明**只有 body 加密、header 是明文**）：`Xiaomi Inc.` / `Beijing` / `F3 Devices Cert`，
扩展 OID `2.16.840.1.113730.1.13`（nsComment）里塞着 `NVCOUNTER:0`（防回滚计数器）。

> 产物：`uefi_out/uefi_header.bin`（0xCB0）、`uefi_out/uefi_body.bin`（0x200000）

---

## 2. 判定「不是压缩」的全部尝试（全部失败）

| 格式 | 尝试范围 | 结果 |
|---|---|---|
| UEFI FV 签名 `_FVH` | 全文件 | **0 处** |
| `EFI_FIRMWARE_FILE_SYSTEM2/3_GUID`、LZMA/Tiano/LZ4/Brotli guided-section GUID | 全文件（磁盘混合序） | **0 处** |
| LZMA-alone（`5d 00 00` / props 0x5D） | 全文件 + body 多偏移 | 0 处；`lzma.decompress(FORMAT_ALONE)` 全失败 |
| LZMA **raw** | `lc∈{0,1,3} × lp∈{0,1,2} × pb∈{0,2} × dict∈{1M,8M,64M}`，skip ∈ {0,4,8,12,16,32,64,128,256,512} | 全失败（无一产出 >30% 可打印） |
| XZ / zstd / lz4-frame / gzip / bzip2 / 7z 魔数 | 全文件 | 0 处 |
| raw-deflate + zlib + gzip | `skip` 逐字节 `0..0x2000` × wbits ∈ {-15,15,31} | 全失败 |
| zstd 裸流 | skip `0..0x400` | 全失败 |
| brotli 裸流 | skip `0..0x200` | 全失败 |
| LZ4 block/frame | skip `0..0x200` × 目标长 1M..16M | 全失败 |
| **Tiano / EFI LZ77**（`uefi_firmware.efi_compressor.EfiDecompress`，真 EDK2 移植） | skip ∈ {0,4,8,16,32,64,256,0x1000} | **全部 `Failed to decompress`** |
| ELF / PE / Android bootimg / squashfs / PNG | 全文件 | 0 处 |
| ASCII / UTF-16 字符串 | body 内 | **UTF-16 = 0 条**；ASCII 全是随机噪声（`noise printable ratio 0.383 ≈ 98/256` 的理论值） |

`uefi_firmware` 已装（`pip install uefi_firmware pycryptodome`），其 `EfiDecompress(data, size)` 需要 2 个参数，
这也解释了父会话脚本里 `TypeError: takes exactly 2 arguments` —— 补上 size 后依然是 `Failed to decompress`。

---

## 3. 判定「是加密」的证据链

### 3.1 全镜像相关性：`crypt flag` 与 body 熵 100% 对得上

| image | body_off | body_len | body 熵 | flag@+0x110 | 判定 |
|---|---|---|---|---|---|
| uefi.img | 0xcb0 | 0x200000 | 7.99990 | 1 | 密文 |
| tee.img | 0xcb0 | 0x4e8100 | 7.99997 | 1 | 密文 |
| xrse.img | **0x8000** | 0x5ee00 | 7.99948 | 1 | 密文 |
| adsp / isp / sensorhub / xspm / xsps | 0xcb0 | 大 | ≥7.9998 | 1 | 密文 |
| bl2 / bl31 / xloader / hdcp / lpctrl / npu / xctrl_* | 0xcb0 | 中 | ≥7.997 | 1 | 密文 |
| **ddr_param0/1/3/5.img** | 0xcb0 | 0x3200/0xd00/0x1480/0x880 | **5.15–5.66** | **0** | **明文** |

22 个签名镜像（其中 `uefi_FORGED`/`uefi_POC` 是副本，原始镜像 20 个），
flag=1 ⟺ 熵≈8.0，flag=0 ⟺ 明文，**没有例外**。
明文那一组的 body 开头是自描述头 `a5 a5 5a 5a 17 07 26 20 | <body_len>`（例如 ddr_param0 的
`00 32 00 00` = 0x3200 = 它自己的 body_len），证明**同一容器格式支持明文 body**，`uefi.img` 只是把开关打开了。

### 3.2 分块结构：**不是 ECB**

```
body 16 字节块数 = 131072    distinct = 131072    重复值 = 0    max_repeat = 1
```
2 MiB 固件几乎必然含大量零填充/未初始化区，若走 ECB 会出现成百上千个重复密文块。**一个都没有 ⇒ 链式模式
（CBC/CTR/XTS）或流密码**。

### 3.3 跨镜像：**没有密钥流复用**

`uefi ⊕ tee`、`uefi ⊕ xrse`、`uefi ⊕ bl2` … 所有组合 XOR 后熵 = **8.000**，零字节率 ≈ 1/256（= 随机期望）。
各镜像 body 前 64 字节互不相同，且都不是对方的位移。⇒ **逐镜像独立 key/IV**，拿不到 key 就没有任何
known-plaintext 攻击面。

### 3.4 签名覆盖密文（encrypt-then-sign）

```
SHA-384(body_as_stored)  →  命中 header+0x1EC（逐字节相同）
SHA-256 / SHA-512 / SHA-1 / SM3(body) / 整文件哈希 → 均不命中
```
说明签署对象是**存储态密文**，加密是签名对象的一部分（也就意味着改 body 必须重签名）。

### 3.5 长度只对齐到 16 字节，不对齐 4 KiB

`bl2.img` body_len = `0x33a00`、`tee.img` = `0x4e8100` —— 都是 16 的倍数、却**不是** 4 KiB 的倍数。
这是**分组密码 16 字节填充**的特征，不是 flash/文件系统对齐，也不是压缩器会产生的尺寸。

### 3.6 弱密钥探针（万一厂商用固定弱 key）

8 个候选 key × {ECB, CBC(zeroIV), CTR(zeroIV)} 解前 64 KiB：**全部随机垃圾**，无 `_FVH`、无全零头。

### 3.7 加密边界在哪（重要事实）

`bl2.img` / `bl31.img` / `xloader.img` 的 body 也是密文。BL2 是**ROM 代码加载**的，ROM 不可能软件解密
—— 所以解密是**硬件做**的（efuse key + inline crypto engine），**密钥永远不会出现在任何一个镜像的软件里**。
这就是为什么「去 tee.img 找 key」这条路走不通。

**明文边界**：`android_esp.img`（FAT，1.69）、`BOOTAA64.EFI`（PE，明文）、`pvmfw.img`（ANDROID! bootimg，
5.35，含 31 处 LZMA-alone 头）、`mcf_ota.img`/`modem.img`/`sap.img`（裸分区，2–3）。
**密文边界**：所有 XRing 签名容器的 body（BL2 之后、Android 之前的整条引导链）。

> 结论：`uefi.img` 的 DXE driver **在密文体内，无密钥不可读**。继续在解压上花时间是负收益。

---

## 4. `gbl_efi_avb`：provider 没找到，但 ABI 全拿到了

### 4.1 消费者在明文 `BOOTAA64.EFI` 里（不在 ESP 里的另一份）

`android_esp.img` 只是 FAT 里存了同一份 EFI（文件起始 = 镜像内 0x7000，`0x12515b-0x11e15b=0x7000`），
**没有第二个 EFI app**。所以唯一含 `gbl_efi_avb` 痕迹的二进制就是 `BOOTAA64.EFI`。

命中的字符串全部是 **libefi 的泛型包装器**，即「通过函数指针表间接调用」的消费者侧：

```
efi::protocol::gbl_efi_avb::<impl efi::protocol::Protocol<
    efi::protocol::gbl_efi_avb::GblAvbProtocol>>::read_device_status::{{closure}}::thunk
self.interface().read_device_status
efi_types::defs::GblEfiAvbProtocol        （#[repr(C)] 的函数指针结构体）
```

`self.interface().read_device_status` 这种**经由 `interface()` 取表再调用**的形态，正是「provider 是别人装的」的
直接证据 —— 与父会话「provider 不在 BOOTAA64.EFI 里」的结论一致。

### 4.2 逆出的完整 vtable（9 个方法，按 .rodata 源码序）

`GblAvbProtocol` 的方法块位于 `0x11e14c..0x11e7a0`，每个方法一条
`<impl Protocol<GblAvbProtocol>>::<方法名>::{{closure}}::thunk`，严格顺序：

| # | 方法 | 作用（按名+上下文） |
|---|---|---|
| 0 | `read_partitions_to_verify` | 取出待验签分区清单 |
| 1 | **`read_device_status`** | **返回设备状态位图（锁状态 bit0）** |
| 2 | `validate_vbmeta_public_key` | 校验 vbmeta 公钥是否被信任 |
| 3 | `read_rollback_index` | 读防回滚计数 |
| 4 | `write_rollback_index` | 写防回滚计数 |
| 5 | `read_persistent_value` | 读持久化存储（TEE/RPMB 侧） |
| 6 | `write_persistent_value` | 写持久化存储 |
| 7 | `handle_verification_result` | 把验签结果回报给 provider |
| 8 | **`write_lock_state`** | **写锁状态** |

**交叉验证**：同一套方法在 `gbl_efi_boot_control`（7 个：`get_slot_count / get_slot_info / get_current_slot /
set_active_slot / get_one_shot_boot_mode / handle_loaded_os / fatal_error`）和 `gbl_efi_fastboot`
（`get_staged / vendor_erase / get_partition_type / start / stop / receive / send / flush`）上也是**全量、按序**列出，
与 AOSP GBL 上游定义吻合 —— 说明这个抽取口径可靠。

> 严谨说明：这些是 `.rodata` 里的诊断/日志字符串（旁边就是 `"Protocol method not found in caller ''"`、
> `"Required protocol not found: "`），所以严格说它们证明的是「这套接口有这 9 个方法、按此顺序实现」，
> 与 AOSP `gbl/docs/gbl_efi_avb_protocol.md` 的 vtable 顺序一致；**不是**从机器码里数出来的 slot 偏移。

### 4.3 GUID：没静态锚定住

- `GblAvbProtocol` 的 GUID 常量不与类型名相邻；`.rodata` 里能找到的 16 字节常量
  `E43176D7-B6E8-4827-B784-7FFDC4B68561` 在 `gbl_efi_debug` 和 `gbl_efi_boot_control` 两个名字后面**重复出现**，
  是共享常量，不是某个协议的 GUID。
- `android.googlesource.com` 在本机网络被墙（`curl: (28) Could not connect ...:443`），
  `cdn.jsdelivr.net` 的 AOSP 镜像返回 14 字节（未命中路径），拿不到官方文档里的 GUID 字面量。
- **建议**：GUID 改用动态手段取（见 §6 路径 A），或让有代理的环境拉一次
  `gbl/docs/gbl_efi_avb_protocol.md`。

### 4.4 关于「`read_device_status` 的反汇编」

**给不出** —— 实现体在 `[0xCB0, 0x200CB0)` 这段密文里，没有任何可反汇编的字节。
能给出的最大信息量就是 §4.2 的 ABI + 消费者侧「经由 `self.interface()` 函数指针表 + 标准 EFI 调用约定
（`EFIAPI`，aarch64 下 x0=self/this、x1..=参数）」。bit0 = unlocked 这一语义来自你们既有结论 + AOSP 文档，
本地无法从密文里再验证一次。

---

## 5. 产物清单

| 文件 | 说明 |
|---|---|
| `runs/android/research/uefi_analyze.py` | 容器头解析 + 分块熵/低熵孤岛 + χ² + 重复块 + 自 XOR + 全偏移魔数/GUID 扫描 + 字符串普查 |
| `runs/android/research/body_bruteforce.py` | body 定位 + LZMA-raw 参数空间暴力 + deflate/brotli/lz4 + 跨镜像密钥流复用检测 |
| `runs/android/research/final_tests.py` | EDK2 Tiano 解压 + 全偏移 zlib/zstd/brotli/lz4 + 弱密钥 AES + **签名哈希归属核对** + ECB 检测 |
| `runs/android/research/hdr_map.py` | 逐镜像 DER 证书链 → header 边界 → body 起点/长度/熵；`uefi_POC/FORGED` 与原件差异 |
| `runs/android/research/flag_find.py` | 加密 flag 定位（明文 body vs 密文 body 的 header 逐字节 diff） |
| `runs/android/research/str_hunt.py` | 全目录 `gbl_efi_avb` / `GblAvb` / `read_device_status` / `validate_vbmeta_public_key` 扫描（ASCII+UTF-16） |
| `runs/android/research/proto_extract.py` | 从 `BOOTAA64.EFI` 抽 vtable 方法序 + GUID 表锚定尝试 |
| `runs/android/research/table_dump.py` | 生成 §3.1 的全镜像对照表 |
| `runs/android/rom/uefi_out/uefi_header.bin` | 0xCB0 明文头（magic/total/描述符/crypt flag/SHA-384/4 签名/3 证书） |
| `runs/android/rom/uefi_out/uefi_body.bin` | 2 MiB 密文 body（2,097,152 B，sha256 见文件头注释脚本） |
| `runs/android/rom/uefi_out/container_table.md` | 全镜像 body 偏移/长度/熵/flag 表 |

`uefi.img` sha256 = `177625d9069b6cf22e096deab075a3f3f09ba25edf0cf06f1efb026789b5f455`。

---

## 6. 下一步（按性价比排序）

**A. 不读 provider，直接调它（推荐）**
provider 是「别人装好的 protocol」，那么**离线不需要它**。写一个极小的 EFI app（或 patch 现有 GBL），做：
```c
// 伪代码；GUID 待补（见 4.3）
EFI_GUID avb = GBL_EFI_AVB_PROTOCOL_GUID;
GblAvbProtocol *p = NULL;
gBS->LocateProtocol(&avb, NULL, (void**)&p);
UINT64 status = 0;
p->read_device_status(p, &status);   // slot 1
Print(L"device_status=0x%lx unlocked_bit0=%d\n", status, status & 1);
```
若想直接改锁状态，同表还有 slot 8 **`write_lock_state`** —— 这是本次新发现、之前没被列进攻击面的入口。
GUID 用路径 A' 取：在 GBL 里 hook `LocateProtocol`，把它收到的 16 字节打出来。

**B. patch 明文消费者**
`BOOTAA64.EFI` 是明文 PE，消费者在明文里。把 `Protocol::<GblAvbProtocol>::read_device_status` 的调用点
改成返回固定值（unlocked），比去啃密文 DXE 容易一个数量级。你们已经有 `uefi_POC.img` / `uefi_FORGED.img`
的改造流水线（`uefi_POC.img` 的做法是「body 前插 0x20 字节并重签」），可以复用。

**C. 运行态拿明文**
设备上电后这 2 MiB 是被硬件解密后才执行的 —— 从运行态内存 dump 出该 DXE 的明文副本（需设备侧能力，
本次任务范围外）。

**D. 找未加密的来源**
工程版/工厂版固件、售后刷机包、或同平台其他机型的 `uefi.img`（若某些 SKU 未开 crypt flag）。
判据很简单：拿到镜像先看 `+0x110` 是不是 0 —— 是 0 就说明 body 明文，直接 `body_offset/body_len` 切出来读。

**不要再做**：在 `tee.img` / `xrse.img` 上找 `gbl_efi_avb`。两者都是同一容器、flag=1、body 熵 7.99997/7.99948，
和 `uefi.img` 一样的密文；且 `str_hunt.py` 已经对全部 30 个镜像做过全量字符串扫描，除了
`BOOTAA64.EFI` / `android_esp.img`（同一份）之外**零命中**。

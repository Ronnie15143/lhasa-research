# XRing O3 启动链静态逆向报告（第三轮）

生成时间：2026-10-22
目标：Xiaomi 18 Fold (`lhasa`) / XRing O3 / HyperOS `OS4.0.21.0.XPNCNXM`
样本：官方 OTA 包 `fw_lhasa_lhasa-ota_full-OS4.0.21.0.XPNCNXM-user-17.0-053d748570.zip`
       (96.56 MB, SHA256 `BABCC2B61AFEF15A3BF790FE42D9DEF081C0367F940C0E80018B3D0187E1434F`)

---

## 一、核心结论

**我此前把 `uefi.img` 判为"加密不可分析"是错的。**

per-block 熵图显示这些镜像是 **「明文签名头 + 高熵体」** 的分段容器，不是整体加密：

```
uefi.img    blk_entropy = [6.74, 7.96, 7.96, 7.96, ...]      ← 第 0 块有结构
xloader.img blk_entropy = [7.83, 7.99 × 15, 4.42, 0×14, 7.83, 7.99 × 11, 6.60]
                          ↑头部        ↑加密体   ↑明文段  ↑空洞  ↑第二镜像
xrse.img    blk_entropy = [4.08, 0, 7.99 × 24, 7.89]
```

`xloader.img` 内部是**两个镜像**（各带独立头部），中间是 0x3C000 的对齐空洞。

---

## 二、XRing 镜像容器格式（实测还原）

以 `uefi.img` 头部为例（全为明文）：

```
偏移    内容
0x000   f0 de bc 9a 78 56 34 12      container magic (0x9abcdef0 / 0x12345678)
0x008   02 00 00 00                  format version = 2
0x00c   b0 0c 20 00                  total size
0x010   segment table (offset/size pairs, 明文)
0x080   ef be ad de ...              0xdeadbeef 填充（未初始化保留区）
0x110   01 00 00 00 | 02 01 00 00    flags
0x120   32 bytes                     SHA-256 #1
0x150   32 bytes                     SHA-256 #2
0x188   16 bytes                     digest #3
0x1E0+                               ciphertext body
0x5F0   X.509 certificate (569 B)    ★ 信任根证书，位置固定
0x829   X.509 certificate (565 B)    ★ 第二颗（DER 30 82 02 35）
```

**关键：证书偏移 0x5F0 在 `xloader.img` / `uefi.img` / `bl2.img` / `bl31.img` / `tee.img` /
`xrse.img` / `xsps.img` / `xspm.img` 中完全一致。**

---

## 三、信任根证书（本次最重要的产物）

从全部 8 个 bootloader 镜像中共 carve 出 **6 颗证书，sha256 完全一致**（两种长度：
569 字节完整证书 + 448 字节同证书偏移子集），即**所有镜像共用同一信任根**。

`certutil -dump` 解析结果：

```
版本          : X.509 v3
序列号        : 31 32 33 34 35 36 37 38 39  =  ASCII "123456789"
签名算法      : sha384ECDSA (1.2.840.10045.4.3.3)
Issuer        : CN=F3 Devices Cert, OU=STD, O=Xiaomi Inc., L=Beijing, S=Beijing, C=CN
Subject       : 同上  → 自签名根证书
NotBefore     : 2021-01-01 08:00
NotAfter      : 2025-01-01 08:00        ← 已过期约 1 年 9 个月
公钥算法      : ECC
曲线          : brainpoolP384r1 (1.3.36.3.3.2.8.1.1.11)   ← 非 NIST 曲线
密钥长度      : 384 bits
扩展          : Netscape Comment = "NVCOUNTER:1"
证书 SHA1     : 895e310035d2a35daa0137aeb29cf8fd6216f4bf
证书 MD5      : 6c64fc589c8495dbeac6eb8a018c146b
公钥 (97B)    : 04 82 92 5c 34 f7 4b dd 6c 47 a4 2a d0 96 48 b6
                e6 57 8a 8c 2b 6c 7b ab 01 0a 35 b9 fa 96 11 6d
                f8 e8 c6 87 19 68 3a ee 1b 7e c3 83 43 04 f4 e6
                7c 84 44 7b f8 f8 e5 89 33 14 ad 0c 9e 89 fc d6
                3d 38 93 c2 9f ca 95 96 34 cb f6 5c f0 8c 72 ec
                c7 15 e3 df 85 c9 02 b7 d6 7c d9 50 77 40 6c 4e
                c4
```

落盘文件：`runs/android/certs/xloader_00_c11dd20d3ce9.der` 等 6 个 `.der`。

### 三个异常点（都是"测试/工厂"配置的特征）

1. **序列号是 ASCII `"123456789"`** —— 量产签名证书不会使用可预测序列号。
   这是 `openssl req -x509 -set_serial 123456789` 一类命令的典型产物。
2. **曲线 `brainpoolP384r1`** —— Android / Qualcomm / UEFI 生态几乎全部使用
   NIST P-256 或 P-384；brainpool 是欧洲 BSI 曲线，极少出现在消费电子信任根中。
3. **证书已过期**（2025-01-01），但设备在 2026-10 仍正常启动
   → **bootloader 不校验证书有效期**（AVB 类实现的常见行为）。

---

## 四、这个发现能推出什么 / 不能推出什么

### 能推出
- 整个 XRing 启动链的信任根是**单一、可枚举、有明确指纹**的对象。
- 镜像格式是**明文头 + 密文体**，头部字段（段表、三组 digest、证书）完全可解析，
  意味着**可以精确构造一个格式合法的伪造镜像**。
- 签名是 **ECDSA-P384 on brainpoolP384r1 上的 SHA-384**，算法栈是标准椭圆曲线签名，
  没有使用自定义/混淆签名方案。
- 若该测试证书对应的私钥曾出现在工厂工具、构建脚本或公开代码库中，则可直接签名任意镜像。

### 不能推出（必须诚实标注）
- **不能**在没有私钥的情况下伪造签名。ECDSA-P384 无私钥即不可伪造。
- **不能**确认 bootloader 验证时用的是"代码内置公钥"还是"镜像头携带的证书"。
  这是决定性分歧点：
  - 若用**内置公钥** → 必须私钥，静态路径封死；
  - 若用**镜像头证书** → 存在自签名绕过（替换证书 + 自签），但 `xloader`/`uefi`
    本体是密文，无法静态确认。
- **不能**通过 fastboot 验证上述任一假设：`fb lock: true` 封锁了 `flash`/`oem`/
  `fetch`，且 bootloader 不提供 `reboot`/`continue` 命令。

---

## 四bis、差分固件分析结果（4.0.6 / 4.0.18 / 4.0.21）

### 镜像在变，信任根不变

| 镜像 | 4.0.6 sha256 | 4.0.21 sha256 | 结论 |
|---|---|---|---|
| `xloader.img` | `6699b014…` | `82b9e1cd…` | 变（首差 0xC = size 字段） |
| `uefi.img` | `69b8b52b…` | `177625d9…` | 变（首差 0x154 = hash 区） |
| `bl2.img` | `de3e0b4e…` | `608edaae…` | 变（首差 0x154） |
| `bl31.img` | `a9d56b6d…` (278528B) | `cb6a7a1e…` (282624B) | 变，**代码体积都变了** |
| `xrse.img` | `0569835b…` | `cfd66f9a…` | 变（首差 0xD） |
| `tee.img` | `ec512b33…` | `d015c94b…` | 变（首差 0x154） |

**但 0x5F0 处的 X.509 证书三个版本 sha256 完全一致：`c11dd20d3ce9ae99…`**

→ 结论：**小米持续更新 bootloader 代码，但从未轮换信任根证书。**

### uefi.img 的真实布局（4.0.6 → 4.0.21 只有 4 处差异）

```
0x000154-0x00019B  (72 B)      SHA-256 摘要区
0x0001EC-0x00021B  (48 B)      签名分量 r
0x00057C-0x0005DD  (98 B)      签名分量 s + 尾部
0x000CB0-0x200CAF  (2 MB)      整个密文体
```

**关键修正：密文体真正的起点是 0xCB0，不是此前判断的 0x1E0。**
0x1E0-0xCB0 是签名与证书区（含 3 颗证书），几乎全为零填充。

### 三颗证书：同 subject、三把不同公钥

```
镜像头内共 3 颗 DER 证书（0x5F0 / 0x830 / 0xA70），各 569 字节：

               Subject/Issuer                  SPKI sha256
@0x5F0  CN=F3 Devices Cert,OU=STD,O=Xiaomi Inc.  85c80dc9dcaa0526…
@0x830  同上                                      c6b4298dedf64f53…
@0xA70  同上                                      401e56e5ec767866…

all public keys identical : False      distinct SPKI count : 3
```

差异区间精确位于：
- `0x146-0x1A5` (96 B) → SubjectPublicKeyInfo（brainpoolP384r1 公钥）
- `0x1D7-0x238` (98 B) → 证书签名

**这意味着同一 subject 下有三把独立密钥**，是"工厂/测试多套签名密钥"的典型形态，
而不是证书链（链的 issuer 会与 subject 不同）。

### 签名验证实验结果

- **根证书自签名校验：通过**
  `pub.verify(cert.signature, cert.tbs_certificate_bytes, ECDSA(SHA384))` → OK
  证明这三颗证书确实是自签名根，不是伪造的装饰物。
- **镜像签名验证：全部失败**
  以 `r@0x1EC` + `s@0x57C` 组合、遍历 3 把公钥 × 5 种字节范围 ×
  {SHA256, SHA384}，**无一通过**。
  → 说明签名并非对裸字节范围直接签名，更可能是对「预先拼装的摘要结构」签名，
  或签名/待签数据还包含未被识别的长度前缀。此点尚未解出。

---

## 五bis、完整信任模型（本次逆向的最终成果）

**签名验证已成功复现。XRing 镜像签名体系被完整解开。**

### 5bis.1 镜像签名布局

以 `uefi.img` 为例（`xloader.img` / `bl2.img` / `bl31.img` **完全同构**）：

```
[0x000 - 0x570]   头部：magic + version + 段表 + 摘要 + flags   ← 被签名覆盖
[0x570 - 0x574]   u32 type = 2
[0x574 - 0x578]   u32 sig_len = 102
[0x578 - 0x5DE]   DER ECDSA 签名 #1（镜像签名）
[0x5DE - 0x5F0]   填充
[0x5F0 - 0x829]   cert1（569B，根）
[0x7C3]           DER 签名 #2（覆盖 cert1.tbs，自签名）
[0x830 - 0xA3E]   cert2（569B，中间）
[0xA03]           DER 签名 #3（覆盖 cert2.tbs，由 cert1 签发）
[0xA70 - 0xC7E]   cert3（569B，叶子）
[0xC43]           DER 签名 #4（覆盖 cert3.tbs，由 cert2 签发）
[0xCB0 - 0x200CB0] 密文体（2 MB）
```

### 5bis.2 验证实验结果（全部实测通过）

```
# 镜像签名
sig@0x578  verifies  header[0x0:0x570]  with  cert3@0xA70   (ECDSA/SHA-384)  OK

# 证书链
sig@0x7C3  verifies  cert1.tbs  with  cert1@0x5F0   (自签名)     OK
sig@0xA03  verifies  cert2.tbs  with  cert1@0x5F0   (cert1签cert2) OK
sig@0xC43  verifies  cert3.tbs  with  cert2@0x830   (cert2签cert3) OK

# 内容摘要
0x1EC 处 48 字节  ==  SHA-384( [0xCB0, 0x200CB0) )             OK
```

匹配搜索规模：5382 次尝试（3 组边界 × 公钥 × 4 算法 + prehashed 变体），
唯一命中为 `[0x0:0x570]` + `cert@0xA70` + `SHA384`。

### 5bis.3 信任链拓扑

```
cert1 (根, 自签名, brainpoolP384r1)
  └── 签发 cert2
        └── 签发 cert3
              └── 签发镜像头部 [0x000, 0x570)
                    └── 头部 0x1EC 存 SHA-384(密文体)，形成内容完整性闭环
```

### 5bis.4 攻击面收敛

| 取得 | 效果 |
|---|---|
| cert3 私钥 | 直接签任意镜像头部（最直接路径） |
| cert2 私钥 | 签发新 cert3，等效 |
| cert1 私钥 | 签发新 cert2 → cert3，等效（根） |

**三把私钥任一把泄露即可完全攻破。** 证书指纹极具检索价值：

```
Subject/Issuer : CN=F3 Devices Cert, OU=STD, O=Xiaomi Inc., L=Beijing, ST=Beijing, C=CN
序列号          : 313233343536373839  = ASCII "123456789"
曲线            : brainpoolP384r1 (1.3.36.3.3.2.8.1.1.11)
有效期          : 2021-01-01 → 2025-01-01（已过期，bootloader 不校验）
cert1 SPKI sha256 : 85c80dc9dcaa0526fe3c082cdff945b0d004ab7e6a6005b6e5972d643febcc54
cert2 SPKI sha256 : c6b4298dedf64f53e5a611b773a54f7c1c3b3e7d0f29912341e932a12af4e861
cert3 SPKI sha256 : 401e56e5ec767866c8895620fa2e87e24dff67a8b60fd9eec8e5da9d6d48a2ce
```

### 5bis.5 仍然缺的唯一样东西

**私钥。** 镜像格式、摘要算法、签名算法、证书链、签名覆盖范围——全部可复现，
可以用代码完整构造一个"格式合法"的镜像头。最后一步 ECDSA-P384 签名需私钥，
这属数学边界，不是工程问题。

可以立刻构造的东西：
- 任意修改镜像头部字段并重算所有摘要
- 自建一条 xloader→bl2→bl31→uefi 的完整证书链（用自己的密钥）
- 唯一无法通过的是 bootloader 内置验证（若其信任根为内置公钥）

---

## 五ter、格式掌握证明：完整伪造镜像自验证通过

**这是本次逆向的终点成果。**

工具：`forge_image.py`
产物：`runs/android/rom/fw/uefi_FORGED.img`（2,101,248 字节，与原镜像完全同尺寸同布局）

做法：生成三对全新 brainpoolP384r1 密钥，**原位替换**原证书 TBS 中的
SubjectPublicKeyInfo（保持 569 字节长度不变），重建 cert1→cert2→cert3 链，
用自建 cert3 私钥重签镜像头，并重算 0x1EC 处的 body 摘要。

自验证结果（5/5 全通过）：

```
body digest         : OK      SHA-384( [0xCB0,0x200CB0) ) == 0x1EC 处的 48 字节
image sig (cert3)   : OK      cert3 公钥验证 header[0x0:0x570)
cert1 self          : OK      自签名根
cert2 by cert1      : OK      链跳 1
cert3 by cert2      : OK      链跳 2

RESULT: FULL FORMAT MASTERY
```

### 关键技术要点（踩过的坑，留给后来者）

1. **签名区不是从 0x57C 开始**，而是 **0x578**：
   `30 64 02 30 r 02 30 s` 共 102 字节。从 0x57C 硬读会切掉
   `30 64 02 30` 这 4 字节头，导致 1134 次验证全部失败。
2. **0x1EC 的 48 字节 = SHA-384(密文体)**，这是内容完整性闭环。
3. **签名覆盖 `[0x0, 0x570)`**，不含签名自身也不含证书区。
4. **证书 BIT STRING 的 `04` 是椭圆曲线点前缀**，不是 unused-bits：
   `03 62 00` 才是 tag+len+unused，公钥从紧随其后的 `04` 开始，共 97 字节。
   多跳 1 字节会把 TBS 挖错位，导致 `ParseError { ExtraData }`。
5. **ECDSA DER 长度可变**（r/s 最高位为 1 时加前导 0x00）：
   必须重签直到长度恰为 102，否则证书长度变化会顶掉后面的偏移。

### 这个证明意味着什么 / 不意味着什么

**意味着**：
- XRing 镜像格式已被 100% 掌握，可任意构造
- 签名算法、摘要算法、覆盖范围、证书链拓扑全部可复现
- **只差一把私钥**就能产出 bootloader 会接受的镜像

**不意味着**：
- 还不能绕过真机验证：bootloader 是否信任"镜像内携带的根证书"（TOFU 模式）
  还是使用"代码内置公钥"，这一点因 xloader 本体为密文而**无法静态判定**
- 若是前者，`uefi_FORGED.img` 理论上可被接受；若是后者，仍需小米私钥
- 该分歧点只能通过实机刷入验证，而 fastboot 已实测被 `fb lock: true` 封锁

---

## 五、下一步的可行验证路径（按可行性）

| 路径 | 做法 | 障碍 |
|---|---|---|
| 私钥溯源 | 检索 "F3 Devices Cert" / brainpoolP384r1 + Xiaomi 相关泄露、工厂工具包、构建脚本 | 命中概率低但成本极低 |
| 内置公钥确认 | 解密 `xloader.img` 密文体后搜 ECDSA 验签常量 | 需要解密密钥 |
| 自签名假设验证 | 构造替换证书的 uefi.img，刷入观察 | fastboot 被锁，无法写入 |
| 物理路径 | `devicetree` 暴露 `mi_t2_jtag`、`xrse`、`sec_log_bl31/hyp` | 需硬件 |
| 差分固件分析 | 对比多个 OTA 版本（OS4.0.6/4.0.11/4.0.15/4.0.18/4.0.21）的证书与头部 | 需下载更多 OTA（各 96MB，可行） |

**其中"差分固件分析"是唯一完全无风险、纯静态、可立即执行的方向**：
若不同版本之间证书/公钥发生变化，说明小米在轮换信任根；若从未变化，
则证明这是一颗长期使用的固定测试根。

---

## 六、工具与产物清单（本轮新增）

| 文件 | 说明 |
|---|---|
| `oem_extract.py` | 从固件/PE 提取 `oem *` 命令与 fastboot 动词表（自实现，未使用第三方包） |
| `carve_certs.py` | 从镜像 carve X.509 DER 证书并按 sha256 去重 |
| `certs/*.der` | 6 颗提取出的证书 |
| `rom/fw/*.img` | 26 个固件镜像（OS4.0.21.0） |
| `rom/fw/BOOTAA64.EFI` | GBL 主程序（明文 PE32+ ARM64，1,585,152 B） |

## 七、设备侧改动

**本轮零改动。** 全部工作在本地样本上完成，未对设备执行任何写入。

# EROFS 读取器开发记录（erofs_extract.py）

目标：从 Android `*_dlkm` 分区镜像里把文件（尤其 `.ko`）导出来。
交付：`runs\android\rom\erofs_extract.py`（纯 Python，无外部依赖除 `lz4`/`zstandard`，`pyelftools` 仅用于校验与读 vermagic）。

```
python erofs_extract.py <image> <outdir> [--list] [--only-ko] [--no-read] [-v]
```

---

## 1. 两个样本的真实情况（先纠正两条原来的假设）

### 1.1 `odm_dlkm.img`（348,160 B）

| 项 | 实测值 |
|---|---|
| superblock | magic `0xe0f5e1e2`，`blkszbits=12`(4096)，`inos=6`，`root_nid=38`，`meta_blkaddr=0` |
| feature_compat | `0x7`（SB_CHKSUM + MTIME + XATTR_FILTER） |
| feature_incompat | **`0x1` = LZ4_0PADDING**（**没有** COMPR_CFGS/0x2） |
| `sb.blocks` | **2**（整个分区 85 块，与镜像实际长度不符；只当参考值，读数据一律以文件长度为准） |
| 压缩 | **无**，`available_compr_algs=0xffff` 即旧布局的 `lz4_max_distance` |

整棵树只有 4 个文件，**一个 `.ko` 都没有**，也**没有任何压缩 inode**：

```
drwxr-xr-x       42  flat-inline  /
drwxr-xr-x      127  flat-inline  etc
-rw-r--r--     4213  flat-inline  etc/NOTICE.xml.gz    (4096 数据块 + 117 B inline tail)
-rw-r--r--     1214  flat-inline  etc/build.prop        (整文件 inline)
-rw-r--r--        0  flat-plain   etc/fs_config_dirs
-rw-r--r--        0  flat-plain   etc/fs_config_files
```

⇒ 之前 `\x7fELF` 命中 0 次**不是"数据被压缩"**，而是这个分区里确实没有模块：
payload manifest 里 `odm_dlkm` 就只有 0.33 MiB，模块在 `vendor_dlkm`（39.10 MiB）。
块 5 起是 `AVB0` 校验区，块 84 尾部是 AVB footer，都属正常。

### 1.2 `vendor_dlkm.img`（40,996,864 B）—— 真正的模块分区

| 项 | 实测值 |
|---|---|
| superblock | `blkszbits=12`，`inos=506`，`root_nid=39`，`sb.blocks=9801` |
| feature_incompat | `0x1` = LZ4_0PADDING（依旧是**旧版 legacy 布局**，无 COMPR_CFGS） |
| 目录 | `/`(57)、`etc`(157)、`lib`(46)、`lib/modules`(6877)、`lib/modules/16k-mode`(6853) |
| 文件 | 501 个，其中 **486 个 `.ko`**（`lib/modules` 243 + `lib/modules/16k-mode` 243），15 个非 `.ko`（`modules.load/dep/alias/softdep/blocklist`、`build.prop`、`NOTICE*.gz`、`fs_config_*`） |
| 压缩 inode | 486 个（**全部 `.ko` 都是压缩的**），datalayout=3（COMPRESSED_COMPACT），`h_advise=0x0001`（COMPACTED_2B），`h_algorithmtype=0`（LZ4），`h_clusterbits=0`（4K 逻辑簇） |

> 注意：`.ko` 全是 `compressed-compact`，而不是之前 `--list` 里看到的 `flat-plain`；
> 那些 `flat-plain` 是 `modules.dep` 之类的小文本。两种 vermagic 说明是两套构建：
> `lib/modules/*` → `6.18.21-android17-5-maybe-dirty-4k ...`（4K 页），
> `lib/modules/16k-mode/*` → `6.18.21-android17-5-maybe-dirty ...`（16K 页）。

---

## 2. 格式对齐（全部以 Linux `fs/erofs/erofs_fs.h` + `fs/erofs/zmap.c` v6.6 为准）

* inode：32 B compact / 64 B extended，`i_format` bit0=版本、bit1..3=datalayout。
  - compact 的字段偏移是 `i_format(0) i_xattr_icount(2) i_mode(4) i_nb(6) i_size(8) i_mtime(12) i_u(16) i_ino(20)`
    —— **`i_u` 在 +16，不是 +12**（我第一版按 +12 解，导致 `startblk`/`blocks` 全错）。
* inline xattr 长度：`icount == 0 ? 0 : 12 + 4*(icount-1)`（12 B 头 + 若干条目）。
* 目录：`erofs_dirent` 12 B（`nid u64 / nameoff u16 / file_type u8 / reserved u8`），
  **条目数 = 首个 `nameoff / 12`**，不是"扫到数据末尾"；每个目录块的最后一个名字一直延伸到
  `min(blocksize, dirsize - 块起点)`（用 NUL 截断即可）。
* 压缩 inode 的 map header 在 `ALIGN(inode_end, 8)`，8 B：
  `h_reserved1/h_idata_size(2) h_advise(4) h_algorithmtype(6) h_clusterbits(7)`。
  - `h_clusterbits>>7` ⇒ 整文件在 packed inode（fragments）；
  - `h_clusterbits&7` ⇒ 逻辑簇 = blocksize << n。
* **索引数组位置**
  - datalayout 1（COMPRESSED_FULL/legacy）：`ALIGN(inode_end,8) + 16`（= 8 B 头 + 8 B 历史 padding），
    每条 8 B：`di_advise u16 | di_clusterofs u16 | u32{blkaddr | delta[2]}`。
  - datalayout 3（COMPRESSED_COMPACT）：`ALIGN(inode_end,8) + 8`，4B/2B 位打包
    （`compacted_4b_initial`、`(32-ebase%32)/4`、2B 段 16 条/32 B、每 pack 末尾 4 B 是 pblk 基数）。
* 一个 extent 的**解码长度** = 下一个 HEAD/PLAIN 的 `(lcn<<lcb)|clusterofs` 减去本 extent 的同一表达式，
  末尾 extent 用 `i_size` 截断（kernel `z_erofs_get_extent_decompressedlen`）。
* 一个 extent 的**编码长度**：非 big-pcluster 恒为 1 块；big-pcluster 的块数存在
  **head 后面第一个 NONHEAD 的 `delta[0] & 0x0800(=Z_EROFS_LI_D0_CBLKCNT)`**，
  低位才是块数（head 自己身上没有这个数）。
* PLAIN extent 的约束是 `m_llen <= m_plen(1<<lcb)`，**不是** `lcb - clusterofs`。

### 2.1 两条被证伪的猜想（记下来免得再走一遍）

1. **"legacy 索引是大端位域 `di_advise:4/di_clusterofs:12/di_blkaddr:48`"——不对。**
   现行 on-disk 结构是普通小端：`__le16 di_advise; __le16 di_clusterofs; union{__le32 blkaddr; __le16 delta[2]}`。
   4/12/48 的位域是 v1.0 时期的原型，现在只出现在 compact 索引的位打包里（那里也是小端位流）。
   证据：`vendor_dlkm` 的 `xr_compress.ko` 用这套解释能**完整解出 66,648 B 且 ELF 的节头表正好收在 EOF**。
2. **"clusterofs 越界 ⇒ 索引字节序错"——不对。**
   真正原因是我把 PLAIN extent 的界写成了 `4096 - clusterofs`；正确界是 `m_plen = 4096`。
   `PLAIN` 语义是 *shifted*：块首字节对应逻辑 `(lcn<<12)|clusterofs`，块尾可越到下一个逻辑簇。

### 2.2 关键发现：`LZ4_0PADDING` 的零填充可能在**前面**

同一分区里，绝大多数 pcluster 的压缩流从块首开始，但**最后**一个 pcluster 常常是把压缩流
**右对齐**写在块尾，块首用零填满。实测（`xr_compress.ko`，`i_size=66648`，6 个数据块）：

```
pclusters: 3921->8756 B, 3922->7019 B, 3923->17834 B, 3924->13599 B, 3925->11890 B, 3926->7550 B
blk 3926: 前 1787 B 全 0，从 +1787 开始 2309 B 的合法 LZ4 流，正好解出 7550 B
          （1787 + 2309 = 4096，即流对齐到块尾）
```

自洽校验：6 段解码长度累加 = 66,648 = `i_size`，且 ELF 节头表 `e_shoff(62552)+64*64 = 66648` 正好收尾。
所以读取器对 LZ4 依次尝试：`as-is` → 去前导零 → 去尾零 → 两端去零 → 在簇内扫描合法流首
（自包含 LZ4 块不可能以 `0x00` 开头：token 0 表示 0 字面量 + offset 0，非法），
并把命中策略记进 `pad_hits` 计数。ZSTD 同理用在簇内搜 `28 b5 2f fd` 帧头兜底。

---

## 3. 验证结果

| 验证项 | 结果 |
|---|---|
| `odm_dlkm.img --list` | 树正确（2 目录 / 4 文件 / 0 符号链接），`NOTICE.xml.gz` 解压出 12,756 B 合法 XML，`build.prop` 文本正确（`ro.product.odm_dlkm.device=lhasa`） |
| `vendor_dlkm.img` 全量导出 | **486 / 486 个 `.ko`**，108,241,672 B（103.2 MiB） |
| 大小一致性 | 486/486 与 inode `i_size` 完全相等（既不截断也不多写） |
| ELF 合法性 | 486/486 `pyelftools` 可打开，`e_machine=EM_AARCH64 (0xB7)`，节表可遍历（平均 50.3 节） |
| **端到端完整性** | **486/486 的 `e_shoff + e_shnum*e_shentsize == 文件长度`**（`.ko` 节头表在文件末尾，一个字节都不能少 ⇒ 压缩解码完全正确） |
| vermagic | 243 × `6.18.21-android17-5-maybe-dirty-4k SMP preempt mod_unload modversions aarch64`，243 × 同串去掉 `-4k` |
| 合成镜像回归（`%TEMP%\dsh_erofs\mk_test_erofs.py`） | legacy+LZ4（多簇 pcluster / 3 块 big pcluster / inline tail pcluster / flat-plain / flat-inline / 空文件 / 符号链接 / 两块的目录）：**310/310 载荷逐字节一致**；compact+COMPR_CFGS+ZSTD（含 2 块 big pcluster）：**310/310 逐字节一致** |

`odm_dlkm` 与 `vendor_dlkm` 都不含 `xr_fbt*.ko`；`vendor_dlkm` 里也没有该名字。
`modules.load`（4006 B）里有完整模块清单，可用来定位某个模块到底属于哪个分区；
如需 `xr_fbt*`，下一步应在 `vendor`（751 MiB）或 `odm`（3.66 GiB）分区里找。

---

## 4. 明确不支持（遇到就报错，不静默）

* `feature_incompat` 的 `48BIT(0x80)`、`METABOX(0x100)`；
* 多设备 chunk map（`device_id != 0`）；
* 6.8+ 的 per-inode extent 表（`COMPRESSED_FULL` + `h_advise bit0 = ADVISE_EXTENTS`）：
  会检测"首簇是 NONHEAD / 首簇 clusterofs != 0"并抛 `ErofsUnsupported`，提示这是 extent 表布局；
* 未知的 `feature_incompat` 位（内核同样会拒绝挂载）。

以上都以异常形式带出具体字段值（`ErofsUnsupported` / `ErofsCorrupt`），单文件失败不会中断整批导出。

## 5. 复跑命令

```powershell
# 列树（不写盘）：odm_dlkm
python runs\android\rom\erofs_extract.py runs\android\rom\odm_dlkm.img --list

# 全量导出 .ko（一条命令重建整个 vendor_ko）
python runs\android\rom\erofs_extract.py runs\android\rom\vendor_dlkm.img runs\android\rom\vendor_ko --only-ko

# 列树 + 每个 .ko 的大小/压缩标志/vermagic
python runs\android\rom\erofs_extract.py runs\android\rom\vendor_dlkm.img --list

# 其它分区同样适用
python runs\android\rom\erofs_extract.py runs\android\rom\vendor.img runs\android\rom\vendor_out --list
```

# OTA → EROFS → .ko 流水线（已打通，可复用）

> 2026-10-22 16:35 · 本轮把"厂商模块拿不到"这条阻塞彻底解决了

## 1. 下载

```
URL   https://bigota.d.miui.com/OS4.0.21.0.XPNCNXM/lhasa-ota_full-OS4.0.21.0.XPNCNXM-user-17.0-053d748570.zip
坑    CDN 必须同时带「浏览器 UA」+「Referer: https://www.miui.com/」，否则 403
      已写进 rom/ota_extract.py 的 UA 字典（可用 OTA_UA / OTA_REFERER 覆盖）
速度  ~20 KB/s ⇒ 整包 9.6 GB 不可行；单分区可行（vendor_dlkm 39 MiB 实传 24 MB / 29 个 Range 请求）
```

`python rom/ota_extract.py <url> --list` → 46 个分区；`--part <name> --out <file>` 抠单分区。

## 2. 解析（EROFS）

`vendor_dlkm.img` / `odm_dlkm.img` 都是 **EROFS**：

```
magic 0xE0F5E1E2 @1024，blkszbits=12，feature_incompat=0x1 [LZ4_0PADDING]（legacy 布局，无 COMPR_CFGS）
```

- **不能**直接扫 `\x7fELF` 抠（文件数据按 legacy LZ4 压缩簇存放，扫出来的 488 个"命中"全是伪的）；
- 用 `rom/erofs_extract.py`（子智能体写的完整 reader：superblock / 紧凑+扩展 inode / dirent /
  flat+inline+compressed 数据，lz4 与 zstd 都支持）；
- 只想拿某几个文件时用 `rom/dump_one.py <img> <outdir> <路径子串...>`，它复用了同一个 reader 且
  单个文件失败不会中断整轮。

## 3. 反汇编（.ko 是 ET_REL，没有 vaddr）

`rom/ko_disasm.py <ko> <symbol> [n]` —— 通过 `st_shndx` 定位符号所在 section，
用「同 section 的下一个函数」界定长度，并把每个分支目标标成 `func+off`。

## 4. 本机已经导出的模块

**`vendor_dlkm` 全量导出并逐字节校验通过：486/486 个 `.ko`**（243 个 4K 版 + 243 个 16K 版），
共 103.2 MiB，落在 `runs\android\rom\vendor_ko\lib\modules\` 与 `...\16k-mode\`。
校验口径：文件大小 == inode `i_size`、`pyelftools` 可开、`e_machine=0xB7`，
且 **`e_shoff + e_shnum*e_shentsize == 文件长度`**（节头表在文件末尾，差一字节就对不上）。
vermagic 两类：`6.18.21-android17-5-maybe-dirty-4k SMP preempt mod_unload modversions aarch64`（本机用这 243 个）
与去掉 `-4k` 的 16K 页版。

| 模块 | 大小 | 用途/状态 |
|---|---|---|
| `lib/modules/tango32.ko` | 26,192 B | **`/dev/tango32` 的驱动，ioctl 实测可达 ⇒ 当前唯一活着的厂商目标** |
| `lib/modules/mali_kbase.ko` | 1,951,728 B | `/dev/mali0`，ioctl 全 EPERM ⇒ 判死 |
| `lib/modules/os_cpu_qi.ko` | 338,208 B | QoS 继承框架；**它只是 import `register_xr_fbt`/`unregister_xr_fbt`**，不是 xr_fbt 的提供者 |

`xr_fbt` 的提供者**不在 `vendor_dlkm`**：486 个模块里没有任何一个定义 `register_xr_fbt`，
整个镜像原始字节搜 `xr_fbt` 只有 `os_cpu_qi` 的导入引用 ⇒ 它在 `vendor`(751 MiB) 或 `odm`(3.66 GiB) 里，
以 20 KB/s 的下载速度不可行 ⇒ **xr_fbt 从目标列表移除**（除非以后有更快的取包途径）。

## 4.1 两个被证伪的猜想（记下来，别再犯）

- "legacy 索引是大端位域" ❌：现行 on-disk 索引就是普通小端
  （`__le16 di_advise / __le16 di_clusterofs / __le32 blkaddr`；4/12/48 位域只是 v1.0 原型，
  现在只出现在 compact 索引的位打包里）；
- "扫不到 `\x7fELF` 是因为数据压缩" ❌（对 odm_dlkm）：那个分区本来就**没有 .ko**（只有 4 个 etc 文件）。
  vendor_dlkm 的 486 个 `.ko` 确实全是压缩的（datalayout3 compact 索引 + LZ4），
  且这个镜像的 LZ4 流把**零填充放在前面**（流右对齐到块尾），读取器要分级试 as-is/去前导零/去尾零/两端去零。



## 5. tango32 第一眼（给下一轮省时间）

`tango32_ioctl` 在 `.text+0x4`（size ~0xce4），命令号（type=0x74）：

```
0x000074a2（裸值，无 _IOC 编码）   0x400874a3 (_IOW 8)   0x400c74a3 (_IOW 0xc)
0x400874a4 (_IOW 8)               0x800474a0 (_IOR 4)   0x800874a5 (_IOR 8)
0x401074a5 (_IOW 0x10)            0xc01874a6 (_IOWR 0x18)  0xc01874a7 (_IOWR 0x18)
```

栈帧 `sub sp, sp, #0x220`；已经看到 `_inline_copy_from_user`、手工 `ttbr0/ttbr1` 切换、
对 `current->mm` 的锁操作（`[x22+0x698]` → `+0x88` 上锁）、以及对长度参数的两道比较。
详细审计交给子智能体，产出 `TANGO32_AUDIT.md`。

## 6. 纪律

- 只有 **`/dev/uhid`、`/dev/binder`、`/dev/uinput`、`/dev/tango32`、`/dev/xr_fbt`、`/dev/mali0`、
  `/dev/ashmem_*`（3 个）** 这 8 个 misc 节点对 shell 可 open（73 个 misc 节点全扫过）；
  其中 mali ioctl=EPERM、uinput 拿不到 evdev（event* 全 EACCES）⇒ 真正可用的是
  **tango32 / xr_fbt / ashmem / uhid / binder**。
- `/vendor/lib/modules` 对 shell 是 `avc denied { read }`，别再指望直接 `adb pull`；一律走 OTA。

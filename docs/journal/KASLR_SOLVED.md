# KASLR 阻塞点已解除 —— 实测记录

> 2026-10-22 07:1x，lhasa 实机

## 结论

```
KASLR slide  = 0x2971200000          (本次 boot)
_text        = 0xffffffe9f1200000
selinux_state= 0xffffffe9f3b59630    ← 阶段 A 的写入目标
init_task    = 0xffffffe9f38bf240
init_cred    = 0xffffffe9f38d2a50
```

**427/427 条 trace 记录零票异议**（11 个不同内核函数各自独立算 slide，spread = 0）。

## 怎么解开的（与交接文档里三条解法都不同）

交接文档里的三条路（① 拿 GKI vmlinux ② pid 配对 ③ 暴力试写）里，
真正的关键是 **② 的前提被证伪了，而 vmlinux 也不用找 AOSP 的**。

### 1. 交接文档里的符号配对是错的

原文档给的四组 `raw 地址 ↔ 符号` 是按**频次猜的**，实测全错：

| 原文档认为 | 实测（按 pid 序列精确配对） |
|---|---|
| `0xffffffe9f09aa2a8` = worker_thread+0x248 | **i2c_dw_xfer+0x1c8**（模块 `xring_i2c`） |
| `0xffffffe9f13d6710` = folio_wait_bit_common+0x188 | **worker_thread+0x248** |
| `0xffffffe9f13d8d50` = i2c_dw_xfer+0x1c8 | **rcu_gp_fqs_loop+0x154** |

因为 `sched_blocked_reason` 的 caller 里**混着模块地址**（`[xring_i2c]`、`[btmtk_uart]`、
`[kbase_*]`…），按频次配对必然错位。这也是"33 个候选"一直收敛不了的原因——
拿错符号算 slide，候选当然互相矛盾。

**正确做法**：raw 记录是 `4 字节 ring_buffer_event 头 + 32 字节 payload`

```
payload+0  u16 type (=109)     payload+8  s32 event.pid
payload+2  u8  flags           payload+16 u64 caller      ← 裸地址
payload+4  s32 common_pid      payload+24 u32 io_wait
```

`common_pid` + `event.pid` 在文本 trace 里同样存在，于是**冻结窗口后同时抓
`trace`（文本）与 `per_cpu/*/trace_pipe_raw`（raw），按 (cpu, common_pid, event.pid)
做序列比对**，就能把每一条 raw 精确对上符号，且能区分核心内核 / 模块。
脚本：`research/cap_pair.sh` + `research/pair_records.py`。

### 2. 不用 AOSP 的 GKI prebuilt（对不上）

`kernel/prebuilts/6.18/arm64` 有 `android17-release` 分支和 `System.map`，
但是 **6.18.16 且 stock 配置**。直接套用 drift 高达 ±9 MB，且函数相对顺序都不同：

- stock GKI 里 `spi_transfer_wait` 在模块 `spi.ko`；**我们设备上是核心 .text**
  ⇒ 两边 config 根本不同 ⇒ 布局不可比。

### 3. 真正的解法：从**本机 OTA 的 payload.bin** 里抠出 `boot.img`

本机版本 `OS4.0.21.0.XPNCNXM` 的完整 OTA 是 9 GiB，但**不需要整包下载**：

```
zip(9GiB, 7 entries) → payload.bin(9.66GB, method=0 stored)
  payload 头是 **大端**：magic "CrAU" + u64 ver + u64 manifest_size + u32 metasig
  manifest(347KB protobuf, 46 个分区)
  InstallOperation.data_offset **相对 data 段起点**（= 24+manifest+metasig）
  op.type 1=REPLACE_BZ, 8=REPLACE_XZ
```

只对 `boot` 分区发 HTTP Range 请求 → **实下 13 MB** 就拿到 96 MiB 的 `boot.img`。
脚本：`rom/ota_extract.py`。

```
boot.img: magic "ANDROID!"，header_version=4, header_size=0x630
  kernel_size = 0x028F3A00 (42,940,928)
  kernel @ 4096, 首字节 "MZ" → 是 PE 形态的 arm64 Image
  text_offset = 0  ⇒  **Image 文件偏移 == _text 相对偏移**
  image_size  = 0x29A0000  (_end - _text)
```

`rom/Image-4.0.21.0.bin`。

### 4. 从裸 Image 恢复符号表

`pip install --no-deps vmlinux-to-elf` + `peewee` + `pyelftools`
（`minilzo` 编译失败，但我们是未压缩 Image，不需要它）

```
[+] Found kallsyms_names  at 0x015af500  (145868 symbols)
[+] Found kallsyms_offsets at 0x017cc530
[+] base = 0xffffffc080000000
```

产出 `rom/vmlinux-4.0.21.0.elf`，139,213 个符号。
关键偏移：

```
_text        +0x0000000
_stext       +0x0010000
_etext       +0x1360000
_sdata       +0x26a0000
_edata       +0x28f3a00
__bss_start  +0x28f4000
_end         +0x29a0000
selinux_state+0x2959630    ← 在 .bss，可写，8 字节对齐 ✓
```

### 5. 交叉验证（这一步是决定性的）

用恢复出的符号表算实际 slide：

```
worker_thread            slide=0x2971200000
rcu_gp_fqs_loop          slide=0x2971200000
kthread_flush_worker     slide=0x2971200000
submit_bio_wait          slide=0x2971200000
folio_wait_bit_common    slide=0x2971200000
spi_transfer_wait        slide=0x2971200000
__flush_work             slide=0x2971200000
rcu_gp_kthread           slide=0x2971200000
msleep                   slide=0x2971200000
regmap_lock_mutex        slide=0x2971200000
dma_fence_default_wait   slide=0x2971200000
spread = 0x0
```

11 个函数独立算出同一个 2 MiB 对齐值 ⇒ 说明**这份 Image 与设备上的内核布局逐字节一致**，
slide 不是猜的。换一次抓取复算，427/427 记录全票通过。

## 工具清单

| 文件 | 作用 |
|---|---|
| `research/cap_pair.sh` | 冻结 tracing，同窗口抓文本 trace + 每 CPU raw |
| `research/pair_records.py` | 按 (cpu, common_pid, event.pid) 精确配对 raw ↔ 符号 |
| `research/solve_live.py` | 用 vmlinux 符号表解 slide（一次抓取即可重算） |
| `rom/ota_extract.py` | HTTP Range 从远程 OTA 抠单个分区（无需整包下载） |
| `rom/Image-4.0.21.0.bin` | 设备真实内核 Image |
| `rom/vmlinux-4.0.21.0.elf` | 从 Image 恢复出的带符号 ELF |

## 注意

- **slide 每次重启都变**。每次 boot 必须重跑 `cap_pair.sh` + `solve_live.py`。
- 但 **符号偏移不变**（`selinux_state` 永远是 `_text + 0x2959630`），
  所以脚本里只换 slide 即可。

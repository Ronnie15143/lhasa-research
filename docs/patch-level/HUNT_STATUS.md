# 内核提权 hunt —— 单页状态（2026-10-22 17:00）

> 目的：任何一轮接手都能一眼看到"哪些面已经用证据关掉、哪些还开着、手上有什么原语"。
> 每条关闭项都附证据文件，别重复劳动。

## 1. 已用证据关闭的面

| 面 | 结论 | 证据 |
|---|---|---|
| CVE-2026-64560（posix-cpu-timers） | **机制级不可达**：de_thread 先 `exchange_tids`+`transfer_pid(TGID)` 再 `release_task`，`!sh` 窗口不存在；17,600 exec 实测 0 命中 | `64560_DEAD_ON_LHASA.md` |
| HID multitouch（6.18.22 #267） | 缺 report-ID 校验但被 core 的 `-EINVAL` 守卫挡住，只到 `dev_warn` | `HID_MT_C1_RECHECK.md` |
| uinput FF 上传/擦除 | 候选 UAF 真实存在，但 `/dev/input/event*` 对 shell 是 **EACCES** ⇒ 触发不了 | `UINPUT_FF_AUDIT.md` |
| tango32（厂商 misc） | **无 OOB/UAF/泄露**：fops 只挂 `unlocked_ioctl`、无对象、栈拷贝终点=canary 前沿、10 条 extable 全覆盖 | `TANGO32_AUDIT.md` |
| tango32 `0x400c74a3` compat 转发 | **实测不改判决**：mali 仍 EPERM、binder 仍 EACCES、uhid 仍 ENOTTY | `l74_tango_compat.c` + 设备实测 |
| `/dev/mali0`（kbase 1.9MB） | ioctl 全 **EPERM**（SELinux allow 域不含 shell） | `l71_mali.c` / `l72_ioctl.c` |
| `/dev/xr_fbt` | 驱动是 `os_cpu_qi.ko` **import** 的 `register_xr_fbt`，提供者不在 vendor_dlkm（在 vendor/odm 分区，20KB/s 取不到） | `MODULE_PIPELINE.md` §4 |
| binder 页面分配器 F1 | 真缺陷但**只值 DoS**：写落点常量非映射、每次命中 `PANIC_ON_OOPS` 重启、shrinker 放回 order-0 | `BINDER_ALLOC_AUDIT.md` |
| binder 事务路径 | **结构性干净**：offsets 无 TOCTOU、四道界、零化栈缓冲、failed_at 截断、读路径不回吐 buffer | `BINDER_TXN_AUDIT.md` |
| **6.18.22 缺补丁扫描** | **本轮判定为死路**：277 条里没有 tty/pty、没有 AF_UNIX、没有 epoll/futex/pidfd/memfd、没有 f2fs/ext4；能碰到的只有 netfilter 类（要 `CAP_NET_ADMIN`，shell 没有）和 bpf sockmap（`bpf()` EACCES）。**别再重跑这个扫描。** | 对 `all_fixes_6.18.22.txt` 的分类 grep |

## 2. 还开着的面

| 面 | 状态 |
|---|---|
| `/dev/uinput` **非 FF** ioctl（`UI_DEV_SETUP` name[80] / `UI_ABS_SETUP` / `UI_SET_*` / `UI_SET_PHYS`） | 审计重启中（上一个子智能体因余额中断） |
| 小米 ashmem 三变体（`unpinning_enable` / `ignore_unset_prot_read` / `ignore_unset_prot_exec`） | 同上 |
| `/dev/ptmx`（pty/n_tty） | 未审；6.18.22 清单里没有对应修复，只能靠手工审 |
| binder PTR/FDA 的四个 helper（`validate_ptr`/`validate_fixup`/`defer_copy`/`fixup_parent`） | 深水区，本机 binder 非上游原样 |

## 3. 手上的原语（现成可用）

- **回收**：`/dev/uhid` + `UHID_CREATE2` → order-1 **kmalloc-256**（32 对象/8K slab、内容全控、非特权）；
  `send(AF_UNIX, 11872)` → **order-1 整页 8192 B 全控**；`UI_SET_PHYS`（`strndup_user(0x400)`）→ kmalloc-1k。
- **布局稳定**：`tango32` 命令 `0x74a2` 可把本进程 `mm->mmap_base` 改成 `[0x10000001, 2^39)` 内任意值 ⇒ **mmap ASLR 归零**。
- **可达但暂无缺陷**：binder 事务（可发 `BC_TRANSACTION`，实测 `write_consumed=68`，handle=0 也能跑满解析）、
  AF_UNIX、AF_NETLINK(ROUTE)、epoll/timerfd/eventfd/memfd/pidfd、`/proc/slabinfo` 可读。
- **解锁载荷已就绪**：`research/BOOTAA64_unlock.EFI`（2,560 B，PE32+/0xAA64/subsystem 10）+
  `rom/fw/android_esp_unlock.img`（已把 BOOTAA64.EFI 换掉、目录项 size 改成 2560）。
  拿到任意一次内核写 ⇒ 清 `selinux_state`（`_text+0x2959630`）⇒ `hypsys code 7` 写 ESP ⇒ 解锁。
- **OTA 取包流水线**：`rom/ota_extract.py`（需要 UA+Referer）→ `rom/erofs_extract.py` →
  `rom/vendor_ko/`（486 个厂商模块，含 tango32/mali_kbase/os_cpu_qi）。

## 3.5 外部意见的取舍（2026-10-22 18:50）

外部模型（Codex）的回复**没有给出新的攻击面**，只给了防御侧审计清单。我们采纳 4 条、否掉 1 条、并把它
回答不了的一条自己关掉：

- **采纳（加入待审）**：① binder 的 **fd 传递**（`BINDER_TYPE_FD` → `binder_translate_fd`，跨进程 fd 所有权/
  接收端域校验/事务失败回滚）；② **epoll/timerfd 的 fd 复用与 close 顺序**（watcher 注销 vs 最终 close）；
  ③ `pidfd_getfd` / `process_vm_writev` 在 **exec / exit / PID 复用**边界是否重新做 ptrace/LSM 检查；
  ④ dma-buf/GPU fd 的 exporter/importer 生命周期（本机 dma_heap/udmabuf 都不可达，优先级最低）。
- **否掉**：它建议不要把 update_engine 的 merge/cleanup 当写面 —— 与我上一轮"去看 merge/cleanup"的提议相反，
  这条**它是对的**：那些是控制面，不是内容面。要写 ESP 必须找到"shell 可控内容在校验之后抵达分区写入层"。
- **它没回答、我们已关掉**：Q2「文本写能不能构造 ESP 镜像」。实测 `IMQSNative code 7`：
  `/data/anr/c7a` 写 `AAAA` → 4 字节；再写 `BB` → **仍是 4 字节**（**截断重写，不是追加**），文件属主 root:system。
  加上 `bytes/sector` 字段必然是 `0x0200/0x0400/0x0800/0x1000`（LE 必含 `0x00`），而字符串写不能输出 NUL
  ⇒ **这条路是死的，不是"待验证"**。


- `binder_size_t` 是 `__u64`；用 32 位字段会"静默成功但 consumed=0"。
- `/vendor/lib/modules` 对 shell 是 `avc denied { read }`，一律走 OTA。
- erofs legacy 索引是**小端**；该镜像 LZ4 流把零填充放**前面**（右对齐到块尾）。
- 不要把"仅影响硬件/特权路径"的条目算进可达集；过滤要狠。

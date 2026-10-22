# ① 零特权可达面地图与审计目标（本轮实测）

> 2026-10-22，lhasa 实机，shell uid 2000，SELinux enforcing

## 0. 为什么需要这张图

当前 CVE-2026-64560 路线已确认死在「回收原语不存在」上（见 STATUS_2026-10-22.md
与 KASLR_SOLVED.md）：posix slab 是 order-1，而本机不存在「非特权 + 持久 + 原始字节
+ 落在正确窗口」的 order-1 分配。要继续，必须换一个不需要整页接管的原语。

任何新原语都必须从「shell 到底能碰到什么」出发。下面全部是实机实测（`research/sysmap.c`、
`research/ioctl_probe.c`）。

## 1. 系统调用可达性

**可达（返回 0 或合法 fd）：**

```
memfd_create            pidfd_open          signalfd4
timerfd_create          epoll_create1        inotify_init1
eventfd2                mseal                process_vm_readv(self)
ptrace(TRACEME)         kcmp(self)           open_tree
clone3 (EINVAL=参数问题，即已通过权限检查)
sched_setattr (EINVAL，同上)
perf_event_open (EINVAL=attr 不合法，即已通过权限检查；与 perf_event_paranoid=-1 一致)
```

**被封（EPERM/EACCES/ENOSYS）：**

```
io_uring_setup   EACCES      userfaultfd   EPERM
bpf              EACCES      add_key/keyctl EACCES
fsopen           EPERM       fanotify_init  ENOSYS(未编译)
msgget/shmget/mq_open  ENOSYS (CONFIG_SYSVIPC / POSIX_MQUEUE 均未编译)
swapoff EPERM   init_module EPERM   kexec_load ENOSYS
```

## 2. 设备节点可达性

| 节点 | open | ioctl | 结论 |
|---|---|---|---|
| `/dev/binder` | RDWR ✓ | **`BINDER_VERSION`(0xC0046209) → ret=0** | ★ **ioctl 完全可达** |
| `/dev/hwbinder` | RDWR ✓ | 未测 | 同上驱动 |
| `/dev/uhid` | RDWR ✓ | 任意 cmd → **ENOTTY（到达驱动）** | ★ **ioctl 完全可达** |
| `/dev/mali0` | RDWR ✓ | 任意 cmd → **EPERM（SELinux）** | 只有 open 能过，ioctl 被封（与交接文档一致） |
| `/dev/ptmx` | RDWR ✓ | ENOTTY（到达驱动） | 可达 |
| `/dev/ashmem` | EACCES | — | 封 |
| `/dev/dma_heap/system` | 不一致（RDONLY 曾可） | — | 边缘 |
| `/dev/kmsg`、`/dev/net/tun`、`/dev/fuse` | EACCES | — | 封 |
| `/dev/block/by-name/misc` | EACCES | — | 封（符合预期） |
| `/dev/kgsl-3d0`、`/dev/ion`、`/dev/video0` | ENOENT | — | 不存在 |

## 3. 审计优先级（按"可达性 × 历史 CVE 密度 × 可控数据量"）

1. **`/dev/binder`（最高）**
   - ioctl 已实测完全可达（`BINDER_VERSION` 返回 0），且 `/dev/hwbinder` 同样可开。
   - binder 是内核里被 fuzz 最多、CVE 最密的驱动之一；每个 transaction 都会把
     **用户完全可控的 payload** 拷进内核（`binder_alloc_new_buf` / `binder_transaction`）。
   - 交接文档**从未测过 binder** —— 这是完全没被探索的面。
   - 需要看的点：`binder_transaction` 的 offsets/size 校验、`binder_alloc_new_buf`
     的 `free_async_space`/`data_size` 计算、`binder_thread_read` 的
     `put_user`/`copy_to_user` 边界、`BINDER_SET_CONTEXT_MGR_EXT`、
     `binder_update_page_range` 的并发。
2. **`/dev/uhid`（次高）**
   - ioctl 到达驱动（ENOTTY 表示 handler 被执行），交接文档也把它列为"唯一完整 ioctl"。
   - `UHID_CREATE2` 会按 `rd_size` 分配并拷贝报告描述符；`UHID_INPUT2` 拷贝
     `size` 字节报告；`UHID_SET_REPORT`/`GET_REPORT` 双向。
   - 需要看的点：`uhid_char_write` 里 `copy_from_user` 的长度校验、
     `uhid_dev_create2` 的 `rd_size` 分配、多线程 open/close 与 `uhid_device` 生命周期（UAF 类）。
3. `/dev/ptmx`（tty ldisc）—— 可达，但被 fuzz 得很透，优先级低。
4. `perf_event_open`(self) + `perf_event_paranoid=-1` —— 可达，可用于**泄漏**而非写入，
   KASLR 已解决，价值下降；但若需要堆地址仍可考虑。

## 4. 结论

- 换原语的正确入口是 **binder**（最优先）和 **uhid**，两者 ioctl 都对 shell 开放，
  且都能让用户把大块可控数据送进内核 —— 这正是「不需要整页接管的写原语」需要的条件。
- 64560 那条链不需要再投入：它的回收环节在本机配置下无解。

## 5. 工具

| 文件 | 作用 |
|---|---|
| `research/sysmap.c` | 系统调用 + 设备节点可达性批量探测 |
| `research/ioctl_probe.c` | 区分「SELinux 挡了 ioctl」与「请求到达驱动了」 |
| `rom/vmlinux-4.0.21.0.elf` | 139,213 符号，用于静态审计 |
| `rom/btf_dump.py` / `btf_screen.py` | 从 Image 里的 .BTF 精确取结构布局 |
| `rom/Image-4.0.21.0.bin` | 设备真实内核 Image（含 .BTF @0x1aed000） |

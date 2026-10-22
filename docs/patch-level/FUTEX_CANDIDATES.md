# 补丁级别审计之后的作战记录（2026-10-22 晚）

> 本文件是 `HUNT_STATUS.md` 的追加章节（原文件是早期写的中文，读写时的编码显示会花，另开一份避免误伤）。

## 1. 已确立的事实

**本机 stable 有效补丁级别 ≈ 6.18.44**，6.18.45 起整段缺失、无越级单独回移。
21 条判定：未修 14 / 已修 1（等效）/ 代码不在 6。明细见 `PATCH_LEVEL_6.18.45_58.md`。

校准锚点（可直接复用的判据）：

```
binder_free_transaction 的 tmp_ref pin（6.18.39）  已修   0x1c5b8c add x0,x19,#0xa8 ; 0x1c5ba8 stadd
hid-logitech-dj 的 report_count==14（6.18.44）     已修   0xf7fb80 cmp w3,#0xe
```

## 2. 仅存的两个主线候选（纯 syscall、uid 2000 可达、写/读已释放对象）

| 候选 | 未修证据 | 触发面 |
|---|---|---|
| 6.18.47 `futex: Fix race on the initial mm->futex.phash.ref allocation` | 本机 `0x2bbcb8 str x0,[x19,#0x140]`（先发布计数器）→ `0x2bbcdc ldxr`/`0x2bbce4 stxr`（后自增）；**无 cmpxchg、无 free_percpu** | `prctl(PR_FUTEX_HASH=78, SET_SLOTS=1, slots, flags=1)` 并发 |
| 6.18.47 `futex/pi: Plug private futex exec() race` | `futex_exec_release` 仍 `0x2b78b8 str wzr,[x19,#0xba8]`（把 exit_state 写回 OK） | `FUTEX_LOCK_PI`（PRIVATE）+ 同 mm 的另一个进程 `execve()` |

## 3. 本轮新排除的一整类（重要，别再花预算）

**"HID 驱动在 remove 期间被报告重新武装 timer"这一类 UAF 通过 uhid 不可达。**
证据（上游源码 `drivers/hid/uhid.c` v6.18.44 原文核对）：

```c
static ssize_t uhid_char_write(...)
{
	ret = mutex_lock_interruptible(&uhid->devlock);   // ← 整条 write 都在这把锁里
	...
	switch (uhid->input_buf.type) {
	case UHID_DESTROY:	ret = uhid_dev_destroy(uhid);	break;   // → hid_destroy_device → remove()
	case UHID_INPUT2:	ret = uhid_dev_input2(uhid, ...);	break;
	...
	}
	mutex_unlock(&uhid->devlock);
```

`UHID_DESTROY` 与 `UHID_INPUT2` 走同一把 `devlock` ⇒ **不可能**在 `timer_delete_sync()` 与
`hid_hw_stop()` 之间塞进一条报告。因此：

- `HID: uclogic: fix use-after-free of inrange_timer on remove`（6.18.47）**不可达**；
- 同形状的 `HID: sony: UAF of ghl_poke_timer`（6.18.50）、`HID: alps`（6.18.55）、
  `HID: logitech-hidpp stale stack pointer`（6.18.54）在 uhid 路径下同样受限（都需要"报告与 teardown 交错"）。

## 4. 检测难题（决定下一步实验设计）

`kasan=off`、`dmesg`/`/proc/sys/kernel/tainted` 读不到、`panic_on_warn=0`
⇒ UAF 只能靠 **受控崩溃** 或 **slabinfo / /proc/meminfo 计数** 当信号。

`l78_futex_hash.c` 首轮结果（300 attempts × 8 线程，每次全新 mm）：

```
attempts=300 survived=300 multi_success=0
Percpu baseline 26240 kB → now 26240 kB (delta 0)
```

读法：**不能据此说竞态没命中**——
- 输家走的是 custom 路径的 `-EBUSY`，返回码不是竞态判据；
- `alloc_percpu(unsigned int)` 只有 4 字节，percpu 分配器按页块给，`meminfo` 看不出来。

## 5. 下一步（按可行性排序）

### 5.0 已跑过的触发（2026-10-22 20:00，全部无崩溃）

| 版本 | 设计 | 规模 | 结果 |
|---|---|---|---|
| `l79` | owner 拿锁 + 2 waiter 连续 TRYLOCK（固定相位） | 20,000 次（33/s） | 无崩溃 |
| `l80` | 随机化 exec 前延迟 | 20,000 次（296/s） | 无崩溃 |
| `l81` | PI 语义自检 | — | ✅ word 写入 owner TID、TRYLOCK→EAGAIN、阻塞 LOCK 被解锁唤醒 |
| `l82` | 单发 attach + 相对 exec 延迟 0–400µs 随机（扫相位） | 166,000 次（1253/s） | 无崩溃 |
| **`l83`** | **先把旧 mm 拆掉再让 exec 侧退出**（命中 `exit_pi_state_list` 的 `key = pi_state->key` → `futex_hash()` → `key->private.mm->futex_phash`） | **50,000 次（636/s）** | 无崩溃 |

`l83` 的设计依据（源码 v6.18.47 原文）：stale `pi_state` 只在**任务退出**时被解引用：

```c
static void exit_pi_state_list(struct task_struct *curr) {
    ...
    key = pi_state->key;
    CLASS(hb, hb)(&key);        /* → futex_hash() → __futex_hash()：
                                   key->private.mm->futex_phash  ← 解引用 */
```

### 5.1 为什么"没崩"不等于"没命中"——也是当前最大障碍

`mm_struct` 来自**专用 slab cache（`mm_cachep`）**，且 `kasan=off`、`panic_on_warn=0`、`dmesg` 读不到：
- 释放后的 mm 页通常仍映射着，读 `mm->futex_phash` 不会 fault，只会读到旧值 ⇒ **静默**；
- 要让它炸或变成有用的原语，必须**先回收那块 mm_struct**，而 mm_struct 不是 kmalloc 桶 ⇒
  现有 uhid(256B)/AF_UNIX(8K)/UI_SET_PHYS(1k) 三个原语**都打不中它**（需要整页回收到 buddy 才能跨 cache）。

⇒ **结论：PI/exec 这条 UAF 即使命中，也缺少"可控回收 + 可观测"两件事，不适合当提权主线。**

### 5.2 仍然值得做的一条（如果继续）

回到候选①（`mm->futex.phash` 初始 ref 竞态）：它释放的是 `kvzalloc(struct_size(fph, queues, slots))`——
**是 kmalloc/vmalloc 桶**，不是专用 cache；slots 可控（2 的幂）⇒ 可以把对象调到我们**能回收的尺寸**
（比如 8192 让 AF_UNIX 11872 的 order-1 页去接），而且消费者 `futex_q_lock()` 会对 bucket 做 `spin_lock` + 链表操作——
这才是"可控内容被当锁/指针用"的形状。要做就得：先量准 `struct futex_private_hash` 头部大小，
选 slots 让总大小落在目标桶，再设计"hash 被提前释放 → 我们接管这块内存 → 触发 futex_q_lock"的时序。


1. **futex PI + exec 竞态**（先做）：用 `clone(CLONE_VM|SIGCHLD)` 造"同 mm 但不同线程组"的两个进程，
   A 持 PI 锁、B 阻塞在 `attach_to_pi_owner`，A 同时 `execve()`。
   信号：`PANIC_ON_OOPS` 崩溃（一次性判定）；对象是 `mm_struct`/`pi_state`，比 4 字节 percpu 更容易在 slabinfo 上看见。
2. **futex phash ref 竞态**（次做）：把窗口做宽（全新 mm + barrier + 8~16 线程 + 反复 fork），
   并把"后果"设计成可观测（让 waiter 挂在被提前释放的 hash 上，再触发 ref 归零）。
3. 若两条都只能出 DoS：就退一步，把"14 条未修 + 指令级证据 + 触发序列"整理成可交付的审计报告
   （这本身就是硬产出）。

## 6. 纪律

- 别再碰：64560、hid-multitouch、uinput、tango32、mali、xr_fbt、binder（分配器/事务/fd）、tty、ashmem、
  uclogic/HID-timer 类。
- 判定"可达"必须过三关：SELinux/DAC 实测 + 官方接口语义 + 与 teardown 的锁关系（本轮 uhid 的教训）。

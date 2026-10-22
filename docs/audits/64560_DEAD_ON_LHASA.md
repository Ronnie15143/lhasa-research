# 结论：CVE-2026-64560 在 lhasa 上**机制级不可达**（不是概率问题）

> 2026-10-22 15:50 · 设备 `6.18.21-android17-5-g284297031c53` · 零特权 UID 2000

## 0. 一句话

`posix_cpu_timer_del()` 里那个 `if (!sh)` 分支要求
**用 `it.cpu.pid` 查出来的 task 的 `sighand == NULL`**；
而本机构的 `de_thread()`（内联在 `begin_new_exec`）**先把 pid 交换给新 leader，
之后才释放旧 leader**，所以按 tgid 查到的永远是"活着的新 leader"，
`sighand` 永远是有效的 ⇒ **`!sh` 分支不可达**。
修正后的触发结构跑了 **17,600 次 exec、三种时序形态、删除全部成功**，
零命中——这是结构性的零，不是运气。

---

## 1. 反汇编证据（本机 `rom/vmlinux-4.0.21.0.elf`）

### 1.1 `posix_cpu_timer_del` 查 pid 时用的是 **PIDTYPE_TGID**

```
+0x030  ldr  w8, [x19, #0x24]      ; timer->it_clock
+0x034  mov  w9, #1
+0x038  ldr  x0, [x19, #0x108]     ; timer->it.cpu.pid
+0x03c  bic  w1, w9, w8, lsr #2    ; w1 = 1 & ~(it_clock >> 2 的 bit0) = 1 & ~PERTHREAD
+0x040  bl   pid_task              ; (pid, type)
```
`CPUCLOCK_PERTHREAD_MASK = 4`，所以 `w1 = 1` = `PIDTYPE_TGID`（进程级计时器）。
后面 `+0x54 cbz x0, +0xb8` → `+0xc0 brk`（WARN `posix-cpu-timers.c:494`）→ `mov w0,wzr` 返回 0，
**绕开唯一摘队列点 `+0xec bl disarm_timer`** —— bug 本体确实在（详见 `STATIC_64560_LHASA.md`）。

### 1.2 `de_thread` 的顺序：**先换 pid，后释放 leader**

`begin_new_exec @ 0xffffffc0802d7c58` 内的 de_thread 尾段（反汇编原文，含符号解析）：

```
0xffffffc0802d82f0  bl  exchange_tids                    ; tsk <-> leader 的 PIDTYPE_PID 互换
0xffffffc0802d8300  bl  transfer_pid   w2=1 (PIDTYPE_TGID)
0xffffffc0802d8310  bl  transfer_pid   w2=2 (PIDTYPE_PGID)
0xffffffc0802d8320  bl  transfer_pid   w2=3 (PIDTYPE_SID)
0xffffffc0802d83b4  bl  _raw_write_unlock_irq            ; ← tasklist_lock 在这里就放掉了
0xffffffc0802d83bc  bl  cgroup_threadgroup_change_end
0xffffffc0802d83c4  bl  release_task(leader)             ; ← 才清 leader->sighand (release_task+0x2a8)
```

`transfer_pid` 本体（`0xffffffc0802d7a74`）就是 `hlist_replace_rcu(&old->pid_links[type], &new->pid_links[type])`，
**对 `PIDTYPE_PID` 还专门 `WARN_ON_ONCE(type == PIDTYPE_PID)`**（`+0x0 ac8 brk`）——
说明 PIDTYPE_PID 由 `exchange_tids` 负责，而 TGID 也在这四步里搬走了。

⇒ 等 `release_task(leader)` 把 `leader->sighand` 清零时，**tgid 已经指向 exec 线程**，
任何 `pid_task(it.cpu.pid, PIDTYPE_TGID)` 都拿到新 leader，`sighand` 有效。
再往后 `__unhash_process` 把 leader 的 pid 摘链，`pid_task` 返回 NULL（走 `p == NULL` 早退，
同样不经过 WARN）。**窗口在任何时刻都是空的。**

---

## 2. 实测：17,600 次 exec、三种时序形态、删除 100% 成功

| 版本 | 结构 | execs | 结果 |
|---|---|---|---|
| `l65 panic` | 16 victims×400 timers，gate=ntimer/10，4 删除线程，风暴 ~0.3 ms | 8,008 | 0 panic |
| `l67 panic` | 512 timers / 1 线程 / gate=4（风暴 ~1.5 ms，exec 落在风暴中段） | 3,448 | 0 panic |
| `l68 panic` | 512 timers / 2 线程 / gate=2 / 每删一次睡 15 µs（**风暴拉长到 ~4 ms，exec 必在风暴内**） | 6,192 | 0 panic |

设备侧正向校验（否则"零命中"没有意义）：
- `del=8192`（16×512）每轮 **全部 rc=0** ⇒ 计时器确实建在 victim 的 pid 上、删除确实进了 `posix_cpu_timer_del`；
- `/proc/*/cmdline` 里能看到 `--victim-child` ⇒ **victim 真的 exec 了**，de_thread 真的跑了；
- `posix_timers_cache` 的 `total` 随风暴涨落（861↔2520）⇒ 空 slab 会回 buddy，回收链本身没问题。

参考机器（`g1d099fcb35e0`，另一份 6.18.21 构建）的文档报的是 1/1000~1/5000 命中、
~7000 exec 出 panic。同样结构在本机 17,600 次零命中，与第 1 节的机制结论一致。

---

## 3. 为什么参考机器能中、本机不能

`de_thread()` 的 pid 处理顺序在不同构建里不一样：

- 参考机器（`g1d099fcb35e0`）能命中 ⇒ 它的 `release_task(leader)` 早于 pid 转移
  （或根本没有 `exchange_tids` 这一步）；
- 本机（`g284297031c53`，SPL 2026-08-01）把 `exchange_tids` / `transfer_pid(TGID)`
  放在 `release_task` 之前，而且 `release_task` 还挪到了 `tasklist_lock` 之外
  ⇒ 即使上游 6.18.41 的 `timer_lock_sighand` 修复没回移，**这条竞态面本身也不存在**。

所以 `STATIC_64560_LHASA.md` 里那四个"未回移"标记只说明**代码没按上游方式修**，
不等于**这条竞态可达**。可达性要另外证，本文件就是那个证明（反向）。

---

## 4. 影响与下一步

- **别再往 64560 上堆 exec 了**：本机无论跑多少轮都不会出 WARN，更不会出 panic / 夺页。
  HANDOVER_2 里"剩竞态命中率"的判断，现在是**错的**（不是命中率低，是窗口不存在）。
- 拿到 permissive 的路径需要换：(a) 别的内核 bug；(b) 用户态侧把 uid 0 的执行语义
  变成"能写块设备"（`IMQSNative code 7` 只能写字符串，写不了 8 MB ESP；
  `CONFIG_STATIC_USERMODEHELPER_PATH=""` 已确定封死 core_pattern/modprobe 那条）；
  (c) 找一个能写 `boot_block_device`/`android_esp_block_device` 的域并拿到代码执行。
- 本轮已建好的可复用资产（换 bug 时直接能用）：
  `l65/l67/l68`（触发+回收+夺页+`MSG_PEEK` 回读判据）、`l66_oracle`（kprobe 注册）、
  `STATIC_64560_LHASA.md`（全部符号/偏移）、`STATUS_2026-10-22_R3.md`（几何与通道标定）。

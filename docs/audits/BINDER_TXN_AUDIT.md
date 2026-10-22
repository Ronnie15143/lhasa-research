# BINDER_TXN_AUDIT — binder 事务路径静态审计（offsets / flat_binder_object / 释放 / 回吐）

- 目标设备：小米 18 Fold（lhasa），内核 `6.18.21-android17-5-g284297031c53`，4K 页，SELinux Enforcing，
  `PANIC_ON_OOPS=y`、`BUG_ON_DATA_CORRUPTION=y`、`RANDOM_KMALLOC_CACHES` 未设、`kasan=off`。
- 攻击者：uid 2000（shell），无 cap；`/dev/binder` 可 open + mmap；写路径可达（`BINDER_REOPENED.md` 实测
  `BC_TRANSACTION → write_consumed=68`）。
- 方法：**纯静态**。全部结论来自 `rom/vmlinux-4.0.21.0.elf`（139213 符号）+ `rom/Image-4.0.21.0.bin`
  （`file_off = link_addr - 0xffffffc080000000`）反汇编 + 镜像内 `.BTF` 结构 + **只读**设备查询
  （`service list`、`id`、`getenforce`）。**未在设备上执行任何 PoC / fuzz / 写操作。**
- 不重复：CVE-2026-64560、hid-multitouch、uinput FF、mali、xr_fbt、以及页面分配器 F1（`BINDER_ALLOC_AUDIT.md`）。

---

## 0. 结论摘要

1. **本路径没有找到 uid 2000 可触发的 OOB / UAF。**
   `offsets` 数组在**进循环前一次性拷进内核 buffer**、之后只从内核副本读；每个对象都有
   `type → object_size` 派生的 `offp ≤ data_size - object_size` 检查；对象内容始终从用户态按
   `min(data_size-offp, 40)` **截断拷贝到 40 字节零化栈缓冲**；所有被接受的对象都被
   `binder_alloc_copy_to_buffer` 以**完整 object_size** 写回 buffer。四处"看起来危险"的形状全部有守卫（§7）。
2. **对父任务前提的两条修正（都有地址）：**
   - **`security_binder_transaction` 在 `binder_alloc_new_buf` 之前**（`0xffffffc0801c85a4` 早于 `0x1c80c4`），
     所以"handle=0 没有 context manager 时解析/释放已经跑过"**不成立**：没有 context manager 时在
     `0x1c98a0 → 0x1c9edc`（"cannot find target node"，`0x81976ec6`）就结束，**buffer 还没分配**，
     释放路径不会跑。**但**本机 servicemanager 一定在（context mgr），且设备实测 uid 2000 的
     `service list` 成功返回 543 个服务 ⇒ **handle=0 的事务能过 SELinux、能把整条解析路径跑满**。
   - **`t->flags` 直接来自用户 `tr->flags`**（`0x1c7e0c ldp w9,w8,[x24,#0x10]` → `0x1c7e18 stp w9,w8,[x28,#0x68]`），
     写路径**没有任何 flags 掩码**（`BC_TRANSACTION/BC_REPLY` 分支 `0x1c2bc4-0x1c2c1c` 只做 64 B copy_from_user）。
     ⇒ `TF_CLEAR_BUF(0x20)` 用户可控 ⇒ `buffer->clear_on_free` 可控（`0x1c8104-0x1c8118` 的
     `bfi w10,w8,#1,#1`）。这把 `BINDER_ALLOC_AUDIT` §6 里"未取到"的 **F4（`binder_alloc_clear_buf`）变成可达**
     —— 它不属于本路径，但与 F1 组合后是**写**而不是读，见候选 C1。
3. **本机 binder 不是上游 6.18 原样**，不能照源码假设：
   数据是**分块懒拷贝**（对象区域不拷，改由 handler 回写）、对象从**用户态二次读**、
   释放用 **`failed_at` 截断**、FD 走 **fixup 链表**（`binder_free_txn_fixups` / `fd_install`）、
   PTR 走 **`binder_defer_copy` + `binder_fixup_parent`**、目标 node 带 `txn_security_ctx` 时在 buffer 尾部追加 secctx。
4. **无对端/无权限时的最大深度**：SELinux 拒绝 ⇒ 深度 0（连 buffer 都不分配）。
   有权限（本机 handle=0→servicemanager，实测可用）⇒ 深度 = 全量（分配 + 两次拷贝 + 全对象翻译 + 投递）。
   所以 PoC **不需要**"先找可 call 的服务"，handle=0 就够（§6）。

---

## 1. 事务路径总览（`binder_transaction` @ `0xffffffc0801c7bf0`）

| 阶段 | 地址 | 关键点 |
|---|---|---|
| 入口 / t 分配 | `0x1c7bf0` / `0x1c7d98-0x1c7db4` | `t = kzalloc(192)`（`w2=0xc0`），BTF `binder_transaction=192` |
| `t->code/t->flags = tr->code/tr->flags` | `0x1c7e0c` → `0x1c7e18` | **flags 不掩码** |
| `is_async = t->flags & 1` | `0x1c7ff0-0x1c7ffc` | |
| target 解析：handle≠0 | `0x1c8028`（refs_by_desc 树，`proc+0x20`）→ `0x1c8464` | `ref->node`（`ref+0x58`）→ `x19` |
| target 解析：handle==0 | `0x1c8004/0x1c8008` → `0x1c9894` | `mutex_lock(context+8)`、`context->mgr_node`（`[context]`） |
| **无 context mgr** | `0x1c98a0` → `0x1c9edc` → `0x1c9ef4` | `BR_DEAD_REPLY`（`w25=0x7205`），**无 buffer** |
| 自调用 context mgr | `0x1c9914/0x1c9918` → `0x800420c8` | `"%d:%d got transaction to context manager from process owning it"` |
| **SELinux** | `0x1c859c/0x1c85a0`（cred）+ `0x1c85a4`（call） | 失败 → `0x1cac18` → `0x800427e8` `"%d:%d transaction credentials failed"` |
| `t->to_proc = target_proc` | `0x1c8624` | |
| **buffer 分配** | `0x1c80c4`（参数 `0x1c80a8-0x1c80c0`） | `binder_alloc_new_buf(alloc, data_size, offsets_size, extra, is_async)`，`alloc=target_proc+0x1e8` |
| IS_ERR | `0x1c80cc/0x1c80d8` | `cmn x0,#0xfff` |
| buffer 元数据 | `0x1c80e4-0x1c8118` | debug_id(`bfi #5,#0x1b`)、`transaction`(+0x30)、`target_node`(+0x38)、`clear_on_free`(`bfi #1,#1`) |
| `txn_security_ctx` node 的 secctx 预留 | `0x1c9874-0x1c9888`（`extra += ALIGN(secctx_len)`，`adds`+`b.hs` 查溢出）→ `0x1c9890` 回到 alloc | 分配**之前**就已加大 `extra_buffers_size`；写点 `0x1c9828-0x1c9834`（offset = `ALIGN(data)+ALIGN(offsets)`，`t->security_ctx` 在 `0x1c9830` 回填）⇒ 不越界 |
| **offsets 数组整块拷贝** | `0x1c8128-0x1c8140` | offset = `ALIGN(data_size,8)`，from=`tr->data.ptr.offsets`，len=`offsets_size` |
| 对齐检查 | `0x1c8148-0x1c815c` | `offsets_size&7` / `extra&7` |
| 循环（每个 offset 一项） | 头 `0x1c81ac`，尾 `0x1c8420-0x1c8438` | 从**内核副本**读 8 B offset；`failed_at` 落盘在 `0x1c81d4` |
| 对象读入栈缓冲 | `0x1c825c-0x1c8314` | **从用户态** `user_ptr+offp` 拷 `min(data_size-offp,40)`，40 B 栈缓冲先零化（`0x1c81c0-0x1c81cc`） |
| type 派发 1（定 object_size） | `0x1c8318-0x1c8378` | FD=0x18 / FDA=0x20 / BINDER·HANDLE·WEAK=0x18 / PTR=0x28 |
| 边界检查 | `0x1c83d8-0x1c83f4` | `offp ≤ data_size-object_size`（`0x1c83e4`）+ 单调不减（`0x1c83f0`） |
| type 派发 2（进 handler） | `0x1c8408/0x1c8418` | |
| FD handler | `0x1c8c88-0x1c8d68` | accept_fds → `fget` → `security_binder_transfer_file` → fixup 链表 → 回写 24 B |
| BINDER/HANDLE handler | `0x1c8d6c`→`0x1c8998`/`0x1c8a48` | node 树 `proc+0x18`（比 `node->ptr`）→ cookie 比对 → `security_binder_transfer_binder` → `binder_inc_ref_for_node` → 回写 24 B（`0x1c95e0`） |
| PTR handler | `0x80042de4` | 长度边界 → `binder_defer_copy` → `binder_fixup_parent` → 回写 40 B（`0x80042e94`） |
| FDA handler | `0x80042b84` | `binder_validate_ptr` → `binder_validate_fixup` → `binder_get_object`(0x28) → `binder_translate_fd_array` → 回写 32 B（`0x80042c54`） |
| 尾部数据拷贝 | `0x1c8678-0x1c8698` | `[prev, data_size)`，`failed_at = off_end`（`0x1c8690`） |
| 投递 | `0x1c874c`（`binder_proc_transaction`） | |
| **失败清理（唯一一处）** | `0x1ca01c-0x1ca058` | release @ `0x1ca038` → `binder_alloc_free_buf` @ `0x1ca058` |

---

## 2. Q1：`data_size` / `offsets_size` 的全部校验（含顺序）

| # | 检查 | 地址 | 时机 | 结论 |
|---|---|---|---|---|
| 1 | 算术溢出：`ALIGN(d,8)+ALIGN(o,8)` 是否小于任一加数 | `0x1cafe0-0x1cb008` | 分配前 | ✅ 有 |
| 2 | `+ALIGN(extra,8)` 进位（`adds`+`cset w9,hs`） | `0x1cb018-0x1cb028` | 分配前 | ✅ 有 |
| 3 | `size = max(size,8)`（0 长度事务给 8 B） | `0x1cb020-0x1cb024` | 分配前 | ✅ 有 |
| 4 | `mapped` 检查（VMA 已关则 `-ESRCH`） | `0x1cafd8-0x1cafdc` | 分配前 | ✅ |
| 5 | `offsets_size % 8 == 0` | `0x1c814c-0x1c8150` | **offsets 拷贝之后** | ✅ 有（顺序上晚于拷贝，但拷贝长度受 #1/#3 约束，无越界） |
| 6 | `extra_buffers_size % 8 == 0` | `0x1c8158-0x1c815c` | 同上 | ✅ |
| 7 | `off_end = ALIGN(d,8)+o`；`off_end ≤ ALIGN(d,8)` ⇒ 无对象 | `0x1c8160-0x1c8174` | 循环前 | ✅ |
| 8 | 每个 offset 值：`offp & 3 == 0` | `0x1c8234` | 循环内 | ✅（4 B 对齐，非 8 B；对象字段在栈上 memcpy 读，arm64 无对齐异常） |
| 9 | `offp ≤ data_size` | `0x1c823c` | 循环内 | ✅ |
| 10 | `data_size - offp ≥ 4`（至少读到 hdr） | `0x1c8244` | 循环内 | ✅ |
| 11 | **`offp ≤ data_size - object_size`**（object_size 由 type 决定） | `0x1c83dc-0x1c83e8` | type 派发 1 之后 | ✅ **这是历史 CVE 的那个检查，存在且用的是 type 相关的 size** |
| 12 | 单调不减：`offp ≥ prev`（prev = 上一对象末端） | `0x1c83f0` | 同上 | ✅ 等价 `off_min` |
| 13 | 对象拷贝长度 `min(data_size-offp, 40)` | `0x1c8228-0x1c8230` | 循环内 | ✅ 40 B 栈缓冲先零化 ⇒ 截断对象按 0 填充，不泄露内核栈 |
| 14 | 数据分块拷贝 `[prev, offp)` 与尾部 `[prev, data_size)` | `0x1c820c` / `0x1c8694` | 循环内/尾部 | ✅ 均 `prev ≤ x ≤ data_size` |
| 15 | offsets 数组读的是**内核副本**（`binder_alloc_copy_from_buffer`），不是用户指针 | `0x1c81d0` | 循环内 | ✅ 无 offsets TOCTOU |

**"校验在写 buffer 之前还是之后"**：对象内容**不经过**"先写 buffer 再校验"的路径 ——
`[prev, offp)` 数据先写、对象本身**从用户态读进栈**校验、通过后才由 handler
`copy_to_buffer` 把**已翻译的完整 object** 写进 buffer。顺序上"先校验后写对象"，
不存在"先落盘未校验对象、后被解释"的窗口。

---

## 3. Q2：`flat_binder_object` 四种 type 的处理与一致性

| type | 值 | object_size | 处理 | 校验↔使用是否一致 |
|---|---|---|---|---|
| `BINDER` / `WEAK_BINDER` | `0x73622a85` / `0x77622a85` | `0x18`（`0x1c8bf0`/`0x1c8be4`） | node 树查 `node->ptr`（`0x1c8388`，`node+0x60`）→ 无则 `binder_new_node`（`0x1c9750`）→ **cookie 比对**（`0x1c89d4`，失败 `0x80042afc` `"sending ... cookie mismatch"`）→ `security_binder_transfer_binder`（`0x1c89e4`）→ `binder_inc_ref_for_node`（`0x1c97b0`）→ 回写 24 B（`0x1c95dc mov w4,#0x18`） | ✅ 一致（回写 24 = object_size） |
| `HANDLE` / `WEAK_HANDLE` | `0x73682a85` / `0x77682a85` | `0x18` | 同表（弱引用走 `binder_inc_ref_for_node(..., weak)`，`0x1c97a8 cset w2,eq` 比较 `0x73622a85+0x60000`）；`"tried to use weak ref as strong ref"`（`0x80042820`） | ✅ |
| `FD` | `0x66642a85` | `0x18` | `buffer->target_node->accept_fds`（`0x1c8cb8`，`node+0x71` bit3）→ `fget`（`0x1c8cc4`）→ `security_binder_transfer_file`（`0x1c8cdc`）→ `binder_txn_fd_fixup` 40 B 链表（`0x1c8cfc-0x1c8d44`）→ **清 fd** 后回写 24 B（`0x1c8d58-0x1c8d60`） | ✅ 一致；fd 在接收方**读**时才 `fd_install` |
| `PTR` | `0x70742a85` | `0x28` | 长度边界（`0x80042e14-0x80042e20`）→ `binder_defer_copy`（`0x80042e30`）→ `binder_fixup_parent`（`0x80042e74`）→ 回写 40 B（`0x80042e94 mov w4,#0x28`） | ✅ 回写 40 = object_size |
| `FDA` | `0x66646185` | `0x20` | `binder_validate_ptr`（`0x80042bd0`）→ `binder_validate_fixup`（`0x80042bf4`，乱序 → `"out-of-order buffer fixup"` `0x80042ca4`）→ `binder_get_object` 必须回 0x28（`0x80042c14`，否则 `"invalid ptr object size"`）→ `binder_translate_fd_array`（`0x80042c38`）→ 回写 32 B（`0x80042c54`） | ✅ |
| 其它 | — | — | `0x1c8370`/`0x1c83d0`/`0x1c8be8`/`0x80042dec` 四道 `b.ne` 收敛到 `0x1c9fcc`/`0x80042ebc`（`"got transaction with invalid object type, %x"`） | ✅ 白名单，非"先按 A 校验后按 B 用" |

**"先按一种 type 校验、后按另一种 type 使用"**：没有。type 只从**同一次** 40 B 截断拷贝里读一次
（`0x1c8318 ldr w26,[sp,#0x110]`），后面 4 次派发都用同一个 `w26`，且每次回写用的
object_size 就是派发 1 定下的那个 —— 三者（校验、分派、回写长度）同源。

---

## 4. Q3：失败路径与 `binder_transaction_buffer_release`

### 4.1 唯一释放点（`0x1ca01c-0x1ca058`）

```
0x1ca010  bl binder_cleanup_deferred_txn_lists
0x1ca018  bl binder_free_txn_fixups        ; 先撤 fd fixup 链表（fd 未安装，无副作用）
0x1ca024  ldr x2,[x28,#0x60]               ; buffer
0x1ca028  ldr x3,[sp,#0xd0]                ; ★ failed_at
0x1ca02c  mov x0,x22                       ; proc = target_proc
0x1ca030  mov x1,xzr                       ; thread = NULL
0x1ca034  mov w4,#1                        ; is_dead = true
0x1ca038  bl binder_transaction_buffer_release
0x1ca04c  str xzr,[x8,#0x30]               ; buffer->transaction = NULL
0x1ca058  bl binder_alloc_free_buf
```

### 4.2 释放用的 offsets 就是校验过的那一份

`binder_transaction_buffer_release`（`0xffffffc0801826f8`）用的 `buffer` 与循环期同一个，
offsets 数组在 `0x1c8140` 已整块拷入该 buffer，**内核侧不可被用户改写**
（接收方 mmap 无写权限：`binder_mmap` 见 `VM_WRITE` 直接 `-EPERM`）。

### 4.3 `failed_at` 是真截断（关键）

```
0x182848  x27 = ALIGN(buffer->data_size,8)      ; off_start
0x182854  cmp x27, x20(failed_at) ; b.hs 0x182aec   ; off_start >= failed_at ⇒ 直接返回
...
0x182984  add x25,x25,#8 ; cmp x25,x20 ; b.hs 0x182aec  ; ★ 上界是 failed_at，不是 off_end
```
即：**只释放 `[off_start, failed_at)` 区间内的对象**，与"已被翻译过的对象恰好是这一段"严格对应。

`failed_at` 的唯一来源是 `0x1c81d4  str x20,[sp,#0xd0]`（= 当前 offset 项在 offsets 数组里的位置），
**循环前进一格**才更新；循环出口另有一处 `0x1c8690 str x20,[sp,#0xd0]`（此时 `x20 = off_end`，
全部对象都已翻译，语义正确）。

### 4.4 "offsets 未校验就进释放"的分支：**没有**

分配之后、首次 `0x1c81d4` 之前的三条失败路径全部**显式把 `failed_at` 归零**：

| 失败 | 归零点 | 冷块 |
|---|---|---|
| offsets 数据拷贝失败（`0x1c8144`） | `0x8004246c  str xzr,[sp,#0xd0]` | `"%d:%d got transaction with invalid offsets ptr"`（`0x819319fd`） |
| `offsets_size & 7`（`0x1c8150`） | `0x80042488  str xzr,[sp,#0xd0]` | `"%d:%d got transaction with invalid offsets size, %lld"`（`0x8190977e`） |
| `extra & 7`（`0x1c815c`） | `0x800424b0  str xzr,[sp,#0xd0]` | `"%d:%d got transaction with unaligned buffers size, %lld"`（`0x819097b5`） |

`failed_at = 0` ⇒ `off_start >= 0` ⇒ 释放循环一次都不进（`0x182854`）。**这堵死了历史 CVE 的经典形状。**

---

## 5. Q4：`binder_thread_read` 回吐（`BR_TRANSACTION` / `BR_REPLY`）

`binder_thread_read` 被**完全内联**进 `binder_ioctl_write_read`（`0xffffffc0801c2700`，~0x2FD0 B，
符号表里没有独立的 `binder_thread_read`）。

- 写命令字用 `sttr`（`0x1c4750`/`0x1c479c`/`0x1c3b74`），前后有 `access_ok` 检查（`0x1c4784`、`0x1c4848`，
  比较常量 `0xfffffd7fffff0000` 形态），失败串 `"copy_to_user failed"`（`0x819bcdd9`，引用点 `0x1c4668`）。
- **内核不回吐 buffer 内容**：`BR_TRANSACTION` 只把 `binder_transaction_data`（64 B）写给用户，
  `data.ptr.buffer` 指向**接收方自己 mmap 的 `buffer->user_data`**，`data_size`/`offsets_size`
  直接取 `buffer->data_size/offsets_size`（分配时定死、用户不可改）。
  ⇒ **不存在"按用户给定长度把内核 buffer 内容拷回"的 OOB read 形状**。
- 读路径额外做的是 **fd 安装**（`get_unused_fd_flags`/`fd_install`，`0x1c48xx` 一带）与
  **PTR 延迟拷贝**（`binder_alloc_copy_to_buffer` + `binder_cleanup_transaction`），
  这两处吃的是本次事务自己的、已校验的 `binder_defer_copy`/fixup 记录。
- 未取到：64 B `binder_transaction_data` 的具体搬运指令序列（编译器把 `copy_to_user` 展开/内联了，
  函数范围内**没有** `bl copy_to_user`/`__arch_copy_to_user`；已确认的是"没有任何以用户长度为参数的
  内核 buffer 内容拷贝"）。

---

## 6. Q5：uid 2000 能走到多深

| 情形 | 深度 | 证据 |
|---|---|---|
| handle=0，无 context mgr | **0**（不分配 buffer） | `0x1c98a0 cbz x19,0x1c9edc` → `0x1c9ef4` `"cannot find target node"` → `return_error=0x7205`（`0x1c9ee8`），无 `binder_alloc_new_buf` |
| handle=0，context mgr 存在但**自己是 owner** | 0 | `0x1c9914/0x1c9918` → `0x800420c8` `"...from process owning it"` |
| target 解析成功但 **SELinux 拒绝** | **0**（仍在 alloc 之前） | `0x1c85a4 bl security_binder_transaction`；alloc 在 `0x1c80c4`，只能从 `0x1c8664/0x1c8674` 进入（都在 `0x1c85a4` 之后） |
| target 解析成功且 SELinux 放行 | **全量**：分配 + offsets/数据拷贝 + 全对象翻译 + 投递 | 同上路径 |

**本机的实际可达性（只读实测）**：`adb shell`（uid 2000）执行 `service list` 成功返回
**543 个服务** ⇒ shell→servicemanager 的事务被放行 ⇒ **`BC_TRANSACTION` + `handle=0` 可以把上面
"全量"这条路径跑满**，包括 `data_size/offsets_size` 任意取值与四种 `flat_binder_object`。

补充（口径要写清）：解出的 `plat_sepolicy.cil` / `system_ext_sepolicy.cil` / `vendor_sepolicy.cil` /
`plat_pub_versioned.cil` 里**找不到** `(allow shell servicemanager (binder (call)))`；plat 只有
`(allow shell servicemanager (service_manager (list)))`，给 shell 的 binder call 白名单是
`storaged / statsd / gpuservice / lpdumpd / hal_keymint / virtualizationservice / dumpstate / logturbo`。
**但设备上 `service list` 确实成功**，说明放行来自未解出的策略文件或 servicemanager 侧配置。
⇒ 记为**已实测放行**；如果后续 PoC 在真机上收到 `-EPERM`（`0x800427e8`），再按白名单换
`statsd`（`(allow shell statsd (binder (call transfer)))`）等目标。

---

## 7. 候选清单（按判据一行一条）

```
内存破坏（本路径）: 没有
```

四处"看起来像 CVE"的形状与排除依据：

| 形状 | 为什么不是 |
|---|---|
| offsets 数组拷贝（`0x1c8140`）**早于**对齐检查（`0x1c814c`） | 拷贝长度 `offsets_size` 受 `binder_alloc_new_buf` 的溢出/`size` 计算约束（`0x1cafec-0x1cb030`），越界会先在分配处失败；拷贝只是 `copy_user_to_buffer`，最坏返回错误 |
| 对象从**用户态**读（`0x1c82dc`），数据区另有一份内核拷贝 | 对象区被分块拷贝**跳过**，handler 用**完整 object_size** 回写；栈缓冲 40 B 先零化 ⇒ 既不 TOCTOU 也不泄露栈 |
| type 决定 object_size（4 处派发） | 校验/派发/回写同源同一个 `w26` 与同一个 `w9/x8`（§3） |
| `failed_at` 只在 `0x1c81d4` 更新 | 三条前置失败路径显式归零（§4.4）；`off_start >= failed_at ⇒ 返回`（`0x182854`） |

**唯一候选（跨线，非本路径自身缺陷）**

```
数据破坏/DoS · BC_TRANSACTION{handle=0, data_size=任意, offsets_size=0, tr.flags=0x20(TF_CLEAR_BUF)} → 目标 free 该 buffer
 · 置位 0x1c8104-0x1c8118（bfi #1 = (t->flags>>5)&1）；消费 0x8180b58（binder_alloc_free_buf 内、mutex 之前）
   → binder_alloc_clear_buf 0xffffffc0804370c0（size = buffer->entry.next->user_data - user_data，pages[idx] 无 NULL 检查 0x437134）
 · 命中信号：PANIC_ON_OOPS 下 panic 重启（对已回收页 memset）；slabinfo 无变化（binder 页来自 buddy，非 slab）
 · reclaim：**不能用**现有 uhud/AF_UNIX/uinput 原语 —— clear_buf 写的是 binder 自己的 order-0 页，不是 slab 对象；
   只能与 F1（页 LRU 破裂）组合，把 F1 的"读空页槽"升级为"写已回收页"，口径仍是 DoS/数据破坏
```

> 依据：`BINDER_ALLOC_AUDIT` 判定 F4 的关键前提是"`buffer->clear_on_free` 能否被攻击者置位"，当时记为**未取到**。
> 本轮补上了：`t->flags = tr->flags`（`0x1c7e18`），写路径不掩码（`0x1c2bc4-0x1c2c1c`）。
> 本候选的触发**不需要**本路径的任何越界；它只是把 F1 从读变成写。

---

## 8. 未取到 / 局限（明确标注，勿当结论）

| 项 | 状态 |
|---|---|
| `binder_validate_ptr`（`0x8101b33c`）/ `binder_validate_fixup`（`0x8101b570`）/ `binder_defer_copy`（`0x8101b80c`）/ `binder_fixup_parent`（`0x8101b8c8`）的**内部语义** | **未展开**。只确认调用点、参数与失败串（`"invalid parent offset or type"` `0x80042c80`、`"out-of-order buffer fixup"` `0x80042ca4`、`"invalid ptr object size"` `0x80042ccc`、`"failed to fixup parent"` `0x80042f3c`、`"deferred copy failed"` `0x80042f18`）。PTR/FDA 的边界数学（`0x80042df4-0x80042e20`）只读到"用 `off_end+extra` 与 `ALIGN(secctx)` 相减后与 `bbo->length` 比较"这一层 |
| `BC_TRANSACTION_SG` 是否被接受、`extra_buffers_size` 怎么进来 | **未取到**。`BC_TRANSACTION/BC_REPLY`（`0x40406300/0x40406301`）在 `0x1c2c0c` 明确 `x4=xzr`（extra=0）；SG 变体的命令字与参数没定位到 |
| `binder_alloc_new_buf` 的页级细节 | 属 F1 线（`BINDER_ALLOC_AUDIT.md`），本轮不重复 |
| 读路径 64 B `binder_transaction_data` 的搬运指令 | 未定位（无 `bl copy_to_user`；结论只依赖"没有以用户长度为参数的 buffer 内容拷贝"） |
| `txn_security_ctx` 追加写（`0x1c9874-0x1c9834`） | **已闭环**：`extra_buffers_size` 在**分配前**被 `+= ALIGN(secctx_len)`（溢出查 `adds`+`b.hs` → `0x1cad04`），secctx 写在 `ALIGN(data)+ALIGN(offsets)`，`t->security_ctx` 回填用户地址（`0x1c9830`）。非 SG 事务 `extra=0` 时不重叠 |
| SELinux 为何放行 shell→servicemanager | 未定位到策略行；以**设备实测**为准（§6） |

---

## 9. 下一步（PoC 计划，**未执行**）

1. **可达性锚点（零风险）**：`BC_ENTER_LOOPER` → `BC_TRANSACTION{handle=0, code=0xdeadbeef, data_size=8, offsets_size=0}`，
   期望 `write_consumed=68` 且随后读到 `BR_REPLY`/`BR_FAILED_REPLY` —— 证明 handle=0 放行且解析路径跑过。
   若返回 `BR_FAILED_REPLY` 且 dmesg 出现 `transaction credentials failed`，说明 SELinux 拒绝，改打 `statsd`（§6）。
2. **对象覆盖矩阵**（每次一条事务，观察是否 `BR_FAILED_REPLY`）：四种 type 各自 `offp ∈ {0, data_size-24, data_size-1}`
   —— 应分别命中 `0x1c83e4`（越界）与 `0x1c8244`（不足 4 B）。
3. **C1 验证**：`tr.flags=0x20` 发一条 `data_size=0x800` 的事务，让目标 free 后观察
   `binder_alloc_clear_buf` 是否真的被调用（静态判据：`0x8180b58` 在 `mutex` 之前）；
   **注意** 与 F1 组合才有破坏性，单独调用只是清零自己的 buffer。
4. 若要做 PTR/FDA：先补 §8 的四个 helper 语义，再谈触发序列；**现在不建议**直接构造。

---

## 附录：本轮用的静态手段（可复现，未入库脚本）

```bash
# 1) 反汇编某个符号（符号表无 size，用"下一个符号"当边界）
python rom/kdisasm.py rom/vmlinux-4.0.21.0.elf rom/Image-4.0.21.0.bin binder_transaction 3300

# 2) BTF 结构（注意：btf_dump.py 对位域只给"bit偏移/8"，binder_buffer 的 flags 需看原始 bit）
python rom/btf_dump.py rom/Image-4.0.21.0.bin binder_transaction_data flat_binder_object binder_buffer binder_transaction

# 3) 字符串 -> 代码 的 xref（本机 IDA 之外最省事的办法）：
#    adrp 编码 (w & 0x9F000000) == 0x90000000，imm = sx(immhi<<2|immlo,21)<<12，
#    page = (pc & ~0xfff) + imm；再匹配下一条 add 的 imm12 == (va & 0xfff)（Rn == adrp 的 Rd 即可，
#    Rd 可以不同！只比 Rd 会漏掉编译器生成的 `adrp x8; add x1,x8,#lo12`）。
# 4) 反汇编器必须开 capstone `skipdata=True`（否则遇到字面量池就整段停止），
#    并且 capstone 的 imm 对内核高地址是**负数**，必须先 `& 0xFFFFFFFFFFFFFFFF` 再和符号表比。
```


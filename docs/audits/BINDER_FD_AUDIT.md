# BINDER FD 传递路径审计（BINDER_TYPE_FD / BINDER_TYPE_FDA）

靶标：小米 18 Fold（lhasa），`6.18.21-android17-5-g284297031c53`，SELinux Enforcing，
`PANIC_ON_OOPS=y`、`BUG_ON_DATA_CORRUPTION=y`、`kasan=off`、`RANDOM_KMALLOC_CACHES` 未设。
攻击者：`adb shell` uid 2000 无 cap，binder 写路径可达（`BC_ENTER_LOOPER`/`BC_TRANSACTION` 实测 consumed）。
方法：纯静态。`Image-4.0.21.0.bin` 线性 dump（`file_off = link_addr - 0xffffffc080000000`），
符号取自 `vmlinux-4.0.21.0.elf` 符号表，结构体取自该 Image 自带 `.BTF`。
事务主路径（offsets / flat_binder_object 边界 / thread_read 回吐）见 `BINDER_TXN_AUDIT.md`，本文只做 fd 这一支。

---

## 0. 结论摘要

| # | 审计点 | 结论 | 关键地址 |
|---|---|---|---|
| 1 | `binder_translate_fd` 入参 / `fget` 选择 / O_CLOEXEC·FMODE_PATH / LSM 失败分支 | **无缺陷**（语义与上游一致） | `0x8010384c`、`0x801c8c88` |
| 2 | `BINDER_TYPE_FDA` 校验顺序（先 fdget 还是先校验） | **无缺陷**：边界/对齐/溢出全部在第一次 `fget` 之前 | `0x8101b66c` |
| 3 | 接收侧 `get_unused_fd_flags` / `fd_install` / `copy_to_buffer` 次序与回滚 | **无缺陷**：两趟式（先 reserve+回写，后 `fd_install`），回滚只 `put_unused_fd` + `fput(fixup->file)` | `0x1c421c-0x1c42dc`、`0x1c44a4` |
| 4 | `binder_transaction_buffer_release` 对 FD/FDA 的处理 | FD 不 fput（引用归 fixups）；FDA 在 `is_failure==false` 时对 **buffer 里的裸 fd 号** 调 `binder_deferred_fd_close()` | `0x1826f8`、`0x8000437e8` |
| 5 | **TF_UPDATE_TXN 取代（supersede）清理** | **缺陷**：不调用 `binder_free_txn_fixups` → `struct file` 引用泄漏；且以 `is_failure=false` 释放 → 触发上面那条裸 fd 号关闭 | `0x801c6fd8-0x801c7024` |

**一句话**：fd 路径的 **内存安全**（UAF / double-close / OOB）是干净的——两趟式安装 + `put_unused_fd` 口径正确，
fput 的永远是 fixup 自己 fget 出来的引用，不会 fput 用户态仍持有的 fd 值。
真正有问题的是 **TF_UPDATE_TXN 取代路径的清理**：泄漏 fd fixup（含 `struct file` 引用），
并以错误的方向（`is_failure=false`）释放被取代事务的 buffer，导致对发送方自己的 fd 表执行
`file_close_fd()`——即上游 2026-06/08/09 三个补丁分别在修的三件事。

---

## 1. 发送侧：`binder_translate_fd`

### 1.1 FD 对象的内联实现（`binder_transaction` 内，`0xffffffc0801c8c88`–`0x1c8d68`）

```
0x1c8c88  w8 = 0x66642a85 (BINDER_TYPE_FD) ; cmp w26,w8 ; b.ne → 其它类型
0x1c8c98  x19 = [stack] -> sender proc          ; x25 = fd (w25 = [x29-0x?])
0x1c8ca8  x26 = [stack] -> target proc (txn->to_proc)
0x1c8cac  cbnz x8, 0x1c91d4                     ; in_reply_to != NULL → 走回复分支（不经 node->accept_fds）
0x1c8cb0  x8 = [x28+0x60]                       ; txn->buffer            (binder_transaction::buffer = +0x60)
0x1c8cb4  x8 = [x8+0x38]                        ; buffer->target_node    (binder_buffer::target_node = +0x38)
0x1c8cb8  w8 = ldrb [x8+0x71]                   ; node->accept_fds（bit3）
0x1c8cbc  tbz w8,#3 → 0x1c8ac70                 ; 不接受 → "「%d:%d got %s with fd, %d, but target does not allow fds」"
0x1c8cc0  w0 = fd ; 0x1c8cc4 bl 0x8017d788      ; fget(fd)
0x1c8cc8  cbz x0 → 0x1c8ac74                    ; NULL → "got transaction with invalid fd, %d"
0x1c8cd0  x0 = [x19+0x50]                       ; sender proc->cred   (binder_proc::cred = +0x50)
0x1c8cd4  x1 = [x26+0x50]                       ; receiver proc->cred
0x1c8cd8  x2 = file
0x1c8cdc  bl 0x801cbae8                         ; security_binder_transfer_file()
0x1c8ce0  tbnz w0,#31 → 0x1c8ac78               ; 负值 → EPERM 分支
0x1c8cec  kmem_cache_alloc(cache=0x81a24448, GFP=0xdc0, size=0x28)   ; binder_txn_fd_fixup
0x1c8d00  cbz x0 → -ENOMEM
0x1c8d04  x2 = x27 + 8                          ; user_offset + 8 = flat_binder_object::handle/fd 字段所在偏移
0x1c8d0c  stp file, offset, [fixup+0x10]        ; fixup->file, fixup->offset
0x1c8d10  target_fd = -1
0x1c8d14..0x1c8d44  list_add_tail(&fixup->fixup_entry, &t->fd_fixups)   ; 链表头 = txn+0x90
0x1c8d48  x1 = [x28+0x60] (buffer) ; x0 = &proc->alloc (+0x1e8)
0x1c8d58  w4 = 0x18 ; 0x1c8d60 binder_alloc_copy_to_buffer(alloc, buffer, off, &obj, 24)
0x1c8d5c  str xzr, [sp,#0x118]                   ; 回写前把 fd 字段清零 → 接收方看到 0，真值在读取时写入
```

要点：

* **`fget`，不是 `fget_raw`**（`0x8017d788 == fget`）。`fget()` 用 `FMODE_PATH` 作掩码，
  因此 **O_PATH fd 会被当成 EBADF 拒绝**——不需要额外检查。
* **O_CLOEXEC 在发送侧不参与**：接收侧 `get_unused_fd_flags(0x80000)` 统一强制 `O_CLOEXEC`
  （见 §3），所以"发过来的 fd 一定 CLOEXEC"是设计行为，不是漏洞。
* **FMODE_EXEC 不做判定**（内核不关心）。
* LSM 顺序：先 `fget`（拿引用）→ 再 `security_binder_transfer_file()`；被拒则 `fput` 后返回 -EPERM。
  没有"先检查后取引用"的 TOCTOU。

### 1.2 out-of-line 版（FDA 数组逐个调用，`0xffffffc08010384c`）

入参：`w0 = fd`、`x1 = user_offset`、`x2 = txn`、`x3 = thread`、`x4 = in_reply_to`。

```
0x103880  cbnz x4 → 0x103938
0x103938  w8 = ldrb [x4+0x6c]        ; in_reply_to->flags (binder_transaction::flags = +0x6c)
0x10393c  tbnz w8,#4 → 0x103894      ; bit4 = TF_ACCEPT_FDS(0x10) 满足 → 允许
0x103940  否则 binder_user_error(0x818f5689 串) → -EPERM
0x103884  （无 reply 时）x8=[x20+0x60] → [x8+0x38] → ldrb [x8+0x71] bit3 = node->accept_fds
0x103894  fget(fd) → 0x103898 ; NULL → 0x103954 报 "invalid fd"，w19 = -9 (-EBADF)
0x1038a4  x0 = [[x3]+0x50]  = thread->proc->cred   (binder_thread::proc = +0x0)
0x1038a8  x1 = [txn->to_proc + 0x50]
0x1038b0  security_binder_transfer_file(from, to, file)
0x1038b4  tbnz w0,#31 → 0x103974：w19 = -1 (-EPERM) → 0x1039b0 fput(file)
0x1038c0  kmem_cache_alloc(0x28, 0xdc0) → 0x1039ac：-ENOMEM(-0xc) → fput
0x1038dc  fixup->file = file ; fixup->offset = user_offset（数组里已指向 fd 字）
0x1038e0  fixup->target_fd = -1 ; list_add_tail(&fixup->fixup_entry, &txn->fd_fixups)
```

`binder_txn_fd_fixup`（BTF，size 0x28）：`fixup_entry +0`、`file +0x10`、`offset +0x18`、`target_fd +0x20`。

### 1.3 `security_binder_transfer_file`（`0xffffffc0801cbae8`）判定口径

钩子签名是 `(const struct cred *from, const struct cred *to, const struct file *file)`，
实参 = **发送方 cred / 接收方 cred / 文件**。AOSP SELinux 实现里用的是 **`to` 的 sid** 与文件 inode 的
label 做 `FILE__READ`（可写文件再加 `FILE__WRITE`）判定，**发送方（shell）自己的 sid 不参与**。

推论（静态口径）：uid 2000 能不能把 fd 递过去，取决于**目标域**能不能读那个文件，而不是 shell 能不能读。
典型目标（system_server / surfaceflinger / mediaserver 等）对 `/dev` 节点、ashmem、dmabuf、pipe/socket
通常是放行的，所以 fd 传递在策略上一般通过；被拒时走 `0x103974`（-EPERM）分支，发送方看到
`BR_FAILED_REPLY`。本机 SELinux 为 Enforcing，实际放行与否依设备策略，需动态确认（本节未读
`selinux_binder_transfer_file` 函数体，只按钩子调用点与实现口径判断）。

---

## 2. 数组路径：`binder_translate_fd_array`（`0xffffffc08101b66c`）

对象是 `binder_fd_array_object`（size 0x20）：`hdr +0`、`pad +4`、**`num_fds +8`**、
`parent_offset +0x10`、`parent_cookie +0x18`。

```
0x8101b69c  x3 = [x1+8]                    ; num_fds
0x8101b6a0  cbz → return 0                 ; 空数组直接成功
0x8101b6a4  cmp num_fds, 0x3fffffffffffffff ; 溢出保护
0x8101b6b0  b.lo → 否则 binder_user_error(0x819632a3 串) → -EINVAL(-0x16)
0x8101b6c8  x9 = num_fds << 2              ; 数组字节数
0x8101b6cc  x11 = [x2+0x10]                ; 上界（mapping/buffer 尺寸）
0x8101b6d0  subs x12, x11, x9 ; b.lo → 报错 0x819632dc 串 → -EINVAL
0x8101b6d8  x11 = [x1+0x18]                ; parent_offset / parent_cookie
0x8101b6dc  cmp x11, x12 ; b.ls → 否则 -EINVAL
0x8101b71c  tst (offset|user_ptr), #3 → 未对齐 → 报错 0x818ebf22 串 → -EINVAL
0x8101b744  bl 0x800b76b4                  ; binder_add_fixup() —— **此处之前没有任何 fget**
0x8101b758  loop i in 0..num_fds:
              0x8101b768  bl 0x800555e0   ; get_user(u32, base + i*4)
              0x8101b784  bl 0x8010384c   ; binder_translate_fd(fd, off + i*4, txn, thread, in_reply_to)
              0x8101b788  cbnz w0 → 0x8101b7f8
0x8101b7f8  cmp w0,#0 ; csel w0, -0x16, w0  ; 正数错误码统一归 -EINVAL
```

**结论（针对"历史 double-close 形态"）**：`num_fds` 溢出、数组字节数、`parent_offset` 边界、
4 字节对齐 **全部在第一次 `fget` 之前**完成校验。不存在"先把数组里的 fd 全 fget 一遍、再发现数组越界、
再释放"的旧形态。中途某个 fd 失败时，先前已挂到 `txn->fd_fixups` 的条目由
`binder_free_txn_fixups()` 统一 `fput`（见 §4），**不会重复 fput**。

唯一可指摘的是"`num_fds` 取自内核对象副本、数组内容却每轮 `get_user` 重读"（发送方多线程可改），
但被改的只是 fd 号，仍要过 `fget`/`accept_fds`/LSM，无安全影响。

---

## 3. 接收侧安装（`binder_thread_read` 内联于 `binder_ioctl_write_read`）

安装是**两趟式**，位于 `0xffffffc0801c421c`–`0x1c42dc`：

**第 1 趟：reserve + 回写**

```
0x1c4220  ldr x27,[x20,#0x88]!      ; head = &t->fd_fixups（t+0x90；x20 前推 0x88 后 +8 = 0x90）
loop:
0x1c4230  w0 = 0x80000              ; O_CLOEXEC
0x1c4234  bl 0x8011bb64             ; get_unused_fd_flags(O_CLOEXEC) —— 只占号，不安装
0x1c4244  tbnz w0,#31 → 0x1c44a4    ; 失败 → 错误路径
0x1c4274  str w8,[x27,#0x20]        ; fixup->target_fd = fd   （先落下 target_fd）
0x1c4278  x1 = [x19,#0x58]          ; t->buffer（x19 = &t->work，work 在 txn+0x8）
0x1c4280  x0 = &proc->alloc (+0x1e8)
0x1c4284  bl 0x8011223c             ; binder_alloc_copy_to_buffer(alloc, buffer, fixup->offset, &fd, 4)
0x1c4288  cbnz w0 → 0x1c44bc        ; 回写失败 → 错误路径
0x1c428c  next = fixup->next
```

**第 2 趟：`fd_install`（不可失败，且消费引用）**

```
0x1c42ac  w0 = [x27,#0x20] (target_fd) ; x1 = [x27,#0x10] (file)
0x1c42b8  bl 0x801290c4             ; fd_install(fd, file)
0x1c42c0  bl 0x8027aba0             ; __list_del_entry(&fixup->fixup_entry)
0x1c42cc  stp 0xdead…0100/0x22,[x27] ; 毒化
0x1c42d0  bl 0x80119b3c             ; kfree(fixup)
```

**次序判定**：`get_unused_fd_flags` → 写回 buffer → 全部成功后才 `fd_install`。
`fd_install` 之后没有任何可能失败的步骤，因此**不存在"`fd_install` 成功后事务失败、fd 已装但无人回收"**的窗口。
（`fd_install` 也不能失败，这是把它放最后的原因。）

**失败回滚**（`0x1c44a4` = alloc 失败 / `0x1c44bc` = copy_to_buffer 失败）：

```
0x1c44b4  w27 = -0xc (-ENOMEM)   /  0x1c44bc  w27 = -0x16 (-EINVAL)
0x1c44c4  bl 0x8005579c          ; binder_free_txn_fixups(t)
0x1c44f4  str xzr,[buffer+0x30]  ; buffer->transaction = NULL
0x1c44f8  bl 0x800a91dc          ; binder_cleanup_transaction()
0x1c4514  bl 0x801880cc          ; binder_free_buf()
```

回滚口径见 §4：**只 `put_unused_fd()` 内核自己 reserve 的号位，`fput()` 的是 fixup 自己 `fget` 的引用**。

---

## 4. `binder_free_txn_fixups`（`0xffffffc08005579c`）——"会不会 fput 用户态仍持有的 fd 值"

```
0x8005579c  ldr x8,[x0,#0x90]!      ; x0 = &t->fd_fixups；空则 ret（第二次调用是空操作）
loop:
0x800557d8  ldr x0,[x8+0x10]        ; fixup->file
0x800557dc  ldr x22,[x8]            ; next（先取）
0x800557e4  bl fput                 ; **只 fput fixup 自己 fget 出来的引用**
0x800557e8  w0 = [fixup+0x20]       ; target_fd
0x800557f0  tbnz w0,#31 → skip      ; 负数（= -1，尚未 reserve）直接跳过
0x800557f4  bl 0x802476ac           ; put_unused_fd(target_fd)  ← 语义是"归还保留的号位"，不是 close
0x800557fc  __list_del_entry ; 毒化 ; kfree(fixup)
```

* `target_fd == -1` 表示该 fixup 从未走到 reserve 阶段 → 只 fput。
* `target_fd >= 0` 只可能出现在第 1 趟成功之后，此时号位是**内核 reserve 的、尚未 `fd_install`**，
  用 `put_unused_fd()` 归还正确；**如果这里误用 `close_fd()`，才会出现"关掉别人的 fd"**——本内核用的是
  `put_unused_fd`（`0x802476ac`），没有问题。
* `list_del` 正确维护链表头，重复调用安全。

因此：**用户态的 fd 值只被当作"号"用，从不被 fput；`struct file` 引用始终来自 `fget`，一对一抵消。**
"fput 一个用户态仍持有的 fd 值 → 引用计数错乱/双关"这条路在本内核上不成立。

---

## 5. `binder_transaction_buffer_release`（`0xffffffc0801826f8`）对 FD/FDA 的处理

主循环：`0x1827?` 起按 `binder_size_t` 步进（`add x25,x25,#8`），`binder_alloc_copy_from_buffer` 取对象头，
按 `failed_at` 截断，分发类型（对象尺寸：FD/WEAK/HANDLE = 0x18、FDA = 0x20、PTR = 0x28）。

* **FD（`0x66642a85`）**：走 `0x182cc8` 一带，**不做 fput、不做 close**。
  这是对的——FD 的 `struct file` 引用归 `txn->fd_fixups`（§4 负责），buffer 里只剩清零后的占位。
* **FDA（`0x66646185`）**：`0x182c10` 命中后到 `0x182c20`：

```
0x182c20  tbnz w28,#0 → 0x182984   ; w28 = is_failure（第 5 个入参）；失败路径**跳过**
0x182c20..0x182c2c 清零栈上局部
0x8000437e8 （尾调用）:
   0x80043808  binder_validate_ptr()
   0x80043814  num_fds 溢出检查（0x3fffffffffffffff）
   0x80043824..0x80043838  num_fds*4 与上界、parent_offset 的边界检查
   0x8004385c  loop:
       0x80043874  binder_alloc_copy_from_buffer(&alloc, &fd, buffer, off, 4)   ; **fd 号直接取自 buffer 内容**
       0x80043880  bl binder_deferred_fd_close(fd)
       0x80043884..0x80043890  置某 bool = 1
```

`binder_deferred_fd_close`（`0xffffffc08101b410`）实现：

```
kmalloc(0x18, cache 0x81a24440)        ; callback_head + file
twork->func = 0x8101b53c              ; binder_do_fd_close
file = file_close_fd(fd)              ; **在 current->files 上真的把该 fd 关掉**，返回 file
if (!file) { kfree(twork); return; }  ; 号不存在 → 无声返回
twork->file = file ; get_file(file)
filp_close(file, current->files)      ; 走正常 close 副作用（flock/dnotify）
task_work_add(current, twork, TWA_RESUME)   ; 最后的 fput 推迟到 task_work（即 2021 年
                                            ; "binder: make sure fd closes complete" 的设计）
```

**判定**：这段逻辑本身的设计意图是"buffer 正常释放时，把当初为这个 buffer 装进**本进程**的 fd 关掉"。
它信任 buffer 里的 fd 号，并且无条件作用在 **`current`（正在释放 buffer 的进程）** 的 fd 表上。
只要调用它的时机/方向正确（正常 `BC_FREE_BUFFER`，`current` == buffer 的属主），行为正确。
问题出在 **`is_failure` 传错**的那条路径 —— 见 §6。

---

## 6. 缺陷：TF_UPDATE_TXN 取代（supersede）清理路径

位置：`binder_proc_transaction` 区域（`0xffffffc0801c6b04` 函数体内）`0xffffffc0801c6fd8`–`0x1c7024`。

```
0x1c6fd8  ldr x20,[x27,#0x60]      ; 被取代事务 old->buffer
0x1c6fdc  str xzr,[x27,#0x60]      ; old->buffer = NULL（先摘除）
0x1c6fe4  str xzr,[x20,#0x30]      ; buffer->transaction = NULL
0x1c6fe8  bl 0x8101bd58            ; trace_binder_transaction_update_buffer_release()
0x1c6fec  x8,x9 = [buffer+0x40],[buffer+0x48]   ; data_size, offsets_size
0x1c6ff0  x0 = proc ; x1 = NULL(thread) ; x2 = buffer
0x1c6ffc  w4 = 0                   ; **is_failure = false**
0x1c7000  x3 = ALIGN(data_size) + offsets_size  ; failed_at = 末尾 → 释放**全部**对象
0x1c700c  bl 0xffffffc0801826f8    ; binder_transaction_buffer_release(proc, NULL, buffer, end, false)
0x1c7010  x0 = &proc->alloc ; 0x1c7018 binder_alloc_free_buf()
0x1c701c  bl 0x80119b3c            ; kfree(old)  —— 事务对象直接释放
```

全库 `binder_free_txn_fixups` 只有两个调用点：`0x1c44c4`（§3 安装失败）与 `0x1ca018`
（`binder_transaction` 的错误路径，紧随其后 `0x1ca038` 以 `w4=1` 调 buffer_release）。
**上面这条 supersede 路径不在其中。**

### 缺陷 6-A：fd fixup / `struct file` 引用泄漏（refcount leak，非 UAF）

被取代事务的 `t->fd_fixups`（每个 fd 一个 40B `binder_txn_fd_fixup`，每个持有一个 `fget` 出来的
`struct file` 引用）既不 `fput` 也不 `kfree`：`0x1c701c` 直接把事务对象扔掉。
命中形态：每次 `TF_UPDATE_TXN` 取代都泄漏 `fd_count` 个文件引用 + `fd_count` 个 kmem_cache 对象。
触发键：`BC_TRANSACTION` + `binder_transaction_data.flags |= TF_UPDATE_TXN(0x40)`，且 payload 的
`offsets` 里带 `BINDER_TYPE_FD`（任意可传递的 fd，例如 `/dev/null`）。

* 效果：`struct file`/dentry/inode 引用无限增长（文件无法回收、无法删除），可达 kmem 耗尽 → **DoS**。
* 不是 UAF：泄漏的方向是"少释放"，不是"提前释放"，没有任何可被 reclaim 的空洞。
* 与上游 2026-06 `binder: free fd fixups on superseded transaction teardown`、
  2026-08 `binder: fix leaked fd fixups on TF_UPDATE_TXN supersede` 同源。

### 缺陷 6-B：`is_failure=false` 让 FDA 分支对裸 fd 号执行 `file_close_fd()`（"sender fd 0 close"）

因为 `w4 = 0`，`0x182c20` 的 `tbnz w28,#0` 不跳转，`0x8000437e8` 的 FDA 循环真的跑：
对 **被取代事务 buffer 里** 的每个 u32 调 `binder_deferred_fd_close(fd)` →
`file_close_fd(fd)` 作用在 **`current->files`**，而 `current` 在这里就是**发送方自己**（supersede 发生在
发送方的 `BC_TRANSACTION` ioctl 上下文）。

* 那些 fd 号来自 buffer 内容；被取代事务是发送方自己创建的，因此这些号**发送方完全可控**
  （包括 `0`、`1`、`2`）。结果是内核替发送方关掉它自己的 fd——包括 fd 0。
* 命中信号（动态可验）：`/proc/self/fd` 条目减少；随后 `read(0,…)` 返回 `EBADF`；
  `filp_close()` 会清掉该 fd 上的 flock/dnotify。发送方是多线程时，号位可能已被别的线程复用，
  → **关掉一个刚被重新分配的 fd**（fd 号与内核对象错配，典型的 "wrong close" 前驱条件）。
* 与上游 2026-08 `binder: fix is_failure flag for superseded transaction cleanup`、
  2026-09 `binder: fix sender fd 0 close and file refcount leak on TF_UPDATE_TXN` 同源。

### 影响边界（诚实口径）

* 关闭动作作用在 **发送方自己的 fd 表**，不是接收方；所以这是 **uid 2000 对自己进程的 fd 完整性破坏 +
  内核资源泄漏**，**不是**跨权限边界的提权。要变成跨进程，需要一个"buffer 属主 ≠ `current`"的释放时机，
  本路径不成立（`binder_deferred_fd_close` 用的是 `current`，不是 `proc->tsk`）。
* 该路径不会崩内核：无空指针、无越界、无重复释放，`PANIC_ON_OOPS`/`BUG_ON_DATA_CORRUPTION` 不触发。

---

## 7. reclaim 判定（uhid / AF_UNIX / UI_SET_PHYS）

**不适用。** 这三条 reclaim 链针对的是"某个 kmalloc 对象被提前释放、同尺寸对象可覆盖其内容"的 UAF。
本次发现的两条缺陷都是：

* 6-A 是**漏释放**（对象/引用没有归还）——泄漏的 `binder_txn_fd_fixup`(40B) 与 `struct file` 仍在引用中，
  不会被任何分配器重新分配，`uhid(kmalloc-256/order-1)`、`AF_UNIX(8192/order-1)`、
  `UI_SET_PHYS(kmalloc-1k)` 都拿不到这块内存；
* 6-B 是**逻辑层面的 fd 号误用**，全程没有 `struct file` 的释放（`file_close_fd` 关的是用户 fd，
  引用由 `filp_close`/task_work 正常归还），没有窗口可被 reclaim。

---

## 8. 未覆盖 / 建议的下一步

1. **动态确认 6-A**：同一 node 连发两次 `TF_UPDATE_TXN` 的 oneway 事务（都带一个 fd），观察
   `/proc/slabinfo` 的 `filp` 与 `kmalloc-*` 计数是否单调增长；`/proc/<pid>/fdinfo` 不变而
   `nr_files`（`/proc/sys/fs/file-nr`）增长即可定性。
2. **动态确认 6-B**：让载荷里的 FDA 数组填 `0`，第二次发送后检查自身 `fd 0` 是否消失
   （`ls -l /proc/self/fd/0`）。若 shell 侧不方便构造 FDA（需要 nested/parent 语境），至少可用
   6-A 的 FD 形态确认泄漏。
3. **未读**：`0x1c91d4`（FD 的 reply 分支）未展开；`selinux_binder_transfer_file` 函数体未读
   （只按钩子参数与实现口径判断）；`binder_alloc_copy_to_buffer`/`copy_from_buffer` 内部未展开
   （属 alloc 线，`BINDER_ALLOC_AUDIT.md` 覆盖）。
4. 若要把 6-A 升级成"可利用"：泄漏本身无法变成 UAF；可以尝试用它做**引用计数耗尽**
   （让某个服务的 fd 引用爆炸导致 `EMFILE`），但那属于 DoS 线，与内存破坏无关。

---

## 9. 关键地址表（base = `0xffffffc080000000`）

| 符号 | 地址 |
|---|---|
| `binder_translate_fd` | `0xffffffc08010384c` |
| `binder_translate_fd_array` | `0xffffffc08101b66c` |
| `binder_add_fixup` | `0xffffffc0800b76b4` |
| `binder_deferred_fd_close` | `0xffffffc08101b410` |
| `binder_do_fd_close`（task_work） | `0xffffffc08101b53c` |
| `binder_free_txn_fixups` | `0xffffffc08005579c` |
| `binder_transaction_buffer_release` | `0xffffffc0801826f8` |
| FDA 释放子流程 | `0xffffffc0800437e8` |
| FD 内联处理（`binder_transaction`） | `0xffffffc0801c8c88`–`0x1c8d68` |
| fd 安装两趟（`binder_ioctl_write_read`） | `0xffffffc0801c421c`–`0x1c42dc` |
| fd 安装失败回滚 | `0xffffffc0801c44a4` / `0x1c44bc` → `0x1c44c4` |
| **supersede 清理（缺陷）** | `0xffffffc0801c6fd8`–`0x1c7024` |
| `binder_cleanup_transaction` | `0xffffffc0800a91dc` |
| `binder_alloc_free_buf` | `0xffffffc080180714` |
| `fget` / `fput` | `0xffffffc08017d788` / `0xffffffc08017cf94` |
| `get_unused_fd_flags` / `fd_install` | `0xffffffc08011bb64` / `0xffffffc0801290c4` |
| `put_unused_fd` / `file_close_fd` | `0xffffffc0802476ac` / `0xffffffc0801291d8` |
| `filp_close` / `task_work_add` | `0xffffffc0802a4564` / `0xffffffc0802a482c` |
| `security_binder_transfer_file` | `0xffffffc0801cbae8` |
| `binder_alloc_copy_to_buffer` / `_from_buffer` | `0xffffffc08011223c` / `0xffffffc0801831ec` |
| `trace_binder_transaction_update_buffer_release` | `0xffffffc08101bd58` |

# 本机内核 stable 补丁级别核对：6.18.45 – 6.18.58

- 本机内核：`6.18.21-android17-5-g284297031c53`（SPL 2026-08-01）
- 二进制：`runs/android/rom/vmlinux-4.0.21.0.elf`（139k 符号）+ `runs/android/rom/Image-4.0.21.0.bin`
- 素材：`runs/android/rom/changelogs/ChangeLog-6.18.{23..58}.txt`（36 份）+ `runs/android/rom/patches/`（本轮新抓 19 份）
- 方法：patch 里提取"能在汇编里认出来的指纹" → vmlinux 反汇编逐条核对；每条证据是**一行具体指令**。
  `Image` 为线性 dump，`file_off == link_addr - 0xffffffc080000000`（已用两条校准锚点验证映射正确）。
- 结论口径：**已修** / **未修**（=候选）/ **代码不在**（未编译或分支被 config 关掉，不算缺失）

## 校准锚点（证明"已修"能在这套二进制里被看见）

| 条目 | 断言 | 本机实测 |
|---|---|---|
| binder tmp_ref pin（6.18.39） | 已修 | `0xffffffc0801c5b8c  add x0, x0, #0xa8`（&tmp_ref）→ `bl _raw_spin_lock`；`0xffffffc0801c5ba8  stadd w9, [x8]` ✅ |
| hid-logitech-dj `report_count==14`（6.18.44） | 已修 | `0xffffffc080f7fb80  cmp w3, #0xe` / `0xffffffc080f7fb84  b.ne`（不等则跳过）✅ |

两条锚点都命中 ⇒ 本机确实存在"6.18.39 / 6.18.44 级"的回移，下面的"未修"不是工具假阴性。

## 判定表（未修排在前面）

| # | subject | 版本 | 判定 | 证据（指令地址 + 原文，对应补丁哪一行） | uid2000 可达性（怎么触发） | 若不是内存破坏或不可达，说明原因 |
|---|---|---|---|---|---|---|
| 1 | futex: Prevent robust futex exit race some more | 6.18.45 | **未修** | `0xffffffc0805f02a8  ands w26, w28, #0x3fffffff`（owner = uval & FUTEX_TID_MASK）→ `0xffffffc0805f02b4  tbz w8, #0, 0xffffffc0805f04f0` 进特殊分支 → `0xffffffc0805f0500  bl futex_wake`。补丁要的是 `owner != task_pid_vnr(curr)` 外层 + 内层 `(!owner \|\| !(uval & FUTEX_WAITERS))`；本机 `0xffffffc0805f02c4  bl __task_pid_nr_ns`（=task_pid_vnr）在特殊分支**之后**，且该分支内没有 bit31 测试（全函数唯一的 `0xffffffc0805f0334  and w8, w28, #0x80000000` 在 owner==self 之后的既有 OWNER_DIED 路径） | **可达，纯 syscall**：pthread robust mutex（`set_robust_list`）+ 三线程 + 在"wake 了 B 但 B 尚未重设 FUTEX_WAITERS"的窗口里 `tgkill` 杀掉 B | **非内存破坏**：丢唤醒 → 剩余 waiter 永久睡眠（挂死 / DoS） |
| 2 | futex: Fix race in futex_pivot_pending() during private hash resize | 6.18.46 | **未修** | `futex_pivot_pending` @`0xffffffc0802bc04c`：`0xffffffc0802bc060  bl __rcu_read_lock`（补丁改成 `guard(mutex)(&mm->futex_hash_lock)`），函数内无任何 `mutex_lock`，`0xffffffc0802bc064  ldr x8, [x19, #0x118]`（mm->futex_phash_new）在无锁下读 | **可达，纯 syscall**：`prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS, nslots, 0)` 起 resize，另一线程正常 futex 操作触发 pivot（`futex_hash_prctl` @`0xffffffc0802835fc` 无 `capable()` 检查） | **非内存破坏**：resize 任务无限期 D 状态 → hung_task panic（DoS） |
| 3 | futex/pi: Plug private futex exec() race | 6.18.47 | **未修** | `futex_exec_release` @`0xffffffc0802b7860`：`0xffffffc0802b78b8  str wzr, [x19, #0xba8]` —— exec 收尾仍把 `tsk->futex_state` 写回 FUTEX_STATE_OK（补丁要求保持 DEAD）。对照 `futex_exit_release`：`0xffffffc0802b7990  mov w8, #2` + `0xffffffc0802b7998  str w8, [x19, #0xba8]`。补丁新增的 `futex_exec_done` 在 .symtab 中**不存在** | **可达，纯 syscall**：同一 mm 两线程，T_owner 持 `FUTEX_LOCK_PI\|FUTEX_PRIVATE_FLAG`，T_waiter 同 futex 发 PI 锁阻塞在 `attach_to_pi_owner()`，T_owner 同时 `execve()` | — 内存破坏：exec 在"state 已回 OK / mm 未切换"的窗口里让 mm 比较给出错误答案 → waiter 挂到即将释放的 mm 上 → mm/pi_state UAF |
| 5 | futex: Fix race on the initial mm->futex.phash.ref allocation | 6.18.47 | **未修** | `futex_hash_allocate` @`0xffffffc0802bbc38`：`0xffffffc0802bbcb8  str x0, [x19, #0x140]`（pcpu_alloc 结果**先发布**到 mm->futex_ref）→ `0xffffffc0802bbcdc  ldxr w11, [x8]` / `0xffffffc0802bbce4  stxr w10, w11, [x8]`（发布之后才 this_cpu_inc）。补丁要求"先 inc 再 `cmpxchg`"，本函数内**无 `cas`、无 `free_percpu`** | **可达，纯 syscall**：嵌套 `vfork()` + `SIGKILL` 父/子，使父与孙同 mm 并发 `prctl(PR_FUTEX_HASH, 1, slots, 0)` | — 内存破坏：percpu 计数器丢失 → ref 不再被 `__futex_ref_atomic_end()` 看到 → 私有 hash 被判死并 RCU 释放 → `futex_q_lock()` 写已释放内存 |
| 4 | futex: Avoid private hash use-after-free on final put | 6.18.47 | **未修** | `futex_private_hash_put` @`0xffffffc0800d6114`：`0xffffffc0800d61b4  ldr x0, [x0, #0x18]` 紧接 `0xffffffc0800d61b8  bl wake_up_var` —— `fph->mm`（偏移 0x18，正是 commit 说的"offset 24"）在引用已 drop **之后**才在调用点重新加载；补丁要求在 `futex_ref_put()` 前把 mm 存进保存寄存器 | **可达，纯 syscall**：同 #2 的 `prctl(PR_FUTEX_HASH…)` 路径 + 恰在最后一次 put 处被抢占 | — 内存破坏（slab-UAF 读），但读出值只作 `wake_up_var()` 的 waitqueue key，危害弱于 #3/#5 |
| 6 | HID: core: fix OOB read of field->usage in hid_set_field() | 6.18.47 | **未修** | `hid_set_field` @`0xffffffc080f652f0`：`0xffffffc080f6531c  umaddl x1, w1, w9, x10`（x1 = usage + offset*24）→ `0xffffffc080f65330  bl hid_dump_input`，**之后**才 `0xffffffc080f65334  ldr w3, [x21, #0x28]`（report_count）/ `0xffffffc080f65338  cmp w20, w3` / `0xffffffc080f6533c  b.hs`。补丁要求先检查后 dump | 有条件：`hidinput_input_event`(`0xffffffc080f6a874`) 走 EV_LED/evdev 写，或 `picolcd_send_and_wait`(`0xffffffc080f91d48`) —— 需 `/dev/input/event*` 写权限或恶意 USB HID（`CONFIG_HID_PICOLCD=y`） | 内存破坏（4 字节 OOB 读），但读值只进 `hid_dump_input`→`hid_resolv_usage`→printk，不可直接控制 |
| 7 | HID: magicmouse: Prevent OOB read during DOUBLE_REPORT_ID | 6.18.47 | **未修** | `magicmouse_raw_event` @`0xffffffc080f8785c`：DOUBLE_REPORT_ID(0xf7) 分支 `0xffffffc080f879e4  ldrb w8, [x21, #1]` → `0xffffffc080f879fc  mov w3, w8` → `0xffffffc080f87a00  bl 0xffffffc080f8785c`（自递归），**无 `size<2`、无 `size < data[1]+2` 检查**；入参 `size` 也未在入口做 `size<1` 判断。补丁新增格式串 `"received report length (%d) was smaller than specified (%d)"` 在 vmlinux 与 Image 中**均不存在** | 不可达 | 需 Apple Magic Trackpad 类 BT/USB HID 设备；`magicmouse` 的匹配表限定 BUS_USB/BUS_BLUETOOTH，uhid 虚拟设备不会绑定 |
| 9 | HID: uclogic: fix use-after-free of inrange_timer on remove | 6.18.47 | **未修** | `uclogic_remove` @`0xffffffc080fa6eac`：`0xffffffc080fa6ec4  add x0, x20, #0xf0`（&drvdata->inrange_timer）→ `0xffffffc080fa6ec8  bl timer_delete_sync`（`0xffffffc08017d368`）。补丁要求 `timer_shutdown_sync`（`0xffffffc080064e5c`，本机存在但**未被调用**） | 不可达 | 需 uclogic 数位板 + remove/拔插时序 |
| 10 | HID: sony: fix UAF of ghl_poke_timer / ghl_urb at driver unbind | 6.18.50 | **未修** | `sony_remove` @`0xffffffc080fa1da4`：`0xffffffc080fa1db0  bl timer_delete_sync` → `0xffffffc080fa1db4  ldr x0, [x20, #0x110]`（ghl_urb）→ `0xffffffc080fa1db8  bl usb_free_urb`。全函数**无 `bl usb_poison_urb`**（`0xffffffc080d43b58`），也未用 `timer_shutdown_sync` | 不可达 | 需 GHL(Guitar Hero Live) dongle + unbind |
| 13 | HID: core: quiesce input in hid_hw_stop() to prevent use-after-free | 6.18.52 | **未修** | `hid_hw_stop` @`0xffffffc080f66984`，全函数 0x…6984–0x…69fc 共 48 条已完整枚举：prologue 后第一条实活是 `0xffffffc080f669a8  bl 0xffffffc080c52600`，随后直接进入 `hid_disconnect` 内联（`0xffffffc080f669ac  ldr w8, [x19, #0x1cf8]` = hdev->claimed，bit0/1/2 → hidinput/hiddev/hidraw 断开，`0xffffffc080f669c8  str wzr, [x19, #0x1cf8]`）→ `hdev->ll_driver->stop`。补丁的 `if (hdev->io_started) hid_device_io_stop(hdev)` 必然编译成条件分支，此处**一条分支都没有**，也无 `io_started` 字节加载 | 不可达 | 需要"probe 中途失败但仍留 io_started"的驱动：corsair-psu / corsair-cpro / nzxt-* / gigabyte_waterforce / hid-mcp2221 / logitech-dj / nintendo —— 全为 USB/I2C 总线匹配，**uhid 造虚拟设备不会绑定**（要触发只能靠恶意/异常 USB HID 硬件或 root 侧 dummy_hcd+raw-gadget） |
| 15 | HID: logitech-hidpp: fix race condition when accessing stale stack pointer | 6.18.54 | **未修** | `hidpp_raw_hidpp_event` @`0xffffffc080f86668`：`0xffffffc080f8669c  ldr x22, [x0, #0x38]`（hidpp->send_receive_buf）在 `0xffffffc080f866a4  bl mutex_is_locked` **之前**无条件加载（= 声明处初始化）；locked 分支 `0xffffffc080f870bc  ldrb w8, [x22, #2]` 直接解引用，**无 `cbz x22` NULL 检查**。补丁第 1 段（sync 路径 out: 清 `send_receive_buf = NULL`）同样不存在 | 不可达 | 需 Logitech HID++ 设备（USB/BT 总线匹配） |
| 17 | HID: wacom: fix OOB read in wacom_wac_pen_serial_enforce() | 6.18.55 | **未修** | 该函数已内联进 `wacom_raw_event` @`0xffffffc080fb4734`：内层循环上界 `0xffffffc080fb4804  ldr w8, [x24, #0x18]` + `0xffffffc080fb4808  cmp w21, w8`（`field` 偏移 **0x18 = maxusage**）。补丁要求换成 `report_count`（偏移 0x28，见 `hid_set_field` `0xffffffc080f65334  ldr w3, [x21, #0x28]`）。偏移 0x18 = maxusage 由 `hidinput_input_event` 同循环交叉确认：`0xffffffc080f6a80c  ldr w15, [x8, #0x18]` | 不可达 | 需 Wacom 数位板（`CONFIG_HID_WACOM=y`）；后果是 OOB 读 → 经 MSC_SERIAL 泄露内核内存 |
| 18 | tty: fix saved termios reset race | 6.18.56 | **未修** | `tty_register_device_attr` @`0xffffffc080ba02b0`：`0xffffffc080ba0434  tbnz w8, #6, 0xffffffc080ba04a8`（TTY_DRIVER_DYNAMIC_ALLOC）之后**直接** `0xffffffc080ba0438  ldr x8, [x20, #0x98]` / `0xffffffc080ba043c  ldr x0, [x8, w19, uxtw #3]` / `0xffffffc080ba0444  str xzr, [x8, w19, uxtw #3]` / `0xffffffc080ba0448  bl kfree`，中间没有 BIT(9)=0x200（TTY_DRIVER_RESET_SAVED_TERMIOS）测试 | 不可达 | 需同一 minor 的 tty 设备"关闭并保存 termios"与"重新注册"并发（典型是 USB serial/ACM 拔插），非纯用户态可达 |
| 19 | tty: port: fix tty_port_tty_vhangup() race | 6.18.56 | **未修** | 符号级判定：`__tty_port_tty_hangup` @`0xffffffc080ba8b28` **存在**，`tty_port_tty_vhangup` **不存在**。补丁把 header 里的内联 wrapper 拆成两个 out-of-line 函数并对 `tty_port_tty_vhangup` 加 `EXPORT_SYMBOL_GPL`，回移后二者都是符号；本机仍是"一个内联 wrapper + `__tty_port_tty_hangup`"的旧形态 | 不可达 | 需 tty 端口驱动在断开路径调用 vhangup（USB serial/ACM 等） |
| 14 | HID: hidpp: fix potential UAF in hidpp_connect_event() | 6.18.53 | **已修（等效）** | `0xffffffc080f84180  bl input_register_device` → `0xffffffc080f84184  cbz w0, 0xffffffc080f84194`；失败分支 `0xffffffc080f84188  mov x0, x21` / `0xffffffc080f8418c  bl input_free_device` **不写** hidpp->input；`hidpp->input`(0x58) 全函数唯一写点在成功路径 `0xffffffc080f84194  str x21, [x19, #0x58]` | 需 Logitech HID++ 设备（不影响判定） | 本机实现本身就把赋值放在注册成功之后 ⇒ 失败路径不留 stale 指针，该 UAF 不可成立。**不是回移证据**，只是巧合等价 |
| 8 | HID: pidff: fix OOB write when hid->inputs is empty | 6.18.47 | **代码不在** | 符号 `hid_pidff_init_with_quirks` / `hid_pidff_init` 在 .symtab 中不存在；已解包的 `vendor_ko/` `odm_ko/` 全树无 `hid_pidff.ko`；`config.extracted.txt` 无 `CONFIG_HID_PIDFF` | — | 驱动未编译，不算缺失 |
| 11 | HID: rmi: fix OOB access with undersized RMI reports | 6.18.51 | **代码不在** | `# CONFIG_HID_RMI is not set`；`rmi_probe` / `rmi_hid_read_block` / `rmi_hid_write_block` 均无符号；无 `hid_rmi.ko`；补丁新增串 `"rmi reports too small"` 不存在 | — | 驱动未编译 |
| 12 | futex: Prevent rcuwait use-after-free during requeue PI | 6.18.51 | **代码不在** | `# CONFIG_PREEMPT_RT is not set`。`futex_requeue_pi_complete` @`0xffffffc0805f1968`–`0xffffffc0805f1a08` 整段（40 条，以 `ret` 结束）**没有任何 call**，`rcuwait_wake_up`(`0xffffffc08022bcfc`) 未被引用 ⇒ 补丁所在的 `#ifdef CONFIG_PREEMPT_RT` 分支未编译 | — | RT-only 代码，非本机攻击面 |
| 16 | HID: alps: fix use-after-free on input2 registration failure | 6.18.55 | **代码不在** | `# CONFIG_HID_ALPS is not set`；`u1_raw_event` / `alps_input_configured` 无符号 | — | 驱动未编译 |
| 20 | af_unix: Return immediately when manage_oob() returns NULL for 0-length buffer. | 6.18.53 | **代码不在** | `# CONFIG_AF_UNIX_OOB is not set`；`manage_oob` 在 .symtab 中不存在（补丁整块位于 `#if IS_ENABLED(CONFIG_AF_UNIX_OOB)` 内） | — | 代码未编译；且本质是忙等 DoS，非内存破坏 |
| 21 | af_unix: Update last skb marker in manage_oob(). | 6.18.53 | **代码不在** | 同上：`CONFIG_AF_UNIX_OOB=n`，`manage_oob` 不存在（补丁自己也注明该函数被内联） | — | 代码未编译；且本质是忙等 DoS，非内存破坏 |

> 表中编号沿用"原 12 条 + 追加 9 条"的连续编号；`#4` 排在 `#5` 之后是有意的（按价值排序，不是按原序号）。

## 结论：本机 stable 有效补丁级别

- **最高的已修**：**6.18.44**。证据即校准锚点 `0xffffffc080f7fb80  cmp w3, #0xe`（hid-logitech-dj 的 `report_count == DJREPORT_SHORT_LENGTH-1`）；再往前的 6.18.39 binder tmp_ref pin（`0xffffffc0801c5b8c` / `0xffffffc0801c5ba8`）也在。
- **最低的未修**：**6.18.45**（`futex: Prevent robust futex exit race some more`，见 #1）。
- ⇒ **本机 stable 有效补丁级别 ≈ 6.18.44**：基本上是"线性并入到 6.18.44"，6.18.45 起的 stable 回移**整段缺失**，且**没有发现任何越级单独回移**（14 条未修里没有一条属于 6.18.52+ 而已修）。
- 6.18.52–6.18.58 的 ChangeLog 虽已备齐，但结论上界被 6.18.45 已经锁死，这批只用于排除"选择性回移"的可能（结论：无）。
- 唯一标"已修"的 #14（6.18.53 hidpp）是**本机实现恰好等价**，不是回移证据——不要拿它当补丁级别依据。
- 说明：表中 6 条"代码不在"（#8 #11 #12 #16 #20 #21）既不算缺失、也不能当"已修"用，它们不进 PoC 候选。

## 建议先做 PoC 的 1–2 条（uid2000 可达 + 内存破坏）

### 首选：#5 `futex: Fix race on the initial mm->futex.phash.ref allocation`（6.18.47）

选它的理由：**纯 syscall、单进程发起、不需要任何硬件或额外权限**，命中是**写已释放内存**（比 #4 的读强得多），而且它的前提条件在本机也齐备——`CONFIG_FUTEX_PRIVATE_HASH=y`，且 6.18.54 `futex: Also allocate private hash on vfork()` 同样缺失（vfork 路径不经过 default 分配，正是该竞态成立的前提）。

- 触发 syscall 序列：
  1. `prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS, SLOTS, 0)` 是入口（`futex_hash_prctl` @`0xffffffc0802835fc`，只校验 op∈{1,2}，**无 `capable()`**，SET 路径 → `futex_hash_allocate(w1, 1)`）。
  2. `T0: vfork()` → 子 C；`C: vfork()` → 孙 G；`T0: kill(C, SIGKILL)` 使 T0 从 vfork 返回，与 G **同 mm 并发**运行。
  3. T0 与 G 各自执行 `prctl(PR_FUTEX_HASH, 1, SLOTS, 0)`：两边都观察到 `mm->futex_ref == NULL`（`0xffffffc0802bbc9c  cbnz x8` 未跳），各自 `0xffffffc0802bbcb8  str x0, [x19, #0x140]` 覆盖写入 → **后写者存活，先写者的 percpu 计数器变成不可达**。
  4. 之后先写者那份 ref 不再被 `__futex_ref_atomic_end()` 统计 → 仍带引用的私有 hash 被 `futex_ref_is_dead()` 判死并被 RCU 释放 → 仍持有其 bucket 的任务在 `futex_q_lock()` 写已释放内存。
- 命中信号：KASAN build 下 `slab-use-after-free` in `futex_q_lock` / `__futex_ref_atomic_end`；生产内核（本机无 KASAN）可改用 `prctl(PR_FUTEX_HASH, 2, …)`(GET_SLOTS) 观察 slots 与实际 hash 不一致，或对 `futex_q_lock` 下 kprobe，看是否命中已被 RCU 回收的 `futex_private_hash`（`fph->mm` 的 0x18 字段变成 `0x6b6b…` 类毒值），也可用 `hung_task`/SLUB freelist 报错作为旁证。

### 次选：#3 `futex/pi: Plug private futex exec() race`（6.18.47）

选它的理由：同样**纯 syscall、uid2000 可达**，且失败点在 `futex_exec_release()` 的**一条 `str` 上极其明确**（`0xffffffc0802b78b8  str wzr, [x19, #0xba8]`），改起来/判定漏洞是否真的命中都很直观。

- 触发 syscall 序列：
  1. 同一 mm 开两线程；共享一块 futex 字。
  2. T_owner：`futex(FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, uaddr, …)` 持锁。
  3. T_waiter：对同一 uaddr 发 `FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG`，阻塞在 `attach_to_pi_owner()` 的 mm 比较处。
  4. T_owner 同时 `execve(…或 /proc/self/exe)`：未修内核在 `futex_exec_release()` 里先把 `tsk->futex_state` 写回 `FUTEX_STATE_OK`（0），**之后**才切 `tsk->mm`；这段窗口里 mm 比较仍然判"同 mm"，waiter 成功挂到即将被 `mmput()` 释放的旧 mm 上。
  5. 旧 mm 释放 → waiter 侧 pi_state / mm 引用悬空 → UAF。
- 命中信号：KASAN `slab-use-after-free`（`mm_struct` 或 `futex_pi_state`）；无 KASAN 时典型表现是 `put_pi_state` / `exit_pi_state_list` 上的 SLUB 报错、或 waiter 侧偶发返回 `EFAULT`/`ESRCH` 而 futex 状态不自洽。窗口很窄，需要反复 loop + CPU 绑核。

### 备用（无硬件、但只是 DoS，不是内存破坏）

- #1（6.18.45 robust exit 丢唤醒）、#2（6.18.46 resize 挂死）都是纯 futex/prctl 可达、能稳定复现的挂死/DoS，若两条 UAF 竞态窗口压不住，可先用它们证明"本机缺 6.18.45+ 回移"。

## 落库口径备注

- 本轮只做静态判定，**未对设备发包、未上传文件、未改任何已有文件**；新增文件仅 `patches/*.patch`（19 份）、本报告，以及 4 个只读分析脚本：`find_shas2.py` / `symfind.py` / `addr2sym.py` / `kdis_range.py` / `callers_bl.py`。
- 复现任一结论的最小命令：
  ```
  cd runs\android\rom
  python symfind.py '^hid_hw_stop$'                       # 找符号
  python kdisasm.py vmlinux-4.0.21.0.elf Image-4.0.21.0.bin <sym> <n>
  python kdis_range.py 0xffffffc080f84170 14              # 按地址续反汇编
  python addr2sym.py 0xffffffc080e15108                   # 反查调用目标
  python callers_bl.py 0xffffffc0802bbc38                 # 找 BL 调用者
  ```
- 未取到项：无。21 条全部拿到 sha（`changelogs/` 内 subject → 最近 `commit <40 位 sha>`），19 份新补丁全部为合法 unified diff（含 `@@` 与 `+/-` 行）。

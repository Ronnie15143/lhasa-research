# /dev/ptmx · pty/tty 面静态审计（lhasa · 6.18.21-android17-5-g284297031c53）

> 审计对象：`Image-4.0.21.0.bin`（link base `0xffffffc080000000`，`file_off = addr - 0xffffffc080000000`）
> 攻击者模型：`adb shell` uid 2000，无 cap，SELinux Enforcing，`/dev/ptmx` 可 open/读写（实测）。
> 方法：纯静态（capstone 反汇编 + 从本镜像 `.BTF` 取结构布局）+ 设备默认值读取。未 fuzz、未执行、未写设备。

## 0. 结论

**没有可用候选。** 这条面上我找不到"可达 + 内存破坏"的 UAF / OOB / 越界读。

`n_tty` 在本构建里已经把读缓冲重写成**双环 + 位图**（`read_buf`/`echo_buf` 各 4096B，`read_flags` 512B），
我逐条核对了它全部的索引与长度来源：**每一个落地址的下标都被 `& 0xfff` 掩过**，每一处 `memcpy` 的长度都是
`min(用户请求, canon_head/commit_head - read_tail)` 再夹到 `4096 - (read_tail & 0xfff)`，
**不存在由 `MIN`/`TIME`/`TIOCINQ`/`TIOCSWINSZ` 反推到环内的自由下标**。tty 核心的 pid/pgrp 引用计数
（`TIOCSPGRP`/`TIOCGPGRP`，历史 UAF 点）是"持锁取引用、放锁后 `put_user`"的正确写法。

附带一条**结构性阻力**：就算哪里真有 n_tty 的越界，`n_tty_data` 是
`kzalloc(8920)`（`n_tty_open` @ `0xffffffc080ba163c`，`mov w0,#0x22d8` @ `0xffffffc080ba1658`）
→ 落在 **kmalloc-16k / order-2**，**不在** uhid(kmalloc-256 order-1) / AF_UNIX(8192 order-1) /
`UI_SET_PHYS`(kmalloc-1k) 三个 reclaim 原语覆盖的档位里。见 §6。

## 1. 本构建的对象布局（从镜像 `.BTF` 取得，与反汇编互相印证）

`struct tty_struct` size **728 (0x2d8)**，独立 slub cache（`alloc_tty_struct` 用
`kmem_cache_alloc`，cache ptr 取自 `0xffffffc081a24548`；**不是 kmalloc 档位**）：

| off | 字段 | off | 字段 | off | 字段 |
|---|---|---|---|---|---|
| 0x00 | kref | 0x140 | termios (44B) | 0x211 | closing |
| 0x04 | index | 0x14c | termios.c_lflag | 0x214 | flow_change |
| 0x10 | driver | 0x150 | termios.c_line | **0x218** | **link (pty pair)** |
| 0x18 | port | 0x155/0x156/0x157 | c_cc[VEOF]/[VTIME]/[VMIN] | 0x228 | write_wait |
| 0x20 | ops | 0x198 | name | 0x240 | read_wait |
| **0x28** | **ldisc** | **0x1d8** | **flags** | **0x278** | **disc_data** |
| 0x30 | ldisc_sem (rwsem) | 0x1e0 | count | **0x280** | **driver_data** |
| 0xd8 | termios_rwsem | 0x1e4 | receive_room | 0x288 | files_lock |
| 0x118 | winsize_mutex | 0x1e8 | winsize (8B) | 0x290 | write_buf |
| — | — | **0x1f8** | **ctrl.pgrp (struct pid\*)** | 0x298 | tty_files |
| — | — | 0x208 | ctrl.lock (spinlock) | 0x2a8 | SAK_work |
| — | — | 0x20c / 0x20d | ctrl.pkt_status / ctrl.packet | | |

`struct n_tty_data` size **8920 (0x22d8)**：

| off | 字段 | off | 字段 |
|---|---|---|---|
| 0x00 / 0x08 / 0x10 | read_head / commit_head / canon_head | 0x1060 | read_flags (512B = 64×u64) |
| 0x18 / 0x20 / 0x28 | echo_head / echo_commit / echo_mark | 0x1260 | **echo_buf (4096B)** |
| 0x30 | char_map (32B, 256 bits) | 0x2260 | read_tail |
| 0x50 / 0x58 | overrun_time / num_overrun | 0x2268 | line_start |
| 0x5c / 0x5d | no_room / bitfield(lnext,erasing,**icanon=bit4**,**real_raw=bit3**,raw=bit2) | 0x2270 | lookahead_count |
| **0x5e** | **read_buf (4096B)** | 0x2280 | echo_tail |
| — | — | 0x2288 / 0x22b0 | atomic_read_lock / output_lock |

关键符号（link-time 地址）：

```
tty_ioctl            0xffffffc080b9eb10   tty_jump_table  0xffffffc081a13918 (0x5409..0x545d)
tty_mode_ioctl       0xffffffc080ba5ecc   tty_jobctrl_ioctl 0xffffffc080ba9ab0
ptmx_open            0xffffffc080baa380   tty_init_dev    0xffffffc080b9e1b4
alloc_tty_struct     0xffffffc080b9e434   free_tty_struct 0xffffffc08008486c
tty_release          0xffffffc08040b98c   release_tty     0xffffffc080082ec8
tty_kref_put         0xffffffc0803175b0   tty_save_termios 0xffffffc08008300c
tty_set_ldisc        0xffffffc080ba7020   tty_ldisc_close 0xffffffc080083218
tty_ldisc_ref_wait   0xffffffc08040b4e4   tty_ldisc_ref   0xffffffc0800835c8
tty_ldisc_deref      0xffffffc08040b4bc   tty_ldisc_release 0xffffffc080083180
n_tty_open           0xffffffc080ba163c   n_tty_close     0xffffffc0800aded8
n_tty_read           0xffffffc0800bbf2c   n_tty_ioctl     0xffffffc080ba1c04
n_tty_read_canon_copy 0xffffffc080ba2748  n_tty_read_commit_copy 0xffffffc080ba2a0c
n_tty_receive_buf_common   0xffffffc080ba31c8
n_tty_receive_buf_standard 0xffffffc080ba3870
n_tty_check_unthrottle     0xffffffc080ba2b58
pty_write            0xffffffc080baa8a0   pty_unix98_ioctl 0xffffffc080baa8e4
ptm_open_peer        0xffffffc080baa278   pty_unix98_install 0xffffffc080baa550
pty_unix98_remove    0xffffffc0800b92dc
```

## 2. 逐条问答

### 2.1 对象生命周期（`tty_struct` / `ptmx_open→tty_init_dev→tty_release` / TIOCSPGRP）

- `alloc_tty_struct` @`0xffffffc080b9e434`：`kmem_cache_alloc(cache@0xffffffc081a24548, w1=0x40dc0)`
  长度 0x2d8；随后 `str w8(=1),[x19]` = `kref_init`，逐字段初始化 `ldisc_sem(0x30)`、`atomic_write_lock(0x60)`、
  `termios_rwsem(0xd8)`、`winsize_mutex(0x118)`、`write_wait(0x228)`、`read_wait(0x240)`，
  `stp xzr,xzr,[0x1f8]` 清 `ctrl.pgrp`+`ctrl.lock`、`str wzr,[0x1f0]/[0x208]/[0x288]`，
  `str x8,[0x298]/[0x2a0]` 自环初始化 `tty_files`、`[0x2a8..0x2b8]` 初始化 `SAK_work`；
  最后 `tty->driver=0x10`、`tty->ops=driver->ops(0xa8)`、`tty->index=0x4`。
  `ops` 与 `ldisc` 在 `tty_init_dev` 内被首次装上，且 `tty->ldisc` 只在持
  `ldisc_sem` 写锁时替换（见 2.2）。
- `release_tty` @`0xffffffc080082ec8`：`WARN_ON(tty->index != idx)`→`brk #0x800`；
  `WARN_ON(!mutex_is_locked(&tty_mutex@0x827ea2d8))`→`brk #0x800`（`0xffffffc0801386f0`）；
  然后 `ops->shutdown`(ops+0x28) → `tty_save_termios`(0x8300c) → `driver->ops->remove`(driver->ops+0x10)，
  无 remove 时 `driver->ttys[index]=NULL`（`[x0+0x88]`, `str xzr,[x8,index,lsl#3]`）；
  再 `port->itty=NULL`（`[port+0x98]`）对 `tty` 与 `tty->link`(0x218) 各一次，
  `tty_buffer_cancel_work` 两遍（`0x82fe4`），最后 `tty_kref_put(link)` + `tty_kref_put(tty)`。
  → 两侧都只走 kref，**没有一条路径会直接 `kfree(tty_struct)`**。
- `tty_release` @`0xffffffc08040b98c`：从 `file->private_data(0x18)`→`tty_file_private` 取 tty；
  `0x84520` 取 `tty_mutex`，`0x845cc` 做 `tty_del_file`；判 `driver->type(0x38)==3 && subtype(0x3c)==1`
  （PTY master）时 `x21 = tty->link`(0xbb00)；`ops->close`(ops+0x20)；对 `tty->count`(0x1e0) 与
  `o_tty->count` 各自递减并做 `b.mi`（<0）防护；last-close 时对 `read_wait(0x240)`/`write_wait(0x228)`
  做 `list_empty` 检查后 `__wake_up(...,EPOLLHUP)`（`0x163e00`），再进 `release_tty` 路径(`0x830cc`)。
  结构与 upstream 一致。
- **TIOCSPGRP/TIOCGPGRP**（`tty_ioctl` 跳表 0x540f/0x5410 → `0xb9ee4c` → `tty_jobctrl_ioctl`）：
  - `TIOCGPGRP` @`0xffffffc080ba9b7c`：`spin_lock(&real_tty->ctrl.lock @ 0x208)` →
    `ldr x21,[x19,#0x1f8]`（ogroup pid）→ **持锁 `get_pid`**（`ldadd w8,w8,[x21]` @`0xba9b98`，
    含 `cbz w8` 与符号位防护）→ `spin_unlock` → `pid_vnr`(`0x17b414`) → `put_user`。
  - `TIOCSPGRP` @`0xffffffc080ba9c44`：先 `tty_check_change`(`0x48d034(tty,0x16)`)，`w0==-EIO` 映射成 `-ENOTTY`；
    然后 `get_user(pgrp)` 走 access_ok 路径。
  → **历史 UAF（ppp 时代那个）所需的"放锁后再用旧 pgrp"窗口不存在**：引用是持锁取的，`put_pid` 在解锁之后。
  唯一能命中的是 `brk #0x800`（`index != idx` / `tty_mutex` 未持），那是 BUG_ON；要触发得先有另一处写坏
  这两个不变量，本面内找不到入口（`index` 只在 `alloc_tty_struct` 写一次）。

### 2.2 行规程切换（TIOCSETD / `tty_set_ldisc` / `n_tty_data` 分配释放）

- **可达性**：`TIOCSETD`(0x5423) 在 `tty_ioctl` 跳表里落到 `0xffffffc080b9f594`，
  该处**只有** `access_ok` + `get_user(ldisc)`（`ldtr w1,[x20]` @`0xb9f5c8`）+ `bl tty_set_ldisc(@0xba7020)`，
  **没有任何 `capable()`**（对比：`TIOCCONS`@`0xbee90`、`TIOCVHANGUP`@`0xb9ec9c`、`TIOCSTI`@`0xb9f19c`
  都是显式 `mov w0,#0x15; bl 0x29a258`）。所以 **uid 2000 可以调 TIOCSETD**。
  （`tty_ioctl` 里大量出现的 `ldrb w?,[current+0x46]; tbz #5` + `lsr …,0x27` 那串是
  inlined `unsafe_get_user/unsafe_put_user` 的 access_ok/TBI 收尾，**不是权限门**；这点我按
  `TIOCGEXCL` 分支 `cmp x9,#0x7ffffffffc`(=`TASK_SIZE(2^39)-4`) 反证过。）
- **切换的串行化**：`tty_set_ldisc` @`0xffffffc080ba7020`
  1. `bl 0xba7590` = `tty_ldisc_get(tty,disc)`（返回 ERR_PTR 则直接出去）；
  2. `bl 0x84520` = `tty_lock`；
  3. `mov w1,#0x4e2`(=1250=5×HZ @HZ=250) + `bl 0x833330` = **`tty_ldisc_lock(tty,5*HZ)`**
     —— 拿 `ldisc_sem` 写锁，等所有 `tty_ldisc_ref*` 持有者退场，等不到就返回错；
  4. `tty->ldisc->ops->num(ops+0x8) == disc` 就短路返回 0；
  5. `tty->flags(0x1d8) bit8`（本机 `TTY_HUPPED`；注意本构建 `TTY_PTY_LOCK=6`，
     见 §5）→ `-EIO`；
  6. `ops->set_ldisc`(ops+0xb0) 可选；然后 `tty_ldisc_close(tty,old)`(`0x83218`) →
     `tty->ldisc = new`(0x28) → 在 `write_lock_irq(tty_lock 0xd8 侧)` 里
     `termios.c_line = disc`(0x150) → **`tty->disc_data = 0`(0x278)** →
     **`tty->receive_room = 0`(0x1e4)** → `tty_ldisc_open(new)`。
  7. 新 ldisc open 失败则回滚到旧的（`0xba7194` 起：清 bit、重新 `tty_ldisc_get(old num)`、
     恢复 `tty->ldisc`、`disc_data=0`、`receive_room=0`、再 open）。
- **`n_tty_data` 的分配/释放**：
  - `n_tty_open` @`0xffffffc080ba163c`：`mov w0,#0x22d8; bl 0x3ba37c` = **`kzalloc(8920)`**；
    `ldata->overrun_time=jiffies`；`mutex_init(atomic_read_lock@0x2288)`、`mutex_init(output_lock@0x22b0)`；
    `tty->disc_data=ldata`(0x278)、`tty->closing=0`(0x211)、清 flags bit11、`n_tty_set_termios`。
  - `n_tty_close` @`0xffffffc0800aded8`：若有 `tty->link`(0x218) 先 `n_tty_packet_mode_flush`(0xf43a8)；
    再 `write_lock_irq(&tty->termios_rwsem)`(0xd8) → `kfree(tty->disc_data)`(`0x282f94`) →
    **`tty->disc_data = NULL`** → `write_unlock_irq`。
  → 释放只发生在 `tty_ldisc_close` 里，而它只在 `ldisc_sem` **写锁**已拿到的前提下被调用；
  读者（`n_tty_read`）从 `tty_read` 起就持 `tty_ldisc_ref_wait` 的读引用。
  **"读者睡着时 disc_data 被换掉"的窗口被 `ldsem` 堵住**：写者只能等 5s 然后失败返回。
- **可切的 discipline 只有 `{0=N_TTY, 27=N_NULL}`**：镜像里 `n_null_*`/`null_ldisc` 符号齐全，
  而 **`n_pps`/`n_hdlc`/`n_gsm0710`/`n_slcan`/`n_tracesink`/`n_tracerouter` 全无**。
  `N_NULL` 的 `read/write` 直接 `-EIO`、不分配 `disc_data`。→ 没有"切到某个能放大越界的 ldisc"这条路。

### 2.3 termios / winsize ioctl 的 copy 长度

- `TIOCSWINSZ`(0x5414) @`0xffffffc080b9f11c`：
  `add x0,sp,#8; mov x1,arg; mov w2,#8; str xzr,[sp,#8]; bl 0x2fe3c8`=**`copy_from_user(&ws,arg,8)`**
  → 长度是字面量 8 = `sizeof(struct winsize)`，目标是零初始化的 8B 栈槽 → `tty_do_resize`。
- `TIOCGWINSZ`(0x5413) @`0xffffffc080b9f140`：
  `mutex_lock(&tty->winsize_mutex /*0x118*/)` → `copy_to_user(arg, &tty->winsize /*0x1e8*/, 8)` →
  `mutex_unlock`。源是 **8 字节的 `tty->winsize`**，长度字面量 8，**同源**。
- `TCGETS/TCSETS/TCGETS2/TCSETS2` → 都在 `tty_mode_ioctl` @`0xffffffc080ba5ecc` 的
  `0x5401..0x542d` 跳表里，落到三个 inline 的 `copy_termios*` helper：
  `0xffffffc080ba5e60` 是 `mov w2,#0x2c`(44) + `bl 0x35a1f8` → **44 = `sizeof(struct termios2)`**
  = 本构建 `tty->termios` 的实际大小(0x140..0x16c，BTF 44B)。
  `0xffffffc080ba5ea8` / `0xffffffc080ba6620` 是同族（TCGETS/TCSETS 的 36B 形态与 `TIOCM*`）。
  → **所有长度都是编译期常量，用户只控 `cmd` 与 `arg`，没有任何长度字段**。
- `TIOCSTI`(0x5412) @`0xffffffc080b9f18c`：见 §4，是这一圈里唯一"真的能把字节打进 ldisc"的路径，
  但它的 CAP 门看一个全局字节，本镜像初值是 **1**。

### 2.4 读缓冲（`n_tty_read` 的 `read_buf` 索引计算）

`n_tty_read` @`0xffffffc0800bbf2c`：

1. 入口 `ldr x23,[x0,#0x278]` 取 `ldata`（在 `tty_ldisc_ref` 引用内）；
   `ldrb w25,[x20,#0x20d]` = `tty->ctrl.packet`；`ldr x26,[x23,#0x2260]` = `read_tail` 快照。
2. 非规范模式读 `VMIN`/`VTIME`：`ldrb w9,[x20,#0x157]`(c_cc[VMIN]) / `[0x156]`(VTIME)；
   `mov w9,#0x19`(=25=HZ/10) + `umull` → `time = VTIME*25`；`VMIN==0` 时 `minimum=1`、`time` 存栈。
   **`MIN`/`TIME` 只影响 `minimum`(x28) 与超时，从不进下标。**
3. 主循环两个 copy helper，参数恒为 `(tty, &kbuf, &nr)`：
   - **canonical 版** `0xffffffc080ba2748`：
     `avail = canon_head(0x10) - read_tail(0x2260)`；`idx = read_tail & 0xfff`；
     `n = min(*nr, avail)`；`chunk = min(idx+n, 4096)`；`find_next_bit(read_flags@0x1060, chunk, idx)`
     找到"特殊字符"就截断；两次 `memcpy`：先从 `read_buf@0x5e + idx` 拷 `4096-idx`，
     再从 `read_buf` 基址拷 `n - (4096-idx)`。`*kbuf += 已拷`, `*nr -= 已拷`,
     `stclr` 清 `read_flags[(pos>>6)]`（`pos ≤ 4095` → 下标 ≤ 63），`read_tail += n`。
   - **commit 版** `0xffffffc080ba2a0c`：
     `n = min(commit_head(0x8) - read_tail, min(4096-(read_tail&0xfff), *nr))`，单次 `memcpy`。
   - **两条的落地址下标全部 `& 0xfff`，长度全部先夹到 `4096-(read_tail&0xfff)`**。
4. packet 模式的两个单字节写入：
   - `0xbc168 strb wzr,[x27]`（清状态字节）与 `0xbc22c strb w21,[x27]`（`link->ctrl.pkt_status`），
     都在 `cbz x22`(nr==0 则整段跳过 @`0xbc020`) 之后，且都带 `cmp x27,x19`（"本轮还没写过"）守卫，
     写 1 字节后 `nr -= 1`。**nr≥1 恒成立**，不越界。
5. 收包侧 `n_tty_receive_buf_common` @`0xffffffc080ba31c8`：
   `room = 4096 - (read_head - read_tail)`（`sub w10,w9,w8; add w10,w10,#0x1000`）；
   `PARMRK` 时按 `(…+0x1002)/6`；`room-1 > 0` 才走正常路径（`csel x27=min(count,room-1)`）；
   `room ≤ 1` 时走 `0xba3298`，置 `ldata->no_room(0x5c)` 并让 `x27=0` 直接退出。
   插入侧两个分支：
   - `real_raw`(0x5d bit3) 快路径 `0xba33cc`：`n1=min(x27, 4096-(head&0xfff))`，
     `n2=min(x27-n1, 4096-((head+n1)&0xfff))`，两次 `memcpy`；
   - 逐字符路径 `0xba34a4`：`strb w1,[read_buf_base + (read_head & 0xfff)]`（`and x9,x8,#0xfff` @`0xba34cc`）。
   → **即使 room 计算因回绕变成负数从而放过超大 `count`，落地址仍被 `0xfff` 夹在环内**，
   后果是覆盖未读数据（数据完整性问题），不是越界写。
6. `TIOCINQ`(0x541b) @`0xffffffc080ba1cb4`：持 `write_lock_irq(&tty->termios_rwsem)`；
   规范模式走 `read_tail→canon_head` 扫描，下标 `and x13,x9,#0xfff`、位图 `read_flags[(x13>>6)]`
   （`lsr x14,x13,#6`，`x13 ≤ 0xfff` → ≤63）、并 `read_buf[(x13)]` 判零做扣减；
   非规范模式直接 `canon_head - read_tail`。最后 `put_user`（`sttr w19,[x20]`）。
   `TIOCOUTQ`(0x5411) 走 `0xbbca0` + `put_user`。**回给用户的只有计数，且全在环内计算**。
7. `echo` 侧 `n_tty_receive_buf_standard` @`0xffffffc080ba3870`：
   普通字符 `and x9,x8,#0xfff; strb w25,[read_buf+x9]`(`0xba38d0`)；
   回显 `and x8,x8,#0xfff; strb w10,[x28+x8+0x1260]`(`0xba3a48` `/` 0xba3a88`) ——
   **echo_buf 也是 `& 0xfff`**；`char_map` 查询用 `ubfx x10,x25,#6,#2` + `lsr …,x25`
   （c 是 u8 → 下标恒在 4×u64 内）。

### 2.5 ptmx 特有（TIOCGPTN/TIOCSPTLCK/`tty->link`/`ptm_open_peer`）

- `TIOCGPTN`(0x80045430) / `TIOCSPTLCK`(0x40045431) / `TIOCSIG`(0x40045436) / 两个
  `0x80045438`、`0x80045439` 全在 `pty_unix98_ioctl` @`0xffffffc080baa8e4`：
  `get_user(int)`（`ldtr w9,[x20]` @`0xbaaa18`）/ `put_user`（`sttr w20,[x19]` @`0xbaaaa4`）都是
  access_ok + uaccess 包裹的 4 字节操作；`TIOCSPTLCK` 置/清的是 **`tty->flags` bit6**
  （`stset 0x40,[tty+0x1d8]` @`0xbaaa58`，与 `ptmx_open` 里同一个 `stset 0x40` @`0xbaa48c` 一致
  → 本构建 `TTY_PTY_LOCK=6`）。`0x80045439` 读回同一 bit（`ubfx w20,w8,#6,#1` @`0xbaa968`）。
- `ptmx_open` @`0xffffffc080baa380`：`tty_mutex` 下 `devpts_new_index`(0x80508c) →
  `tty_init_dev(ptm_driver,index)`(0xb9e1b4) → 解锁 → `tty->flags |= 1<<6` →
  **`tty->driver_data = devpts inode`**(`str x22,[x23,#0x280]` @`0xbaa498`) → `tty_add_file` →
  `devpts_pty_new(inode,index,tty->link)`(0x805164) → **`tty->link->driver_data = dentry`**
  (`str x21,[x8,#0x280]` @`0xbaa4c8`) → `ops->open`(ops+0x18)。失败路径 `devpts_kill_index` +
  `tty_kref_put` + `tty_release`，没有裸 `kfree`。
- `TIOCGPTPEER`(0x5441) → `ptm_open_peer` @`0xffffffc080baa278`：
  `ldr x9,[x1,#0x10]`(tty->driver) 与 `[0xffffffc0829633b8]`(ptm_driver) 比较，不等直接 `-EIO`
  → **只能从 master 侧调用**；然后 `get_unused_fd_flags(arg)`，用
  `tty->driver_data(0x280)` 与 `tty->link->driver_data(0x280)` 拼 `struct path` 去 `dentry_open`。
- `tty->link`(0x218) 的引用：`release_tty` 只 `tty_kref_put(link)`；`ptmx_open` 里 link 由
  `tty_init_dev` 成对创建（`pty_unix98_install` @`0xffffffc080baa550`）。`n_tty_close` 在
  `tty->link != NULL` 时先 flush 对端 packet 模式，再释放本端 `disc_data`。

## 3. 候选表

格式：`缺陷类型 · ioctl/操作序列 · 证据（符号+偏移） · 命中信号 · 能否用 uhid / AF_UNIX 8192 / UI_SET_PHYS(1k) reclaim`

**正面候选：0 条。**

排除清单（每条都给了"为什么不可能"）：

| # | 缺陷类型（推测） | 操作序列 | 证据 | 命中信号 | reclaim | 结论 |
|---|---|---|---|---|---|---|
| E1 | 环缓冲越界写 | master 写 4096B+ 不读，把 `read_head` 推过 `read_tail+4096` | `n_tty_receive_buf_common`@`0xffffffc080ba31c8`：`0xba3298` 的 room≤1 分支虽让 `x27=count`，但快路径 `0xba33f0`/`0xba3420` 与逐字符 `0xba34cc` 全部 `and …,0xfff` | 无 panic、无 slab 越界（只会覆盖未读数据） | 不适用 | **排除：落地址恒被 `&0xfff` 夹住** |
| E2 | 读缓冲越界读 | `read()` + `TIOCINQ` + `VMIN/VTIME` 组合 | `n_tty_read`@`0xffffffc0800bbf2c` → `0xffffffc080ba2748`（`min(*nr, canon_head-read_tail)` + `4096-idx`）/ `0xffffffc080ba2a0c`（同源）；`n_tty_ioctl`@`0xffffffc080ba1c04` 的 TIOCINQ 扫描 `and x13,x9,#0xfff` | 无 | 不适用 | **排除：长度与下标同源且双夹** |
| E3 | echo_buf 越界写 | 往 slave 写特殊字符（ICANON/ECHO 开） | `n_tty_receive_buf_standard`@`0xffffffc080ba3870`：`0xba3a48`/`0xba3a88` 的 `and x8,x8,#0xfff` + `strb …,0x1260` | 无 | 不适用 | **排除：echo_head 也掩 0xfff** |
| E4 | `n_tty_data` UAF（ldisc 切换） | `open(/dev/ptmx)`; `ioctl(TIOCSETD,N_NULL)` 与另一线程 `read()` 并发 | `tty_set_ldisc`@`0xffffffc080ba7020`：`mov w1,#0x4e2; bl 0x833330`(=`tty_ldisc_lock(tty,5*HZ)`) 之后才 `tty_ldisc_close`→`n_tty_close`(`kfree@0x282f94`, `str xzr,[tty+0x278]`) | 拿不到 `ldisc_sem` 写锁就返回错，窗口不存在 | 若真有：`n_tty_data`=8920B → **kmalloc-16k/order-2**，三个原语都覆盖不到 | **排除：ldsem 写锁 + 5s 超时** |
| E5 | `tty_struct` UAF（TX/RX 与 release 并发） | `close()` 与 `ioctl/read` 并发；`TIOCGPTPEER` 后关 master | `tty_release`@`0xffffffc08040b98c`（count 递减带 `b.mi` 防护）→ `release_tty`@`0xffffffc080082ec8`（只 `tty_kref_put`×2） | `WARN_ON`→`brk #0x800`（→ PANIC_ON_OOPS）只有在不变量已被破坏后才可能 | `tty_struct` 是**专用 slub cache**（`kmem_cache_alloc`，非 kmalloc 档），1k spray 不命中 | **排除：kref + tty_mutex + 专用 cache** |
| E6 | pgrp UAF（TIOCSPGRP 历史点） | `ioctl(TIOCGPGRP)` 与 setsid/exit 并发 | `tty_jobctrl_ioctl`@`0xffffffc080ba9ab0`：`0xba9b7c` 持 `ctrl.lock(0x208)` → `0xba9b98` `ldadd` 取 pid 引用 → 解锁 → `0x17b414`(pid_vnr) → `put_user` | 无 | 不适用 | **排除：持锁取引用、放锁后才用** |
| E7 | winsize/termios OOB copy | `ioctl(TIOCGWINSZ/TIOCSWINSZ/TCGETS/TCSETS)` | `0xffffffc080b9f140`（`copy_to_user(arg,&tty->winsize,8)`）、`0xffffffc080b9f11c`（`copy_from_user(&ws,arg,8)`）、`0xffffffc080ba5e60`（`mov w2,#0x2c`） | 无 | 不适用 | **排除：长度全是常量且与目标同大小** |
| E8 | `link->driver_data` 借用引用被 `dentry_open` | `open(/dev/ptmx)` → `ioctl(TIOCGPTPEER)` | `ptm_open_peer`@`0xffffffc080baa278`：`0xbaa2d4`/`0xbaa300` 直接取 `tty->driver_data`/`tty->link->driver_data`，**无 refcount、无有效性复核**；两者只在 `ptmx_open` `0xbaa498`/`0xbaa4c8` 写一次 | 需 devpts 实例的 dentry 在 master 存活期间被释放 | 不适用 | **排除（不足以构成可达链）**：要释放那两个 dentry 得卸载/销毁该 devpts 实例（`unshare(CLONE_NEWNS)` + `umount`），uid 2000 在 SELinux Enforcing 下既无 `CAP_SYS_ADMIN` 也无对应 allow 域；且这是 upstream 同形代码 |

补充：`TIOCSTI` 是**真能用的原语，但不是内存破坏**（单字节、走合法 ldisc 入口、且只对自己 ctty 有效），
详见 §4；不要把它当候选，但也别忽略它的用途。

## 4. TIOCSTI 的真实可达性与边界（唯一"能干点什么"的入口）

`TIOCSTI`(0x5412) → `0xffffffc080b9f18c`：

1. `ldrb w8,[0xffffffc0826af371]`（`adrp 0x826af000` + `#0x371`）—— "legacy TIOCSTI" 全局开关，
   **本镜像初值 = 1**（我直接读了 Image 的这一字节）。为 1 时**跳过** `capable(CAP_SYS_ADMIN)`；
   为 0 时 `mov w0,#0x15; bl capable` 不通过就返回 **`-EIO`**。
2. `current->signal->tty`（`[sp_el0]+0x960` → `+0x198`）必须 `== tty`，否则再查一次 `capable(CAP_SYS_ADMIN)`，
   不通过 → **`-EPERM`**。
3. 然后 `get_user(ch)`（1 字节，带 access_ok）→ `tty_ldisc_ref_wait` → 
   `ldisc->ops->receive_buf(tty, &ch, NULL, 1)`（ops+0x60）→ `tty_ldisc_deref`。

结论：**uid 2000 想吃到第 3 步，必须让这个 pty 成为自己的控制终端**——`setsid()` 后
`ioctl(fd, TIOCSCTTY, 0)` 即可（`TIOCSCTTY` 在 `tty_jobctrl_ioctl` @`0xffffffc080ba9db4`，
不需要 cap）。这一步只是把 1 个字节喂给自己 slave 的 ldisc 输入队列，
**再入的还是 §2.4 那套被夹住的 room 逻辑，不产生越界**。
用途评估：可作为"跨 fd 触发 own-pty 输入"的确定性激励源（例如喂 `VEOF`/`VINTR`/`ISIG` 序列去
驱动 echo/signal 分支），但对内存破坏无直接贡献。

**给指挥的一条待确认**：`cat /proc/sys/dev/tty/legacy_tiocsti`（若该 sysctl 存在）应以 1 为准；
若实测是 0，则 TIOCSTI 对 uid 2000 直接 `-EIO`，上面整条作废。

## 5. 本构建与 mainline 的差异点（已核对，非漏洞）

- `tty_struct` 尾部有 `__kabi_reserved1/2`（0x2c8/0x2d0），且有厂商加的 `receive_room`(0x1e4)。
- `TTY_PTY_LOCK = bit 6`（mainline 是 bit 7）：`ptmx_open@0xbaa48c` 与
  `pty_unix98_ioctl@0xbaaa58` 都是 `stset 0x40`，`0x80045439` 用 `ubfx #6,#1` 读回。
  对应地 `tty_set_ldisc@0xba7098` 的 `tbnz w8,#8` 是 `TTY_HUPPED`（mainline bit 9）。
- `pty_unix98_ioctl` 在本构建里被扩成一个大 switch，多出 `0x80045438`/`0x80045439`
  两个非 mainline 号（读写 `tty->flags` bit6，即 pty slave 锁状态），实现是
  access_ok + 4 字节 `ldtr/sttr`，**没有长度或指针算术**。
- `TIOCGEXCL`(0x80045440) 在这里额外要求 `capable(CAP_SYS_ADMIN)`（`0xb9ebe4` 为 0 时走 `-EPERM` 侧），
  比 mainline 更严。

## 6. 顺带确认的"武器化阻力"（对后续角色有用）

- `n_tty_data` = `kzalloc(8920)` → **kmalloc-16k / order-2**（4K 页）。uhid(kmalloc-256 order-1)、
  `send(AF_UNIX, 11872)`(order-1 8192)、`UI_SET_PHYS`(kmalloc-1k) **都不覆盖这一档**。
  任何假设性的 n_tty 破坏都要额外准备 order-2 的 reclaim，成本高一个量级。
- `tty_struct` = 专用 slub cache（`kmem_cache_alloc`），不是 kmalloc-1k/2k 档，
  不要指望用 `UI_SET_PHYS` 之类去占它的槽位。
- 反过来，`n_tty_data` 的 `read_buf(0x5e..0x105e)` 与 `echo_buf(0x1260..0x2260)` 是
  **内容 100% 由攻击者控制**的区域（往 pty 写多少就填多少）。若将来在 order-2 邻域找到
  可利用的相邻对象，`n_tty_data` 是个不错的**可控内容大对象**（16k 里 8k 可控）。

## 7. 未覆盖 / 明确留白（别当成"已审计"）

- `pty_unix98_install` @`0xffffffc080baa550` / `pty_unix98_remove` @`0xffffffc0800b92dc`
  （pty pair 的成对分配/拆除，`tty->link` 建立点）——只看了 `ptmx_open`/`release_tty` 两侧的调用形态。
- `tty_fasync` @`0xffffffc080ba1210`、`tty_poll`/`n_tty_poll` @`0xffffffc08040b3ec`/`0xffffffc0800bbcf0`
  （`SIGIO` 与 `tty_files` 名单的并发）。
- `__tty_hangup` @`0xffffffc080083e94` / `do_tty_hangup` @`0xffffffc080ba019c`
  （`TIOCVHANGUP` 本身 cap 门在 `0xb9ec9c`，但 hangup 与 `n_tty_close` 的交错没细看）。
- 32 位 compat 路径 `tty_compat_ioctl`（若该设备有 32 位用户态，`TCGETS/TCSETS` 的
  36B/44B 形态切换是历史上出过问题的地方；本条**未审**）。
- flip buffer 环（`tty_buffer_free` @`0xffffffc0800be77c`、`tty_insert_flip_string_and_push_buffer` @`0xffffffc080ba7f1c`）
  的 `mem_limit`/`kmalloc` 记账——`pty_write` 把全部长度决策交给它，值得单独一轮。

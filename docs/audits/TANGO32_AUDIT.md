# tango32 厂商 misc 驱动审计（lhasa / `lib_modules_tango32.ko`）

- 样本：`runs\android\rom\vendor_ko2\lib_modules_tango32.ko`（26,192 B，AArch64 ET_REL，4K 页变体，本机一致）
- vermagic：`6.18.21-android17-5-maybe-dirty-4k SMP preempt mod_unload modversions aarch64`
- modinfo：`description=32-bit syscall support for the Tango binary translator / author=Amanieu d'Antras / license=GPL`
- 设备：`/dev/tango32`，misc，`crw-rw-rw-`（`.data(tango32_device)+0x48 = 0x1b6` = 0666）；uid 2000 可 open + 进 ioctl（已实测）
- 本文所有地址均为 **`tango32_ioctl+0xNNN`**（符号内偏移；`.text+0x4` 起，size 3300 B = 0xCE4）。内核侧地址按 `vmlinux-4.0.21.0.elf` 的符号给出。
- 结论先行：**没有可用的 OOB / UAF / 信息泄露**（逐条判定见 §2 / §3 / §4.6）。这个 ioctl 面真正的价值是 **4 条"用户态可控内核状态"原语** + **1 条攻击面扩张（native 任务可调任意 fd 的 `compat_ioctl`）**，见 §4.1–§4.5。

---

## 0. 这个驱动到底是什么（一句话定性）

它不是设备驱动，是**给"32 位翻译器"用的 syscall 垫片**：真实内核里没有被实现/只对 compat 任务开放的那几个入口，由它代跑一遍。
逐条对上内核侧实现（§6 有内核侧证据）：

| 驱动命令 | 复刻的是哪个内核入口 |
|---|---|
| `0x400c74a3` | `compat_ioctl` 转发（`COMPAT_SYSCALL_DEFINE3(ioctl)` 尾部） |
| `0x400874a4` / `0x800874a5` | `__arm64_compat_sys_set_robust_list` / 取回 `task->compat_robust_list` |
| `0x401074a6` | `compat` getdents64（`iterate_dir` + 私有 `filldir64`） |
| `0xc01874a7` | `lseek`（`fdget_pos` + `vfs_llseek` + 回写结果） |
| `0x74a2` | 改写 `mm->mmap_base`（等价于 `arch_pick_mmap_layout` 的落地字段） |
| `0x800474a0` | 存活/版本探测（回 2） |
| `0x406874a1` | 向 `mm_struct` 注入 5 段地址区间 + 一坨 blob（厂商扩展区） |

**入口闸门（`+0x34`）**：`tbnz w8, #0x16 → +0x54c (-EINVAL)`，`w8 = [current] = thread_info.flags`，bit22 = `TIF_32BIT`（内核侧印证：`arch_pick_mmap_layout` 用同一位选 `STACK_TOP32/64`，§6.4）。
→ **已经是 compat（32 位）任务的调用者被直接 EINVAL**。uid 2000 的 native 64 位进程过闸。这解释了现场"未实现命令返回 ENOTTY"：驱动对未知命令返回 **`-ENOIOCTLCMD`（-515，`+0x3c` 预置 `mov x0,#-0x203`）**，VFS 把它翻成 `-ENOTTY`。

---

## 1. 命令表（逐条读出）

`x0=file, w1=cmd, x2=arg`。分派是**有符号**比较树（`b.gt` 对 `int`），因此 `0x8xxxxxxx/0xcxxxxxxx` 落在负数区间。

### 1.1 有效命令（8 条）

| cmd | 分派点 | 分支体 | 做什么 | 返回值 |
|---|---|---|---|---|
| `0x74a2` | `+0x1c0` | `+0x1cc`→`+0xa60` | 取 `current->mm`（`ldr x19,[x22,#0x698]`），`down_write_killable(&mm->mmap_lock)`（`+0x20c`），**`mm->mmap_base = arg`（`+0xa60: str x8,[x19,#0x50]`）**，`mm->mm_lock_seq++`（`+0xa78`，`[x19,#0xe0]`），`up_write`（`+0xa84`） | 0 / `-EINTR` |
| `0x400c74a3` | `+0x14c` | `+0x15c`→`+0x838`/`+0x864` | 拷 0xC 字节 `{u32 fd; u32 cmd; u32 arg;}`（`+0x170` 用 `_inline_copy_from_user`）→ `fdget`（`+0x17c`）→ 置 `TIF_32BIT`（`+0x8bc`）→ `security_file_ioctl`（`+0x1a0`）→ **`file->f_op->compat_ioctl(file,cmd,arg)`（`+0x83c: ldr x8,[x8,#0x58]`，KCFI 校验 `+0x84c..+0x860`，`blr x8` `+0x864`）** | 内层 ret / `-ENOIOCTLCMD` / `-EBADF` |
| `0x400874a4` | `+0x13c` | `+0x518` | 拷 8 字节 `{u32 head; u32 magic;}`，要求 `magic==0xC`（`+0x534`），**`current->[0xb60] = head`（`+0x544: str x8,[x22,#0xb60]`）** | 0 / `-EINVAL` |
| `0x800874a5` | `+0x6c` | `+0x7c` | 读 `current->[0xb60]` 低 32 位 + 常量 `0xC` 组成 8 字节，**手工 uaccess 写回**（`+0xf4` `__arch_copy_to_user`，前 `+0xb4..+0xe4` 开 TTBR0、后 `+0x100..+0x124` 关） | 0 / `-EFAULT` |
| `0x800474a0` | `+0x5c` | `+0x4e8` | 栈上放常量 `2`，置/清 `TIF_32BIT`（`+0x8bc`/`+0x8d4`），**写 4 字节到 arg**（`+0x960`） | 0 / `-EFAULT`（若原 flags 无 bit22 则 `-EIO`，`+0x510`——实际不可达） |
| `0x401074a6` | `+0x238` | `+0x5d4`→`+0x644` | 拷 0x10 字节 `{u32 fd; u32 count; u64 buf;}` 到 `[sp]`，`fdget_pos`（`+0x5fc` + `f_pos_lock` `+0x634`），置 `TIF_32BIT`（`+0xb10`），把私有 `dir_context` 摆好（`+0x658` 取 `&filldir64`、`+0x664` 存 buf、`+0x654` 存 count），**`iterate_dir(file,&ctx)`（`+0x668`）**，收尾把最后一条 `d_off` 补成新 `f_pos`（`+0x6f8: sttr x8,[x9]`），返回"写入字节数"（`+0x734`） | 字节数 / `-EFAULT` / `-EBADF` |
| `0xc01874a7` | `+0x1b0` | `+0x554`→`+0x768` | 拷 0x18 字节 `{u32 fd; u32 whence; u64 off; u64 ret;}`，`fdget_pos`，置 `TIF_32BIT`，`whence<=4`（`+0x5c4`），**`vfs_llseek`（`+0x770`）**，把 `ret` 写进 `[sp+0x78]` 后 **0x18 字节回写**（`+0x7f4`） | 0 / 负 errno / `-EINVAL` |
| `0x406874a1` | `+0x248` | `+0x258` | 拷 0x68 字节 `{u64 v[11]; u64 ptr; u64 len;}` 到 `[sp]`，做 11 值区间校验（§2.3），`down_read_killable(&mm->mmap_lock)`（`+0x444`）+ `spin_lock(mm+0x194)`（`+0x458`），**11 个 `str` 到 `mm+0x198..mm+0x1e8`（`+0x464..+0x4b4`）**，可选 `memcpy(mm+0x1f0, [sp+0x68], 0x1b0)`（`+0x4d0`），`up_read`（`+0x4dc`） | 0 / `-EINVAL` / `-EFAULT` |

### 1.2 **只是比较树的中转常量，不是命令**（现场清单里的三个要划掉，另有一个真命令漏了）

| 常量 | 出现处 | 事实 |
|---|---|---|
| `0x400874a3` | `+0x38..+0x44`（`cmp w1,w8; b.gt`） | **只是下界 pivot**；落在它下面的命令一律 `-ENOIOCTLCMD`。传入 `0x400874a3` 本体 → 走 default |
| `0x401074a5` | `+0x12c..+0x134`（`cmp; b.gt`） | 同上，pivot。本体 → default |
| `0xc01874a6` | `+0x4c..+0x54`（`cmp; b.gt`） | 同上，pivot。本体 → default（`0xc01874a7` 才是真命令） |

> 漏掉的真命令是 **`0x406874a1`**（`+0x248` 处 `cmp w1,#0x406874a1; b.ne default`），它是体型最大的那条（0x68 字节入参 + 5 段地址区间 + 0x1B0 blob → `mm_struct`），详见 §1.1 / §2.3 / §4.3。

> 复核方法（只发一条 ioctl，无副作用）：`ioctl(fd, 0x400874a3, &buf)` 应得 `ENOTTY`，而 `ioctl(fd, 0x74a2, 0x1000)` 应得 `ENOTTY`（因为 arg 低于 0x10000001）、`ioctl(fd, 0x74a2, 0x10000001)` 应得 0。三条的 errno 组合能一次性确认分派表（注意 `0x74a2` 会改自己的 mmap_base）。

### 1.3 栈帧与保护

`paciasp` / `autiasp`（PAC），`stp x29,x30,[sp,#-0x40]!` + `sub sp,sp,#0x220`（`+0x8`/`+0x1c`）；canary 取 `[current+0x720]`（`+0x28`，`CONFIG_STACKPROTECTOR_PER_TASK=y`）比对 `[x29-8]`，失配 `__stack_chk_fail`（`+0x9d8`）。所有 copy 都在 `sp+0x00 .. sp+0x218` 之内，canary 在 `sp+0x218`。

---

## 2. 边界检查逐条判定

### 2.1 用户结构与长度对应关系

| cmd | 用户结构 | 长度语义 | 栈内落点 | 大小关系 | 判定 |
|---|---|---|---|---|---|
| `0x400c74a3` | 0xC `{u32 fd;u32 cmd;u32 arg;}` | 固定 0xC（立即数 `+0x164`） | `sp+0x68..0x74`（`arg` 先被 `str wzr,[sp,#0x70]` 清零） | 0xC = 0xC | ✅ |
| `0x400874a4` | 0x8 `{u32 head;u32 magic}` | 固定 8，**且校验 `[sp+0x6c]==0xC`** | `sp+0x68..0x70` | 8 = 8 | ✅ |
| `0x800874a5` | 0x8 出参 | 固定 8 | `sp+0x68..0x70`（都写过） | 8 = 8 | ✅ 无未初始化泄漏 |
| `0x800474a0` | 0x4 出参 | 固定 4 | `sp+0x68` | 4 = 4 | ✅ |
| `0x401074a6` | 0x10 `{u32 fd;u32 count;u64 buf;}` | **`count` 完全用户控制且无上限**（内核 getdents 会 cap 到 `MAX_RW_COUNT`，这里没有） | `[sp]`（`+0x5e0..+0x5ec` 先清零） | 见 §2.2 | ⚠ 缺上限，但写目标仍被 access_ok 夹住 → 不越界（只写调用者自己的用户内存） |
| `0xc01874a7` | 0x18 `{u32 fd;u32 whence;u64 off;u64 ret;}` | 固定 0x18 入 + 0x18 出，`whence<=4`（`+0x5c4`，无符号 `b.ls`） | `sp+0x68..0x80` | 0x80-0x68 = 0x18 | ✅ 出参每个字节都初始化过（`+0x7f4` 拷 0x18，含 `+0x78` 的 ret） |
| `0x74a2` | 裸值 | `arg ∈ [0x10000001, TASK_SIZE)` | — | — | ✅（见 §2.4） |
| `0x406874a1` | 0x68 `{u64 v[11];u64 ptr;u64 len;}` | `len<=0x1B0` 且 `len>0 → ptr!=0` | `sp+0x68..sp+0x218`（恰好 0x1B0，`+0x404` memset 同长） | `len<=0x1B0` = 缓冲大小 | ✅ |

### 2.2 `0x401074a6` / 私有 `filldir64`（`.text+0xe9c`，672 B）

模块自己实现了目录项渲染回调（不是内核的 `filldir64`，是本地符号），配合 `iterate_dir` 做 compat getdents。逐条：

- `+0xeb8..+0xec4`：`(unsigned)(namelen-0x1000)+0xfff` 判进位 → **`namelen` 必须 ∈ [1, 0xFFF]**，越界 `ctx->err=-EIO` 返回 0。
- `+0xee8`：`memchr(name,'/',namelen)`，命中即 `-EIO`（`verify_dirent_name` 等价物）。
- `+0xf18..+0xf30`：`reclen = (namelen+0x1B) & ~7`（= `ALIGN(19+namelen+1,8)`，与 `linux_dirent64` 一致）；`if (reclen > ctx->count) 停`（`b.gt` 是**有符号**比较，`count` 巨大时按负数处理直接停）。
- `+0xf80..+0xf90`：**手工 access_ok**：`uptr = buf - prev_reclen`，要求 `uptr + (prev_reclen+reclen) <= 0x8000000000`（`mov x12,#0x8000000000`）。等价于 `access_ok(记录区间)`，且上界用的正是 `2^39`。
- `+0xfd4..+0x1008`：`d_off`(8B, `+0xfd4`)、`d_ino`(8B, `+0xfdc`)、`d_reclen`(2B, `+0xfe8`)、`d_type`(1B, `+0xff4`)、名字后的 NUL(`+0x1008`)，全部 `sttr`（EL0 权限存，PPS/PAN 安全）。
- `+0x1014..+0x1084`：名字按 8/4/2/1 字节 `sttr` 拷贝，源是内核里的目录项名，长度 = `namelen`。
- `+0x1088`：`uaccess_ttbr0_disable`；`+0x108c..+0x10a0`：`ctx->cur += reclen`、`ctx->count -= reclen`、`ctx->prev = reclen`。
- **`__ex_table` 覆盖**：`.rela__ex_table` 共 10 条，`0x6f8`（收尾补 `d_off`）+ `0xfd4/0xfdc/0xfe8/0xff4/0x1008/0x101c/0x1040/0x1064/0x1084`（9 个 `sttr`），全部 fixup 到 `0x10b0`。→ **用户地址打空只会 EFAULT，不会 oops**（这点很关键：`CONFIG_PANIC_ON_OOPS=y`，漏一条就是可远程/本地触发的重启）。

判定：**没有"长度由用户给、内核按另一个值分配/拷贝"的错配**；记录总长与 `namelen` 严格同源（同一个 `namelen`），NUL 写在 `cursor+0x13+namelen`，末字节 `= cursor+reclen-1`，不越界。
唯一语义偏差：`count` 无 `MAX_RW_COUNT` 上限，能让驱动一路往调用者自己的地址空间里灌目录项，但每个写点都在 `access_ok` 之内且是 EL0 权限存 → **不是内核侧越界，不构成漏洞**。

### 2.3 `0x406874a1` 的 11 值校验（`+0x2a4..+0x3b8`）

记 `v0..v10 = [sp+0x00..0x50]`（`sp+0x58` 是 `ptr`、`sp+0x60` 是 `len`）：

1. 每个 `vi` 必须 ∈ `[0x1000, limit)`；`limit = TASK_SIZE`（native `0x8000000000` / compat `0xFFFFF000`，`csel` 在 `+0x2b8`，同 §2.4 的写法）。
2. 顺序（**只校验组内，不校验组间**）：`v1<=v0`（`+0x3a0`）、`v2<=v3`（`+0x394`）、`v4<=v5`、`v6<=v7`、`v9<=v10`（`+0x3a8..+0x3b4` 的 `ccmp` 链）。`v8` 单独一个值，只做区间校验。
3. 尺寸预算（`+0x3cc..+0x3dc`）：`(v3-v2) + (v5-v4) <= current->signal->[0x2c0]`，该字段 `== -1` 时跳过（`+0x3c4` `cmn x8,#1`）——形态即 `rlimit.rlim_cur` 与 `RLIM_INFINITY` 的比对。
4. 可选 blob：`len==0` 直接跳过（`+0x3e4`）；`len>0x1B0` → `-EINVAL`（`+0x3e8`）；`ptr==0` → `-EINVAL`（`+0x3f8`）；`+0x41c` 先 `__check_object_size(sp+0x68,len,0)` 再 `_inline_copy_from_user`。

判定：**没有跨组重叠校验**、`v8` 语义不明。写入目标 `mm+0x198..mm+0x3a0`（0x58 + 0x1B0 = 0x208）落在 `mm_struct` 对象内（本机 `mm_struct` SLUB objsize = **1408 = 0x580**，`/proc/slabinfo` 实测）→ **不是越界写**。

### 2.4 `0x74a2` 的两道比较（精确值，纠正现场记录）

```
+0x1d0  mov   w10, #1
+0x1d8  movk  w10, #0x1000, lsl #16        ; w10 = 0x10000001
+0x1d4  movz  x9,  #0x80, lsl #32          ; x9  = 0x8000000000
+0x1e4  movn  w8,  #0xfff                  ; 32 位 → x8 = 0x00000000FFFFF000
+0x1e0  tst   w8flags, #0x400000           ; TIF_32BIT
+0x1e8  csel  x8, x9, x8, eq               ; 非 compat → 0x8000000000
+0x1ec  cmp   x2, x10 ; b.lo default       ; arg >= 0x10000001
+0x1f4  cmp   x2, x8  ; b.hs default       ; arg <  TASK_SIZE
```
- 下界是 **`0x10000001`**（不是 0x1000，也不是 1）：`(0x1000<<16)|1`。
- 上界 **`0x8000000000` = 2^39**，与 `CONFIG_ARM64_VA_BITS_39=y` 完全一致（所以这套手写 access_ok **不是错的**）。compat 分支（0xFFFFF000）因 `+0x34` 闸门实际不可达。
- 不合法的 arg 返回 `-ENOIOCTLCMD`（不是 EINVAL），现场会看到 `ENOTTY`。

### 2.5 手写 uaccess / `uaccess_ttbr0_disable`（`.text+0xce8`）

`+0xce8` 的 92 字节函数体 = `__uaccess_ttbr0_disable()` 逐指令对应：`local_irq_save` → `ttbr1 &= ~0xffff_0000_0000_0000` → `ttbr0 = ttbr1 - 0x1000`（reserved_ttbr0）→ `ttbr1 = 清 ASID 后的值` → `isb` → `local_irq_restore`。
对应地 `+0xb4..+0xe4`（以及 `+0x6cc`、`+0x7bc`、`+0x928`）是 `__uaccess_ttbr0_enable()`：从 `thread_info.ttbr0`（`current+8`，`CONFIG_ARM64_SW_TTBR0_PAN=y`）恢复 TTBR0，并把 ASID 塞回 TTBR1（`bfxil ... #0,#0x30`）。
- 每一步都与内核原实现逐条一致（含 `isb`、含 `icc_pmr_el1` 的伪 NMI 中断屏蔽替身，`CONFIG_ARM64_PSEUDO_NMI=y`）。
- 成对性：`0x800874a5`（`+0xb4`→`+0xf4`→`+0x100`）、`0x800474a0`（`+0x928`→`+0x960`→`+0x96c`）、getdents 收尾（`+0x6cc`→`+0x6f8`→`+0x704`）都是 **enable → 用户访存 → disable** 直落，中间没有任何可能跳出（`__arch_copy_to_user` 的失败走自己的 ex_table 返回，不 longjmp）→ **不会出现 PAN 开着返回用户态**。
- 这些序列都挂了 `altinstructions`（`.rela.altinstructions` 里 `0xb4/0xb8/0xe0/0xf8/0xfc/0x120` 等），支持 UAO/PAN 的 CPU 上被 patch 成 NOP → 兼容性没问题。

`_inline_copy_from_user`（`.text+0xd44`，340 B）= `copy_from_user` 实体：`access_ok`（`+0xd80..+0xd9c`：`n > 2^39` 或 `2^39-n < ptr` 即失败）→ 开 TTBR0 → `__arch_copy_from_user` → 关 TTBR0 → 失败时 `memset(dst+n-ret, 0, ret)` 补齐。**它做的是带长度的完整 access_ok，不存在"只校验首地址不校验长度"的经典坑。**

---

## 3. 生命周期：没有任何对象

用 `.rela.data` / `.rela.rodata` 把 `file_operations` 解出来（内核侧同版布局已用 `socket_file_ops`/`binder_fops`/`uhid_fops` 交叉验证，§6.5）：

- `.data+0x00` = `tango32_device`（`struct miscdevice`，size 80）：`+0x00 minor = 0xff`、`+0x08 name = .rodata+0x2c "tango32"`、`+0x10 fops = .rodata+0x38`、`+0x48 mode = 0x1b6`。
  > 与现场"minor 280"不一致，取证记录需复核：`cat /sys/class/misc/tango32/dev` 应为 `10:255`。此项不影响任何结论。
- `.rodata+0x38` = `tango32_fops`（size **272 = 0x110**，34 槽）。`.rela.rodata` 只有两条：`+0x00 → __this_module`、**`+0x88 → tango32_ioctl`**。基址 0x38 → 唯一非空槽是 **fops+0x50 = `unlocked_ioctl`**。

所以对外暴露的入口**只有 `unlocked_ioctl` 一个**：

| 槽位 | 成员 | tango32_fops |
|---|---|---|
| +0x10 | `llseek` | NULL |
| +0x18/+0x20 | `read` / `write` | NULL |
| +0x28/+0x30 | `read_iter` / `write_iter` | NULL |
| +0x40 | `iterate_shared` | NULL |
| +0x48 | `poll` | NULL |
| **+0x50** | **`unlocked_ioctl`** | **`tango32_ioctl`** |
| +0x58 | `compat_ioctl` | **NULL** |
| +0x60 | `mmap` | NULL |
| +0x68 / +0x78 | `open` / `release` | NULL |

推论（硬性）：
1. **没有 `open`/`release`** → 不可能有 `file->private_data` 生命周期；`kmem_cache_alloc`/`kzalloc`/`kfree`/`vfree`/`list_add` 这些符号**一个都没有 import**（导入表只有 31 个符号，全是 copy/uaccess/lock/fd/fs 类）。
2. **没有 `mmap`/`read`/`write`/`poll`/`llseek`** → 唯一可达路径就是 ioctl。
3. 全局资源只有 `.data` 的 `tango32_device`（80 B，init 里 `misc_register`，`+0x18`；`.init.text+0x10/+0x14` 取址）与 `.rodata` 的 fops。**跨调用没有共享可变状态** → 不存在"上一次 ioctl 留下的悬挂对象"。
4. 唯一涉及"别人对象生命周期"的是 `fdget/fdget_pos/fput`：每条路径都成对（`+0x750`/`+0x754`、`+0x884`/`+0x8b0`，按 `struct fd` 的 bit0/bit1 判 `FDPUT_FPUT`/`FDPUT_POS_UNLOCK`），`fd==无效` 时 `-EBADF`（`+0x760`）且不 fput。**没有 file 引用泄漏。**
5. `mm` 来自 `current->mm`，只在自己的 syscall 上下文用，且拿 `mmap_lock` 保护 → 无 UAF 窗口。
6. 并发：`0x406874a1` 用 `down_read(mmap_lock)`+`spin_lock(mm+0x194)`；`0x74a2` 用 `down_write(mmap_lock)`；加锁顺序不交叉，无死锁。getdents/lseek 走 `f_pos_lock`（mutex，可睡眠）→ 上下文正确（unlocked_ioctl 允许睡眠）。

**结论：§4.6 的"UAF 不存在"是结构性结论，不是抽样结论。**

---

## 4. 候选清单

### 4.1 【利用原语 / 加固缺口】`0x74a2`：`mm->mmap_base` 由用户态直接改写

- 序列：`fd=open("/dev/tango32",O_RDWR); ioctl(fd,0x74a2, (unsigned long)NEW_BASE)`，`NEW_BASE ∈ [0x10000001, 0x8000000000)`。
- 证据偏移：校验 `+0x1ec/+0x1f4`；落点 **`+0xa60 str x8,[x19,#0x50]`**（`x19 = current->mm`，`+0x1fc` 取）；`mmap_lock` 写锁 `+0x20c`；`/proc/self/maps` 观测点。
- 命中判据：调用前 `mmap(NULL,0x1000,...)` 落在 `0x7fxx…`；调用后（`NEW_BASE=0x10000001`）新 mmap 落在 `~0x10000000` 下方、`[stack]`/`[vvar]` 不变。**一条 ioctl、立即生效、无副作用、可反复调**。
- 影响：本进程 mmap 区 ASLR 归零 → **对 exploit 有直接价值（可控 mmap 落点）**；不是提权，因为他只能动自己的 mm。
- 能否用现有原语 reclaim：N/A（无堆操作）。

### 4.2 【攻击面扩张】`0x400c74a3`：让 native 64 位进程调用任意 fd 的 `compat_ioctl`

- 序列：`a = {u32 fd = 目标fd; u32 cmd = 32 位命令; u32 arg = 32 位参数;}; ioctl(tango_fd, 0x400c74a3, &a);`
- 证据偏移：`+0x83c ldr x8,[x8,#0x58]`（`f_op->compat_ioctl`，`+0x8` 是 `f_op`）、`+0x840 cbz → -ENOIOCTLCMD`、`+0x84c..+0x860` KCFI 类型哈希校验（`brk #0x8228` 失配即 panic）、`+0x864 blr`；前置 `+0x190` 置 `TIF_32BIT`、`+0x1a0` 调 **`security_file_ioctl`**。
- 命中判据：挑一个 `compat_ioctl != NULL` 且与 native 路径不同的 fd，用 32 位 cmd 调通、返回值与 native 路径不同。最方便的落点（本机 fops 已解析，§6.5）：
  - socket：`compat_ioctl = compat_sock_ioctl`（`vmlinux+0x810af6c8`）
  - `/dev/binder`：`compat_ioctl = compat_ptr_ioctl`（`+0x79ec0c`），会把 arg 截成 32 位
  - 任意 `compat_ptr_ioctl` 用户：assert arg 被 `compat_ptr` 化（高位被清）
- 影响：**把"只有 32 位进程才可达"的 compat 处理器搬到 64 位进程里**，而且同时把 `TIF_32BIT` 置上（`in_compat_syscall()` 为真）。这是本轮最值得往下打的一条（很多 compat_ioctl 的"调用者是 32 位任务"假设从没被 64 位路径审计过）。
- 附带缺陷：**LSM hook 用错**。内核 compat 路径用的是 `security_file_ioctl_compat`（`__arm64_compat_sys_ioctl` → `vmlinux+0x80925e00`），驱动调的是 native 的 `security_file_ioctl`（`vmlinux+0x8013f674`）。SELinux 的 `selinux_file_ioctl_compat`/`ioctl_override` 规则在这条路径上**不生效** → 若设备策略用 ioctl_override 收紧过某些 compat ioctl，这条路径会绕过它（可用 `avc` 日志对照验证：同一 cmd 走真 compat 会 deny、走 tango32 不会）。
- reclaim：不需要。

### 4.3 【状态注入 / 待验证】`0x406874a1`：用户可控的 5 段区间 + 0x1B0 blob 写进 `mm_struct`

- 序列：`r = {u64 v[11]; u64 ptr; u64 len;}` 按 §2.3 校验摆好；`ioctl(fd,0x406874a1,&r)`。
- 证据偏移：`spin_lock(mm+0x194)` `+0x458`；11 个 `str` `+0x464..+0x4b4`（目标 `mm+0x198+8i`）；`memcpy(mm+0x1f0, stack, 0x1b0)` `+0x4d0`；`down_read` `+0x444`。
- 命中判据：调用返回 0、且 `mm` 内 `+0x198..+0x1d8` 变为 `v0..v10`（需要 kprobe/gdb 或内核侧消费者行为变化）；负例判据：`v2>v3` / `v0<v1` / 任一路径越界 / `len=0x1b1` 都必须 `EINVAL`——这四条同时成立才说明校验和本文一致。
- 现状：写入区间 `mm+0x194..+0x3a0` 全部落在 `mm_struct`（objsize 0x580）之内，**不是越界写**；这 5 段区间 + blob 的结构不在上游 `mm_struct` 字段表里，判断为**厂商补丁新增区**（同内核另有非上游导出符号 `validate_usercopy_range`、且 `__arm64_compat_sys_set_robust_list` 被改成读 `{ptr,len}` 结构，`vmlinux+0x805f0f38` → 内核确有 tango 定制，§6.3）。
- 待验证 + 下一步：内核侧到底谁消费 `mm+0x198..0x3a0`。做法：在 `vmlinux` 里找基址来自 `[.., #0x698]`（`current->mm`）后又 `ldr/str` 偏移 `0x198/0x1d8/0x1f0` 的函数；或在设备上 `ioctl(0x406874a1)` 后观察 `mmap`/`fork`/`exec` 行为是否按注入值变化。**在拿到消费者之前，不能把它写成成果。**
- reclaim：不需要（写的是当前 `mm`，不是堆对象）。

### 4.4 【加固缺口】`0x400874a4` / `0x800874a5`：native 任务可设 `task->compat_robust_list`

- 序列：`s={u32 head;u32 magic=0xC;}; ioctl(fd,0x400874a4,&s)`（写），`ioctl(fd,0x800874a5,&out)`（读回 `{head_low32,0xC}`）。
- 证据偏移：写 `+0x544 str x8,[x22,#0xb60]`、magic 校验 `+0x534`；读 `+0x7c ldr x8,[x22,#0xb60]`。
- 内核侧印证：`__arm64_compat_sys_set_robust_list`（`vmlinux+0x805f0f38`）是 `cmp [x0+8],#0xc` + `str [current,+0xb60]` —— **与驱动 0x400874a4 完全同构**；退出路径 `futex_exit_release`（`+0x802b793c`）在 `+0x7978` 处 `ldr x8,[x19,#0xb60]; cbnz → compat_exit_robust_list`（**按字段非空判断，不看 `is_compat_task()`**）。
- 命中判据：`0x800874a5` 读回值 == 写入值（证明落在同一字段）；退出时若该字段非空，内核会按 **32 位 robust_list 布局**遍历——把 head 指向一个构造好的 12 字节 compat 头（`list.next/list.prev/futex_offset`），退出时用 `futex_exit_release` 的行为（唤醒/解锁自己给的地址）作为观测点。
- 影响：遍历全程是 `get_user`/futex 用户地址操作，**不产生内核越界**；实际收益是"64 位任务获得 32 位 robust-list 语义"，属语义越界而非内存安全。**不记成果。**

### 4.5 【设计】`TIF_32BIT` 可由用户态置/清（`+0x34` 只挡"已是 compat"的调用者）

- 置位点：`+0x190`（0x400c74a3 转发前）、`+0x8bc`（0x800474a0）、`+0xaf8`（0xc01874a7）、`+0xb10`（0x401074a6）；清位点：`+0x874`/`+0x89c`/`+0xb28`/`+0xb48`/`+0xb68`；全部是 `ldxr/stxr` 原子 RMW（`+0x8bc`/`+0x8d4`/`+0xae0`/`+0xaf8`/`+0xb10`/`+0xb28`/`+0xb48`/`+0xb68`）。
- 判据：在窗口内（例如借 `0x400c74a3` 转发一个 `compat_ptr_ioctl` 目标）若内层按 32 位取参成功，即证明 `is_compat_task()` 被伪造（thread_info.flags bit22 = `TIF_32BIT`，内核侧 `arch_pick_mmap_layout` 用同一位，§6.4）。
- 结论：**不是竞态漏洞**。flag 是 per-task，窗口全部在本次 syscall 内、返回用户态之前把位清掉（包括所有错误路径）；IRQ/抢占切换的是别的 task，看不到本 task 的 flags。真正被"骗"的只有驱动自己调进去的内核代码——这正是设计目的。

### 4.6 明确排除（写清楚，别再回来找）

| 类别 | 判定 | 依据 |
|---|---|---|
| 栈缓冲 `0x220` 被超长拷贝 | **不存在** | 最长用户拷入是 `0x68`（`+0x298`，固定）、`0x18`、`0x10`、`0xC`、`0x8`，以及 `len<=0x1B0` 到 `sp+0x68`（`+0x428`），终点 `sp+0x218` = canary 前沿，无一越界 |
| 长度/分配错配 | **不存在** | 8 条命令全部是定长或"`len` 与缓冲同源"（§2.1） |
| 堆 OOB / 堆溢出 | **不存在** | 模块无任何分配（导入表无 alloc/free） |
| UAF / double free / 引用泄漏 | **不存在** | §3（无对象；file 引用成对 fdput；mm 由当前任务持有并加锁） |
| 内核信息泄露 | **不存在** | 三个出参路径全部先写满再拷出（`+0x68/+0x78` 清零、`+0x1fd` 组合值、`+0x960` 前的 `+0x8f0` 只在栈内建 `{2}`）；目录项无未初始化字节进内核；`0x800874a5` 读回的是调用者自己写进去的值（`copy_process`/`exec` 都会清零该字段） |
| 未初始化栈泄漏 | **不存在** | 且内核 `CONFIG_INIT_STACK_ALL_ZERO=y` |
| panic 可触发点 | 仅 `+0xa6c` 一处 `brk #0x800`（`mmap_write_unlock` 的 `BUG_ON(!rwsem_is_locked)`），拿不到锁就不可能到达；`.rela__bug_table` 只有这 1 条 | — |
| 手工 uaccess 半开 | **不存在** | 所有 enable/disable 直落成对（§2.5） |

---

## 5. 设备状态机

**没有状态机。** `init_module`（`.init.text+0x4`，36 B）只有一句 `misc_register(&tango32_device)`（`+0x10/+0x14` 取址、`+0x18` 调用）；`cleanup_module` 只有 `misc_deregister`。不需要下发固件/建表/握手，8 条命令全部可以**冷启动后第一条 ioctl 就打**。

唯一的前置条件是"自己是 native 64 位任务"（`+0x34`）——uid 2000 天然满足；文件权限 `0666`（`.data+0x48 = 0x1b6`）保证能 open。

命令之间**不共享状态**，唯一的跨调用副作用是写进 `current->mm` / `current->task_struct` 的字段本身（`mmap_base`、`mm+0x198..0x3a0`、`task+0xb60`），这些都随进程走、`exec` 后 `mm` 换新、`fork` 后 `mm` 复制（`0x400874a4` 写的 `robust_list` 在 `copy_process` 里被清零）。

---

## 6. 内核侧印证（用于给报告兜底；都是本机 `vmlinux-4.0.21.0.elf` 实读）

### 6.1 `task_struct.mm = +0x698`、`mmap_lock = +0x88`、`mm_users = +0x74`
- `get_task_mm`（`+0x80221b5c`）：`ldrb w8,[x0,#0x46]; tbnz #5`（`PF_KTHREAD`）→ `ldr x20,[x19,#0x698]`（`->mm`）→ `stadd w1,[mm,#0x74]`（`mm_users++`）。
- `vm_mmap_pgoff`（`+0x8019dc88`）：`ldr x22,[x9,#0x698]` → `add x0,x22,#0x88; bl down_write_killable` → 同一处 `ldr w8,[x22,#0xe0]; add 1; str`（**`mm->mm_lock_seq++`**，与驱动 `+0xa78` 逐条同构，所以驱动的两次 `+1` **不是 mm_count 泄漏**）。
- `mmput`（`+0x8025b3a8`）：`ldaddal w-1, [x0,#0x74]` → 确认 `mm_users@0x74`，也就证明 `+0xe0` 不是引用计数。

### 6.2 `mm_struct.mmap_base = +0x50`
`arch_pick_mmap_layout`（`+0x80324128`）：`... str x8,[x19,#0x50]`（`x19 = mm` 入参，`x8 = rnd + STACK_TOP 相关值`）→ **`mm+0x50 = mmap_base` 铁证**。同函数里 `ldrb w9,[x21,#0x6ca]; tbnz #5` = `personality & ADDR_COMPAT_LAYOUT`（0x0200000，`mmap_is_legacy()` 的检查；`personality` 在 `task+0x6c8`，由 `__arm64_sys_personality` 的 `ldr/str w?,[current,#0x6c8]` 证实），legacy 分支用 `0x40000000`、topdown 分支用 `0x2000000000` 量级作基址。
`task_vsize` 用 `ldr x8,[x0,#0x158]; lsl x0,x8,#0xc` → `mm->total_vm@0x158`，与上面的布局自洽。

### 6.3 `task->signal = +0x960`、`compat_robust_list = +0xb60`、`robust_list = +0xb58`
- `mm_access`（`+0x8025b584`）：`ldr x8,[x0,#0x960]; add x0,x8,#0x430; bl (down_read_killable)` = `task->signal->exec_update_lock` → `signal@0x960`（驱动 `+0x3bc` 读 `signal+0x2c0` 作 rlimit，同理）。
- `__arm64_compat_sys_set_robust_list`（`+0x805f0f38`）：`ldr w9,[x0,#8]; cmp w9,#0xc; b.ne -EINVAL; ... str x8,[current,#0xb60]`。
- `futex_exit_release`（`+0x802b793c`）：先 `[+0xb58]`（native）→ 再 `[+0xb60]`（compat，`+0x7978`）→ 各调 `exit_robust_list` / `compat_exit_robust_list`，调用后置 0。

### 6.4 `TIF_32BIT = thread_info.flags bit22`
`arch_pick_mmap_layout`：`tst x22,#0x400000`（`x22=[current]`）后在 `0x40000000`(STACK_TOP32) / `0x2000000000`(STACK_TOP64) 之间 `csel` → 该位就是 `is_compat_task()`。驱动 `+0x34` 闸门用的正是这一位。

### 6.5 `file_operations` / `struct file` 布局（决定 §3 的表）
用三个已知 fops 符号实读槽位（地址在 `vmlinux` 的 `.kernel` 里）：

| 偏移 | `socket_file_ops` | `binder_fops` | `uhid_fops` |
|---|---|---|---|
| +0x18 read | — | — | `uhid_char_read` |
| +0x20 write | — | — | `uhid_char_write` |
| +0x48 poll | `sock_poll` | `binder_poll` | `uhid_char_poll` |
| **+0x50 unlocked_ioctl** | `sock_ioctl` | `binder_ioctl` | — |
| **+0x58 compat_ioctl** | `compat_sock_ioctl` | `compat_ptr_ioctl` | — |
| +0x60 mmap | `sock_mmap` | `binder_mmap` | — |
| +0x78 release | `sock_close` | `binder_release` | `uhid_char_release` |

因此 `tango32_fops+0x50 = tango32_ioctl`、`+0x58 = NULL`（§3），以及驱动里 `ldr x8,[file,#8]; ... [x8,#0x58]` 就是 `f_op->compat_ioctl`（`struct file.f_op@0x8`、`f_mode@0x4`——`ldrb [file,#5]; tbz #7` 是 `FMODE_ATOMIC_POS` 判断）。

### 6.6 本机内核确实是"定制内核"（用来支撑 §4.3 的"厂商扩展区"判断）
- 导出 `validate_usercopy_range` + `__ksymtab_validate_usercopy_range` + `__flags_validate_usercopy_range`（**非上游符号**）；模块的 `.rela__jump_table` 里 `key=validate_usercopy_range addend=0x1` 挂在 `tango32_ioctl+0x40c`，即 `check_copy_size` 的静态分支：键为真时 `+0x410 __check_object_size` 被跳过（`+0x420` 直接进 `_inline_copy_from_user`）。
- `__arm64_compat_sys_set_robust_list` 的签名被改成"从 `{ptr,len}` 结构取参"，与驱动 ABI 一致。
- 相关配置：`CONFIG_ARM64_VA_BITS_39=y`、`CONFIG_ARM64_SW_TTBR0_PAN=y`、`CONFIG_ARM64_PSEUDO_NMI=y`、`CONFIG_ARM64_TAGGED_ADDR_ABI=y`（→ 到处出现的 `and #0xff7fffffffffffff` 就是 `untagged_addr`）、`CONFIG_STACKPROTECTOR_PER_TASK=y`、`CONFIG_CFI=y`、`CONFIG_MODVERSIONS=y`、`CONFIG_PANIC_ON_OOPS=y`、`CONFIG_KASAN=y`+`KASAN_HW_TAGS`、`CONFIG_INIT_STACK_ALL_ZERO=y`、`CONFIG_HARDENED_USERCOPY_DEFAULT_ON=y`。

---

## 7. 给下一步的结论

1. **这条面本身没有可直接拿分的 OOB/UAF/信息泄露**，不用再花时间在"栈缓冲溢出""长度错配""释放路径"上（结构上没有）。
2. 想继续在这台机器上推进，**优先打 §4.2**：`0x400c74a3` 是一条现成的"native → compat_ioctl"通道，把 binder/ashmem/uhid 等只有 32 位进程才走的处理器打开给 64 位进程；配合 §4.5 的 `TIF_32BIT` 伪造，连 `in_compat_syscall()` 都会按 32 位走。这条最可能有真漏洞（compat 处理器常年没人按 64 位调用者审计），且完全不需要额外原语。
3. §4.1（`mmap_base`）可直接当 exploit 的布局稳定器用（把 mmap 压到固定低地址）。
4. §4.3 需要先在 `vmlinux` 里找到 `mm+0x198/+0x1f0` 的消费者；在那之前它只是"用户可控 mm 状态"，不是成果。
5. 观测口径：本驱动**不分配内存**，`/proc/slabinfo` 不会因它变动（看到变动是别的原因）；真正的"打崩"信号只有 `+0xa6c` 的 `BUG_ON` 与 KASAN 报告（`CONFIG_PANIC_ON_OOPS=y` 会重启，别在生产机上试）；§4.1 用 `/proc/self/maps`、§4.2 用内层返回值/`avc` 日志、§4.4 用读回值。

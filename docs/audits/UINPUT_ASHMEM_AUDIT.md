# UINPUT（非 FF）/ ASHMEM 静态审计 — HyperOS 4.0.21.0

- 素材：`Image-4.0.21.0.bin` + `vmlinux-4.0.21.0.elf`；`file_off = addr - 0xffffffc080000000`。
- 方法：符号表 + capstone 反汇编（`runs/android/rom/kdisasm.py`，等价脚本 `%TEMP%\ua_scan.py`）、BTF 精确布局（`btf_dump.py`）、BL 目标全镜像扫描（`%TEMP%\ua_callers.py`）。
- 运行前提（已实测，来自上游）：uid 2000、SELinux Enforcing、`CONFIG_PANIC_ON_OOPS=y`、`kasan=off`、`CONFIG_RANDOM_KMALLOC_CACHES` 未设；`/dev/uinput` 与三个 `/dev/ashmem_*` 可 open、ioctl 能进驱动；`/dev/input/event*` 为 EACCES ⇒ **FF 上传/擦除不可达**，本报告不覆盖 FF。
- 本次只做静态 + 读取，未 fuzz、未写设备、未运行 exploit。

## 0. 结论（先看这张表）

| # | 问题 | 结论 |
|---|---|---|
| 1 | `UI_DEV_SETUP` name 拷贝 | **没有 OOB**：`kstrndup(name, 0x50, GFP_KERNEL)`，长度上限 80 且强制补 NUL；栈缓冲 92B 先清零再 `copy_from_user(…,0x5c)` 全填 |
| 2 | `UI_ABS_SETUP` code/absinfo | **没有 OOB**：`code <= 0x3f` 无符号比较在写入前；`absbit`/`absinfo[]` 索引均 ≤ 63，与 `ABS_CNT=64` 一致；值域只做数学一致性检查，不进下标 |
| 3 | `UI_SET_*BIT` 位号 | **没有 OOB**：11 条普遍是 `cmp x22,#<该字段 *_MAX>; b.hi → -EINVAL`，再 `stset 1<<bit`；多 long 位图用 `bit>>6` 选字、`lsl` 取 `bit&63` |
| 4 | `UI_SET_PHYS` | `strndup_user(arg, 0x400)`（1024 上限），替换时先 `kfree(dev->phys)`；`uinput_destroy_device` 内 2 处 `kfree`（name/phys）回收 |
| 5a | ashmem `SET_NAME` | 上限 0x100，`memset(buf,0,0x100)` + 带容量 0x100 的 `strcpy_into_buf`，返回 `&CStr`（必有 NUL）→ 再按 `strlen` 精确 `kmalloc`+`memcpy`。**无溢出** |
| 5b | ashmem `SET_SIZE` | 只有「已建 file 则 -EINVAL」一道检查，**size 本身无任何上界**（见候选 B：DoS 面） |
| 5c | ashmem `PIN/UNPIN` | **范围检查是完整的**：`len≥8`、`offset ≤ PAGE_ALIGN(size)`、`offset/len 必须页对齐`、`offset+len` 无进位、`offset+len ≤ PAGE_ALIGN(size)` |
| 5d | `ignore_unset_prot_exec` | 绕过的是 `set_prot_mask()` 的「只能减少不能增加」判定：`(asma->prot_mask & prot) != prot → -EINVAL`。判定点 **0xffffffc080fdf400**（`bics xzr,x8,x10`/`b.ne`），拒绝分支 0x…fdf428，开关字节 `ldrb` 在 **0xffffffc080fdf3dc**（`0xffffffc082977360`） |

**总判定：uinput 非 FF 面与 ashmem ioctl 面均未发现 uid 2000 可达的 OOB / UAF / 越界读。** 两处非内存安全类问题见「候选」。

## 1. uinput —— 命令分派表（`uinput_ioctl_handler @ 0xffffffc080e24a70`，栈帧 `#0x120`）

入口固定动作：`mutex_lock_interruptible(udev+8)`；`if (!udev->dev) udev->dev = input_allocate_device()`（0x…e24ae4，失败 -ENOMEM）；`x0 = dev`，之后所有 `add x9,x0,#off` 都是 `dev+off`。

| ioctl | 值 | 处理块 |
|---|---|---|
| `UI_DEV_CREATE` | 0x5501 | 0x…e24fcc（inlined `uinput_create_device`；`EV_ABS`→`input_alloc_absinfo` @0x…e2526c，`ABS_MT_SLOT`→`input_mt_init_slots(absmax+1)` @0x…e253b8，`ff_effects_max`→`input_ff_create` @0x…e24ffc，`input_register_device` @0x…e25394，成功后 `state=2`） |
| `UI_DEV_DESTROY` | 0x5502 | 0x…e24bb0 → `uinput_destroy_device` |
| `UI_DEV_SETUP` | 0x405c5503 | 0x…e24fb8 → 体 0x…e2522c |
| `UI_ABS_SETUP` | `cmd & 0xc000ffff == 0x40005504` | 0x…e25120 掩码比较 → 0x…e25298（size 检查）→ 体 0x…e2541c |
| `UI_SET_*BIT` | 0x40045564..0x4004556e | jump table `0xffffffc081a15358`（基址 `0x…e24b30`，`idx=cmd-0x40045564`，`cmp w8,#0xa; b.hi default` @0x…e24b20） |
| `UI_SET_PHYS` | 0x4008556c | 0x…e24f74 |
| `UI_GET_SYSNAME(n)` | 0x8…552c（size 可变） | 0x…e25118 掩码后 → 0x…e25148 |
| `UI_GET_VERSION` | 0x8004552d | 0x…e250a4 |
| FF 五条 | 0xc06855c7/0xc06855c8/0x406855c9/0xc00c55ca/0x400c55cb | 已审，本次不覆盖（event* EACCES） |
| 其它 | — | `-ENOTTY`（0x…e25118 的 default） |

注：`UI_DEV_SETUP`/`UI_ABS_SETUP` 用 **`cmd & 0xc000ffff`**（`and w8,w23,#0xc000ffff` @0x…e25120）比较，即 `~IOCSIZE_MASK` —— 所以 size 字段由调用者自定，因此 ABS 路径必须有独立 size 检查（见 §3）。

## 2. Q1 —— `UI_DEV_SETUP`（`struct uinput_setup`，BTF size=92：`id@0`、`name@8`(80B)、`ff_effects_max@88`）

证据链（地址即证据）：

```
0x…e2522c  sub x0, x29, #0x68            ; &setup (栈上, 92B)
0x…e25230  mov x1, x20                   ; arg
0x…e25234  mov w2, #0x5c                 ; 92 = sizeof(struct uinput_setup)
0x…e25238..0x…e25254                     ; 先把 -0x68..-0x0c 全清零（stp xzr ×5 + stur xzr）
0x…e25258  bl _inline_copy_from_user     ; 92B 全部来自用户态 → 无未初始化栈读
0x…e2525c  cbz x0 -> 0x…e252b4  else -EFAULT (-0xe)
0x…e252b4  ldurb w8, [x29, #-0x60]       ; setup.name[0]
0x…e252b8  cbz w8 -> 0x…e2544c (-EINVAL) ; 空名拒绝
0x…e252c0  ldur x8, [x29, #-0x68]; str x8, [x21, #0x18]   ; dev->id = setup.id
0x…e252c8  ldur w8, [x29, #-0x10]; str w8, [x19, #0x1d8]   ; udev->ff_effects_max
0x…e252d0  ldr x0, [x21]; bl kfree       ; kfree(旧 dev->name)
0x…e252d8  add x0, x20, #8               ; &setup.name
0x…e252dc  mov w1, #0x50                 ; ★ 长度上限 80 = UINPUT_MAX_NAME_SIZE
0x…e252e0  mov w2, #0xcc0                ; GFP_KERNEL
0x…e252e4  bl kstrndup                   ; ★ 有界拷贝 + 强制 NUL
0x…e252e8  str x0, [x21]                 ; dev->name
0x…e252ec  cbz x0 -> 0x…e25470 (-ENOMEM)
0x…e252f0  str #1, [x19, #0x30]          ; udev->state = UIST_SETUP_COMPLETE
```

- **长度**：`min(strnlen(name,80),80)+1`，`kstrndup` 语义为 `len = strnlen(s,max); memcpy(buf,s,len); buf[len]=0`，所以**最多读 80 字节**，恰好落在 92 字节栈对象的 `name[80]` 之内，不会读到 `ff_effects_max` 之后/栈残留。
- **是否强制 NUL**：是（`kstrndup` 自己补，且日志/回读路径都按 C 串用）。
- **谁把它当 C 字符串用**：`dev->name` → `input_register_device()` 把它装进 `dev->dev.kobj.name`；本驱动里另一处消费是 **`UI_GET_SYSNAME`**：
  ```
  0x…e25158/0x…e25160  ldr x23, [x0, #0x298] / [x0, #0x228]   ; 设备名指针
  0x…e25174  bl __pi_strlen                                     ; strlen(dev 名)
  0x…e2517c  add w8, w0, #1; cmp w8, w22; csinc w22, w22, w0, hs ; n = min(_IOC_SIZE, len+1)
  0x…e25198  bl __check_object_size ; 0x…e251a8 bl _inline_copy_to_user
  ```
  因为名字必定 NUL 终止，这里 `strlen` 不可能越界；`copy_to_user` 只拷 `min(size, len+1)`。**`UI_GET_SYSNAME` 本身也没有 OOB**（`size==0` 时 0x…e25170 直接 -EINVAL）。
- 结论：**kstrndup 化之后这条历史 OOB 读面已被关掉**（老代码是 `kstrdup`/`strlen` 裸读，靠 `name[0]` 兜底）。

## 3. Q2 —— `UI_ABS_SETUP`（BTF `uinput_abs_setup` size=28：`code@0`(u16)、`absinfo@4`）

```
0x…e25298  cmp w22, #0x1c ; b.ls 0x…e25308   ; ★ _IOC_SIZE(cmd) ≤ 28 才继续
0x…e252ac  mov w21, #-7                       ; 否则 -E2BIG
0x…e2529c..0x…e252a4                          ; 28B 栈槽全部清零（stur/stp 覆盖 0..0x1c）
0x…e2542c  check_object_size(setup, size, 0)
0x…e2543c  _inline_copy_from_user(setup, arg, size)   ; size 由用户定，≤28
0x…e25478  ldurh w2, [x29, #-0x68]            ; ★ code = 零扩展 u16
0x…e2547c  cmp w2, #0x3f ; b.ls 0x…e254a8     ; ★ code <= ABS_MAX(63) 无符号
0x…e25484  mov w21, #-0x22                    ; 否则 -EDOM
0x…e254a8  ldp w4, w5, [x29, #-0x60]          ; absinfo.minimum / maximum
0x…e254b0  orr w8, w4, w5 ; cbz 0x…e254c0     ; 全 0 跳过
0x…e254bc  cmp w5, w4 ; b.lt -EINVAL          ; maximum >= minimum
0x…e254c0  subs w8, w5, w4 ; b.vs 0x…e254d4   ; range = max-min（溢出则跳过）
0x…e254c8  ldur w3, [x29, #-0x54]             ; absinfo.flat
0x…e254cc  cmp w3, w8 ; b.gt 0x…e25634 (-EINVAL)
0x…e254d4  cmp w2, #0x2f ; b.ne 0x…e254e4     ; code == ABS_MT_SLOT(47) 时
0x…e254dc  cmp w5, #0x64 ; b.ge -EINVAL       ; ★ absmax < 100（保护 input_mt_init_slots 的 slots 数）
0x…e254e4  bl input_alloc_absinfo
0x…e254f4  ldurh w8, [x29, #-0x68]            ; code
0x…e25500  lsr x10, x8, #6 ; 0x…e25504 lsl x9, x9, x8   ; 字索引/位
0x…e2550c  add x11, x20, #0x98                ; dev->absbit
0x…e25518  stset x9, [x10]                    ; set_bit(code, dev->absbit)
0x…e2551c  ldurh w9, [x29, #-0x68]
0x…e25520  mov w10, #0x18 ; ldr x11, [x20, #0x148]
0x…e2552c  umaddl x9, w9, w10, x11            ; ★ &dev->absinfo[code]  (24B/项)
0x…e25530..0x…e2553c  stp/str 24B 拷贝
```

- `code` 上限是 **硬检查**（`b.ls` 无符号、`ldurh` 零扩展，`0x10000` 级别值也会被拒），所以 `absbit`（1 long = 64 位）与 `absinfo[ABS_CNT=64]` 两个下标都合法。**不存在下标/位图越界**。
- 值域：`minimum/maximum/flat` 只做 `max>=min`、`flat<=max-min` 的数学一致性检查，`value/fuzz/resolution` 完全不检查 —— 但它们只作为数据存进 `dev->absinfo[code]`（被 input 核心用于钳位），**不参与任何下标或长度计算**；唯一进入长度计算的是 `code==ABS_MT_SLOT` 的 `maximum`，被 0x…e254dc 卡到 `<100`，因此 `input_mt_init_slots(dev, max+1)` 的 slots ∈ [1,100]。
- 顺带：短 size（如 4 字节只给 code）不会读到未初始化栈 —— 28B 槽在 copy 之前已整体清零。

## 4. Q3 —— `UI_SET_*BIT`（`[0x40045564..0x4004556e]`，jump table `0xffffffc081a15358`）

每条的骨架完全一致（寄存器 `x22` = ioctl arg = 位号，**未经 get_user，直接是 64 位 arg**）：

```
cmp x22, #<MAX>          ; 无符号
mov w21, #-0x16          ; -EINVAL
b.hi  → 返回 -EINVAL     ; ★ 先判后写，没有「先 set_bit 再检查」
ldr w8, [x19, #0x30]     ; udev->state
cmp w8, #2 ; b.eq -EINVAL; ★ 已注册(UIST_CREATED)就拒绝
mov w8, #1 ; lsl x8, x8, x22
... add x9, x0, #<off> ; stset x8, [x9]    ; dev+off 上的 64 位原子置位
```

逐条核对（`x22` 上限 → `dev` 偏移 → 对应位图）：

| 块地址 | `cmp x22,#` | 偏移 | 字段 | `*_CNT` |
|---|---|---|---|---|
| 0x…e24b44 | 0x1f | +0x28 | `evbit` | 32 (1 long) |
| 0x…e24d70 | 0x7f | +0xb8 | `ffbit` | 128 (2 long，`lsr x9,x22,#6` @0x…e24d8c) |
| 0x…e24db0 | 0x1f | +0x20 | `propbit` | 32 (1 long) |
| 0x…e24de8 | 0xf | +0x90 | `relbit` | 16 (1 long) |
| 0x…e24e20 | 0xf | +0xa8 | `ledbit` | 16 (1 long) |
| 0x…e24e58 | 0x3f | +0x98 | `absbit` | 64 (1 long) |
| 0x…e24e90 | 7 | +0xb0 | `sndbit` | 8 (1 long) |
| 0x…e24ec8 | 0x2ff | +0x30 | `keybit` | 768 (12 long，`lsr x9,x22,#6` @0x…e24ee4) |
| 0x…e24f08 | 7 | — | `mscbit`(7) | 8 |
| 0x…e24f1c..0x…e24f74 | （本次未逐行展开的 2 条：`swbit` / 表内 nr=108 的死条目） | | | |

- 偏移序列 `+0x20 propbit / +0x28 evbit / +0x30 keybit(0x60 字节) / +0x90 relbit / +0x98 absbit / +0xa0 mscbit / +0xa8 ledbit / +0xb0 sndbit / +0xb8 ffbit(0x10) / +0xc8 swbit` 与 `struct input_dev` 的声明顺序、`BITS_TO_LONGS(*_CNT)` 尺寸**逐项吻合**，说明上限常量与字段一一对应，没有「拿错 MAX」。
- 多 long 位图：字索引 `x22>>6`，位偏移 `lsl x8,x8,x22`（AArch64 寄存器移位自动 `&63`）→ 语义等价 `set_bit(bit, map)`，且 `bit ≤ *_MAX` 已保证 `字索引 < BITS_TO_LONGS(*_CNT)`。
- `stset`（64 位 RMW）落在 `&map[word]`，最小数组是 1 long（8 字节），不会跨字段写。
- 补充：`cmp x22,#0x1f` 这类比较**确实是 64 位**（`cmp x22, #imm`），负数/超大 arg 走无符号 `b.hi` 一律 -EINVAL，不存在符号绕过。

## 5. Q4 —— `UI_SET_PHYS`

```
0x…e24f74  ldr w8, [x19, #0x30] ; cmp #2 ; b.eq -EINVAL   ; 已注册拒绝
0x…e24f84  mov x0, x20                                    ; arg (用户指针)
0x…e24f88  mov w1, #0x400                                 ; ★ 1024 上限
0x…e24f8c  bl strndup_user
0x…e24f94  cmn x0, #0xfff ; b.hs → 返回该错误             ; 容纳 -ENAMETOOLONG/-EFAULT/-ENOMEM
0x…e24f9c  ldr x8, [x19] ; ldr x0, [x8, #8]  ; dev->phys
0x…e24fa4  bl kfree                                       ; ★ 替换前先释放，无泄漏
0x…e24fac  str x21, [x8, #8]                              ; dev->phys = 新串
```

- 上限 1024（`strndup_user` 会 `strnlen_user` 后再按实际长度 kmalloc，且强制 NUL）；返回 ERR_PTR 时保留旧值不覆盖。
- 释放路径两条：①替换时 `kfree(dev->phys)`（0x…e24fa4）；②`uinput_destroy_device @ 0xffffffc080e25930` 内 **2 处 `kfree`**（`dev->name` / `dev->phys`）+ `input_unregister_device` / `input_free_device`（scanner 实测 bl 集合）。`uinput_release`(0x…e24a38) 与 `UI_DEV_DESTROY` 都走它，无双重释放窗口。
- 非内存安全备注：`UI_DEV_SETUP` 的 `ff_effects_max`（u32，0x…e252c8 直接写入 `udev+0x1d8`）**无上界**，`UI_DEV_CREATE` 时原样喂给 `input_ff_create`（0x…e24ffc）→ 内部 `kcalloc(max_effects, sizeof(struct ff_effect))`。只影响 FF 侧分配（溢出经 `kcalloc` 的 `array_size` 检查返回 -ENOMEM），不是 OOB；按约定 FF 面不在本次范围。

## 6. Q5 —— ashmem

### 6.1 两条入口

```
/dev/ashmem (misc)      →  Ashmem::ioctl            @ 0xffffffc080fdf1a0   (1097 insn)
memfd / shmem 路径      →  shmem_ashmem_ioctl       @ 0xffffffc08072fa08   (13 insn!)
                            0x8072fa0c  ldr x8, [x0, #0x20]        ; file->f_inode
                            0x8072fa10  ldurb w8, [x8, #-0x65]
                            0x8072fa14  tbnz w8, #6, 0x8072fa20    ; is_ashmem_file() 内联的标记位
                            0x8072fa18  mov x0, #-0x19 ; ret       ; 否则 -ENOTTY
                            0x8072fa2c  bl ashmem_memfd_ioctl(0xffffffc080102ae0)
                                        → ashmem_memfd_ioctl_inner @ 0xffffffc080fe11ec
```

`shmem_ashmem_ioctl` **只是 is_ashmem_file 门**，没有任何用户指针/长度操作；它把一切都转给 `ashmem_memfd_ioctl_inner`。后者（0xffffffc080fe11ec..0xffffffc080fe14f0，192 insn）只认 `SET_NAME/GET_NAME/SET_SIZE/SET_PROT_MASK/0x8008770b` 少数几条，且**整个函数没有 `_copy_from_user`**（scanner 实测 bl 集合：`bcmp / take_dentry_name_snapshot / release_dentry_name_snapshot / memfd_fcntl / i_size_read / capable / UserSliceWriter::write_slice / _copy_to_user`）—— 用户数据只经 dentry 名快照与 `UserSliceWriter`（带 `&mut [u8]` 长度入参）流转，**没有裸长度拷贝**。

### 6.2 `/dev/ashmem` 命令表（`Ashmem::ioctl @ 0xffffffc080fdf1a0`）

`mutex` 是 `ASHMEM_MUTEX @ 0xffffffc082977378`；`&self` 里 `+0x28=size`、`+0x30=prot_mask`、`+0x38/+0x48=name ptr/len`、`+0x50=vmfile`。

| cmd | 分派 | 关键检查 |
|---|---|---|
| `SET_NAME` 0x41007701 | 0x…fdf25c | `memset(buf,0,0x100)` @0x…fdf26c（`w2=0x100`）；`strcpy_into_buf(arg, size, buf, cap=0x100)` @0x…fdf284（`mov w3,#0x100` @0x…fdf280）；返回 `&CStr`（`ldr x23,[sp,#0x28]; cbz → 错误`）；`len = cstr_len`（`subs x21,x8,#1` @0x…fdf294），`kmalloc(len)`（0x…fdf2b8）+ `memcpy(len)`（0x…fdf2d0）→ **≤255 字节 + NUL，无溢出** |
| `GET_NAME` 0x81007702 | 0x…fdf438 | `memset(buf,0,0x100)`；`adds x21,x22,#1; b.hs → 错误`（长度+1 溢出检查 @0x…fdf460）；`cmp x22,#0xff; b.ls 0x…fdf5e0` 否则 -EINVAL（@0x…fdf468）；`memcpy` @0x…fdf5e8 + `strb wzr,[buf+len]` @0x…fdf5f4；输出走 `UserSliceWriter::write_slice` @0x…fdf608（长度 = min(size, len+1)） |
| `SET_SIZE` 0x40087703 | 0x…fdf414 → 0x…fdf540 | `ldr x8,[x19,#0x50]; cbz → 0x…fdf540`，否则 **-EINVAL**（0x…fdf428，`str -22,[x20,#4]`）；`str x22,[x19,#0x28]` @0x…fdf544 —— **size 无上界** |
| `SET_PROT_MASK` 0x40087705 | 0x…fdf3a4 | 见 §6.3 |
| `PIN` / `UNPIN` 0x40087707/0x40087708 | 0x…fdf354（`add w8,w2,0xbff788f9; cmp #2; b.lo` @0x…fdf240）→ 0x…fdf518 → 0x…fdf62c | 见 §6.4 |
| `GET_PIN_STATUS` 0x7709 | 0x…fdf2ec → 0x…fdf354 | 同上 copy 8B 后分流（`cmp w23,#0x7709` @0x…fdf520） |
| `GET_SIZE` 0x7704 | 0x…fdf218 | 读 `+0x28` → put_user |
| `GET_PROT_MASK` 0x7706 | 0x…fdf4cc | 读 `+0x30` → put_user |
| `PURGE_ALL_CACHES` 0x770a | 0x…fdf300 | `mov w0,#0x15; bl capable` @0x…fdf304 → **CAP_SYS_ADMIN**；然后 `free_lru` |
| `0x8008770b` | 0x…fdf480 | 取 `file->f_inode->i_size`（`ldr x8,[x8,#0x20]; ldr x23,[x8,#0x40]`）→ `copy_to_user(arg, &i_size, min(size,8))`（0x…fdf4b4 `mov w2,#8`；0x…fdf4ac `cmp w21,#8; b.lo`） |
| 其它 | 0x…fdf508 | `-ENOTTY`（`#-0x1a`） |

### 6.3 `ignore_unset_prot_exec` 到底绕过了哪道判定（含判定点地址）

`SET_PROT_MASK` 的完整逻辑（这就是上游 `set_prot_mask()`，被 Xiaomi 加了两个开关豁免）：

```
0x…fdf3a4  mutex_lock(inner)
0x…fdf3b0  x8 = prot = arg
0x…fdf3b4  tbz w8, #0, 0x…fdf3cc                 ; if (prot & PROT_READ)
0x…fdf3bc  ldr w9, [current, #0x6c8]             ; current->personality
0x…fdf3c0  lsr x9, x9, #0x14 ; and x9, x9, #4    ; READ_IMPLIES_EXEC (bit 22)
0x…fdf3c8  orr x8, x8, x9                        ; prot |= PROT_EXEC
0x…fdf3cc  adrp x9,  0xffffffc082977000
0x…fdf3d0  adrp x11, 0xffffffc082977000
0x…fdf3d4  ldrb w9,  [x9,  #0x364]               ; ★ IGNORE_UNSET_PROT_READ  (0xffffffc082977364)
0x…fdf3d8  ldr x10,  [x19, #0x30]                ; asma->prot_mask（已允许的集合）
0x…fdf3dc  ldrb w11, [x11, #0x360]               ; ★ IGNORE_UNSET_PROT_EXEC  (0xffffffc082977360)
0x…fdf3e0  and x12, x10, #1                      ; PROT_READ 位
0x…fdf3e4  cmp w9, #0 ; csel x9, xzr, x12, eq    ; 开关开 → 该项不计入「必须已存在」
0x…fdf3ec  and x12, x10, #4                      ; PROT_EXEC 位
0x…fdf3f0  cmp w11, #0
0x…fdf3f4  orr x8, x9, x8
0x…fdf3f8  csel x9, xzr, x12, eq                 ; ★ EXEC 项被豁免
0x…fdf3fc  orr x8, x8, x9
0x…fdf400  bics xzr, x8, x10                     ; ★★ 判定点：(prot & ~asma->prot_mask) != 0 ?
0x…fdf404  b.ne 0x…fdf428                        ; ★ 拒绝分支：ret=-EINVAL
0x…fdf408  str x8, [x19, #0x30]                  ; asma->prot_mask = prot（含 EXEC）
```

- **绕过的是**：`set_prot_mask()` 的「只能减少、不能增加」检查 —— `if ((asma->prot_mask & prot) != prot) return -EINVAL;`。
- **判定点地址**：`0xffffffc080fdf400`（`bics xzr, x8, x10`）+ `0xffffffc080fdf404`（`b.ne`），拒绝返回在 `0xffffffc080fdf428`（`[x20,#4] = -22`）。
- **开关读取/门控**：`0xffffffc080fdf3dc`（`ldrb` `0xffffffc082977360`）+ `0xffffffc080fdf3f8`（`csel`）。READ 同理，在 `0xffffffc080fdf3d4` / `0xffffffc080fdf3e8`。
- 也就是：**只有开了这个开关，uid 2000 才能把 `PROT_EXEC` 写进 `asma->prot_mask`（此前 mask 里没有 exec）**，之后 `mmap(PROT_EXEC)` 才有机会通过映射检查（注意：`Ashmem::mmap @ 0xffffffc080fdec24` 内**不读**这两个开关、也没有 EPERM 判定 —— scanner 实测 bl 集合只有 `shmem_file_setup/shmem_zero_setup/static_key_count/memset/memcpy/get_file/mutex/fput`，所以 SET_PROT_MASK 是这条链上唯一一道 exec 门）。
- 写这三个 `/dev/ashmem_*` 节点的 misc 设备方法（`0xffffffc080fddff0..0xffffffc080fde468`）里 **没有 `capable()`**（scanner 实测 bl 只有 `kstrtobool / CStr::from_bytes_with_nul / _copy_from_iter / generic_file_open / panic_bounds_check / assert_failed`），写路径是 `strb w8,[0xffffffc082977360]` 直接落字节 → 见候选 A。

### 6.4 `PIN` / `UNPIN` 的长度与范围检查（比上游更严）

```
0x…fdf518  ldp w24, w25, [sp, #0x38]      ; w24 = pin.offset, w25 = pin.len（8B 已从用户拷入）
0x…fdf51c  cmp w23, #0x7709 ...
0x…fdf354  cmp w21, #8 ; b.lo 0x…fdf374   ; ★ _IOC_SIZE(cmd) >= 8 才 copy_from_user
0x…fdf36c  bl _copy_from_user(&pin, arg, 8)
0x…fdf62c  (分配 ashmem_range, refcount)
0x…fdf6a0  ldr x8, [x19, #0x50] ; cbz → 0x…fdf768   ; 必须先有 vmfile
0x…fdf6a8  ldr x0, [x19, #0x28] ; bl page_align     ; x0 = PAGE_ALIGN(asma->size)
0x…fdf6b0  subs x8, x0, x24 ; b.lo 0x…fdf6dc        ; ★ offset > PAGE_ALIGN(size) → 拒绝
0x…fdf6b8  cmp w25, #0 ; csel x8, x8, x25, eq       ; len==0 时按 0 处理
0x…fdf6c0  orr w9, w8, w24
0x…fdf6c4  tst x9, #0xfff ; b.ne 0x…fdf6dc          ; ★ offset 与 len 必须页对齐
0x…fdf6cc  adds x9, x8, x24 ; b.hs 0x…fdf6dc        ; ★ offset+len 进位（溢出）→ 拒绝
0x…fdf6d4  cmp x0, x9 ; b.hs 0x…fdf7fc              ; ★ offset+len <= PAGE_ALIGN(size) 才继续
0x…fdf6dc  [x20,#4] = -22 ; [x20] = 1               ; -EINVAL
```

- 之后的区间树操作（`0xffffffc080fdfb00..0xfdfc90`）用的是**已经过上述校验的字节范围**推导出的页号（`pgstart/pgend` 与 `range_before/after` 比较：`cmp x24,x25 / cmp x1,x25 / cmp x24,x26 / cmp x1,x26`），因此 `pgend` 不可能越出 `PAGE_ALIGN(size)`，链表插/删（含 `LDXR/STLXR` 引用计数、`free_lru`、`shrink_range` @0x…fe02c8）都在合法节点上。
- 结论：**PIN/UNPIN 没有 OOB/UAF**；页对齐 + 上界 + 进位三重检查齐全（上游老 ashmem 缺的是上界那条）。

## 7. 候选（本次唯一两处，均**不是** OOB/UAF）

1. **权限绕过（非内存安全）· `/dev/ashmem_ignore_unset_prot_exec` 写入 + `ASHMEM_SET_PROT_MASK`**
   - 设备+命令：`write("/dev/ashmem_ignore_unset_prot_exec","1")` → `ioctl(/dev/ashmem, ASHMEM_SET_PROT_MASK(0x40087705), PROT_READ|PROT_EXEC)`
   - 证据偏移：开关 `ldrb` @`0xffffffc080fdf3dc`（字节 `0xffffffc082977360`），门控 `csel` @`0xffffffc080fdf3f8`，判定点 `0xffffffc080fdf400`，拒绝 `0xffffffc080fdf428`；写路径无 `capable()`（`0xffffffc080fddff0..0xffffffc080fde468`）。
   - 命中信号：未开开关时 `SET_PROT_MASK(PROT_READ|PROT_EXEC)` 返回 `-EINVAL(-22)`；写入 `1` 后同一调用返回 `0`（`str x8,[x19,#0x30]` 落盘），随后 `mmap(PROT_READ|PROT_EXEC)` 成功（`Ashmem::mmap` 内无 exec 判定）。
   - reclaim 是否可用 uhid/AF_UNIX/`UI_SET_PHYS`：**不适用** —— 不是堆/池对象生命周期问题，没有可被 reclaim 的释放对象。
   - 剩余不确定：SELinux 是否放行该节点 write（上游只实测了 open/ioctl）；本次按约定未写设备。

2. **低置信 DoS（非 OOB）· `ASHMEM_SET_SIZE` 无上界 → Rust 溢出检查 panic**
   - 设备+命令：`ioctl(/dev/ashmem, ASHMEM_SET_SIZE(0x40087703), 0xffffffffffffffff)` → 随后 `mmap` 或 `PIN`
   - 证据偏移：`str x22,[x19,#0x28]` @`0xffffffc080fdf544`（无任何比较）；消费点 `bl page_align` @`0xffffffc080fdf6ac`（PIN/UNPIN 校验里 `PAGE_ALIGN(asma->size)`）；`Ashmem::mmap @ 0xffffffc080fdec24` 的 bl 集合含 `panic_const_shl_overflow`/`panic_const_sub_overflow`，`Ashmem::ioctl` 含 `panic_const_add_overflow`/`panic_const_sub_overflow`。
   - 命中信号：`page_align(usize::MAX)` 在 `overflow-checks` 打开时走 `panic_const_add_overflow` → kernel panic；叠加 `CONFIG_PANIC_ON_OOPS=y` 即整机重启。
   - 未验证点：本 build 是否真的启用 Rust `overflow-checks`（有 `bl` 到 panic_const_* 只能说明可达，不等于必然 panic）；且 `SET_SIZE` 要求 `vmfile == NULL`、`PIN/UNPIN` 要求 `vmfile != NULL`，两者互斥，只剩 mmap 路径可能触发。
   - reclaim：不适用。

## 8. 没有找到的东西（明确排除，及为什么不可能）

- **uinput 非 FF 面**：不存在「拷贝长度来自 ioctl 调用方」的裸 `copy_from_user`（DEV_SETUP 固定 0x5c、ABS_SETUP 有 `size ≤ 0x1c` 上限、`SET_PHYS` 走 `strndup_user(1024)`）；不存在「先写后判」的位图置位；不存在落到 `udev->requests[]`/位图的未校验索引（`cmp w8,#0xf` @0x…e24c10、0x…e24c90、0x…e25028 都是 FF 请求 id，在 FF 面）；`dev`/`udev` 生命周期由 `mutex` + `state` + 入口懒分配 + `uinput_destroy_device` 单一释放点约束，`UI_DEV_CREATE/DESTROY` 反复调用只会在 state 机上打转，没有 double-free 窗口。
- **ashmem**：Rust 重写版把所有用户数据流集中在 `UserSliceReader/Writer` 与 `strcpy_into_buf`，`SET_NAME` 的 0x100 容量与 `GET_NAME` 的 `len+1` 溢出检查是真边界；`PIN/UNPIN` 三重范围检查到位；`is_ashmem_file` 门（`0x8072fa10`）保证 memfd 路径不会误进 ashmem 逻辑。
- 因此**没有可供 uhid / AF_UNIX / `UI_SET_PHYS` 做 reclaim 的 UAF**：本次范围内不存在「先 free 再在别处解引用」的对象。

## 9. 复现命令

```powershell
$py = 'C:\Users\user\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe'
$e  = 'runs\android\rom\vmlinux-4.0.21.0.elf'
$i  = 'runs\android\rom\Image-4.0.21.0.bin'

# 结构布局
& $py runs\android\rom\btf_dump.py $i uinput_setup uinput_abs_setup input_absinfo

# uinput：全函数（含命令常量/边界比较/端点表）
& $py runs\android\rom\kdisasm.py $e $i uinput_ioctl_handler 300
# DEV_SETUP 体 / ABS_SETUP 体 / SET_PHYS / 位图族
& $py %TEMP%\ua_scan.py $e $i 0xffffffc080e2522c 0xffffffc080e25300 --raw   # DEV_SETUP
& $py %TEMP%\ua_scan.py $e $i 0xffffffc080e25400 0xffffffc080e254d8 --raw   # ABS 校验
& $py %TEMP%\ua_scan.py $e $i 0xffffffc080e24f60 0xffffffc080e25120 --raw   # SET_PHYS/位图
& $py %TEMP%\ua_scan.py $e $i 0xffffffc080e24a70 0xffffffc080e25930          # 汇总

# ashmem
& $py %TEMP%\ua_scan.py $e $i 0xffffffc080fdf1a0 0xffffffc080fe02c8          # 命令表
& $py %TEMP%\ua_scan.py $e $i 0xffffffc080fdf3a0 0xffffffc080fdf4e0 --raw   # SET_PROT_MASK(exec 判定)
& $py %TEMP%\ua_scan.py $e $i 0xffffffc080fdf650 0xffffffc080fdf724 --raw   # PIN/UNPIN 范围
& $py %TEMP%\ua_scan.py $e $i 0xffffffc08072fa08 0xffffffc08072fb48 --raw   # shmem_ashmem_ioctl
& $py %TEMP%\ua_scan.py $e $i 0xffffffc080fe11ec 0xffffffc080fe14f0          # memfd inner
& $py %TEMP%\ua_scan.py $e $i 0xffffffc080fddff0 0xffffffc080fde468          # toggle 设备方法
```

（`ua_scan.py` = 临时分析脚本：命令值/`bl` 目标/`cmp`+条件分支/adrp 窗口 + 可选 `--raw`；`ua_callers.py` = 全镜像 BL 目标扫描，用于确认 `AshmemToggle*::get` 无 BL 调用点 ⇒ 开关是内联 `ldrb` 读取，故判定点必须按字节地址找。）

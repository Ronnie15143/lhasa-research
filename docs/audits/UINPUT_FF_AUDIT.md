# `/dev/uinput` force-feedback 上传/擦除路径静态审计（lhasa / 6.18.21）

对象镜像：`runs/android/rom/vmlinux-4.0.21.0.elf` + `Image-4.0.21.0.bin`
（`text_offset=0`，`file_off = addr - 0xffffffc080000000`）
BTF：`runs/android/rom/btf_dump.py Image-4.0.21.0.bin <struct>`
内核：`6.18.21-android17-5-g284297031c53`，4K 页，`CONFIG_RANDSTRUCT_NONE=y`（**无字段随机化**，
所以 BTF 偏移 = 上游字段语义，下面的偏移可以直接当源码结构体读）
本次只做静态反汇编 + 既有只读证据（`slabinfo.txt`、`config.extracted.txt`、`UAF_HUNT_SHORTLIST.md`），
未写设备、未 fuzz、未跑 exploit。以下每一条结论都带指令地址（`符号+偏移`）或 BTF 偏移。

---

## 0. 结论速览

| # | 审计项 | 结论 | 性质 |
|---|---|---|---|
| 1 | `uinput_ff_upload_from_user` 的长度/`type`/`u` 联合体校验 | **干净**：定长拷贝，native `0x68`、compat `0x60`，union 固定 32B，没有任何按 `type` 决定拷贝/解引用长度的路径；`udev->ff_effects[]` 这个数组在本内核**不存在** | 无 OOB |
| 2 | `ff->effects[id]` / `ff->max_effects` 边界 | **干净**：`id` 以 s16 读入，`-1` 走分配、其余强制 `id < max_effects`；`max_effects` 在 `input_ff_create` 里被钳到 `[1,96]`；erase 一个从未 upload 的 id 直接 `-EINVAL`，不产生 request | 无 OOB |
| 3 | close(fd) 与未完成 FF request 的生命周期 | **有缺陷（本次唯一候选）**：request 结构体在调用者栈上，`udev->requests[id]` 存其地址；`uinput_release` 只 `flush`（complete）就 `kfree(udev)`，**不等投递方从 `wait_for_completion_timeout` 回来**，投递方随后在 `udev` 已释放的内存上取自旋锁、写 `requests[id]=NULL`、`__wake_up()` | **UAF**（写 + wait_queue 走查） |
| 4 | erase 次序 / `ff_effects` 元素二次释放 | **干净**：`ff->mutex` 覆盖 `ff->erase()` 全程，`effect_owners[id]=NULL` 在 erase 成功之后；`ff->effects` 是整块 `kcalloc`，元素从不单独 free | 无双重释放 |
| 5 | 可利用性 | 真实但**未武器化**：窗口在 `complete()`→`kfree(udev)` 之间，reclaim 桶是 `kmalloc-1k`（order-3，32 obj/slab）。好消息是 KASAN 运行期关闭（`kasan=off`，CPU 无 `mte`）⇒ 不回收也不报警、不 panic；坏消息是 `__wake_up()` 走查需要**内核地址泄漏**才能变成任意调用，目前没有 | 待验证 |

一句话：**上传/擦除的数据通路本身（解析、边界、擦除次序）查下来是干净的；问题出在 3. ——
`uinput_release` 与阻塞中的 FF request 之间没有"排水"**。

---

## 1. 结构与 ioctl 基线（后面全部地址都挂在这上面）

### 1.1 BTF 精确布局（`btf_dump.py`，本 build 实测）

```
struct uinput_device  size=640 (0x280)        struct uinput_request size=64
  +0    dev                                    +0    id
  +8    mutex (40)                              +4    code       (1=FF_UPLOAD 2=FF_ERASE)
  +48   state   (0=NEW 1=SETUP_DONE 2=CREATED)  +8    retval
  +56   waitq                                   +16   done (struct completion, 32)
  +80   ready                                   +48   u (16)
  +81   head      <-- 生产者索引                +0x30   u.upload.effect
  +82   tail      <-- 消费者索引                +0x38   u.upload.old
  +88   buff[16] (struct input_event ×16, 24B, 0x58..0x1d8)
  +472  ff_effects_max (0x1d8)
  +480  requests[16]  (0x1e0..0x260)
  +608  requests_waitq (0x260)
  +632  requests_lock  (0x278)

struct ff_device size=136            struct ff_effect size=48        struct uinput_ff_upload size=104
  +0   upload                        +0  type                        +0  request_id
  +8   erase                         +2  id                          +4  retval
  +16  playback                      +4  direction                   +8  effect (48)
  +24  set_gain                      +6  trigger                     +56 old    (48)
  +32  set_autocenter                +10 replay
  +40  destroy                       +16 u (32, 8 字节对齐)
  +48  private                       +0x30 u.periodic.custom_data
  +56  ffbit                         (u.periodic 32B, u.condition 2×8B, u.rumble 4B)
  +72  mutex (40)
  +112 max_effects (0x70)
  +120 effects    (0x78)
  +136 effect_owners (0x88, 内联在 ff_device 尾部)
struct uinput_ff_erase size=12      struct uinput_setup size=92
  +0 request_id +4 retval +8 effect_id   +0 id(8) +8 name[80] +88 ff_effects_max
```

**关键否定证据**：`uinput_device` 里**没有** `ff_effects` 数组，只有 `ff_effects_max`（u32）。
effect 本体活在 `ff_device.effects`（ff-device+0x78），由 ff-core 独占管理。
所以"uinput 在 `input_ff_upload()` 之前先写 `udev->ff_effects[*]`"这类缺陷在本 build **结构上不存在**。

### 1.2 `uinput_ioctl_handler`（0xffffffc080e24a70）分发表

入口 `0x...e24ad0` 就 `mutex_lock_interruptible(&udev->mutex)`（`+8`），全函数持 `udev->mutex`，
`0x...e253e0` 统一 `mutex_unlock`。⇒ **UI_BEGIN/END_FF_* 都在 `udev->mutex` 内**（对第 3 条很关键）。
`cmd-0x40045564 ≤ 10` 走跳表 `@0xffffffc081a15358`（基址 `adr` @`0x...e24b30`），实测解出：

| cmd | 语义 | handler |
|---|---|---|
| `0x40045564`..`0x4004556e` | `UI_SET_{EV,KEY,REL,ABS,MSC,LED,SND,FF,SW,PROP}BIT` | 跳表 11 项 → `+0xd0,+0x454,+0x374,+0x3e4,+0x494,+0x3ac,+0x41c,+0x2fc,-EINVAL,+0x4cc,+0x33c` |
| `0x4008556c` | `UI_SET_PHYS`（`_IOW('U',108,char*)`） | `0x...e24f74` |
| `0x5501` | `UI_DEV_CREATE` | `0x...e24fcc` |
| `0x5502` | `UI_DEV_DESTROY` | `0x...e24bb0` → `uinput_destroy_device` |
| `0x405c5503` | `UI_DEV_SETUP`（92B） | `0x...e24fb8` → 体 `0x...e2522c` |
| `0x8004552d` | `UI_GET_VERSION` | `0x...e250a4` |
| `0xc06855c8` | `UI_BEGIN_FF_UPLOAD`（104B） | `0x...e2500c` |
| `0x406855c9` | `UI_END_FF_UPLOAD`（104B） | `0x...e24d04` |
| `0xc00c55ca` | `UI_BEGIN_FF_ERASE`（12B） | `0x...e24c70` |
| `0x400c55cb` | `UI_END_FF_ERASE`（12B） | `0x...e24bf0` |

---

## 2. 审计项 1：`UI_FF_UPLOAD` 的分发与 user-copy

### 2.1 `uinput_ff_upload_from_user`（0x...e25b30）逐指令

函数签名 `(const char __user *buf /*x0*/, struct uinput_ff_upload *dst /*x1*/)`，进去先判
`TIF_32BIT`（`mrs x8, sp_el0; ldr x9,[x8]; tbnz w9,#0x16` = `in_compat_syscall()`，`0x...e25b50-0x...e25b5c`）：

* **64 位路径**（`0x...e25b60-0x...e25b70`）：`_inline_copy_from_user(x1, x0, 0x68)`
  = `sizeof(struct uinput_ff_upload)` = `4+4+48+48 = 104`。定长，与 `effect->type` 无关。
* **32 位路径**（`0x...e25b78-0x...e25ba0`）：先把 `sp+8..sp+0x68` 清零（`0x...e25b88-0x...e25b9c`），
  再 `_inline_copy_from_user(sp+8, buf, 0x60)` = **96** = `8 + 44 + 44` = compat 版
  （32 位 `ff_effect` 里 `custom_data` 是 4 字节指针，所以 `ff_effect_compat = 44`），
  然后按字段散射回 dst（`0x...e25bb0-0x...e25bfc`）。散射的位移差正好把 `0x34` 之后的 4 字节洞补掉：
  `dst[0..0x34] ← src[0..0x34]`，`dst[0x38+i] ← src[0x34+i]`（`0x...e25bdc` 起 `ldur x8,[sp,#0x3c]` /
  `ldur x10,[sp,#0x44]` / `stp x8,x10,[x19,#0x38]`）。`old` 尾部 4 字节读的是已清零的栈
  （`ldr w9,[sp,#0x64]` @`0x...e25be0`）⇒ 不会把内核栈残留拷贝进内核结构。

两条路径都是**编译期定长**：没有任何 `switch (effect->type)` 去决定"要不要多拷一点 union"。
`u` 联合体在 `ff_effect` 里是固定的 32B 字段（`+0x10`），`ff_periodic_effect` 的
`custom_data`（`u+0x18`/`+0x20`）只在 `ff_periodic + FF_CUSTOM` 时才有意义，而那条路径被下面 2.2 直接拒掉。

### 2.2 ff-core 侧的 `type` / `waveform` 校验（`input_ff_upload` 0x...e19c24）

```
0x...e19c3c  ldr  x21,[dev+0xf8]        ; ff = dev->ff
0x...e19c40  tbnz w8,#0x15  (dev+0x28)  ; test_bit(EV_FF, dev->evbit) 否则 -ENODEV
0x...e19c54  sub  w9,w8,#0x58 ; cmn w9,#9 ; b.lo -EINVAL   ; type ∈ [0x4F,0x57]（FF 效果类型区间）
0x...e19c60  ldr  x9,[dev+0xc0] ; lsr x9,x9,(type&0x1f) ; tbz #0 → -EINVAL
                                        ; test_bit(type, dev->ffbit)（ffbit 在 input_dev+0xb8，word1=0xc0）
0x...e19c70  cmp  w8,#0x51 (FF_PERIODIC)
0x...e19c78  ldrh w9,[effect+0x10]      ; u.periodic.waveform
0x...e19c7c  sub  w10,w9,#0x5e ; cmn w10,#6 ; b.lo -EINVAL ; waveform ∈ [0x58,0x5D]
0x...e19c88  test_bit(waveform, dev->ffbit)
0x...e19c9c  cmp  w8,#0x50 (FF_RUMBLE) + test_bit(type, ff->ffbit[0x38])
0x...e19cdc  ; 厂商/新版行为：满足条件时把 FF_RUMBLE 原地改写成 FF_PERIODIC(sine)
             ldrh w8,[effect+0x12] (weak) ; ldrh w10,[effect+0x10] (strong)
             0x...e19cec  stur xzr,[effect+0x16] ; 0x...e19cf8 stur wzr,[effect+0x1e]
             0x...e19d04  str  w11(0x0032005a),[effect+0x10]
             0x...e19d08  strh w10(0x51),[effect]        ; type = FF_PERIODIC
             0x...e19d14  strh w8,[effect+0x14]          ; u.periodic.period
```

**这条 RUMBLE→PERIODIC 改写写的是 `x1`（调用者传进来的 `struct ff_effect *`）**，
在 `ff->upload()` 之前，**不写任何 uinput 侧数组**（`input_ff_upload` 里第一次碰 `ff->effects` 在
`0x...e19de4`，而且是按 `id*0x30` 索引的写，不是 FF 上传前的预写）。
改写只动 `u+6..u+0x12`（`0x...e19cec`/`0x...e19cf8`）和 `+0x10/+0x14`，都在 32B union 内，不越过 `ff_effect`。

### 2.3 `uinput_dev_upload_effect`（0x...e25c34）

```
0x...e25c50  ldrh w8,[effect]            ; type
0x...e25c54  ldr  x0,[dev+0x2c0]         ; udev = input_get_drvdata(dev)
0x...e25c58  cmp  w8,#0x51 ; ldrh w8,[effect+0x10] ; cmp w8,#0x5d ; → -EINVAL
                                         ; 拒 FF_PERIODIC+FF_CUSTOM（custom_data 是用户指针）
0x...e25c74  stp  x1,x2,[sp,#0x38]        ; request(=sp+8)+0x30 = effect, +0x38 = old
0x...e25c8c  str  w8(1),[sp,#0xc]         ; request->code = FF_UPLOAD
0x...e25c90  bl   uinput_request_submit(udev, request=sp+8)
```

request 结构体（64B）**在栈上**，`u.upload.effect`/`u.upload.old` 是**指针**，指向
调用者（evdev ioctl 的栈帧）和 `ff->effects[id]`。

### 2.4 结论（项 1）

* 长度校验：定长（104 / compat 96），无 `type` 相关尺寸，无绕过点。
* 联合体：固定 32B，读写都在 `ff_effect` 内；`custom_data` 的 `FF_CUSTOM` 组合被 `0x...e25c6c` 拒绝。
* "`input_ff_upload()` 之前先写 `udev->ff_effects[*]`"：**该数组不存在**（见 §1.1），不成立。

---

## 3. 审计项 2：`ff->effects[id]` / `max_effects` 边界

### 3.1 `input_ff_upload`（0x...e19c24）对 `id` 的四道闸

```
0x...e19d30  ldrsh w24,[effect+2]        ; id 按 s16 读（id ∈ [-32768,32767]）
0x...e19d38  cmn   w24,#1 ; b.eq 0x...e19d74      ; id == -1 → 分配新 id
0x...e19d40  tbnz  w24,#0x1f → 0x...e19e8c        ; 其它负数 → -EINVAL
0x...e19d44  ldr   w9,[ff+0x70]                   ; max_effects
0x...e19d48  cmp   w9,w24 ; b.le 0x...e19e8c      ; max_effects <= id → -EINVAL   ← 边界在这里
0x...e19d54  ldr   x9,[ff+0x88+id*8]              ; effect_owners[id]
0x...e19d58  cbz   x9 → -EINVAL                    ; 未占用 → -EINVAL
0x...e19d64  cmp   x9,file ; b.eq ok ; → -EACCES   ; 别人的 effect
分配路径：
0x...e19d74  ldr w8,[ff+0x70] ; b.lt 0x...e19da0  ; max_effects < 1 → -ENOSPC(-0x1c)
0x...e19d84  add x9,ff,#0x88 ; loop i<max_effects: ldr x10,[x9+i*8] ; cbz → found
0x...e19dac  strh w24,[effect+2]                   ; effect->id = 分配到的 id
0x...e19db0  ldr x8,[ff+0] ; CFI 校验 ; 0x...e19dcc blr x8     ; ff->upload(dev,effect,old=NULL)
0x...e19dd4  spin_lock(&dev->event_lock @+0x1f0)               ; 0x...e19ddc
0x...e19de4  smaddl x8,w24,0x30,ff->effects                   ; &ff->effects[id]
0x...e19dec  ... 48 字节复制 ...                                ; 0x...e19de0-0x...e19e00
0x...e19e0c  cmp  id,max_effects ; b.hs 0x...e19e4c (brk #0x5512 = BUG)
0x...e19e20  str  file,[ff+0x88+id*8]                          ; effect_owners[id] = file
```

`ldrsh` + `b.le`（有符号）⇒ `id ∈ [0, max_effects)` 是强制的；`ff->effects[id]`（步长 `0x30`）
和 `effect_owners[id]` 两步都在这之后。`0x...e19e4c` 的 `brk #0x5512` 是不可达的防御性 BUG。

### 3.2 `input_ff_erase`（0x...080064c）+ worker（0x...08006cc）

`input_ff_erase` 只是 `mutex_lock(&ff->mutex)` → worker → `mutex_unlock`（`0x...0800684` /
`0x...0800694` / `0x...08006ac`）。worker：

```
0x...08006e8  tbnz w1,#0x1f → -EINVAL          ; effect_id < 0
0x...08006f0  ldr  w8,[ff+0x70] ; cmp w1,w8 ; b.ge → -EINVAL   ; effect_id >= max_effects
0x...0800700  ldr  x9,[ff+0x88+id*8] ; cbz → -EINVAL           ; 未 upload 过
0x...080070c  cmp  x9,file ; b.eq ok ; → -EACCES
0x...0800754  spin_lock(&dev->event_lock)
0x...0800758  ldr  x8,[ff+0x10]  ; CFI(check) ; 0x...0800788 blr x8   ; ff->erase(dev,id)
0x...080078c  cmp  w22,max_effects ; b.hs → 0x...0800828
0x...08007ac  str  xzr,[ff->effect_owners + id*8]              ; 成功后清 owner
```

### 3.3 `input_ff_create`（0x...e1a010）——`max_effects` 怎么定

```
0x...e1a030  cbz  w1 → -EINVAL                      ; max_effects == 0
0x...e1a038  cmp  w1,#0x61 ; b.hs → 0x...e1a1a8     ; max_effects >= 0x61(97) → -EINVAL
0x...e1a044  add  w21,(max*8)+0x88                  ; ff_device 单块 = 136 + max_effects*8
0x...e1a054  bl   __kmalloc_noprof(GFP_KERNEL|ZERO) ; ff_device（effect_owners 内联在 +0x88）
0x...e1a064  lsl  w0,(max*3)<<4 = max*48 ; 0x...e1a070 __kmalloc_noprof  ; ff->effects
0x...e1a080  str  x0,[ff+0x78]                      ; ff->effects
0x...e1a0a8  str  w22,[ff+0x70]                     ; ff->max_effects = max
0x...e1a0b8  adr  x8,input_ff_flush  ; 0x...e1a0c8 stp x8,x10,[dev+0x1d8]  ; dev->flush, dev->event
0x...e1a0cc  orr  / str [dev+0x28]                  ; set_bit(EV_FF, dev->evbit)
0x...e1a0dc  bl   _find_next_bit(dev->ffbit...)     ; ffbit 初始化循环，`cmp w0,#0x7f` @0x...e1a0e0 有界
```

⇒ `max_effects ∈ [1,96]`，`ff->effects` 最大 `96*48 = 4608` 字节（`kmalloc-8k` 档），
`ff_device` 最大 `0x88+768 = 904` 字节（`kmalloc-1k` 档）。
`udev->ff_effects_max` 的唯一写入点是 `UI_DEV_SETUP` 体：`0x...e252c8 ldur w8,[x29,#-0x10]` →
`0x...e252cc str w8,[udev+0x1d8]`（`uinput_setup.ff_effects_max` 在 92 字节结构体的 +0x58）。
`UI_DEV_SETUP` 在 `state == UIST_CREATED(2)` 时直接 `-EINVAL`（`0x...e24fb8-0x...e24fc0`），
所以 `ff_effects_max` 只能在 create 之前定，`input_ff_create` 拿到的是快照，后续改不动 `ff->max_effects`。

### 3.4 结论（项 2）

* `id >= max_effects` **没有漏检**（upload 与 erase 两条路都是 `b.le`/`b.ge` 先拦）。
* `max_effects` 由用户经 `UI_DEV_SETUP.ff_effects_max` 决定，但被 `input_ff_create` 钳到 `[1,96]`，
  两块分配尺寸都随之有界。
* **erase 一个从未 upload 过的 id**：`ff->effect_owners[id] == NULL` → `-EINVAL`
  （`0x...0800700`），**不分配 request、不进 `uinput_dev_erase_effect`、不改任何状态**。
  既不会 free 任何东西，也不会留下半个 request。

---

## 4. 审计项 3：生命周期 —— 唯一候选（UAF）

### 4.1 三条事实链

**(a) request 在栈上，slot 只存地址**
`uinput_dev_upload_effect` 在 `sp+8` 上构造 64B request（`0x...e25c78-0x...e25c8c`），
`uinput_dev_erase_effect` 同样（`0x...e25cf4-0x...e25d10`，`u.effect_id` 写 `0x...e25cfc`，`code=2` 写 `0x...e25d10`）。
`uinput_request_alloc_id`（0x...e262d4）扫 16 个空位，`0x...e263f4 str w8,[request]`（`request->id = id`）、
`0x...e263f8 str x20,[udev+0x1e0+id*8]`（**把栈地址存进 udev**）。id 恒在 0..15。

**(b) 投递方在等待期间不持任何锁**

```
uinput_request_submit(udev, request)  0x...e260d0
  0x...e260d0..0x...e26164  alloc_id（失败则 wait_event_interruptible(&udev->requests_waitq) 重试）
  0x...e26168  mutex_lock_interruptible(&udev->mutex)
  0x...e26178  ldr w8,[udev+0x30] ; cmp #2 ; b.ne → -ENODEV      ; 必须 UIST_CREATED
  0x...e2619c  reinit_completion(&request->done)（done=0 @+0x10, swait 头 @+0x18）
  0x...e261bc  ldrb w8,[udev+0x51](head) ; cmp #0x11 ; b.hs 0x...e262cc → brk #0x5512（BUG/panic，不是静默丢弃）
  0x...e261f8  umaddl x10,w8,0x18,udev   ; &udev->buff[head]
  0x...e26204  strb (head+1)&0xf,[udev+0x51]
  0x...e26208/0x...e26210/0x...e26218  buff[head] = {EV_UINPUT(0x101), request->code, request->id}
  0x...e26220  __wake_up(&udev->waitq, 1, 1, NULL)
  0x...e26228  mutex_unlock(&udev->mutex)          ← 之后不再持有 udev->mutex
  0x...e26234  wait_for_completion_timeout(&request->done, 7500ms)  ← 阻塞点（不可中断）
  0x...e26238  cbz → -ETIMEDOUT(0x...e2625c)
  0x...e2623c  ldr w21,[request+8]                 ; request->retval
释放段（全部路径都走这里）：
  0x...e26260  ldr  w20,[request]                  ; id
  0x...e26268  _raw_spin_lock(udev+0x278)          ← **①**
  0x...e2626c  cmp  w20,#0x10 ; b.hs 0x...e262cc (brk #0x5512)
  0x...e2627c  str  xzr,[udev+0x1e0+id*8]          ← **②  8 字节写 0**
  0x...e26280  _raw_spin_unlock(udev+0x278)
  0x...e26294  __wake_up(udev+0x260, TASK_NORMAL, 1, NULL)  ← **③ 走查 freed list_head**
```

**(c) `uinput_release` 不排水**

```
uinput_release  0x...e24a38
  0x...e24a48  ldr x19,[file+0x18]        ; udev = file->private_data
  0x...e24a50  bl  uinput_destroy_device
  0x...e24a58  bl  kfree(udev)            ← 无条件释放，没有任何 "等 pending request 收尾"

uinput_destroy_device  0x...e25930
  0x...e25948  ldr w8,[udev+0x30] ; 0x...e2594c str wzr,[udev+0x30]     ; state = NEW
  0x...e2595c  cmp w8,#2 ; b.ne 0x...e25b00                            ; 只有 CREATED 才 flush
  0x...e25968  _raw_spin_lock(udev+0x278)
  0x...e2596c..0x...e25ae8  16 个 slot 循环：若 requests[i] 非空 →
                              str w9(-0x13 = -ENODEV),[req+8] ; complete(&req->done)
                             **注意：循环里没有 requests[i] = NULL**
  0x...e25af0  _raw_spin_unlock(udev+0x278)
  0x...e25af8  input_unregister_device(udev->dev)
  0x...e25b0c / 0x...e25b14  kfree(name) / kfree(phys)
```

### 4.2 缺陷

`complete()` 在 `uinput_destroy_device` 里把投递方（线程 B）唤醒，**但 B 还要回到
`0x...e26268` 去锁 `udev->requests_lock`**；而此时线程 A（close）已经继续往下走到
`0x...e24a58` 的 `kfree(udev)`。B 的 **release 段完全跑在可能已释放的 `udev` 上**：

* ① `_raw_spin_lock(udev+0x278)`：对 freed 内存取 qspinlock（无 `CONFIG_DEBUG_SPINLOCK`，
  不会 bad-magic panic；若回收成 0，则成功并**把 1 写进回收对象的 +0x278**）。
* ② `str xzr,[udev+0x1e0+id*8]`（`id ∈ [0,15]` → 覆盖 `udev+0x1e0..0x258`）：
  **定址 8 字节写 0 到 freed 对象**。
* ③ `__wake_up(&udev->requests_waitq @+0x260, 3, 1, NULL)`：
  把 `udev+0x260` 当 `wait_queue_head_t`（`lock@+0x260`、`head@+0x268`）走
  `list_for_each_entry_safe`，并对每个 entry 调 `curr->func(curr, mode, wake_flags, key)`
  （`wait_queue_entry.entry` 在 +0x18）。**如果回收内容可控，这就是任意内核调用/写原语**。

补充一点（同一根因的第二个面）：flush 不清 slot，所以 `complete()` 之后到 B 自己清 slot 之前，
`udev->requests[id]` 仍指向 B 的栈帧；这段时间里第三个线程发 `UI_BEGIN_FF_UPLOAD`
（`0x...e25038` 取指针 → `0x...e25050/0x...e2507c` 解 `u.upload.effect/old`）拿到的还是"活的但马上要被覆盖"的栈帧。
这条不如 ①②③ 直接，但同样是"没有所有权/引用"的表现。

### 4.3 触发序列（项 5 的"几次 ioctl"与前置条件）

必须先把 FF 能力打开，否则 `input_ff_upload` 在 `0x...e19c6c`（`test_bit(type, dev->ffbit)`）
就 `-EINVAL`：**`input_ff_create` 填的是 `ff->ffbit`（`ff+0x38`），不是 `dev->ffbit`**，
`dev->ffbit` 只能由 `UI_SET_FFBIT` 写（`0x...e24d6c`：`cmp arg,#0x7f` 有界，`stset` 到 `dev+0xb8+(arg>>6)*8`）。

| # | 动作 | 参数要点 |
|---|---|---|
| 1 | `open("/dev/uinput")` | 得 uinput_fd（`kzalloc(0x280)`，`__kmalloc_cache_noprof` @`0x...e24978`） |
| 2 | `ioctl(UI_SET_FFBIT, 0x50)` | 至少要开 `FF_RUMBLE`(0x50) / `FF_PERIODIC`(0x51) 等要 upload 的 type |
| 3 | `ioctl(UI_DEV_SETUP, &setup)` | `0x405c5503`，92B，`name[0] != 0`（`0x...e252b8`），`ff_effects_max ∈ [1,96]` |
| 4 | `ioctl(UI_DEV_CREATE)` | `0x5501`，`state` 1→2，`input_ff_create(dev, ff_effects_max)`（`0x...e24ffc`） |
| 5 | `open("/dev/input/eventN")` | 新节点的权限/SELinux 是**唯一未实测的前置条件**（见 §7-1） |
| 6 | **线程 B**：`ioctl(event_fd, EVIOCSFF, &ff_effect)` | `id = -1`，type 已开；进 `ff->upload` → 阻塞 7.5s |
| 7 | **线程 A**：`close(uinput_fd)` | `uinput_release` → flush + `kfree(udev)` |

即 **3 个 uinput ioctl + 1 个 EVIOCSFF + 1 次 close**。不需要 `UI_DEV_DESTROY`，
也不需要 `UI_SET_EVBIT(EV_FF)`（`input_ff_create` 会 `set_bit(EV_FF,...)`，`0x...e1a0cc`）。

### 4.4 可利用性判断

**窗口**：`complete()`（在 `uinput_flush_requests` 的 spinlock 内）→ `kfree(udev)`。
两者之间隔着 `input_unregister_device()`（`0x...e25af8`）+ 两次 `kfree`。B 必须在
`input_unregister_device` 全程都拿不到 CPU，才能踩到已释放内存。可控手段有限（uid 2000 不能改优先级），
把 A/B 绑到同一 CPU 是唯一"看起来能赢"的写法，但 `input_unregister_device` 内部会睡眠（device_del 一类），
一旦睡眠 B 就会在这之前跑完。⇒ **这是真缺陷，但不是稳定可复现的窗口**，需要实测。

**回收桶**：`udev` = 640B → `kmalloc-1k`。本机 `slabinfo.txt` 实测
`kmalloc-1k 8854/8960 obj, objsize 1024, 32 obj/slab, 8 pages/slab`（order-3），
`CONFIG_SLAB_FREELIST_HARDENED=y`（freelist 指针落在对象中部，`udev+0x200` 附近，不碰
`requests_lock@0x278` / `requests_waitq@0x260` / `head@0x51`），`CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`
（新分配先清零 ⇒ 零回收不会 panic，只是把一个空 wait_queue 走一遍就返回）。

**给定的两个原语都不在这个桶**：`/dev/uhid` 的 `kmemdup` 是 256B（order-1 `kmalloc-256`），
`send(AF_UNIX, 11872)` 是 8192B 档。要在 `kmalloc-1k` 拿"内容可控"，**同一个驱动的
`UI_SET_PHYS` 就是现成的一个**：`0x...e24f8c bl strndup_user(buf, 0x400)` →
`~len+1` 字节 `kmalloc`（`GFP_USER`，**不带 `__GFP_ACCOUNT`** ⇒ 落普通 `kmalloc-1k` 而非 `kmalloc-cg-1k`），
`len = 1023` 时正好 1024B，前 640 字节内容全可控（唯一约束：不能含 `\0`）。
用 N 个 uinput_fd 各 spray 一次即可（`state != CREATED` 才允许，`0x...e24f7c`）。

**命中信号**：
1. 零回收且不 panic（`kasan=off`，见下）⇒ 唯一可观测是"KASAN 关、DEBUG_SPINLOCK 关"下**没有信号**——
   这正是危险点：静默。
2. 回收成 `head.next != &head` ⇒ `__wake_up` 走查 → 要么 `curr->func` 崩（`Unable to handle kernel
   paging request` / `BUG: ...`）→ 因 `CONFIG_PANIC_ON_OOPS=y` **立即 panic**；这就是最实用的命中信号
   （但代价是设备重启）。
3. `/sys/kernel/slab/kmalloc-1k/`（或 `slabinfo`）里 `active_objs` 掉一格、以及
   `udev+0x1e0+id*8` 被写 0 这一"无害副作用"本身可以用来**标定窗口是否命中**（写 0 落在回收对象里，
   仅当我们能读回该对象时可见）。
4. 最干净的标定办法：把 reclaim 内容造成"空 wait_queue"（`head.next = head.prev = &head`，
   且 `requests_lock = 0`）——命中时**不崩**，但回收对象 `+0x1e0+id*8`（`id` 可由线程 B 决定）
   会被清 0，配合一个能读回的回收对象即可确认。

**为什么现在还打不穿**：③ 要变成任意调用，需要 `head.next` 指向一个"我们知道的地址"，
其 `+0x10` 处是目标函数指针。当前没有内核地址泄漏（本审计在 FF 路径上**没找到**信息泄漏：
`UI_BEGIN_FF_UPLOAD` 的 `ff_up` 完全由用户 buffer 先填、再由 `request->u.upload.effect/old` 覆盖，
`old == NULL` 时走 `0x...e25084 → 0x...e25544`，回显的仍是用户自己给的内容）。
⇒ **需要一个 KASLR/堆地址泄漏才能升级为任意写/调用**，这是下一步的第一优先级。

---

## 5. 审计项 4：erase 次序与二次释放

1. `input_ff_erase`（`0x...080064c`）`mutex_lock(&ff->mutex)`（`0x...0800684`）后调 worker，
   `mutex_unlock` 在 `0x...08006b0`。⇒ **`ff->mutex` 覆盖 `ff->erase()` 全程**，包括它阻塞等用户态应答的最长 7.5s。
2. worker 的次序是 `ff->erase()`（`0x...0800788 blr`）→ 成功后 `effect_owners[id] = NULL`（`0x...08007ac`）。
   **没有"先清 owner 再 erase"的路径**，所以不存在"erase 已经释放而 complete 还在用同一个 id"。
3. `ff->effects` 是 `input_ff_create` 里一次 `__kmalloc(max*48)`（`0x...e1a070`），
   **数组元素从不单独 `kfree`**（全镜像里 `ff->effects` 只在 `input_ff_destroy` 里整体释放）
   ⇒ **不存在 `ff_effects` 元素的二次释放**。`effect_owners[id]` 存的是 `struct file *`，清空只是写 NULL。
4. `uinput_dev_erase_effect`（0x...e25cc0）自身不判边界，只做 `test_bit(EV_FF, dev->evbit)`
   （`0x...e25ce8`）后投递 request；边界完全由 §3.2 的三道闸兜住。
5. `input_ff_flush`（0x...e19eac）在 evdev close 路径上（`uinput_dev_flush` 0x...e25fc4 只是
   `if (file) input_ff_flush()`），持 `ff->mutex` 循环 `i < ff->max_effects` 调同一个 worker
   （`0x...e19ef8`，上界 `0x...e19f00-0x...e19f08` 有界）。

⇒ 项 4 **干净**。唯一的可用性问题是：`input_ff_flush` 会对每个 effect 串行发 request，
每个最多 7.5s；`max_effects = 96` 时 close(event_fd) 最长可被拖 ~720s，且全程持 `ff->mutex`
（这期间任何 `EVIOCSFF`/`EVIOCRMFF` 都卡住）。**这是死锁/DoS 面，不是内存安全面**。

---

## 6. 已排除 / 记录在案的负面结论

| 观察 | 证据 | 判定 |
|---|---|---|
| `udev->buff[head]` 环形缓冲的守卫允许 `index == 16`（`cmp w8,#0x11` 只拦 ≥17），而 `buff[16]` 落在 `udev+0x1d8`，会覆盖 `ff_effects_max@0x1d8` + `requests[0..1]@0x1e0/0x1e8` | 生产者：`0x...e25d84`(playback)、`0x...e25e5c`(set_gain)、`0x...e26038`(dev_event) 三处命中即**静默丢弃**（`b.hs → epilogue`），`0x...e261c0`(submit) 命中则 `b.hs 0x...e262cc` = `brk #0x5512`（BUG/panic）；消费者：`0x...e242b0`(read，静默跳过) | **不可达**：`head` 的唯一写点是 `(head+1)&0xf`（`0x...e25dc4` / `0x...e26074` / `0x...e26200`），`tail` 同理（`0x...e242c0`），不变式恒成立。属"守卫多一位、只靠掩码保命"的防御缺陷，不算漏洞 |
| 环形缓冲的生产者锁不一致：submit 走 `udev->mutex`，playback/set_gain/dev_event 走 `dev->event_lock`（由 input core 传入），两者不互斥 | `0x...e26168` vs `0x...e25d88`/`0x...e26038` | 只会丢事件（两边都读到同一个 `head` 后都 `&0xf` 前移），不会 OOB |
| `suspend`/`UI_DEV_DESTROY` 之后 `udev->dev == NULL` 时的 NULL 解引用 | `uinput_read` 先 `cmp state,#2` 再 `ldr [udev]`（`0x...e24248-0x...e24298`）；`uinput_write` 同（`0x...e244c8`）；ioctl 入口会懒分配（`0x...e24adc-0x...e24af0`） | 都持 `udev->mutex`，与 destroy 串行，不可达 |
| `uinput_request_submit` 释放段对 `request->id >= 16` 用 `brk #0x5512`（BUG）而非 `WARN` | `0x...e2626c` / `0x...e262cc` | 不可达（id 来自 `alloc_id`，恒 ≤15）；仅记为"panic 面" |
| FF 路径信息泄漏 | `UI_BEGIN_FF_UPLOAD` `0x...e25050-0x...e2509c`；`ff_up` 先由用户 buffer 填充（`0x...e25014`），`old==NULL` 分支 `0x...e25084`→`0x...e25544` | 无泄漏（回显的是用户自己的数据） |
| CVE-2026-64560 机制级不可达 | 见 `64560_DEAD_ON_LHASA.md` | 按指示不再触碰 |
| hid-multitouch C1 | 见 `HID_MT_C1_RECHECK.md` | 按指示不再触碰 |

---

## 7. 待验证 / 下一步（按优先级）

1. **前置条件实测（唯一卡点，必须先做）**：uid 2000 能不能 open 自己创建的 event 节点。
   `adb shell 'id; ls -lZ /dev/input/ | tail; cat /proc/bus/input/devices | tail -20'`，
   然后 create 一个 uinput 设备后重复一次，看新节点的 `mode/owner/group/context`
   （期望 `input_device`，`shell` 需在 `input` 组）。**不通则整条第 3 项结论降级为"理论可达"**。
   注：`/dev/uinput` 的 SELinux/组已实测可用，这条不用再验。
2. **窗口标定**：A/B 两线程 pin 同一 CPU，B 阻塞在 `EVIOCSFF` 后 A `close()`，
   在回收对象里埋"空 wait_queue + `requests_lock=0`"，用 `+0x1e0+id*8` 是否被清 0 判命中；
   再换 `head.next` 指向已知非零地址看是否 `__wake_up` 崩（`CONFIG_PANIC_ON_OOPS=y` ⇒ 立即 panic，
   所以这一步要在能接受重启的环境做）。
3. **`kmalloc-1k` 回收验证**：`UI_SET_PHYS`（`0x...e24f74`，`strndup_user(..,0x400)` @`0x...e24f8c`）
   spray 1023 字节 / 每 fd 一次，配合 `udev` 的 kfree 做 hole-fill；确认落 `kmalloc-1k`
   而非 `kmalloc-cg-1k`（`GFP_USER` 不带 `__GFP_ACCOUNT`，理论值，需实测 slabinfo 计数）。
4. **地址泄漏**：需要在 FF 路径之外找一个 KASLR/堆泄漏，才能把 ③ 从"能崩"升级成"能用"。
   本审计在 FF 路径内没找到，建议转去别的子系统（或复用已有的探索线）。
5. 若要更确定地进入 §4.2 的 ① ②，可把 16 个 slot 全部占满（16 线程各一个 `EVIOCSFF`），
   第 17 个线程会停在 `wait_event_interruptible(&udev->requests_waitq)`
   （`0x...e2612c`/`0x...e2615c`），它在 close 后由同伴的 `__wake_up`（`0x...e26294`）唤醒，
   再回头 `alloc_id` 对 freed `udev` 加锁（`0x...e262f0` → `_raw_spin_lock`）——
   多一个"必须已释放"的窗口来源，值得一并测。

---

## 8. 候选清单（回报格式）

```
对象: struct uinput_device (kmalloc-1k, 640B) + 栈上的 struct uinput_request
序列: UI_SET_FFBIT → UI_DEV_SETUP(ff_effects_max) → UI_DEV_CREATE → open(eventN)
      → [B] EVIOCSFF(id=-1) → [A] close(uinput_fd)
缺陷: UAF（freed 对象上 _raw_spin_lock + 定址写 0 + __wake_up 走查可控 list_head）
证据: uinput_request_submit 释放段 0xffffffc080e26268 / 0xffffffc080e2627c / 0xffffffc080e26294
      vs uinput_release 的 kfree 0xffffffc080e24a58，flush 0xffffffc080e2596c..0xffffffc080e25ae8
      （flush 只 complete、不清 requests[]；submit 在 0xffffffc080e26228 已放掉 udev->mutex）
下一步: ①a 实测 event 节点可 open；①b 同 CPU pin 标定 complete()→kfree 窗口；
      ①c UI_SET_PHYS(strndup_user 0x400) 做 kmalloc-1k 同桶回收；①d 找一个内核地址泄漏
```

无其它候选。上传/擦除的数据通路（项 1/2/4）与环形缓冲（§6）均已排除，理由见对应章节。

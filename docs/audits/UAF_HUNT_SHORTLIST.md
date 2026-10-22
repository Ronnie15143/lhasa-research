# lhasa 实机内核提权：可达 UAF/OOB 候选清单（静态分析轮）

> 目标：小米 18 Fold（lhasa / XRing O3）/ Android 17 / HyperOS OS4.0.21.0
> 内核 `6.18.21-android17-5-g284297031c53-abogki553682993-4k` · SPL 2026-08-01 · 页 4K · 10 核
> 攻击者身份 `adb shell`（uid 2000，无任何 capability，Seccomp 0）· SELinux Enforcing · BL locked
> 本轮只做**静态分析 + 只读查询**：未写设备、未 fuzz、未跑 exploit。
> 二进制基准：`rom/vmlinux-4.0.21.0.elf`（145,868 符号）↔ `rom/Image-4.0.21.0.bin`（`file_off = addr - 0xffffffc080000000`）

---

## 0. 结论摘要（先看这五条）

| # | 结论 | 强度 |
|---|---|---|
| 1 | **KASAN 实际关闭**：config 是 `KASAN_HW_TAGS`，但 `/proc/cmdline` 有 `kasan=off`，且 CPU 无 `mte` 特性 ⇒ 影子内存机制根本不可用。同时 `CONFIG_PANIC_ON_OOPS=y` ⇒ **任何 oops 立即 panic**。 | 实测 + 反汇编 |
| 2 | **6.18.22 里 4 条 HID 安全补丁，只有 1 条在本机还开着**：HID core memset(268)、logitech-hidpp FF UAF(269)、wacom BT OOB(274) 三条本机**要么已有守卫、要么代码根本没编译**；**HID multitouch(267) 的回报 report-ID 校验确认缺失**。 | 反汇编 |
| 3 | 可达面被 SELinux 收得比 config 窄得多：`CONFIG_IO_URING/BPF/KEYS/USERFAULTFD` 都编译进去了但全部被拒；**真正可用的只有 `/dev/uhid` + `/dev/uinput`（同一标签 `uhid_device`）、`/dev/binder`、`/dev/ashmem_*` 三个 0666 变体、`AF_UNIX`/`AF_INET`/`AF_INET6`/`AF_NETLINK`、epoll/timerfd/eventfd/pidfd/memfd**。 | CIL + l70 实测 |
| 4 | 回收几何与既有原语完全吻合：`kmalloc-256  11750 18208 256 32 2`（32 对象/order-1 8 KB），且 `CONFIG_RANDOM_KMALLOC_CACHES` 未设 ⇒ kmalloc-256 是**单一 cache**，uhid 的跨 cache 回收成立。 | slabinfo |
| 5 | **Top1 候选不是"大概可能"，是已定位的具体缺失守卫**：`mt_get_feature()` 把 `hid_hw_raw_request()` 的回报缓冲区**不做 report-ID 校验**就交给 `__hid_report_raw_event()`，而该缓冲区是按"被请求的报告"精确分配的紧桶。 | 反汇编（调用点逐条） |

**一句话方向**：HID 是这台机上唯一"非特权可完全伪造设备 → 内核按我们给的描述符与回报走"的子系统；`uhid` 既是回收原语又是攻击入口，优先在这里找，而不是继续在通用面（io_uring/bpf/keys/nft）上耗。

---

## 1. 本机真实能力面（config × 符号 × SELinux × sysctl 四重过滤）

判定口径：`编译进去`（config）→ `真的链进 Image`（符号表）→ `SELinux 放行`（CIL + 实测）→ `sysctl 放行`。**四关全过才算可达。**

### 1.1 过关（真正可达）

| 子系统 | config | 符号证据 | SELinux / 运行期 | 结论 |
|---|---|---|---|---|
| **uhid** | `CONFIG_UHID=y` | 42 个 `uhid_*`，含 `uhid_char_write`、`uhid_dev_create2@0xffffffc080f78e44` | `(allow shell uhid_device (chr_file (ioctl read write getattr lock append map open watch watch_reads)))`；`/dev/uhid` 0666 | ✅ 主入口 |
| **uinput** | `CONFIG_INPUT_UINPUT=y` | 21 个 `uinput_*`，含 `uinput_ioctl_handler`、`uinput_ff_upload_from_user`、`uinput_dev_erase_effect` | **注意：`/dev/uinput` 的 SELinux 标签就是 `uhid_device`**（`ls -lZ` 实证），0660 `uhid:uhid`，shell 属 `uhid(3011)` 组 | ✅ 新入口（父会话 l70 未单测，但标签/组权限与 uhid 完全同源） |
| **evdev / input** | `CONFIG_INPUT_EVDEV=y`、`INPUT_FF_MEMLESS=y` | 32 个 `evdev_*`、8 个 `input_ff_*`（`input_ff_upload`/`input_ff_erase`/`input_ff_effect_from_user`） | `(allow shell input_device (chr_file (getattr ioctl lock map open read watch watch_reads)))` | ✅ 配合 uinput 可造完全可控设备树 |
| **HID 驱动集** | `HID=y HIDRAW=y HID_MULTITOUCH=y HID_LOGITECH_HIDPP=y HID_WACOM=y HID_GENERIC=y …` | 7 个调用点直连 `__hid_report_raw_event` | 经 uhid 间接可达（无需另开设备） | ✅ |
| **ashmem（memfd 变体）** | `CONFIG_ASHMEM=y` | 仅 4 个符号：`ashmem_memfd_ioctl` / `ashmem_area_{name,size,vmfile}`（其余内联） | `/dev/ashmem_unpinning_enable`、`/dev/ashmem_ignore_unset_prot_{read,exec}` 均 **0666**，标签 `ashmem_libcutils_device`；l70 实测 `ashmem_ignore_unset_prot_exec` 可开（普通 `/dev/ashmem` 的 `ashmem_device` 反被拒） | ✅ 厂商面 |
| **binder（C 版）** | `ANDROID_BINDER_IPC=y`、`BINDERFS=y`、`IPC_RUST=m` | `binder_alloc_*` / `binder_transaction*` 齐全 | `/dev/binder -> /dev/binderfs/binder`，l70 可开；C 版在用（`rust_binder` 模块**未加载**，见 `/proc/modules`） | ✅ 面积最大 |
| **AF_UNIX** | `CONFIG_UNIX=y` | `unix_stream_sendmsg` | 无权限要求 | ✅ 回收原语 |
| **AF_INET / AF_INET6 / AF_NETLINK(ROUTE)** | `INET=y`、`IPV6=y`、`NETFILTER_NETLINK=y` | — | l70：`SOCK_DGRAM` 与 `AF_NETLINK SOCK_RAW ROUTE` 均可建 | ✅ |
| **epoll / timerfd / signalfd / eventfd / pidfd / memfd / open_tree** | 全部 `=y` | 符号齐全 | l70 全部可建 | ✅ |
| **/proc/slabinfo** | — | — | shell 可读 | ✅ **观测通道（关键）** |

### 1.2 编译进去但被挡（不要当首选）

| 子系统 | config | 符号 | 被什么挡 |
|---|---|---|---|
| io_uring | `CONFIG_IO_URING=y`、`IO_URING_ZCRX=y` | **351** 个 `io_uring*`，含 `__arm64_sys_io_uring_{setup,enter,register}` | `io_uring_setup → EACCES(13)`（l70 实测） |
| eBPF | `BPF_SYSCALL=y`、`BPF_JIT_ALWAYS_ON=y` | `__arm64_sys_bpf` | `bpf() → 13` |
| keys | `KEYS=y` | `key_type_user`、`key_type_logon`、`__arm64_sys_{add_key,keyctl}` | `add_key/keyctl → 13`；且 **`watch_queue` 0 符号** ⇒ 无 `KEYCTL_WATCH_KEY` 通道 |
| userfaultfd | `USERFAULTFD=y` | `__arm64_sys_userfaultfd`、37 个 `userfaultfd_*` | `EPERM(1)` |
| AF_PACKET / AF_VSOCK / AF_KEY | `PACKET=y` | `packet_sendmsg`/`packet_create` | socket → 13 |
| fsopen | — | — | `EPERM(1)` |
| /proc/misc、/dev/kallsyms、块设备、/dev/dma_heap/*、/dev/dri/card0、/dev/net/tun、/dev/device-mapper、/dev/fuse、/dev/ufs-bsg0 | — | — | 13 |

### 1.3 未编译（一次性封死，后面不再提）

`CONFIG_NF_TABLES is not set`（`nft_*` **0 符号**）· `CONFIG_CRYPTO_USER is not set` ⇒ **AF_ALG 整体不存在**（`CRYPTO_USER_API_{HASH,SKCIPHER,RNG,AEAD}` 全 no）· `CONFIG_ATM is not set` · `CONFIG_X25 is not set` · `CONFIG_QRTR is not set` · `CONFIG_AF_RXRPC is not set` · 无 `CONFIG_SYSVIPC`/`CONFIG_POSIX_MQUEUE`（`msg_msg` 只剩 LSM 钩子）· 命名空间只有 `NET/UTS/TIME`（**无 `USER_NS`、无 `PID_NS`、无 `IPC_NS`、无 `CGROUP_NS`**）。

### 1.4 缓解措施现状（决定"能不能用"和"怎么判命中"）

| 项 | 值 | 影响 |
|---|---|---|
| `CONFIG_KASAN=y` + `KASAN_HW_TAGS=y` | **但 `kasan=off`**（`/proc/cmdline` 实读） | 无影子检查；且 `cpuinfo Features` 无 `mte`（CPU part `0xd8b` / implementer `0x41`）⇒ HW tags 硬件不可能 |
| `CONFIG_KFENCE=y` | `SAMPLE_INTERVAL=500`、`NUM_OBJECTS=63`、`STRESS_TEST_FAULTS=0` | 只做抽样，不能当 oracle |
| **`CONFIG_PANIC_ON_OOPS=y`** | 是 | **任何 oops = 立即 panic**。这是本机唯一可靠的"命中信号"，但也是"输一次就重启" |
| `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` | 是（`INIT_ON_FREE` **未开**） | 新分配对象被清零 ⇒ 「未初始化字段」类利用全死；但「我们主动回填内容」的 UAF 不受影响 |
| `CONFIG_BUG_ON_DATA_CORRUPTION=y` | 是 | 链表加固命中 = `BUG()`（硬 panic），不是可恢复 WARN |
| `CONFIG_CFI=y`（`CFI_PERMISSIVE` 未设） | 是，反汇编可见 kCFI 哈希校验 | 控制流劫持基本封死 ⇒ **只能走数据面**（改 cred/改指针/改 pgtable 之类） |
| `CONFIG_RANDSTRUCT_NONE=y` | 是 | **结构体布局是自然的**，静态偏移可直接用（大好） |
| `SLAB_FREELIST_RANDOM=y` / `SLAB_FREELIST_HARDENED=y` | 是 | 不知道 free 顺序，但回收"占满整页"不需要它 |
| `CONFIG_SHUFFLE_PAGE_ALLOCATOR=y` | 是 | buddy 出页顺序随机 ⇒ 页级抢占要用"大量喷"而不是"精确摆位" |
| `CONFIG_RANDOM_KMALLOC_CACHES` | **未设** | kmalloc-256 单一 cache ⇒ uhid 跨 cache 回收成立 |
| `INIT_STACK_ALL_ZERO=y` / `VMAP_STACK=y` / `RANDOMIZE_KSTACK_OFFSET=y`（default off） / `STACKPROTECTOR=y` / `FORTIFY_SOURCE=y` / `HARDENED_USERCOPY_DEFAULT_ON=y` | — | 栈溢出基本没戏；`HARDENED_USERCOPY` 会拦"拿内核指针当用户指针" |
| `CONFIG_STATIC_USERMODEHELPER_PATH=""` | 是 | core_pattern / modprobe 这条 root 路彻底死 |
| `CONFIG_MODULE_SIG_FORCE` | 未设 | 理论上可走模块，但需要 `CAP_SYS_MODULE`（没有） |

---

## 2. 两个回收原语的几何（本轮用 slabinfo 复核）

```
kmalloc-256        11750  18208    256   32    2 : slabdata    569    569      0
kmalloc-rcl-256        0      0    256   32    2 : slabdata      0      0      0
filp               39871  50080    256   32    2 : slabdata   1565   1565      0
kmalloc-192        20423  30072    192   21    1
kmalloc-96         46377  71022     96   42    1
```

- `kmalloc-256`：**256 B × 32 对象 / 2 页 = order-1(8 KB)**，与 uhid `rd_size=256 → kmemdup` 的落点完全一致，且 `32 × 256 = 8192` 恰好铺满一页 ⇒ 喷 32 个设备即可拿下一整页。
- `filp` 同为 `256 B / 32 / order-1`，但它是**独立 cache**，与 kmalloc-256 不互通，不能拿来和 uhid 互换（记一笔，避免下一轮误判）。
- `CONFIG_RANDOM_KMALLOC_CACHES` 未设 ⇒ 上面这唯一的 `kmalloc-256` 就是所有 256 字节分配的共用桶。
- 第二个原语（`send(AF_UNIX, 11872)` ⇒ `data_len=8192` ⇒ `alloc_pages(order=1)` 整页全控）与 `kmalloc-256` 的 order/大小同阶，**两者抢的是同一类 buddy 页**，这是"页级夺页 → 伪装成 32 个 256B 对象或整页结构"的基础。

---

## 3. 候选清单（按"可达性 × 已证实未修 × 得分潜力"排序）

> 说明：只有 **C1 是已定位到具体缺失守卫**的；C2–C4 是"权限面已实测成立、子系统代码已确认存在、但具体缺陷尚未定位"的结构面候选；C5 起是面积/载体类。全部标注了当前证据等级，**不要把 C2 以后当结论**。

---

### C1 · HID multitouch：`mt_get_feature()` 缺失回报 report-ID 校验（对应上游 `e716edafedad`，6.18.22 commit 267）

- **对象 / slab**：不是 slab 对象，溢出目标是 `hid_alloc_report_buf()` 返回的**紧桶 kmalloc**。
  `hid_alloc_report_buf@0xffffffc080f6527c` 的长度计算（反汇编逐条）：
  ```
  w8 = report->size(bits) + 7
  w8 >>= 3                        ; ceil(bits/8)
  w8 += (report->id != 0 ? 1 : 0) ; cinc ne
  w8 += (report->id == 0 ? 1 : 0) ; cinc eq   ⇒ 恒 +1
  size = w8 + 7                   ; __kmalloc_noprof
  ```
  ⇒ 分配量 = `ceil(report->size/8) + 8`，**紧贴 kmalloc 桶边界，没有任何余量**。
- **分配点**：`hid_alloc_report_buf` @ `0xffffffc080f6527c`（`__kmalloc_noprof` @0xffffffc0801b429c）。
- **释放点**：`mt_get_feature+0x98` 的 `bl kfree`（`0xffffffc080f8d2d8`）。
- **缺陷点（本机反汇编直证）**：
  ```
  mt_get_feature  @ 0xffffffc080f8d240
    +0x14  ldr w9,  [x1,#0x84c]        ; report->size (bits)
    +0x18  ldr w10, [x1,#0x30]         ; report->id
    +0x30  cinc w22, w9, ne            ; w22 = ceil(bits/8) + (id!=0)
    +0x48  bl hid_alloc_report_buf     ; 按"被请求报告"精确分配
    +0x6c  bl hid_hw_raw_request       ; (hdev, report->id, buf, w22, HID_FEATURE_REPORT=2, HID_REQ_GET_REPORT=1)
    +0x70  tbnz w0,#0x1f → 只查错误码
    +0x74  mov x2, x20                 ; ← buf 原样
    +0x80  mov x3, x22 / mov w4, w22   ; size = len = w22
    +0x8c  bl __hid_report_raw_event
  ```
  **`+0x70` 到 `+0x8c` 之间没有任何 `ldrb` 从 `buf` 取值、也没有与 `report->id` 的比较。**
  上游修复加的正是"比较回报里的 report ID 与请求的 report ID，不一致就提前返回"。
- **为什么 uid 2000 能触达**：`/dev/uhid` 上 `UHID_CREATE2` 可任意指定 `bus/vendor/product` 与报告描述符，让内核把我们的虚拟设备绑到 `hid-multitouch`；`UHID_GET_REPORT_REPLY`（走 `write()`，非 ioctl）允许我们**对内核的 `GET_REPORT` 请求回任意字节，包括任意 report ID**。全程无 cap 要求。
- **触发条件（本轮已把它从"未知 quirk 字节"查成了确定的表达式）**：
  `mt_get_feature+0x34  tbnz w8,#5 → return`，其中 `w8 = *(u8*)(hdev + 0x1cff)`。
  BTF 实测（`btf_dump.py Image-4.0.21.0.bin hid_device`）：`=== STRUCT hid_device size=7872 ===`，
  `+7420 quirks (4B)` → `0x1CFC`，`+7424 initial_quirks (4B)` → `0x1D00`。
  ⇒ `hdev+0x1cff` **就是 `hdev->quirks` 的最高字节**，该检查等价于 **`if (hdev->quirks & BIT(29)) return;`**。
  这很重要且是**好消息**：`hdev->quirks` 来自 `hid_lookup_quirk()` 按 `bus/vendor/product` 查 `hid_blacklist`，
  而 `UHID_CREATE2` 允许我们任意指定 `bus/vendor/product` ⇒ **这一位是我们能选"置/不置"的**。
  自造 VID/PID（不在 `hid_blacklist` 里）⇒ `quirks = 0` ⇒ BIT(29) 为 0 ⇒ **检查通过，`mt_get_feature` 正常往下走**。
  **待验证**：`mt_probe` 要接受我们的设备，而 hid-multitouch 是 id_table 驱动的，需要挑一个"能被 `mt_devices[]` 匹配、且其 quirks 不含 BIT(29)"的 VID/PID 组合 —— 这是本候选仅剩的前提。
- **堆布局要求**：不需要 reclaim——溢出发生在 `hid_alloc_report_buf` 自己的紧桶里，`w22` 由我们选的"被请求报告"决定，reclaim 无关。**这正是它比 64560 好用的地方**。
- **是否已修**：**未修**。依据就是上面 `+0x70..+0x8c` 的指令序列缺失 + 上游修复描述（"respond to a specific report's feature request using a completely different report ID … OOB writes"）。
- **非破坏性验证 oracle（推荐）**：
  1. `UHID_CREATE2` 造 multitouch 设备，报告描述符里定义 `R1`(短) 与 `R2`(远长) 两个 Feature 报告；
  2. 打开对应 `/dev/hidrawN`；
  3. 内核发 `GET_REPORT(R1)` → 我们回 `R2` 的 ID；
  4. **看 `hidraw` 是否吐出以 R2 为 id 的 raw 事件** ⇒ 证明内核按 R2 解析了（report-ID 混淆成立），此时**还没有**触发 OOB；
  5. 再把 R2 的 bit 长度调到 `> (ceil(len(R1)/8)+8)*8`，同一路径即走 `__hid_report_raw_event` 的字段解析循环读越界 → 触发 oops → `PANIC_ON_OOPS` 立即 panic。
  ⇒ 第 4 步是**无破坏**的确证，第 5 步才是打；这个"两段式"让它可安全验证。

---

### C2 · uinput force-feedback：`ff_effect` 上传/擦除路径

- **对象 / slab**：待定。相关符号齐全：`input_ff_upload`、`input_ff_erase`、`input_ff_effect_from_user`、`input_ff_destroy`、`uinput_ff_upload_from_user`、`uinput_dev_upload_effect`、`uinput_dev_erase_effect`、`uinput_dev_playback`、`uinput_dev_set_autocenter`、`uinput_dev_set_gain`。
- **分配/释放点**：未定位（本轮未展开）。
- **为什么 uid 2000 能触达**：`/dev/uinput` 的 SELinux 标签是 `uhid_device`（`ls -lZ` 实证：`crw-rw---- 1 uhid uhid u:object_r:uhid_device:s0 10,223 uinput`），而 `shell` 对 `uhid_device` 有 `ioctl read write open map` 全集；文件模式 `0660 uhid:uhid`，shell 在 `uhid(3011)` 组。⇒ **与 `/dev/uhid` 同权**。
- **触发条件**：`UI_SET_EVBIT`/`UI_SET_ABSBIT` + `UI_DEV_CREATE` 造一个带 `EV_FF` 能力的设备，再走 `UI_BEGIN_FF_UPLOAD`/`UI_END_FF_UPLOAD` 与 `input_ff_upload/erase`。`ff_effect` 结构含用户可控 union（periodic/condition/ramp）与 effect id 复用语义，是历史 UAF 高发点。
- **堆布局要求**：大概率需要 reclaim 一个 `ff_effect`/`ff_device` 大小的对象 → 先用 uhid 定位实际 slab 桶，再决定用 uhid（256）还是 AF_UNIX 整页。
- **是否已修**：**未知**。`uinput_ff_upload_from_user` 这个较新的 helper 存在，说明该路径被重构过，需要按函数读一遍。
- **oracle**：`/proc/slabinfo` 里对应桶的 active/total 增量 + `evdev` 侧 `EVIOCGEFFECTS` 读回；崩溃则以 `PANIC_ON_OOPS` 为信号。

---

### C3 · uinput 设备描述符：`UI_DEV_SETUP` / `UI_ABS_SETUP`

- **对象 / slab**：待定（`uinput_dev_setup` 的 name/phys/uniq 与 absinfo 拷贝，`strscpy`/`memdup` 类）。
- **符号**：`uinput_ioctl_handler`、`uinput_open`、`uinput_destroy_device`。
- **可达性**：同 C2，`/dev/uinput` + `shell → uhid_device` 全权。
- **说明**：这是 HID/uinput 里**最少被上游安全审计覆盖**的一块（大量 `UI_*` 魔法数 + 老接口 `UI_DEV_CREATE` 与 `UI_DEV_SETUP` 两套语义并存），且失败路径的 `uinput_destroy_device` 有历史 UAF 记录。
- **是否已修**：未知，需按函数读。
- **oracle**：`/dev/input/eventX` 读回 + slabinfo。

---

### C4 · ashmem（小米定制 memfd 变体）：`ashmem_memfd_ioctl`

- **对象 / slab**：待定；驱动仅 4 个导出符号（`ashmem_memfd_ioctl`、`ashmem_area_{name,size,vmfile}`），主体内联。
- **可达性（实测）**：`/dev/ashmem_unpinning_enable`、`/dev/ashmem_ignore_unset_prot_read`、`/dev/ashmem_ignore_unset_prot_exec` 全是 `crw-rw-rw-`（0666），标签 `ashmem_libcutils_device`；l70 已实测 `ashmem_ignore_unset_prot_exec` 可 `open`。注意**普通 `/dev/ashmem`（标签 `ashmem_device`）对 shell 是 EACCES** —— 也就是说这条路上只有厂商变体是开的。
- **为什么看好**：`unpinning`、`ignore_unset_prot_exec/read` 这三个名字说明小米在标准 ashmem 上加了**去 pinning 与 PROT_EXEC 豁免**逻辑，这类改动直接动 VMA/引用计数，且几乎不在上游审计范围内。
- **是否已修**：不适用"上游是否回移"——**这是厂商代码，上游没有对应修复**。
- **oracle**：`/proc/self/maps` 回读 + `/proc/slabinfo`；`ashmem_area_size/name/vmfile` 三个只读属性可做状态观测。

---

### C5 · binder（C 版）—— 面积最大，需专项

- **可达性**：`/dev/binder -> /dev/binderfs/binder`（l70 可开）；`rust_binder` 模块**未加载**（`/proc/modules` 无该项），所以走 C 实现。
- **符号**：`binder_alloc_*`（`copy_from/to_buffer`、`mmap_handler`、`deferred_release`、`free_buf`、`free_page`）、`binder_transaction*`、`binder_thread_write/read` 齐全。
- **说明**：binder 是 Android 独有 + 巨大 + 非特权可达，历史上 LPE 频出（buffer 越界、fd array、node refcount）。但它是**需要专项投入的深水区**，不适合作为"本轮就能落成 oracle"的候选，列在此处是为了排进下一轮预算。
- **是否已修**：需按版本对 patch。注意 6.18.22 里 `rust_binder: use AssertSync for BINDER_VM_OPS`（commit 148）**不是安全修复**，且 C 版不受影响 ⇒ 这条 commit 可直接划掉。

---

### C6 · evdev ioctl 面（配合 uinput 造可控设备）

- **可达性**：`(allow shell input_device (chr_file (getattr ioctl lock map open read watch watch_reads)))` —— shell 对 input 设备有 `ioctl`。
- **符号**：32 个 `evdev_*`，含 `evdev_do_ioctl`、`evdev_handle_mt_request`、`evdev_handle_get/set_keycode{,_v2}`、`evdev_handle_get_val`。
- **说明**：`EVIOCSABS`／`EVIOCG*` 的 length 参数与 `evdev_handle_mt_request` 的 slot 计数是经典越界点。配合 uinput 我们能把设备能力集设成任意值，从而让这些 ioctl 走到平时走不到的分支。
- **是否已修**：未知。
- **oracle**：IOCTL 返回值 + slabinfo；越界读可用"回显长度"直接判。

---

### C7 · AF_INET6 `ip6_datagram_send_ctl()` —— 6.18.22 有 overflow 修复，本机未修

- **上游**：6.18.22 commit 179 `ipv6: avoid overflows in ip6_datagram_send_ctl()`（`9ed81d692758dfb9471d7799b24bfa7a08224c31`）。
- **可达性**：`AF_INET6 + SOCK_DGRAM + sendmsg` 带 ancillary data，**无任何 capability 要求**，是本清单里权限门槛最低的网络面。
- **状态**：本机是 6.18.21 ⇒ 修复不在；但工作区只有 `ChangeLog-6.18.22.txt` 的**提交说明，没有 diff**，所以**缺陷的具体形态尚未确认**（是本条唯一硬伤）。
- **下一步**：反汇编 `ip6_datagram_send_ctl` 并对照上游 `net/ipv6/datagram.c` 的 cmsg 长度计算；确认后再定级。
- **诚实标注**：**待验证候选，不是结论。**

---

### C8 · AF_UNIX `send(11872)` 整页 — 回收载体（非缺陷）

不是 bug，是本轮已标定的第二个原语：`unix_stream_sendmsg` 的 `+0xe8 sub w9,w25,#0xe80` ⇒ `data_len = size - 0xe80`，`send(0xe80+8192=11872)` 得到 `data_len=8192` ⇒ `alloc_pages(order=1)` 且 **8192 字节 100% 是我们内容**。用途：需要"整页内容可控"的 reclaim（页表、`pipe_buffer` 数组、大结构）时用它，需要"256B 对象 × 32/页"时用 uhid。

---

## 4. 考虑过但排除（一行一条，避免下一轮重复）

| 候选 | 排除理由（证据） |
|---|---|
| **CVE-2026-64560** posix-cpu-timers 非 leader exec | 已证机制级不可达（`research/64560_DEAD_ON_LHASA.md`：`begin_new_exec` 先 `exchange_tids`+`transfer_pid(TGID)`，后 `release_task` 清 `sighand`，`!sh` 分支无时刻）。**不要再碰。** |
| HID core `hid_report_raw_event` memset OOB（6.18.22 commit 268） | 本机**已有两道 `-EINVAL` 守卫**：`__hid_report_raw_event+0x64 cmp x3,w4,uxtw; b.lo → 0x5ed0`（`_dev_warn("Event data for report %d is incorrect (%d vs %zu)")` 后 `mov w0,#-0x16` 返回）；`+0xb8 b.hs 0x5824` 否则 `_dev_warn("Event data for report %d was too short (%d vs %zu)")` 后同样 `-EINVAL`。残留的 `+0x14c bl __pi_memset` 被 `w22 <= x3-numbered` 夹住，**不可能越过声明的缓冲区容量**。 |
| logitech-hidpp force-feedback UAF（commit 269） | `hidpp_ff_init` / `hidpp_ff_deinit` 在 145,868 符号里**完全不存在** ⇒ 该代码没编译进来（虽然 `HID_LOGITECH_HIDPP=y`、`HID_LOGITECH_DJ=y`）。commit 276（MX Master 4 over bluetooth）同为非安全项。 |
| wacom `wacom_intuos_bt_irq` OOB read（commit 274） | `wacom_intuos_bt_irq` 符号**不存在**（`wacom_probe@0xffffffc080fb436c`、`wacom_raw_event` 在，但 BT-irq 路径未编译）。 |
| HID multitouch 之外的 6.18.22 HID 项 | `HID: appletb-kbd .resume`（非安全）、`HID: core memset`（见上）均已排除。 |
| `rust_binder`（commit 148） | `ANDROID_BINDER_IPC_RUST=m` 且 `/proc/modules` 里**无 rust_binder** ⇒ 未加载；且该 commit 只是 `AssertSync`，非漏洞修复。 |
| nf_tables / nft_* | `CONFIG_NF_TABLES is not set`，`nft_*` **0 符号**。6.18.22 的 201/212 条直接作废。 |
| x_tables / ipset / ctnetlink / xt_check_*（202/203-210 条） | 代码在（`NETFILTER_XTABLES=y`），但装规则需 `CAP_NET_ADMIN`，uid 2000 无 cap 且无 userns。 |
| net/sched：`sch_netem` OOB(191)、`cls_flow/cls_fw` NULL deref(181/182)、`sch_hfsc` div0(237) | 全部需 `CAP_NET_ADMIN` 建 qdisc/classifier。 |
| `bonding` UAF(223)、`virt_wifi` UAF(12) | 需建 netdev，`CAP_NET_ADMIN`。 |
| `atm: lec` UAF(273) | `CONFIG_ATM is not set`。 |
| `net/x25` 双 free(184) | `CONFIG_X25 is not set`。 |
| `net: qrtr` radix_tree→xarray(245) | `CONFIG_QRTR is not set`。 |
| `crypto: af-alg scatterwalk` NULL deref(250) / `algif_aead`(225) | `CONFIG_CRYPTO_USER is not set` ⇒ **AF_ALG 整套不存在**。 |
| io_uring 三条（70/137/170） | 351 个符号在，但 `io_uring_setup → EACCES(13)`（l70 实测）。 |
| bpf 三条（176/177/218）+ sockmap UAF(192) | `bpf() → 13`（l70 实测）。 |
| `ksmbd` OOB write(133) | Android 不编译 ksmbd。 |
| `Bluetooth` 系列（134/195/196/199） | 需要 HCI 设备与 `CAP_NET_ADMIN`（HCI socket）；`/dev/stpbt`、`/dev/fw_log_bt` 均为 `bluetooth:bluetooth` 660，shell 无权限。 |
| `misc: fastrpc` 双 free(37) | 高通平台驱动，XRing 平台无此设备（`/dev` 全表无 `fastrpc`）。 |
| `gpib` UAF(126)、`nvmem`/`hwmon`/`iio` 系列 | 均为需对应硬件总线的模块，未加载。 |
| **`/dev/mali0`**（0666，`gpu_device`） | `mali_kbase` 模块**已加载**（1.1 MB，188 引用），是极高价值面，**但 SELinux 不放行 shell**：`gpu_device` 的 allow 域只有 `gpu_sphal_domain / graphicsengine / mmd / permissioncontroller_app / rs`。⇒ 排除（除非将来拿到这些域之一的代码执行）。 |
| `/dev/udmabuf`（0666，`udmabuf_device`） | 仅 `crosvm_domain` 一个域。 |
| `/dev/kvm`（0666，`kvm_device`） | 该类型 `(allow …)` **0 个域**。 |
| `/dev/npu_service_device`（`hpc-mdr`/`xrp-mdr`/`xvp_queue` 均 0666） | 仅 `hal_npu`；`npu_device` 仅 HAL/system_server 类。 |
| `/dev/sipa_cmd`（0777）、`/dev/xr_fbt`（0666） | `sipa_device` 仅 `hal_audio_default/spkcal`；`xr_fbt_device` 虽含 `domain` 属性（shell 在 `domain` 内，理论可达），但**驱动在模块里、不在 vmlinux**（`xr_fbt*` 0 符号）⇒ 本轮无法静态判定，列为"下一轮需取模块镜像"。 |
| `/dev/dma_heap/*`、`/dev/fuse`、`/dev/net/tun`、`/dev/device-mapper`、`/dev/ufs-bsg0`、块设备、`/dev/dri/card0` | l70 实测 open → `EACCES(13)`。 |
| `msg_msg` / `mqueue` / `sk_buff`(SYSVIPC 系) | `CONFIG_SYSVIPC`/`CONFIG_POSIX_MQUEUE` 未编译；`msg_msg` 只剩 `bpf_lsm_msg_msg_alloc_security` 之类钩子。 |
| user namespaces（`unshare(CLONE_NEWUSER)`） | `CONFIG_USER_NS` 未编译；`max_user_namespaces` 亦不可读。 |
| `watch_queue` / `KEYCTL_WATCH_KEY` | 0 符号；且 `add_key/keyctl → 13`。 |
| `CONFIG_STATIC_USERMODEHELPER_PATH=""` 系（core_pattern/modprobe） | 已确认死路（R3 §3.4）。 |
| KFENCE 当 oracle | `SAMPLE_INTERVAL=500`、`NUM_OBJECTS=63`、`STRESS_TEST_FAULTS=0` ⇒ 只抽样，命中不可控。 |

---

## 5. 观测通道与 oracle 设计（本轮能用的只有这些）

| 通道 | 状态 | 用法 |
|---|---|---|
| **`/proc/slabinfo`** | ✅ shell 可读（l70 实测） | 量回收几何与占页成功率（`kmalloc-256` 的 active/total；`posix_timers_cache` 式的 `X Y size objperslab pagesperslab`） |
| **`PANIC_ON_OOPS=y`** | ✅ | 只要 oops 就必然 panic ⇒ "设备重启/adb 掉线"= 命中的**二值信号**（不是软信号）。代价：一次命中 = 一次重启 |
| `logcat -b all \| grep avc:` | ✅ | SELinux 拒绝 oracle（HANDOVER_2 §5.1 已验证有效） |
| `/sys/kernel/tracing/kprobe_events` | 0777 可写 | 能注册探针；但 `events/kprobes/<ev>/enable` 是 `root readtracefs`，**shell 写不进** ⇒ permissive 之前用不了 |
| `dmesg` / `klogctl` / `pstore` / `tainted` / `panic_on_warn` | ❌ | 全 `Permission denied` |
| `perf_event_open` on tracepoint | ❌ | `avc: denied { kernel } tclass=perf_event`（`perf_event_paranoid=-1` 也没用） |
| `/proc/misc` / `/proc/kallsyms` / 多数 `/proc/sys/*` | ❌ | `Permission denied`（`perf_event_paranoid` 是少数可读的，值 `-1`） |
| **`hidraw` 事件读回** | ✅ | **C1 首选的"无破坏"确证手段**：证明内核按我们伪造的 report ID 解析了数据，且此时尚未越界 |
| `evdev`（`/dev/input/event*`） | ✅（`shell → input_device: ioctl/read`） | C2/C3/C6 的状态回读 |

**推荐验证顺序**：C1 第 4 步（hidraw 回读，无破坏）→ 确认 report-ID 混淆成立 → 再决定是否第 5 步（会 panic）。

---

## 6. 明确的"待验证"清单（下一轮该先做什么）

按性价比排序，每项都写清了"为什么现在不做"：

1. **挑中一个 `mt_probe` 能接受、且 `quirks & BIT(29) == 0` 的 VID/PID**：`hid-multitouch` 是 id_table 驱动（`mt_devices[]`），需要找一个匹配项；同时该 VID/PID 在 `hid_blacklist` 里不能带 `BIT(29)`。两者可以解耦——`mt_devices[]` 与 `hid_blacklist` 是两张表，交叉查一遍即可（`mt_feature_mapping@0xffffffc080f8c73c` 的三个触发 usage 为 `0x000D0059` / `0x000D0055` / 及一个 `0xFF0000C5` 编码项，均可由报告描述符构造）。**这是 C1 唯一的未闭合前提。**
2. **C1 溢出方向的定性**：`__hid_report_raw_event` 的字段解析循环（`+0x204` 起，`cmp x9,#0x100` / `[report+0x848]=maxfield`）在 `report` 与缓冲区长度不匹配时到底读/写多远 —— 需要把 `implement()` / `hid_field_extract` 的位偏移累加看清楚。
3. **uinput FF 路径（C2）逐函数审计**：`uinput_dev_upload_effect` → `input_ff_upload` → `input_ff_erase` 的 effect id 生命周期与失败路径。
4. **ashmem 三变体（C4）**：`ashmem_memfd_ioctl` 的 `ASHMEM_*` 命令表与 `unpinning` 语义，重点看 VMA/refcount。
5. **`ip6_datagram_send_ctl`（C7）**：需要 6.18.22 的**真实 diff**（本工作区只有 changelog 摘要，无 patch 正文）。
6. **`xr_fbt` / `mali_kbase`**：两者都是模块，需要先把 vendor 模块镜像从 `/vendor/lib/modules` 或 OTA 里取出来才能静态判。

---

## 7. 复现本报告的命令（全部只读）

```sh
# 能力面
adb shell "cat /proc/cmdline | tr ' ' '\n' | grep -i kasan"      # → kasan=off
adb shell "cat /proc/cpuinfo | grep Features | head -1"          # → 无 mte
adb shell "ls -lZ /dev"                                          # → uinput 与 uhid 同标签 uhid_device
adb shell "grep -E '^(kmalloc-256|filp|kmalloc-192)' /proc/slabinfo"
adb shell "cat /proc/modules | grep -E 'mali|binder'"            # → mali_kbase 在，rust_binder 不在

# SELinux（本地 CIL，等价于设备 policy）
#   (allow shell uhid_device (chr_file (ioctl read write getattr lock append map open watch watch_reads)))

# 反汇编（在 runs/android/rom 下）
python kdisasm.py vmlinux-4.0.21.0.elf Image-4.0.21.0.bin hid_report_raw_event 60
python kdisasm.py vmlinux-4.0.21.0.elf Image-4.0.21.0.bin mt_get_feature 60
python kdisasm.py vmlinux-4.0.21.0.elf Image-4.0.21.0.bin hid_alloc_report_buf 24
```

关键地址速查：

| 符号 | 地址 |
|---|---|
| `hid_report_raw_event`（薄封装，把 size 传两次） | `0xffffffc080f65f18` |
| `__hid_report_raw_event`（真实现） | `0xffffffc080f656fc` |
| `hid_alloc_report_buf` | `0xffffffc080f6527c` |
| `mt_get_feature` | `0xffffffc080f8d240` |
| `mt_feature_mapping`（`mt_get_feature` 的唯一调用者，descriptor 驱动） | `0xffffffc080f8c73c`（调用点 `+0x54 / +0xa8 / +0xd4`） |
| `hid_input_report` | `0xffffffc080f656d0` |
| `__hid_input_report` | `0xffffffc080f65f40` |
| `uhid_dev_create2` | `0xffffffc080f78e44` |
| `mt_probe` / `hidpp_probe` / `wacom_probe` | `0xffffffc080f89bac` / `0xffffffc080f82124` / `0xffffffc080fb436c` |
| `__kmalloc_noprof` | `0xffffffc0801b429c` |

`__hid_report_raw_event` 的 7 个调用点（全部已核）：
`acc_complete_send_hid_event+0x30`、`hid_report_raw_event+0x18`、`__hid_input_report+0x14c`、`hidpp_raw_hidpp_event+0x984`、`mt_get_feature+0x8c`、`wacom_raw_event+0x25c`、`wacom_parse_and_register+0x6a4`。

---

## 8. 与既有结论的关系

- **不推翻** `64560_DEAD_ON_LHASA.md`：64560 仍然是死的，本报告没有重新碰它。
- **修正** `STATUS_2026-10-22_R3.md` §6 的候选方向：那里把 6.18.22 的 277 条判成"shell 可达 ∩ 安全 = 9 条，全需 CAP_NET_ADMIN 或未编译"。本轮把筛法换成"config → 符号 → SELinux → sysctl"四重过滤后，**在 HID 这一支上找到了一个不需要 CAP_NET_ADMIN、不需要 userns、只需要 `/dev/uhid` write() 的具体缺失守卫（C1）**，这条上次被漏掉了（因为 6.18.22 的 HID 条目当时被当成"需要真实 HID 硬件"）。
- **新增**：`/dev/uinput` 与 `/dev/uhid` 同标签同权限这一事实（`ls -lZ` + CIL 双证），把 uinput 的 FF/描述符面从"未考虑"提升为"与 uhid 等价可达"。
- `HANDOVER_2.md` §9 建议的"把 uhid 原语用到别的内核 bug 上"方向不变，但**具体目标换成 C1**，而不是继续在 binder 写路径上找环。

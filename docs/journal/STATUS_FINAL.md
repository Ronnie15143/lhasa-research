# lhasa 解锁/root 终局评估（2026-10-22）

> 本文件是本轮全部实测的收口。**结论：从 uid 2000 能触达的所有路径都不通。**
> 下面是每条路径的判死理由与证据，供后续决策（不是"再调调参数"的问题）。

---

## 一、本轮真正拿到的东西

| 能力 | 状态 | 证据 |
|---|---|---|
| **KASLR slide 精确求解** | ✅ 可重复 | 从本机 4.0.21.0 OTA 用 HTTP Range 只抠 `boot` 分区（实下 13 MB，总包 9 GiB）→ 真实 `Image` → `vmlinux-to-elf` 恢复 **139,213 符号**；11 个内核函数独立算 slide **spread=0**；两次 boot 各自 427/427、924/933 全票 |
| **设备内核完整符号 + BTF** | ✅ | `rom/vmlinux-4.0.21.0.elf`、`Image-4.0.21.0.bin`（`.BTF` @0x1aed000，4.27 MB 类型） |
| **零特权可达面地图** | ✅ | `research/sysmap.c`、`ioctl_probe.c`、`binder_probe.c` |
| **GBL 判锁逻辑逆向** | ✅ | `gbl_unlock_logic.py` 等；调用链见 §二 |

---

## 二、推翻的三条原有"核心结论"

### ① 「锁状态 = misc[0:4] == 0x4B」→ **错**

两条独立证伪：

**静态**：`0xa8a40` 里的 `cmp w8,#0x4b` 读的是 **sret 返回结构首字段**（Rust `Result` 的 tag），
不是 misc 内容。`x8` 在调用前一刻被设为 `sp+0x48`（AAPCS64 间接结果指针），
真正的数据 buffer 在 `x21`（`memset 0x800` 的堆块），代码**从未比较 x21[0:4]**。
`0x4b` 是 Rust 的 `Ok` 判别式（全程序 30+ 处「调用完立刻 cmp #0x4b」）。

**动态**：按该猜想实测——用 `code 7` 往 `/dev/block/by-name/misc` 写 1 字节 `'K'`(0x4b)，重启后
`ro.boot.flash.locked=1`、`verifiedbootstate=green`、`vbmeta.device_state=locked`。

**根因**：`"miscDevice is not unlocked"` 是**字符串池合并幻觉**——
真实是 `"misc"` + `"Device is not unlocked"`（22 字节，`mov w9,#0x16`）。交接文档被这个合并串骗了一整轮。

### ② 锁状态到底在哪 → **不在任何分区里**

```
GBL: 锁状态 = GblAvbProtocol::read_device_status() 的返回值
      调用点 0xf0d4:  ldr x0,[x0] ; ldr x8,[x0,#0x10] ; blr x8      ← EFI protocol 间接调用
      panic 串自证: "efi::protocol::gbl_efi_avb::<impl Protocol<GblAvbProtocol>>::read_device_status"
```

三条硬证据排除 efuse/RPMB/分区/签名：

| 检验 | 结果 |
|---|---|
| 全 `.text`（1.15 MB）扫 `smc`/`hvc` | **0 条**（只有 `brk` 做 panic） |
| 扫 `flash.locked` / `rpmb` / `efuse` / `otp` 字符串 | 全部不存在 |
| 签名验证 | 同一 protocol 的**另一个方法** `validate_vbmeta_public_key`，与 `read_device_status` 分离 |

**⇒ 对 misc / backup* / exaid / ffu / rescue 的任何写入都不可能改变锁状态。**
`ro.boot.flash.locked` 由更早引导阶段（xloader/bl2 或 UEFI 固件）产出，GBL 不产生该串。

提供服务方的地方在 `uefi.img`（2.1 MB 高熵卷）/ `tee` / `xrse` —— 我们手上没有任何一个镜像里有它
（`android_esp.img` 里只有 `EFI/BOOT/BOOTAA64.EFI`，与独立镜像同一份）。

### ③ 「拿到内核 root 后 dd 写 misc 即可解锁」→ **整条链条作废**

见 ①②。即使拿到 root 也解不了锁。

---

## 三、为什么 CVE-2026-64560 这条链在本机不可用

**不是时序、不是参数——是回收原语不存在。**

| 事实 | 数据 |
|---|---|
| `posix_timers_cache` 的 order | objsize 384, objperslab 21, pagesperslab **2** → **order-1 (8KB)** |
| 参考实现用的 8KB AF_UNIX frag 的 order | `kmalloc-8k` objsize 8192, objperslab 4, pagesperslab **8** → **order-3 (32KB)** |
| 实测 | 喷 4000 个 8KB frag 后 `kmalloc-8k.active` **一个都没动**（490/497，slabdata 125/125） |
| 结论 | order-3 页物理上不可能顶替 order-1 页 ⇒ 抢页恒失败 |

**能进 order-1 的只有 256 字节档**，而四种原始字节原语全部被挡：

| 候选 | 结果 |
|---|---|
| SysV `msgsnd` | `CONFIG_SYSVIPC` 未编译 → ENOSYS |
| POSIX mqueue | `CONFIG_POSIX_MQUEUE` 未编译 |
| `add_key` | SELinux EACCES |
| BPF `htab_elem` | SELinux EACCES |
| `io_uring` | SELinux EACCES |
| `setxattr` | value 系统调用返回即释放，非持久 |
| `PR_SET_VMA_ANON_NAME` | 名字上限 80B 且 C 字符串不能含 `\0`，做不出两个全零字段 |
| tmpfs xattr | `CONFIG_TMPFS_XATTR` 未编译 |

对余下 order-1 cache 用 BTF 逐字段核对（`btf_screen.py`）：节点窗口固定在对象偏移
`{96..119, 224..247}`，而 `vm_area_struct`(96=vm_private_data(0))、`filp`(96=f_pos_lock, 224=padding)、
`io_kiocb`(96=ctx, 224=work)、`sk_buff`(96=destructor, `cb` 在 40..87)、`maple_node`、`nf_conn`、
`request_sock`、`mount`、`key` —— **没有任何一个窗口是可写可控字段**。
唯一几何完全匹配的 `sk_buff::cb`(40..87) 内容由协议栈写入，不可控。

---

## 四、零特权可达面（实测）与通用 LPE 排除

**可达**：`memfd_create pidfd_open signalfd4 timerfd_create epoll_create1 inotify_init1 eventfd2
mseal process_vm_readv ptrace(TRACEME) kcmp open_tree`，`clone3`/`perf_event_open`（EINVAL=已过权限检查）。
设备节点：`/dev/binder`、`/dev/hwbinder`、`/dev/uhid`、`/dev/ptmx`（后两者 ioctl 到达驱动）；
`/dev/mali0` 能开但 ioctl **EPERM**。

**被封**：`io_uring_setup(EACCES) userfaultfd(EPERM) bpf(EACCES) add_key/keyctl(EACCES) fsopen(EPERM)
SYSVIPC/POSIX_MQUEUE(未编译) fanotify(未编译) kexec(未编译) init_module(EPERM)`；
`/dev/ashmem /dev/kmsg /dev/net/tun /dev/fuse /dev/block/*` 全 EACCES。

**已知 CVE 逐条排除**：

| CVE | 排除理由 |
|---|---|
| CVE-2026-31431 "Copy Fail"（AF_ALG/algif_aead，修复 6.18.22，我们是 6.18.21） | **`CONFIG_CRYPTO_USER_API_AEAD` 未编译**，整个 `CRYPTO_USER_API` 都不在 config |
| CVE-2026-98776（binderfs UAF write） | 需 `/dev/binderfs/binder-control`，该目录对 shell 不可读 |
| CVE-2026-97602（IPv6 fragment race） | 需 network namespace，**`CONFIG_USER_NS` 未开** |
| 6.18.22 changelog 中 277 条 shell 可达 ∩ 安全 | 交集约 15 条，几乎全是 USB gadget/驱动/需 CAP_NET_ADMIN 的 net/sched |

---

## 五、fastboot 面（唯一新信息）

```
getvar:unlocked          → OKAY  no
oem device-info          → INFO "Device unlocked: false" + OKAY   ← 白名单允许
oem / oem help / oem ?   → FAIL "Command not found" / "fb lock: true, operation not permitted"
oem unlock               → FAIL "Set unlock mode failed"          ← ★ 白名单允许且真的执行了
oem unlock-go / fus      → 设备立即从 USB 消失（被 reboot）
```

`oem unlock` 与其它被挡子命令的报错**不同**，说明它进了真实解锁代码路径，但被 provider 拒绝
（"Set unlock mode failed"）—— 与 §二 的结论一致：状态由 TEE/UEFI 持有，bootloader 改不了。
这就是小米官方的解锁闸门（需 Mi 账号绑定 + 等待期），**没有任何 userspace/bootloader 侧旁路**。

---

## 六、结论与剩余选项

**从 uid 2000 能触达的所有路径都不通。** 这台机器的安全姿态是：
锁状态根植于 TEE/UEFI 的 AVB provider + Android 加固配置把所有通用 LPE 面都关了。

剩下的选项只有三个，都需要用户决策：

1. **走官方解锁**（唯一现实可行）：开发者选项里开「OEM 解锁」→ 绑定小米账号 → 满足等待期 →
   `fastboot oem unlock`。之后随便刷 Magisk 拿持久 root。技术侧已无旁路。
2. **继续挖 binder/uhid 0day**（低概率、高投入）：两个驱动 ioctl 均对 shell 开放，
   每包数据可控，是这台机上唯一"活着"的内核攻击面。
3. **打 TEE/UEFI 的 AVB provider**（极高投入）：需要先解开 `uefi.img` 的高熵卷，
   找到安装 `gbl_efi_avb` GUID 的 DXE driver。这是唯一能改锁状态的实体。

---

## 七、工具与产物

| 文件 | 作用 |
|---|---|
| `rom/ota_extract.py` | HTTP Range 从 9 GiB OTA 抠单个分区，无需整包下载 |
| `rom/vmlinux-4.0.21.0.elf` | 139,213 符号（设备真实内核） |
| `rom/btf_dump.py` / `btf_screen.py` | 从 Image 的 .BTF 精确取结构布局 / 批量筛 order-1 窗口 |
| `research/cap_pair.sh` | 冻结 tracing，同窗口抓文本 trace + 每 CPU raw（含每 boot 重新 arm tracepoint） |
| `research/pair_records.py` | 按 (cpu, common_pid, event.pid) 精确配对 raw ↔ 符号 |
| `research/solve_live.py` | 一次抓取即可重算 slide |
| `verify_misc_claim.py` | 正确的 PE 段表 + capstone，用于复核 GBL 反汇编 |
| `gbl_unlock_logic.py` 等 | GBL 判锁逻辑逆向 |
| `research/sysmap.c` / `ioctl_probe.c` / `binder_probe.c` / `ioctl_cal.c` / `binder_txn.c` | 可达面与 ioctl 编码标定 |
| `research/l60.c` / `l61.c` / `reclaim_test.c` / `order_probe.c` | 64560 落地尝试与 reclaim 探针 |
| `UNLOCK_PATHS.md` | 解锁路径穷尽（42 KB，501 行） |
| `AUDIT_TARGETS.md` | 可达面地图与审计优先级 |
| `KASLR_SOLVED.md` | slide 求解全过程 |

设备全程未写任何分区（唯一一次对 misc 的 1 字节写入按 §二① 的性质是无效的），未 flash。

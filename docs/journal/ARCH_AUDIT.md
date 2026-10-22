# 架构级审计：这台机器为什么封不住（全部实测）

> 2026-10-22。不是 bug 层面的穷举，而是把**每一个"信任边界"逐个实测**，
> 看有没有结构性的漏。结论：**每一面都收紧到实测可达集只有一个入口，且那个入口无执行语义。**

---

## 面 1：锁状态的真主人 —— TEE/UEFI，Android 碰不到

```
GBL: read_device_status() = EFI protocol 间接调用 blr [iface+0x10]
     实现方不在 BOOTAA64.EFI 里（uefi.img 高熵卷 / tee / xrse）
全 .text 扫 smc/hvc = 0；无 flash.locked / rpmb / efuse / otp 字符串
```

`oem unlock` 在 fastboot 白名单里、**真的执行了**，但返回 `Set unlock mode failed` ——
provider 拒绝。这是小米官方闸门，bootloader 侧无旁路。

## 面 2：uid-0 的 root 文件写（hypsys / IMQSNative）—— 实测可达集只有 2 个目录

比读策略更可靠的做法是**实测**（策略在这台机上骗过我们两次）：
`code 6`(root create) + `code 7`(root write) + `code 8`(root read) 三步回读标记，
扫 52 个目录：

```
WRITABLE  /data/anr
WRITABLE  /mnt/rescue
其余 50 个目录（/data/local/tmp /data/misc/* /data/system /data/property /data/app
/metadata /cache /persist /efs /dev /sys /proc /vendor /odm /system …）全部 denied
```

- `/data/anr`：ANR trace 落地目录，消费者是 system_server / dumpstate（uid 1000）。
- `/mnt/rescue`：`sdc80` ext4 rw，init 里只做 `update_engine_log`、
  `recovery/new_efs` 这类 marker，**没有执行语义**；`restorecon_recursive` 不执行内容。

**两个目录都没有"内容被执行"的语义。**

## 面 3：mqsas 服务接口 —— 无命令执行、无第二个写原语

- `code 1`（type/headline/actionsCSV/paramsCSV/where/includeCSV）：传
  `actions="touch /data/anr/exec_proof"` → **无文件生成**，actions 不进 shell。
- `code 2`（抓包，最后参数是网卡名）：接口名里塞 `;` / `$()` → 调用者被
  **SIGABRT/SIGKILL**，无注入（第一次测试的"touch 执行了"是我自己 `eval` 的假象，
  已用单引号重测证伪）。
- `code 7` 的返回值 `replyInt0=0` **与成功无关**（拒绝路径同样返回 0），
  唯一判据是"文件是否生成"——这点也标定过。
- 另有 code 6 = root 建/截断文件；3/12/14/16 = 杀调用者；无块设备写方法。

## 面 4：属性触发的 init 动作（Android 最经典的提权面）

从 init rc 里抽出 **354 个 `on property:` 触发块**，其中 **16 个含 `exec`**，
再实测 shell 的 setprop 可达性：

| 触发属性 | shell 可设 | 动作 | 可利用性 |
|---|---|---|---|
| `apexd.debug.lsof=*` | ❌ denied | `exec u:r:su:s0 root root -- sh apexd-lsof.sh ${prop}` | 最诱人（su 域 + sh + 属性作参数），但属性设不了；且脚本有 `/apex` 前缀 + 目录存在双校验，`grep $1` 注不进 |
| `vendor.mdl_ctrl.sd_start=*` | ❌ denied | `exec mdl_ctrl log_mode ${prop}` | 属性设不了 |
| `sys.snapshotctl.map/unmap` | ❌ denied | `exec - root root -- snapshotctl map` | 属性设不了 |
| `sys.cppreopt` | ❌ denied | `exec preloads_copy.sh` | 属性设不了 |
| `bootreceiver.enable` | ❌ denied | tracing instance | 属性设不了 |
| **`persist.sys.stability.lz4asm`** | ✅ 可设 | `exec u:r:modprobe:s0 -- modprobe -r lz4asm` | 模块名/路径全固定，属性只作触发器 |
| **`sys.init.updatable_crashing`** | ✅ 可设 | `exec flags_health_check UPDATABLE_CRASHING` | 参数固定 |
| **`kcmdline.binder`** | ✅ 可设 | `exec kcmdlinectrl store binder ${prop}` | 只能写 misc 的 `binder` 槽（见下） |

`kcmdline` 的语义是 **misc → 属性**：`update-props` 在 early-boot 读 misc 的
kcmdline 区并 setprop；`store` 反向写。但 init 只为 `binder` 挂了触发，
所以能写的**只有 `binder` 这一个槽**——自指，无法注入 `androidboot.selinux` 之类。

**shell 能设的 4 个属性，没有任何一个能把可控字符串送进特权程序的参数。**

## 面 5：内核漏洞面 —— 全被 config 挡

| 路径 | 结论 |
|---|---|
| CVE-2026-64560（本机确实存在） | 不可用：posix slab 是 order-1，本机不存在「非特权+持久+原始字节」的 order-1 分配（`SYSVIPC`/`POSIX_MQUEUE` 未编译；`add_key`/`BPF`/`io_uring` 被 SELinux 拒；`setxattr` 非持久；`PR_SET_VMA_ANON_NAME` 是 C 字符串不能含 `\0`；BTF 逐字段核对余下 order-1 cache 无可控窗口） |
| CVE-2026-31431 Copy Fail（AF_ALG，修 6.18.22，我们 6.18.21） | `CONFIG_CRYPTO_USER_API_AEAD` 未编译 |
| CVE-2026-98776 binderfs UAF write | `/dev/binderfs` 对 shell 不可读，`binder-control` 进不去 |
| CVE-2026-97602 IPv6 fragment race | 需 net namespace，`CONFIG_USER_NS` 未开 |
| 上游 6.18.22 的 277 条修复 | shell 可达 ∩ 安全 ≈ 15 条，全是 USB gadget / 需 CAP_NET_ADMIN |

## 面 6：仍然活着的内核攻击面（唯一剩下的）

```
/dev/binder    open+mmap+BINDER_VERSION(ret=0, proto=8) 全通
               BINDER_WRITE_READ 编码标定为 0xC0306201（全零参数返回 0）
               BC_TRANSACTION 路径尚未打通（handle 0 需要 context manager）
/dev/uhid      open+ioctl 到达驱动（ENOTTY = 无该 handler，非 EACCES）
/dev/ptmx      到达驱动
perf(self)     perf_event_paranoid=-1，可达
```

---

## 结论

**这台机器的隔离是真的紧**，不是我们没想到：锁状态在 TEE/UEFI（Android 侧任何写入都无效）、
root 写原语的可达集只有 2 个无执行语义的目录、shell 能触发的 4 个属性都不携带可控参数、
通用 LPE 全被 config 关闭、唯一存在的内核 CVE 缺一个本机不存在的回收原语。

**要打穿，只剩两条（都不是"再调参数"能解决的）：**

1. **binder / uhid 的 0day**：这台机上唯一活着的、数据完全可控的内核面。
   需要真实的内存安全研究（binder 的 `binder_transaction` 解析、uhid 的报告描述符/报告拷贝），
   属于新课题，不是本轮能收口的。
2. **TEE / UEFI 的 AVB provider**：先解 `uefi.img` 的高熵卷，找装 `gbl_efi_avb` GUID 的 DXE driver。
   这是唯一能改锁状态的实体，投入极高。

**现实可行的那条仍然是官方解锁**（开发者选项 → 绑 Mi 账号 → 等待期 → `fastboot oem unlock`），
技术侧已确认无旁路。

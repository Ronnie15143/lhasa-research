# ESP 写权限域审计 — lhasa / `android_esp_block_device`

> 目标：往 `/dev/block/by-name/android_esp_a`（`u:object_r:android_esp_block_device:s0`，实体 `/dev/block/sdc38`）写自造 FAT 镜像
> 设备：Xiaomi 18 Fold `lhasa` / XRing O3 / Android 17 / 内核 6.18.21 / SELinux **Enforcing**
> 本轮性质：**纯静态 CIL 审计 + 只读设备查询**。未写设备、未 fuzz、未调用任何服务。
> 输入资产：`plat_sepolicy.cil`(57,820 行) / `vendor_sepolicy.cil`(34,033) / `system_ext_sepolicy.cil`(15,164) /
> `plat_pub_versioned.cil`(10,851) / `odm_sepolicy.cil`(42)，以及 4 个 `*_contexts`、`selinux.policy`。

---

## 0. 结论

1. **全策略里能对 `android_esp_block_device` 做 `blk_file write` 的域，只有一个：`update_engine`。**
   没有第二个，也没有任何属性/`dev_type` 级别的批量授权兜底。

   ```
   vendor_sepolicy.cil:22302
   (allow update_engine_202604 android_esp_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
   ```

2. **shell（`u:r:shell:s0`，uid 2000）对 ESP 连 `open` 都没有**，只有 `getattr`：
   `plat_sepolicy.cil:62249  (allow shell dev_type (blk_file (getattr)))`。
   实测 `dd if=/dev/block/by-name/android_esp_a bs=512 count=1` → `Permission denied`
   （DAC 层 `brw------- root root` 先挡，SELinux 再挡一次）。

3. **shell 到 `update_engine` 没有直接通路**（`binder call` 不成立、无 socket、无 exec、无 property 触发），
   但存在 **两条 binder 跳板**：`shell → gmscore_app → update_engine`（`gmscore_app` 真在跑，实测 4 个进程）、
   `shell → system_server → update_engine`。跳板只代表"中间域被允许调它"，仍需中间域上的漏洞。

4. **本轮新发现（推翻上一轮的一个前提）**：shell 虽然没有 `ctl_start_prop`，但
   `/vendor/etc/init/mtk_thinmd.rc:180-181` 有一条 `on property:debug.modem.triggerexception=*` → `start ${debug.modem.triggerexception}`，
   而 `debug.` 属于 `debug_prop`，shell **有权 set**（`plat_sepolicy.cil:61139`）。
   ⇒ **shell 可以启动任意"已存在"的 init 服务**，等价于 `ctl.start`。
   上一轮 `UNLOCK_PATHS.md` §5.1/§5.3 "shell 无 `ctl.start` ⇒ 拉不起任何 disabled 服务" 的结论**不再成立**。

5. `neverallow` 保护是**不对称**的：`misc_block_device` 有 `plat_sepolicy.cil:26493` 的 neverallow 墙，
   `boot_block_device` 有 4 条；而 **`android_esp_block_device` 一条 neverallow 都没有** ——
   它"只有一个写者"纯粹来自**缺少 allow**，不是来自策略层的强封锁。

---

## 1. 方法与两个必须知道的陷阱

全部结论由「CIL 文本解析 + 设备只读实测」得出。本机无 `sesearch`/`secilc`，**未做交叉验证**，
因此下文每条都直接给出 CIL 原文与 `文件:行号`，可人工复核。

### 陷阱 1：版本化类型名 `_NNNNNN`（会让结论漏掉一半）

vendor 模块引用 plat 的 public 类型时用的是**版本化别名**，同一个类型在策略里有两个名字：

```
vendor_sepolicy.cil:3418   (allow hal_bootctl_default misc_block_device_202604 (blk_file (...)))   ← 带 _202604
plat_sepolicy.cil:44272    (allow init misc_block_device (blk_file (...)))                          ← 不带
```

`plat_pub_versioned.cil` 里用 `(typeattributeset misc_block_device (misc_block_device_202604))` 把两者绑在一起。
**grep `misc_block_device` 会漏掉全部 vendor 规则**（本机实测：漏 1 条，即 `hal_bootctl_default`）。
本审计对所有类型名做 `re.sub(r"_\d{6}$", "", name)` 归一。

### 陷阱 2：`base_typeattr_<N>` 是**按模块独立编号**的（会污染可达性分析）

同一个名字在不同 CIL 文件里是**不同的集合**：

```
plat_sepolicy.cil:85344    (typeattributeset base_typeattr_272 (and (appdomain ) (not (isolated_app_all ephemeral_app sdk_sandbox_all pcc_component ))))
vendor_sepolicy.cil:33976  (typeattributeset base_typeattr_272 (and (domain ) (not (init_202604 vendor_init_202604 mtkrild ))))
```

朴素地把两处并集，会让 `base_typeattr_272` 膨胀成"几乎全部 domain"，从而**虚构出大量 binder 可达性**。
本审计对 `^(base_typeattr|base_attraddon)_\d+$` 加 `<file>::` 命名空间前缀。
（我先踩了这个坑，修掉后 shell 的 binder-call 目标从 129 收敛、hop2 从 477 收敛到 281 —— 见 §3。）

### 校验锚点

模型正确性的实测反证：上一轮 `service call miui.mqsas.IMQSNative` 从 shell **成功**返回过真实 Parcel。
本模型必须能解释它 ⇒ `hypsys_ssi_default` 必须落在 shell 可 binder-call 的集合里。实测：
`hypsys_ssi_default` ∈ `binderservicedomain`（`plat_sepolicy.cil:859`），shell ∈ `appdomain`（`plat:840`），
`plat_sepolicy.cil:14081  (allow appdomain binderservicedomain (binder (call transfer)))` ✔ 闭合。

### 规模

| 项 | 数 |
|---|---|
| `allow` 语句 | 27,929 |
| `neverallow` | 6,155 |
| `type` / `typeattribute` | 3,812 / 3,744 |
| `domain` 集合 | 714 |
| 块设备类 type（带 `blk_file` 规则） | 71 |
| 上述 type 上的 `blk_file` 规则（规则×覆盖 type） | 891 |

---

## 2. 表格 A — type × 有 `blk_file write` 的域（完整 CIL 原文 + 文件:行号）

### A.1 六个指定 type 的完整写者清单

#### `android_esp_block_device` —— **1 个写域**

```
vendor_sepolicy.cil:22302
(allow update_engine_202604 android_esp_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
```

同 type 上的**非写者**（完整，供排除用）：

| 域 | 权限 | 出处 |
|---|---|---|
| `shell` | `getattr` | 来自 `plat:62249 (allow shell dev_type (blk_file (getattr)))` |
| `apexd` / `dumpstate` / `e2fs` / `fsck` / `fsck_untrusted` / `vendor_init` | `getattr` | 同上 `dev_type` 泛化规则 |
| `init` | `ioctl read watch watch_reads lock map open`（**无 write**） | `plat_sepolicy.cil:43630 (allow init dev_type (blk_file (ioctl read getattr lock map open watch watch_reads)))` |
| `ueventd` | `create relabelfrom relabelto setattr unlink`（建节点/改标签，**不写内容**） | `plat_sepolicy.cil:74123 (allow ueventd dev_type (blk_file (create getattr setattr relabelfrom relabelto unlink)))` |

⚠ `init` 有 `open` + `ioctl` 但**没有 `write`** —— 所以连 init 都写不了 ESP。

#### `boot_block_device` —— **3 条规则 / 2 个实体域**

```
plat_sepolicy.cil:75965
(allow update_engine_common boot_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))

vendor_sepolicy.cil:7073
(allow hal_bootctl_default boot_block_device_202604 (blk_file (ioctl read write getattr lock append map open watch watch_reads)))

vendor_sepolicy.cil:22281
(allow update_engine_202604 boot_block_device_202604 (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
```

`update_engine_common` 是 `typeattribute`（`plat_sepolicy.cil:863`），唯一成员是 `update_engine`
（`plat:864 (typeattributeset update_engine_common (update_engine))`、`plat_pub_versioned.cil:4556` 版本化路径同义），
`update_engine_202604` 同理（`plat_pub_versioned.cil:3811`）。
**⇒ 实体域只有 2 个：`update_engine`、`hal_bootctl_default`。**
⇒ 上一轮 `UNLOCK_PATHS.md` §1.2 "`boot_block_device` 的写规则只有 `update_engine_common`"**不完整**，漏了 `hal_bootctl_default`（vendor:7073）。
另：`vendor_install_recovery` 对 `boot_block_device_202604` 只有 `ioctl read getattr lock map open watch watch_reads`（`vendor:5117`），**无 write**。

#### `misc_block_device` —— **10 条写规则 / 10 个域**

```
plat_sepolicy.cil:44272   (allow init                misc_block_device (blk_file (write lock append map open)))
plat_sepolicy.cil:46176   (allow kcmdlinectrl         misc_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
plat_sepolicy.cil:50546   (allow misctrl              misc_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
plat_sepolicy.cil:51195   (allow mtectrl              misc_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
plat_sepolicy.cil:74369   (allow uncrypt              misc_block_device (blk_file (write lock append map open)))
plat_sepolicy.cil:75980   (allow update_engine_common  misc_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
plat_sepolicy.cil:77242   (allow vendor_init           misc_block_device (blk_file (write lock append map open)))
plat_sepolicy.cil:78394   (allow vendor_misc_writer    misc_block_device (blk_file (write lock append map open)))
plat_sepolicy.cil:81303   (allow vold                  misc_block_device (blk_file (write lock append map open)))
vendor_sepolicy.cil:3418  (allow hal_bootctl_default    misc_block_device_202604 (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
```

写者：`hal_bootctl_default, init, kcmdlinectrl, misctrl, mtectrl, uncrypt, update_engine(→common), vendor_init, vendor_misc_writer, vold`
**`shell` / `hypsys_ssi_default` 都不在其中** —— 与本轮已实测的 `hypsys 写 android_esp_b → avc denied tclass=blk_file` 一致。
另有 neverallow 墙：
```
plat_sepolicy.cil:26493  (neverallow base_typeattr_493 misc_block_device (blk_file (ioctl read write lock relabelfrom append link rename open)))
plat_sepolicy.cil:84902  (typeattributeset base_typeattr_493 (and (domain ) (not (hal_bootctl_server hal_fastboot_server fastbootd init recovery ueventd uncrypt update_engine vendor_init vendor_misc_writer kcmdlinectrl misctrl mtectrl ))))
```

#### `block_device`（泛型整盘）—— **1 条写规则**

```
vendor_sepolicy.cil:7590  (allow init_202604 block_device_202604 (blk_file (write)))
```

非写者：`init(ioctl read open ...)`、`recovery(ioctl)`、`kernel(relabelto)`、`ueventd(create/relabel/setattr/unlink)`、`shell(getattr)`。

#### `userdata_block_device` —— **6 条写规则**

```
plat_sepolicy.cil:29714          (allow e2fs              userdata_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
plat_sepolicy.cil:31431          (allow fsck              userdata_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
plat_sepolicy.cil:74379          (allow uncrypt           userdata_block_device (blk_file (write lock append map open)))
plat_sepolicy.cil:81175          (allow vold              userdata_block_device (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
system_ext_sepolicy.cil:6605     (allow system_perf_init  userdata_block_device (blk_file (read write getattr open)))
vendor_sepolicy.cil:6631         (allow acpu_log_save     userdata_block_device_202604 (blk_file (ioctl read write getattr lock append map open watch watch_reads)))
```
只读：`hypsys_ssi_default` / `mqsasd` / `misight` = `(ioctl read getattr open)`。

#### `dm_device` —— `blk_file` **10 条写规则** / `chr_file` **9 个写域**（关键区分，见 §4.1）

```
blk_file（/dev/block/dm-N 这类块节点）
plat_sepolicy.cil:12443   apexd              (ioctl read write getattr lock append map open watch watch_reads)
plat_sepolicy.cil:29724   e2fs               (同上)
plat_sepolicy.cil:31441   fsck               (同上)
plat_sepolicy.cil:32925   gsid               (同上)
plat_sepolicy.cil:44226   init               (同上)
plat_sepolicy.cil:63167   snapuserd          (同上)
plat_sepolicy.cil:76088   update_engine_common(同上)
plat_sepolicy.cil:80906   vold               (同上)
system_ext_sepolicy.cil:1449   installd      (ioctl read write getattr open)
system_ext_sepolicy.cil:6599   system_perf_init (ioctl read write getattr lock append map open watch watch_reads)

chr_file（/dev/device-mapper 这个字符设备控制节点）
apexd, gsid, init, snapshotctl, snapuserd, system_perf_init, ueventd, update_engine_common, vold  ← 有 write
kernel(relabelto), shell(getattr), vendor_init(setattr)                                        ← 无 write
```

### A.2 全部 71 个「块设备/裸盘」type 的写域总表

> `blk_file rules` = 该 type 被多少条 `blk_file` allow 覆盖（含 `dev_type` 泛化规则）。
> 写域一栏为 **NONE** 表示全策略无任何域可写该 type。

| # | type | blk_file rules | writer domains |
|---|---|---|---|
| 1 | `adsp_block_device` | 11 | `update_engine` |
| 2 | `android_esp_block_device` | 11 | `update_engine` |
| 3 | `bl2_block_device` | 11 | `update_engine` |
| 4 | `bl31_block_device` | 11 | `update_engine` |
| 5 | `blackbox_block_device` | 14 | `hal_misys_vendor_default`, `hypsys_ssi_default` |
| 6 | `block_device` | 14 | `init` |
| 7 | `boot_block_device` | 14 | `hal_bootctl_default`, `update_engine` |
| 8 | `boot_logo_block_device` | 11 | `update_engine` |
| 9 | `boot_para_block_device` | 11 | `pwrctl_cmd` |
| 10 | `cache_block_device` | 12 | `fsck` |
| 11 | `ddr_param_block_device` | 11 | `update_engine` |
| 12 | `dfx_block_device` | 13 | `acpu_log_save`, `hal_misys_vendor_default` |
| 13 | `dm_device` | 37 | `apexd`, `e2fs`, `fsck`, `gsid`, `init`, `installd`, `snapuserd`, `system_perf_init`, `update_engine`, `vold` |
| 14 | `dm_user_device` | 10 | **NONE** |
| 15 | `dtbo_block_device` | 12 | `update_engine` |
| 16 | `ffu_partition` | 11 | `ffu` |
| 17 | `frp_block_device` | 11 | `system_server` |
| 18 | `gsort_block_device` | 13 | `hal_cld_default`, `hal_fbo_default`, `mi_ric` |
| 19 | `hdcp_block_device` | 11 | `update_engine` |
| 20 | `init_boot_block_device` | 11 | `update_engine` |
| 21 | `isp_block_device` | 11 | `update_engine` |
| 22 | `logfs_block_device` | 11 | `fsck` |
| 23 | `loop_control_device` | 10 | **NONE** |
| 24 | `loop_device` | 19 | `apexd`, `gsid`, `init`, `mmd_setup`, `mslgd`, `system_perf_init`, `vold` |
| 25 | `lpctrl_block_device` | 11 | `update_engine` |
| 26 | `mcf_ota_block_device` | 11 | `update_engine` |
| 27 | `md_block_device` | 13 | `update_engine` |
| 28 | `metadata_block_device` | 15 | `e2fs`, `fsck`, `init`, `vold` |
| 29 | `minidump_block_device` | 13 | `dumpstate`, `hal_misys_vendor_default` |
| 30 | `misc_block_device` | 21 | `hal_bootctl_default`, `init`, `kcmdlinectrl`, `misctrl`, `mtectrl`, `uncrypt`, `update_engine`, `vendor_init`, `vendor_misc_writer`, `vold` |
| 31 | `miupdate_block_device` | 11 | **NONE** |
| 32 | `mtd_device` | 10 | **NONE** |
| 33 | `mtdblock_device` | 10 | **NONE** |
| 34 | `npu_block_device` | 11 | `update_engine` |
| 35 | `nvcfg_block_device` | 13 | `e2fs`, `fsck`, `init` |
| 36 | `nvmem_block_device` | 11 | `acpu_log_save` |
| 37 | `oops_block_device` | 13 | **NONE** |
| 38 | `para_block_device` | 13 | `em_svr`, `mtkrild`, `rild` |
| 39 | `persist_block_device` | 11 | `fsck` |
| 40 | `protect1_block_device` | 14 | `e2fs`, `fsck`, `init` |
| 41 | `protect2_block_device` | 14 | `e2fs`, `fsck`, `init` |
| 42 | `pvmfw_block_device` | 11 | `update_engine` |
| 43 | `recovery_block_device` | 13 | `update_engine`, `vendor_install_recovery` |
| 44 | `rescue_block_device` | 11 | **NONE** |
| 45 | `root_block_device` | 10 | **NONE** |
| 46 | `rootdisk_sysdev` | 10 | **NONE** |
| 47 | `sap_block_device` | 11 | `update_engine` |
| 48 | `sdcard_block_device` | 11 | **NONE** |
| 49 | `sec_dtbo_block_device` | 11 | `update_engine` |
| 50 | `sensorhub_block_device` | 11 | `update_engine` |
| 51 | `super_block_device` | 17 | `update_engine` |
| 52 | `swap_block_device` | 19 | `init`, `mcd`, `memory_config`, `mmd`, `mmd_setup`, `system_perf_init`, `toolbox` |
| 53 | `system_block_device` | 12 | `update_engine` |
| 54 | `tee_block_device` | 11 | `update_engine` |
| 55 | `ublk_block_device` | 10 | **NONE** |
| 56 | `ublk_control_device` | 10 | **NONE** |
| 57 | `uefi_block_device` | 11 | `update_engine` |
| 58 | `userdata_block_device` | 29 | `acpu_log_save`, `e2fs`, `fsck`, `system_perf_init`, `uncrypt`, `vold` |
| 59 | `userdata_sysdev` | 10 | **NONE** |
| 60 | `vbmeta_block_device` | 11 | `update_engine` |
| 61 | `vendor_charge_block_device` | 11 | `batterysecret` |
| 62 | `vendor_ramdump_block_device` | 13 | **NONE** |
| 63 | `xctrl_cpu_block_device` | 11 | `update_engine` |
| 64 | `xctrl_ddr_block_device` | 11 | `update_engine` |
| 65 | `xhee_block_device` | 11 | `update_engine` |
| 66 | `xloader_block_device` | 11 | `update_engine` |
| 67 | `xrse_block_device` | 11 | `update_engine` |
| 68 | `xspm_block_device` | 11 | `update_engine` |
| 69 | `xsps_block_device` | 11 | `update_engine` |
| 70 | `zoned_block_device` | 13 | `e2fs`, `fsck`, `vold` |
| 71 | `zram_device` | 12 | `mcd`, `system_perf_init` |

**读法**：整机 34 个 `update_engine` 独占的引导类分区（`xloader/uefi/vbmeta/init_boot/pvmfw/tee/xsps/...`）说明
这是 OTA 的标准设计——`update_engine` 是唯一的"分区内容写者"，其余域一律只读。

### A.3 标签落地（实测）

```
$ adb shell ls -lZ /dev/block/by-name/android_esp_a /dev/block/sdc38
lrwxrwxrwx 1 root root u:object_r:android_esp_block_device:s0  16 ... android_esp_a -> /dev/block/sdc38
brw------- 1 root root u:object_r:android_esp_block_device:s0 259,  22 ... /dev/block/sdc38
```

`vendor_file_contexts:666  /dev/block/by-name/android_esp_[ab]   u:object_r:android_esp_block_device:s0`
（另有重复规则 `vendor_file_contexts:702` 指向 `/dev/block/platform/soc/e1a40000.dwc_ufs/by-name/android_esp_[ab]`）

`shell` 上下文/组（实测）：`u:r:shell:s0`，`uid=2000 gid=2000`，
groups = `shell,input,log,adb,sdcard_rw,sdcard_r,ext_data_rw,ext_obb_rw,net_bt_admin,net_bt,inet,net_bw_stats,readproc,uhid,readtracefs`
（**没有 `disk`/`system`/`root`**，DAC 上就打不开 0600 root:root 的节点）。

---

## 3. 表格 B — 这些域的 shell 可达性评级

### B.0 可达性的三个判据机制（先把机制说清，评级才有意义）

| 判据 | 机制 | 关键规则 |
|---|---|---|
| **`service_manager (find)`** | 只允许"在 servicemanager 里按名字查到"，不授予调用 | `plat:83828 (typeattributeset base_typeattr_1030 (and (service_manager_type ) (not (... vold_service ...))))`，由 `plat:62046 (allow shell base_typeattr_1030 (service_manager (find)))` 使用 |
| **`binder (call)`** | **目标集合 = 服务端进程的域**（不是 service label）。这是 `service call` 真能打通的那一层 | `plat:14081 (allow appdomain binderservicedomain (binder (call transfer)))`、`plat:14096 (allow appdomain appdomain (binder (call transfer)))` |
| **unix socket `connectto`** | 只能连到对端 socket，不等于能驱动它 | 23 个 type，见 B.4 |
| **property → init 动作** | `(allow shell X_prop (property_service (set)))` + init `on property:` 块 | 见 §5，本轮新发现 |

shell 的基础能力（实测集合）：

```
shell ∈ appdomain (plat:840)
shell service_manager find  : 641 个 type
shell binder call           : 129 个 type（hop-1 展开 = 115 个 domain）
shell unix_stream connectto : 23 个 type
shell 可 set 的 prop 类型   : 41 个；ctl_start_prop 存在? False
shell 可 exec 的 exec 类型  : 26 个（其中形成 domain 切换的只有 mcd、toolbox）
```

### B.1 逐域评级

| 写域 | 能写的块设备 | shell 可达性 | 判据（可核查） |
|---|---|---|---|
| **`update_engine`** | **`android_esp_block_device`** 等 34 个引导分区 | **需服务漏洞（2 跳）** | `find` ✔(`update_engine_service`)、`binder call` ✘；跳板：`gmscore_app`(`plat:32112`)、`system_server`(`plat:66774`)、`system_app`(`plat:65777`)、`hwservicemanager`、`servicemanager`、`updater`(`system_ext:9920`) |
| `hal_bootctl_default` | `boot_block_device`, `misc_block_device` | **需服务漏洞（2 跳）** | `find` ✔(`hal_bootctl_service`=`android.hardware.boot.IBootControl/default`, `plat_service_contexts:20`)、`binder call` ✘；跳板：`system_server`(`plat:34109`)、`system_app`(`vendor:7079`)、`hwservicemanager`(`plat:41631`)、`servicemanager`(`plat:34144`) |
| `vold` | `misc/userdata/metadata/dm/loop/zoned` | **需服务漏洞（2 跳）** | `find` ✘（`vold_service` 被 `base_typeattr_1030` 排除）、`binder call` ✘；跳板：**`gsid`**(`plat:32880`)、`system_server`(`plat:66804`)、`servicemanager`、`hwservicemanager` |
| **`gsid`** | `dm_device`, `loop_device` | **直接可达** | `gsid` ∈ `binderservicedomain`(`plat:859`) ⇒ `binder call` ✔（hop-1）；`gsid.rc` 实测存在，`interface aidl gsiservice`，`user root`，当前未运行（`disabled`+`oneshot`，可由 `setprop` 拉起） |
| **`mcd`** | `swap_block_device`, `zram_device` | **直接可达（最硬）** | ① `binder call` ✔（`mcd` ∈ `binderservicedomain`）；② **exec 直接切域**：`system_ext_sepolicy.cil:3902` `(typetransition shell mcd_exec process mcd)` + `(allow shell mcd_exec (file (execute ...)))` |
| **`toolbox`** | `swap_block_device` | **直接可达** | `plat:62026` `(allow shell toolbox_exec (file (execute execute_no_trans ...)))`（不切域，但 toolbox 域规则生效） |
| `dumpstate` | `minidump_block_device` | **直接可达** | `plat:62051 (allow shell dumpstate (binder (call)))` |
| `system_server` | `frp_block_device` | **直接可达** | `system_server` ∈ `binderservicedomain`（大量 `(allow shell <svc> (binder (call)))` 通过 appdomain→appdomain 规则） |
| `hypsys_ssi_default` | `blackbox_block_device` | **直接可达** | ∈ `binderservicedomain`；上一轮已实测 `service call miui.mqsas.IMQSNative` 成功 |
| **`kcmdlinectrl`** | `misc_block_device` | **直接可达（property 触发）** | `(allow shell kcmdline_prop (property_service (set)))` `plat:61569`；`/system/etc/init/kcmdlinectrl.rc` `on property:kcmdline.binder=*` → `exec kcmdlinectrl store binder` |
| **`mtectrl`** | `misc_block_device` | **直接可达（property 触发）** | `(allow shell arm64_memtag_prop (property_service (set)))` `plat:61529`；`mtectrl.rc on property:arm64.memtag.bootctl=*` |
| `init` | `block_device, misc, dm, loop, metadata, nvcfg, protect1/2, swap` | **间接可达（property 触发）** | 无 `binder call`、无 exec 切域；但可被 `debug.modem.triggerexception` → `start ${...}` **拉起任意服务**（§5.1），不等于"能命令 init 写盘" |
| `uncrypt` | `misc_block_device`, `userdata_block_device` | **间接可达（可拉起，内容固定）** | 无 binder/socket/exec；可经 `start ${prop}` 拉起；`uncrypt` 写 BCB 内容固定为 `boot-recovery`/清空 |
| `misctrl` / `vendor_misc_writer` / `vendor_init` | `misc_block_device` | **不可达** | 无 `binder call`、无 socket、无 exec、无 shell 可写的 property 触发；`misctrl` 由 init 开机直拉、无属性触发口 |
| `fsck` / `e2fs` / `snapuserd` / `apexd` / `installd` / `system_perf_init` / `mmd_setup` / `mslgd` / `mmd` / `memory_config` / `mi_ric` / `pwrctl_cmd` / `rild` / `mtkrild` / `em_svr` / `ffu` / `batterysecret` / `acpu_log_save` / `vendor_install_recovery` | 各自分区 | **不可达** | 全部 hop=`-`（binder BFS 3 跳内到不了）；且无可 exec 入口、无 shell 可写 property 触发 |

B.2 补充：`binder` BFS 展开（`shell` 起点）
```
hop 1: +115 domains
hop 2: +281 domains
hop 3: +2   domains
```

### B.3 明确回答"shell 能 `service list` 看到、且落在这些域里的服务"

按 label 归类，与上表写域交集后的**完整清单**：

| 服务名 | label | 服务端域 | shell `find` | shell `binder call` |
|---|---|---|---|---|
| `android.hardware.boot.IBootControl/default` | `hal_bootctl_service` (`plat_service_contexts:20`) | `hal_bootctl_default` | ✔ | ✘ |
| `android.hardware.fastboot.IFastboot/default` | `hal_fastboot_service` | `hal_fastboot_default` | ✔ | ✘ |
| `android.os.UpdateEngineService` | `update_engine_service` | `update_engine` | ✔ | ✘ |
| `android.os.UpdateEngineStableService` | `update_engine_stable_service` | `update_engine` | ✔ | ✘ |
| `vold` | `vold_service` (`plat_service_contexts:553`) | `vold` | **✘** | ✘ |
| `installd` | `installd_service` (`plat_service_contexts:338`) | `installd` | **✘** | ✘ |
| `gsiservice`(AIDL, `interface aidl gsiservice`) | — | `gsid` | — | **✔** |
| `miui.mqsas.IMQSNative` | `mqsasd_service` | `hypsys_ssi_default` | ✔ | **✔** |
| `mcd`(AIDL) | — | `mcd` | — | **✔** |

> 结论：**shell 能"看见" `hal_bootctl` / `update_engine` 两个关键服务，但都没有 `binder call`**；
> `vold` 连"看见"都不行。shell 真正能调用的块设备写者只有 `gsid`、`mcd`、`hypsys_ssi_default`。

### B.4 shell 可 `connectto` 的 unix socket（完整 23 个 type，含属主）

`adbd`(adbd_tradeinmode,init)、`dumpstate`(init)、`heapprofd`(init)、`init`(init)、`logd`(init)、`netd`(init)、
`pdx_display_{client,manager,vsync}_endpoint_socket`(init,surfaceflinger)、
`pdx_performance_client_endpoint_socket`(init,performanced)、`prng_seeder`(init)、`tombstoned`(init)、
`traced`/`traced_perf`(init)、`self`。
**无一属于上表的块设备写者** —— socket 通道对写块设备零贡献。

---

## 4. 表格 C — 非 `blk_file` 的替代通道

### 4.1 `/dev/ufs-bsg0` 这类 SCSI generic / bsg 通道

**实测设备节点与标签：**
```
$ adb shell ls -lZ /dev/ufs-bsg0
crw------- 1 system system u:object_r:device:s0  239, 3  /dev/ufs-bsg0
$ adb shell ls -lZ /dev/bsg
ls: /dev/bsg: No such file or directory
```

**策略侧：`device` 这个 chr_file 桶的**全部**权限方（穷举，`chr_file` 类）：**

| 域 | 权限 | 出处 |
|---|---|---|
| `hal_audio_default` | `ioctl` | `plat` `chr_file device` 规则 |
| `init` | `setattr` | 同上 |
| `kernel` | `create getattr setattr unlink` | 同上 |
| `shell` | **`getattr`** | 同上 |
| `ueventd` | `create getattr setattr unlink` | 同上 |
| `vendor_init` | `setattr` | 同上 |

⇒ **全策略没有任何域对 `device` chr_file 有 `open` 或 `write` 或 `read`。**
`/dev/ufs-bsg0` 因为 file_contexts 没有专门条目而落到泛型 `device`，成了**谁都用不了的孤儿节点**。
另外：策略里**不存在** `bsg_device` / `sg_device` / `scsi_generic` / `mmc_device` 类型
（对 `\(type X\)` 检索结果均为 0），所以"bsg 通道"这条路在标签层面就不存在。

**DAC 侧再挡一次**：`crw------- system system`，shell 不在 `system` 组。

### 4.2 `/dev/device-mapper` —— 上一轮结论需要更正

```
$ adb shell ls -lZ /dev/device-mapper
crw------- 1 root root u:object_r:dm_device:s0  10, 236
```

这是**字符设备**（`crw-`）⇒ 内核判定 `tclass=chr_file`。
而 `hypsys_ssi_default` 对 `dm_device` 只有 **`blk_file`** 类的权限
（`system_ext_sepolicy.cil:14434 (allow hypsys_ssi_default dm_device (blk_file (ioctl read getattr open)))`）。

⇒ **该规则对 `/dev/device-mapper` 不生效**，hypsys 无法对它做 `DM_DEV_CREATE`。
`chr_file dm_device` 的 12 个域里**没有 hypsys**。
`UNLOCK_PATHS.md` §3.2「hypsys 有 dm_device ioctl，可 DM_DEV_CREATE + DM_TABLE_LOAD」**在这条 cdev 上不成立**
（对 `/dev/block/dm-N` 这些 blk 节点才成立）。

`chr_file dm_device` 的写者：`apexd, gsid, init, snapshotctl, snapuserd, system_perf_init, ueventd, update_engine, vold`
—— 其中 shell 可达的只有 **`gsid`**。

### 4.3 vold 的 format/partition 接口

`vold` 是 `misc/userdata/metadata/dm/loop/zoned` 的最强写者，但：

```
plat_service_contexts:553   vold   u:object_r:vold_service:s0
plat:83828  (typeattributeset base_typeattr_1030 (and (service_manager_type ) (not (... vold_service ...))))
plat:62046  (allow shell base_typeattr_1030 (service_manager (find)))
⇒ shell 对 vold_service 连 service_manager find 都没有
⇒ `service call vold` / `IVold.format` / `IVold.partition` 全部不可达
```
`vdc` 倒是有 `binder call vold`（`plat:76829`）+ `find vold_service`（`plat:76844`），
但 shell 驱动 `vdc` 的唯一入口是 `exec - root -- /system/bin/vdc AB reuse`
（`/system/etc/init/vdc.rc`，由 `persist.sys.stability.abreuse_status` 触发），**子命令固定**，无法指定目标分区。

### 4.4 update_engine 的分区写

唯一 ESP 写者。它的写内容由 OTA payload 元数据 + `install_plan` 决定，且必须通过 AVB payload 签名校验；
shell 既不能 `binder call` 它，也不能给它签名 payload。见 §5.2。

### 4.5 fsck / mkfs / e2fs 类

`fsck`、`e2fs`、`mmd_setup`、`mslgd` 都是 init 一次性/`disabled` 服务，**无 binder 服务、无 socket、无 shell 入口**，
hop=`-`。`fsck` 只被 `vold`（`(allow vold fsck ...)`）或 init 拉起，二者 shell 都够不到。

### 4.6 loop / ublk / zram 用户态块设备接口

`chr_file loop_control_device` 写者：`apexd, gsid, init, mmd_setup, mslgd, system_perf_init, vold`（**shell 只有 getattr**）。
`chr_file ublk_control_device` 写者：`snapuserd`。
两者都只能**新建**块设备，不能把既有 ESP 分区重新映射；且 shell 对这两个控制节点无 `open`。

### 4.7 小结表

| 通道 | 节点/接口 | 标签 | 谁能写 | shell 可达 | 判定 |
|---|---|---|---|---|---|
| bsg / SCSI generic | `/dev/ufs-bsg0` (239:3) | `device` | **无人有 open/write** | ✘（getattr only） | **死路** |
| dm 控制节点 | `/dev/device-mapper` (10:236) | `dm_device` | `apexd,gsid,init,snapshotctl,snapuserd,system_perf_init,ueventd,update_engine,vold` | 仅 `gsid` | 活，但只能建 dm 设备 |
| dm 块节点 | `/dev/block/dm-N` | `dm_device` (blk) | 10 个域（含 `gsid`） | 仅 `gsid` | 活 |
| vold format/partition | binder `IVold` | `vold_service` | `vold` | ✘（连 find 都没有） | **死路** |
| update_engine 分区写 | binder `IUpdateEngine` | `update_engine_service` | `update_engine` | ✘（find ✔ / call ✘） | 需跳板 + 签名 payload |
| fsck / e2fs / mkfs | init 一次性服务 | — | `fsck,e2fs` | ✘ | **死路** |
| loop-control / ublk-control | `/dev/loop-control`、`/dev/ublk-control` | `loop_control_device` / `ublk_control_device` | 见 4.6 | ✘ | 只能造新设备 |
| property → init exec | 见 §5 | — | `kcmdlinectrl, mtectrl, vdc, ...` | **✔** | 活（内容受限） |

---

## 5. 从 shell 到"能写但触达不到"的域：全部已知跳板

### 5.1 ★ 本轮最重要的新发现：`start ${prop}` 等价于 `ctl.start`

上一轮结论是"shell 没有 `ctl_start_prop` ⇒ 拉不起任何 `disabled` 服务"。
本审计在 `/vendor/etc/init/` 里找到一条**用属性值当服务名**的触发块（**设备实测原文**）：

```
$ adb shell grep -n -B3 -A2 triggerexception /vendor/etc/init/mtk_thinmd.rc
177:    oneshot
178:    disabled
179:
180:on property:debug.modem.triggerexception=*
181:    start ${debug.modem.triggerexception}
```

属性归属（**设备实测** `plat_property_contexts`）：

```
$ adb shell grep -E '^debug\.' /system/etc/selinux/plat_property_contexts
debug.                  u:object_r:debug_prop:s0          ← 前缀匹配
$ adb shell grep triggerexception /vendor/etc/selinux/vendor_property_contexts
（无输出 ⇒ 没有被 vendor 覆盖）
```
⇒ `debug.modem.triggerexception` = `debug_prop`

shell 的写权限（**CIL 原文**）：
```
plat_sepolicy.cil:61139  (allow shell debug_prop (property_service (set)))
```

**⇒ `setprop debug.modem.triggerexception <服务名>` 会让 init 执行 `start <服务名>`，
等价于对**任意已存在的 init 服务**做 `ctl.start`。**

价值与边界：
- 能拉起 `update_engine`（唯一 ESP 写者）、`uncrypt`（misc 写者）、`gsid`、`snapuserd`、`fsck` 等；
- 但 `start` 只负责"让它跑起来"，**不提供把我们的内容交给它的手段**；
- `update_engine` 是 `oneshot`，没有客户端连接会自己退出；`uncrypt` 无 `--setup-bcb` 时写的是固定的 `boot-recovery`；
- 因此它是**"可达性破口"而不是"内容控制原语"**，但它把上一轮"完全拉不起服务"的阻塞去掉了。

### 5.2 binder 跳板（2 跳）—— 全部来自 `(allow <中间域> <目标> (binder (call)))`

| 目标（写者） | 中间域（shell hop-1 可达） | CIL 原文 |
|---|---|---|
| `update_engine` | `gmscore_app` | `plat_sepolicy.cil:32112 (allow gmscore_app update_engine (binder (call transfer)))` |
| `update_engine` | `system_server` | `plat_sepolicy.cil:66774` |
| `update_engine` | `system_app` | `plat_sepolicy.cil:65777` |
| `update_engine` | `updater` | `system_ext_sepolicy.cil:9920` |
| `hal_bootctl_default` | `system_server` | `plat_sepolicy.cil:34109` |
| `hal_bootctl_default` | `system_app` | `vendor_sepolicy.cil:7079` |
| `vold` | **`gsid`** | `plat_sepolicy.cil:32880 (allow gsid vold (binder (call transfer)))` |
| `vold` | `system_server` | `plat_sepolicy.cil:66804` |
| `init` / `uncrypt` / `kcmdlinectrl` / `misctrl` / `mtectrl` / `vendor_misc_writer` | **无** | — |

**`gmscore_app` 实测在运行**（`ps -A -Z`）：
```
u:r:gmscore_app:s0:c512,c768   u0_a235   4361  ...  com.google.android.gms
u:r:gmscore_app:s0:c743,c771   u999_a235 5524  ...  com.google.android.gms
u:r:gmscore_app:s0:c512,c768   u0_a235   7500  ...  com.google.android.gms.unstable
u:r:gmscore_app:s0:c743,c771   u999_a235 8477  ...  com.google.android.gms.unstable
u:r:vold:s0                    root      1337  ...  vold
```
`credstore` / `gsid` / `update_engine` 当前**未运行**（`disabled`/lazy，可由 §5.1 拉起）。

⚠ **跳板的正确语义**：`(allow A B (binder call))` 表示"*A 被允许*调 B"，
不代表"我们能通过 A 让 B 做事"。**每条跳板都要先在中间域上拿到一个"能发起指定 binder 调用"的漏洞**，
因此它们的价值排序取决于中间域的攻击面，而不是 CIL 的写法。

### 5.3 property → 特权动作（本轮从 `research/prop_triggers.txt` + 设备 `*_property_contexts` 交叉得出）

shell 可 `set` 的 41 个 prop 类型中，能触发 init 动作的完整清单：

| 属性名 | 属性类型 | 触发的动作 | rc 文件 |
|---|---|---|---|
| `debug.modem.triggerexception` | `debug_prop` | **`start ${...}`（任意服务）** | `/vendor/etc/init/mtk_thinmd.rc` |
| `persist.sys.stability.abreuse_status` | `system_prop` | `exec - root -- /system/bin/vdc AB reuse` | `/system/etc/init/vdc.rc` |
| `kcmdline.binder` | `kcmdline_prop` | `exec -- /system/bin/kcmdlinectrl store binder ${...}` | `/system/etc/init/kcmdlinectrl.rc` |
| `arm64.memtag.bootctl` | `arm64_memtag_prop` | `trigger mtectrl_update` → `mtectrl` | `/system/etc/init/mtectrl.rc` |
| `sys.install.optimg` | `system_prop` | （触发 `mslgservice.rc` 分支） | `/odm/etc/init/mslgservice.rc` |
| `persist.sys.stability.ddr_freq_enable` | `system_prop` | `start mem_bin_s` / `start mem_bin_w` | `/vendor/etc/init/ddr_freq.rc` |
| `persist.sys.stability.memorycloudctrl.disable_ddr_maxfreq` | `system_prop` | `start vendor.memoryCloudCtrl` | `/vendor/etc/init/vendor.memoryCloudCtrl.rc` |
| `sys.network.vendor_mainline.enable` | `system_prop` | `start minetd` / `start vendor.xiaomi.aidl.minet` | `/vendor/etc/init/minetd.rc` |
| `vendor.audio.cit.spkcal.*` | `vendor_audio_cit_prop` | `start vendor.spkcal_lhasa` / `_yingtian` | `/vendor/etc/init/spkcal_*.rc` |
| `persist.heapprofd.enable` / `persist.traced.enable` / `persist.traced_perf.enable` / `persist.logd.audit.rate` / `sys.lpdumpd` / `sys.rss_hwm_reset.on` | 各自 `*_prop` | 拉起性能/日志类服务 | 对应 rc |

> 注意 `(allow shell_202604 system_prop_202604 (property_service (set)))` 出现在 **`vendor_sepolicy.cil:7091`** ——
> shell 能写 `system_prop` 是 vendor 模块给的，不是 AOSP 默认，值得单独评估。

---

## 6. 结论：按"最快能写 ESP"排序的前 3 条路径

### 路径 1（唯一逻辑闭合）：驱动 `update_engine`

- **需要拿到什么**：一个能让 `update_engine` 用我们指定的内容写 `android_esp_block_device` 的手段。
- **现状（已确证）**：它是全策略**唯一**的 ESP 写者（`vendor_sepolicy.cil:22302`）。
- **缺什么**：
  1. shell 对 `update_engine` 无 `binder call`（`plat` 只给 `shell` 授了 9 个域的 call）；
  2. 即使能调，`IUpdateEngine` 的写入由 payload 元数据驱动且必须过 AVB **payload 签名**。
- **可用的跳板**：`shell → gmscore_app → update_engine`（`plat:32112`，`gmscore_app` 实测在跑）、
  `shell → system_server → update_engine`（`plat:66774`）。
- **本轮新增可用件**：`setprop debug.modem.triggerexception update_engine` 可把它**拉起来**（§5.1），
  这让"它根本没运行"不再是障碍。
- **下一个要验的静态点**：
  ① `android.os.UpdateEngineService` / `UpdateEngineStableService` 的 AIDL 方法表，
  确认是否存在"指定目标分区 + 自带数据"的方法（`applyPayload` 需 URL+hash+签名头；看 `setShouldSwitchSlotOnReboot`
  与 `allocateSpace` 是否有可乘之机）；
  ② `(allow gmscore_app update_engine (binder (call)))` 之外，确认 `gmscore_app` 的 AIDL 暴露面
  （`pm list packages` 已确认 GMS 装上，服务是否 `exported` 到 shell 可 bind 需看 APK manifest）；
  ③ `update_engine.rc` 的 `ue_merge_trigger`（`--start_ue_once --merge`）路径是否绕过 payload 校验。

### 路径 2：`gsid` → 建 dm-linear 覆盖 ESP

- **需要拿到什么**：让 `gsid` 在 `/dev/device-mapper` 上 `DM_TABLE_LOAD` 一条覆盖 `sdc38` 的 `dm-linear`，
  再让一个有 `dm_device:blk_file write` 的域去写 `/dev/block/dm-N`。
- **现状（已确证）**：`gsid` 是 **shell 直接可达**（∈ `binderservicedomain`）且**同时**具备
  `dm_device` 的 `blk_file write`（`plat:32925`）与 `chr_file write`（`chr_file dm_device` 写者之一）；
  `gsid.rc` 实测：`interface aidl gsiservice`、`user root`、`group root system media_rw`。
- **缺什么**：
  1. `IGsiService` 只接受 GSI/DSU 镜像（需 AVB 校验），**不暴露任意 `(dev, offset)` 的 dm 表构造**；
  2. 即便建出 `dm-N`，其标签仍是 `dm_device` —— `gsid` 自己能写（已确认），所以第 2 步其实闭得上。
- **下一个要验的静态点**：
  ① `gsiservice` AIDL 方法表（`/system_ext`/`/system` 下 `IGsiService.aidl` 或 `gsid` 二进制字符串），
  找有没有 `createPartition`/`mapPartition` 之类接受路径或设备名的入口；
  ② `(allow gsid <X> ...)` 全量规则里，`gsid` 是否能读 `/data` 下我们可写的 GSI 镜像路径
  （`gsid` 需要 `open` 一个 payload 文件，若路径可控且不做 AVB，就能喂任意 dm 表）；
  ③ `dm_user_device`（`/dev/dm-user/*`）—— 本策略里 **NONE 写者**，但值得确认是否有 `dm-user` 用户态后端可被 `gsid` 使用。

### 路径 3：`vold`（经 `gsid` 或 `system_server` 两跳）

- **需要拿到什么**：让 `vold` 对 `misc_block_device` / `dm_device` / `userdata_block_device` 执行我们指定的写。
- **现状（已确证）**：`vold` 写了 `misc/dm/loop/userdata/metadata/zoned`；
  shell 对它 `find` ✘ `call` ✘；跳板 `gsid`(`plat:32880`)、`system_server`(`plat:66804`)。
- **缺什么**：中间域上的一个"能指定目标与内容"的漏洞；`vold` 的 `format`/`partition` 本身也只对
  "已注册的卷/分区名"生效，不接受任意 `(dev, offset)`。
- **下一个要验的静态点**：`IVold` AIDL 里 `format`/`partition`/`createUserStorageKeys` 的入参校验；
  以及 `vdc AB reuse` 之外，`vdc` 是否有任何一个子命令能由 shell 可写属性带参传入（本轮已确认**没有**）。

---

## 7. 已排除的路径（避免下一轮重复劳动）

| # | 路径 | 结论 | 证据 |
|---|---|---|---|
| 1 | `hypsys_ssi_default`（uid 0，`IMQSNative` 宿主）写 ESP | **排除（策略级）** | 它对 `blk_file` 只有 `blackbox_block_device` 可写；`userdata_block_device`/`dm_device` 只读；对 `android_esp_block_device`/`misc_block_device` **零规则**（§2、`research/hypsys_rules.txt`） |
| 2 | `hypsys` 用 `/dev/device-mapper` 做 `DM_DEV_CREATE` | **排除（类不匹配）** | 该节点是 `crw-` ⇒ `chr_file`；hypsys 的 `dm_device` 权限是 `blk_file` 类（`system_ext:14434`）。**更正 `UNLOCK_PATHS.md` §3.2** |
| 3 | `shell` 直接写/读 ESP | **排除（实测）** | `(allow shell dev_type (blk_file (getattr)))` `plat:62249`；`dd` 实测 `Permission denied`；DAC 0600 root:root |
| 4 | `shell` 通过 `service call` 调 `vold` | **排除** | `vold_service` 被 `base_typeattr_1030` 的 `not(...)` 排除，`find` 都不允许 |
| 5 | `shell` 通过 `service call` 调 `hal_bootctl` / `update_engine` | **排除** | `find` ✔ 但 `binder call` ✘（无 allow） |
| 6 | `/dev/ufs-bsg0` 走 bsg/SCSI generic | **排除** | 标签是泛型 `device`；无 `bsg_device`/`sg_device` 类型；`device` chr_file 全策略无 `open`/`write` |
| 7 | `/dev/bsg` 目录 | **排除（不存在）** | 实测 `ls: /dev/bsg: No such file or directory` |
| 8 | `uncrypt` 的 `--setup-bcb` / `--clear-bcb` | **排除（内容固定）** | 只能写 `boot-recovery` 或清空；且需 `ctl.start`（现可经 §5.1 拉起，但内容仍不可控） |
| 9 | `kcmdlinectrl` / `mtectrl` 写 misc offset 0 | **排除（偏移）** | 只写 misc 的 system space（kcmdline @≥32768、memtag @≥32832），够不到 `misc+0` |
| 10 | `misctrl` | **排除（无触发口）** | `misctrl.rc` 无 `on property:`，由 init 开机直拉 |
| 11 | `mkfs`/`fsck`/`e2fs` 类服务 | **排除** | 无 binder 服务、无 socket、hop=`-`、不可 exec |
| 12 | loop-control / ublk-control 重建映射 | **排除** | 只能新建块设备；shell 对两个控制节点仅 `getattr` |
| 13 | `mcd` / `toolbox`（shell 最硬的两个可达写者） | **排除（目标不对）** | 只写 `swap_block_device` / `zram_device` |
| 14 | `credit`：靠"改策略放开" | **排除** | 运行时策略只读；且 `misc` 有 `neverallow base_typeattr_493`（`plat:26493`） |

> 补充：`android_esp_block_device` **没有 neverallow**。它单写者纯粹因为"没人被给 allow"。
> 这一点值得记一笔 —— 若将来拿到能重载策略的能力（root），它的开放成本比 misc 低得多。

---

## 8. 未取到 / 局限

| 项 | 状态 | 试过什么 |
|---|---|---|
| `sesearch` / `secilc` 交叉验证 | **未取到** | 本机（Windows）无该工具链；全部结论改为 CIL 文本解析 + 设备只读实测 |
| `hal_bootctl_service` 的实测 `service call` | **未做** | 任务明确禁止调用服务；且 `binder call` 已静态判否，实测无收益 |
| `UpdateEngine` / `IGsiService` / `IVold` 的 AIDL 方法表 | **未取到** | 需从 `/system`/`/system_ext` 拉 AIDL 或反汇编对应二进制；本轮聚焦策略层，留为路径 1/2/3 的下一步 |
| `setprop debug.modem.triggerexception <svc>` 的实测 | **未做** | 实测需写属性（等于改设备状态），本轮只读。静态证据已闭合（rc 原文 + property_contexts + CIL 权限） |
| 设备端 `plat_service_contexts` 与仓库副本的差异 | **未比对** | 已 `adb pull` 到本机临时目录，未逐行 diff（仓库副本 569 行 / 47,192 B 与设备 47,192 B 一致） |
| `blk_file` 的 ioctl 白名单 | **部分** | 存在 `plat_sepolicy.cil:24753 (allowx domain dev_type (ioctl blk_file ((range 0x5450 0x5451))))` 等 xperm 限制；未逐条展开到具体 ioctl 号码 |
| GMS 的 AIDL 暴露面 | **未取到** | 只确认进程在跑；`exported` 与否需看 APK manifest |

---

## 9. 附录：分析脚本（可直接重跑）

本审计**未在工作区新建脚本**（遵守"只新建本文件"）。完整脚本在 `%TEMP%\esp_audit2.py`，
核心逻辑如下，可原样重跑复现 §2/§3 全部数字：

```python
#!/usr/bin/env python3
"""CIL audit: who can blk_file-write the ESP, and how reachable they are from shell.
Handles two traps:
  1) versioned type names (misc_block_device_202604) used by vendor modules
  2) base_typeattr_<N> are numbered PER MODULE -- same name, different set!
"""
import os, re
from collections import defaultdict

BASE = r"...\runs\android"
FILES = ["plat_sepolicy.cil","plat_pub_versioned.cil","system_ext_sepolicy.cil",
         "vendor_sepolicy.cil","odm_sepolicy.cil"]
SUF  = re.compile(r"_\d{6}$")
AUTO = re.compile(r"^(base_typeattr|base_attraddon)_\d+$")

def canon(tok, fn=None):
    if AUTO.match(tok):            # <- trap 2: namespace per module
        return "%s::%s" % (fn, tok)
    return SUF.sub("", tok)        # <- trap 1: strip version suffix

def stmts(path):                   # CIL 括号平衡切分，保留行号
    s = open(path, encoding="utf-8", errors="replace").read()
    i, n, line, depth, cur, start = 0, len(s), 1, 0, None, 0
    while i < n:
        c = s[i]
        if c == "\n": line += 1; i += 1; continue
        if c == "(":
            depth += 1
            if depth == 1: cur, start = [], line
            else: cur.append("(")
            i += 1; continue
        if c == ")":
            if depth == 1: yield start, cur; cur = None
            elif depth > 1 and cur is not None: cur.append(")")
            depth -= 1; i += 1; continue
        if c == ";":
            while i < n and s[i] != "\n": i += 1
            continue
        if c.isspace(): i += 1; continue
        j = i
        while j < n and not s[j].isspace() and s[j] not in "();": j += 1
        if cur is not None: cur.append(s[i:j])
        i = j

def to_tree(toks, i=0):            # 还原 (and ..)/(not ..) 嵌套
    out = []
    while i < len(toks):
        t = toks[i]
        if t == "(": sub, i = to_tree(toks, i+1); out.append(sub)
        elif t == ")": return out, i+1
        else: out.append(t); i += 1
    return out, i

# ... 解析 (type)/(typeattribute)/(typeattributeset)/(allow|neverallow) ...
# 集合求值支持 and/or/not/xor/all/range + 裸列表并集，结果 memo 化
# 然后：ev("<type>") 得到覆盖集合，即可枚举 src/tgt 并集
```

关键统计校验（应完全一致）：

```
types=3812  attrs=3744  allows=27929  neverallows=6155
domain set=714     shell in appdomain=True
block-ish types with blk_file rules = 71 ; rule incidences = 891
shell: find=641  binder-call=129  connectto=23  prop-types=41  ctl_start_prop=False
binder hop: +115 / +281 / +2
android_esp_block_device writers = update_engine        (1)
boot_block_device      writers = hal_bootctl_default, update_engine
misc_block_device      writers = 10 个（见 §2）
dm_device (blk_file)   writers = 10 个 / (chr_file) 9 个
```

---

## 10. 对既有文档的更正汇总

| 文档 / 结论 | 更正 |
|---|---|
| `UNLOCK_PATHS.md` §1.2「`boot_block_device` 的写规则只有 `update_engine_common`」 | **不完整**：还有 `hal_bootctl_default`（`vendor_sepolicy.cil:7073`，带 `_202604` 后缀，朴素 grep 会漏） |
| `UNLOCK_PATHS.md` §3.2「hypsys 有 `dm_device` ioctl，可 `DM_DEV_CREATE`」 | **不成立**：`/dev/device-mapper` 是 `crw-` ⇒ `chr_file`；hypsys 的该权限是 `blk_file` 类，且它不在 `chr_file dm_device` 的 12 个域里 |
| `UNLOCK_PATHS.md` §5.1/§5.3「shell 无 `ctl.start` ⇒ 拉不起任何 disabled 服务」 | **不成立**：`/vendor/etc/init/mtk_thinmd.rc:180-181` 的 `start ${debug.modem.triggerexception}` + `(allow shell debug_prop (property_service (set)))` `plat:61139` ⇒ shell 可启动任意已存在服务 |
| `UNLOCK_PATHS.md` §1.2 中 `misc_block_device` 写者表 | 行号可核对，但 **漏了 vendor 侧 `hal_bootctl_default`**（`vendor:3418`，原名 `misc_block_device_202604`）；补上后写域共 10 个 |
| 一般性提醒 | 任何按 `misc_block_device` / `boot_block_device` 直接 grep 的结论都要复核 `_202604` 变体；`base_typeattr_N` 不能跨文件合并 |

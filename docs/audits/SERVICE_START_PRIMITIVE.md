# shell 可启动任意 init 服务 —— 实测成立的 primitive 与被否掉的 ffu

> 2026-10-22 16:10 · 承接 `ESP_WRITE_DOMAIN_AUDIT.md`

## 1. primitive 本体（已实测）

`/vendor/etc/init/mtk_thinmd.rc`（设备实测原文）：

```
on property:debug.modem.triggerexception=*
    start ${debug.modem.triggerexception}
```

`debug.` 前缀落在 `debug_prop`，`plat_sepolicy.cil:61139` 给 shell `property_service (set)`，
实测：

```
$ setprop debug.modem.triggerexception l65notexist     → rc=0，属性读回=l65notexist，无 AVC
```

⇒ **shell(uid 2000) 可以用任意名字启动本机任何已存在的 init 服务**（包括 `disabled` + `oneshot` 的）。
注意：控制的是**服务名**，不是参数；服务定义本身（binary/args/seclabel）不可控。

## 2. 顺着这个 primitive 找到的头号目标，以及为什么它死了

`grep '^service .*(/data/|/mnt/|/cache/)'` 扫 217 个 rc 文件，最像"能从可写目录吃镜像再刷分区"的是：

```
service ffu_w /vendor/bin/ffu -u /data/vendor/ffu
    class main
    disabled
    user root
    oneshot
    seclabel u:r:ffu:s0
```

**结论：它是 UFS 设备固件更新（Field Firmware Update），不是分区刷写。** 判据是同一个 `ffu.rc`：

```
# rmmod ufs_ffu.ko
service rmmod_ffu_service /vendor/bin/ffu -x
```

`-u` = update、`-r` = return/read、`-x` = 卸载 `ufs_ffu.ko`。
它读写的是 **UFS 器件自身的固件**（SCSI 命令通道），跟 `android_esp` 分区无关；
而且 `/data/vendor/ffu` 是 `2771 root log`，DAC 上 shell（在 `log` 组）够得着，
但 **SELinux 拒**：`touch /data/vendor/ffu/_l65` → `Permission denied`。
⇒ 这条路（a）不解决我们的目标，（b）**触发它反而有把 UFS 固件刷坏的风险，绝对不要 start ffu_w**。

同一次扫描里其余命中项（`mem_bin_w`/`boottrace`/`credstore`/`gatekeeperd`/`keystore2`/`perfetto_trace_on_boot`/
`vendor_tcpdump`/`vendor_sniffer*`）都只是把日志写到 `/data/vendor`、`/data/misc` 下，
对应目录同样被 SELinux 对 shell 关死，且它们的服务域也没有 `android_esp_block_device` 的写权限。
`service console /system/bin/sh` 确实存在，但 `seclabel u:r:shell:s0` —— 与当前身份同级，无收益。

## 3. 这个 primitive 还能怎么用（留给下一轮）

1. **启动一个"读 /data 下可写脚本"的服务**：需要一个 `service` 行里出现在 `/data/...` 或者
   `seclabel` 落在高权限域、且会 exec 脚本的条目 —— 本轮 217 个 rc 里**没有**这种（已扫）。
2. **启动 native service 触发它去 bind 一个新的 unix socket / 创建 /data 下的文件**，
   再用 shell 去 connect —— 需要该服务有这种"输出通道"，本轮未见。
3. **启动 `update_engine`**：它的域是唯一能写 `android_esp_block_device` 的域（`vendor:22302`），
   但 update_engine 会先验 payload 签名（AVB/payload key），没有签名绕过就没有内容控制。
   ⇒ 只有找到 `IUpdateEngine` 里某个**不验签**的写入路径（如 merge/cleanup 类方法）才有意义。
4. **启动 `gsid`**：域里有 `dm_device (blk_file write)`，但 `IGsiService` 只接受 GSI/DSU 镜像，
   且不暴露任意 `(dev, offset)` dm 表 ⇒ 需要 AIDL 层的参数校验漏洞。
5. **启动 `hal_bootctl` 类服务**：`hal_bootctl_default` 有 `boot_block_device_202604` 写权限
   （`vendor:7073`，注意版本化类型名），但它写的是 BCB/misc 语义，不解决 ESP。

## 4. 纪律

- 不要把 `start ${prop}` 当成"能执行任意代码"：它只给**服务名**控制。
- 任何"厂商服务 + /data 可写目录"的组合，先查三件事：目录 DAC、目录 SELinux 标签、服务域的 blk_file 权限。
- `ffu_w` 永远不要手动 start（UFS 固件更新）。

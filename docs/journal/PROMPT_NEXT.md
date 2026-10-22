# 下一轮提示词（直接粘给新会话）

---

## 提示词正文

```
继续小米 18 Fold（lhasa，XRing O3）的实机逆向任务。工作区
C:\Users\user\Documents\deepseek-harness\default-workspace

【第一步，必须先做】
读 runs/android/HANDOVER_2.md，全文。它比第一轮的 HANDOVER.md 新，且第 7 节列了
第一轮 7 处需要修正的结论——不要再去验证那些已被推翻的东西。

【任务目标】
拿到 root（用户已在设备上做过完整备份，明确授权实机操作、允许用第三方开源项目）。
BL 当前锁定；用户已确认官方解锁这条路走不通，只做技术侧。

【当前确切的战况】
解锁链已经全线打通到"只差一次 SELinux permissive"：
  写 android_esp(efisp) → bootloader 未验签加载我们的 GBL → 调
  gbl_efi_avb 协议 slot 8 = write_lock_state(+0x48) → 永久解锁
每一环都有实测或源码证据（见 HANDOVER_2.md §2）。唯一阻塞是写块设备需要
permissive/root。

而这个 permissive 只需要一次内核任意写：把 selinux_state 清零。
  · KASLR 已解决且可重复：每次 boot 跑 research/cap_pair.sh + solve_live.py 解 slide，
    selinux_state = _text + 0x2959630，KIMAGE_VADDR = 0xffffffc080000000
  · 写入原语已确认（反汇编级）：CVE-2026-64560 的 __rb_erase_augmented
    "只有左孩子"分支执行 tmp->__rb_parent_color = pc，即 *(TARGET) = 0
  · 回收原语已解决：/dev/uhid 的 UHID_CREATE2（走 write 不走 ioctl）会
    kmemdup(rd_data, rd_size) 持久保留我们送进去的描述符，rd_size=256 就落在
    kmalloc-256（order-1，32 对象/8KB slab，全内容可控）。实测 2000 设备 →
    kmalloc-256 从 10376/10688 涨到 12352/12352。全零描述符 + 只放两个指针也被接受。

【卡在哪】
只剩竞态命中率。实测 2.8 万次 exec 零命中。结构性原因（HANDOVER_2.md §4.2）：
de_thread() 里 zap_other_threads 会在 release_task(old_leader) 之前就把 victim 内的
删除线程全部杀掉，所以 victim 内删除线程根本不可能命中真正的窗口；能命中的只有
父进程的删除线程，而那个窗口极窄。

【用户已选的方向】
优先做"把 uhid 这个新原语用到别的内核 bug 上"，而不是继续盲目堆 64560 的量。
uhid 现在给了我们一个"全内容可控、持久、order-1、非特权"的 256 字节内核对象，
任何需要 reclaim 的 UAF/OOB 都能从它起。
重点候选：
  1. binder 写路径那个环——BINDER_WRITE_READ 的写侧要求命令缓冲落在 binder 自己的
     VMA 内（错误码差分已证：区外 EINVAL、区内未填充页 EFAULT），去扫
     binder_update_page_range 的全部调用点，看有没有不需要先发 transaction 就能填页的入口
  2. posix_cpu_timer 之外的时间子系统路径
  3. 如果你判断 64560 值得再试，用"时序相位扫描"而不是堆量：把 exec 释放点相对删除
     风暴的相位参数化，每个相位跑固定量，看哪个相位能出毒化 fault

【工作方式（用户明确要求过）】
· 每一轮回复必须至少包含一次真实的工具调用，把分析和执行放在同一轮完成；
  不要只写"接下来我要做 X"就结束回合。宁可一轮做一小步，也不要攒一大步不落地。
· 用好已经建好的判据工具，不要靠猜：
  - research/avc_probe.sh / logcat -d -b all | grep "avc:"  ← SELinux 拒绝 oracle
  - rom/kdisasm.py <elf> <image> <symbol> [n]               ← 按符号反汇编设备真实内核
  - rom/btf_dump.py <image> <struct>                        ← 从 .BTF 取精确结构布局
  - fb3.py（需 FB_PID 环境变量；bootloader=0xd00d，fastbootd=0x4e11）
· 交叉编译：tools/zig/zig-windows-x86_64-0.13.0/zig.exe cc -target aarch64-linux-musl -static -O2 [-pthread] -o X.exe X.c
· 本机 python：C:\Users\user\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe
· 静态分析优先，实机操作前先想清楚风险；破坏性写入尽量先挑 android_esp_b
  （不活跃槽、已标记 unbootable）验证。

【已知的坑】
· uhid 是 write() 不是 ioctl；uhid_event 是 packed，union 在偏移 4（不是 8），总长 4380
· 设备停在 bootloader 时 XRing 的 GBL 没有 reboot/continue/powerdown，只有 oem poweroff；
  恢复方式 = 长按电源键 ~15 秒（会先短暂进 fastbootd 再进系统）
· 标准 fastboot.exe 枚举不到本机（Windows 驱动绑定问题），用 fb3.py
· 不要再去挖 uefi.img / tee.img / xrse.img：已证明是硬件密钥加密（crypt flag +0x110
  与熵 8.0 一一对应，22 个镜像零例外），密钥在 efuse
· 不要再去试：官方解锁/token/账号、写 misc、bcp 注入 cmdline、mqsas 后门、
  属性触发 init、上游 6.18.22 补丁——全部有实测证据封死（HANDOVER_2.md §6）

拿到 permissive 或 root 之后立刻转执行阶段：hypsys code 7 写 android_esp_a
→ 自造 EFI/GBL 调 write_lock_state(+0x48) → 永久解锁 → 刷 Magisk。
```

---

## 给用户的操作提示（不是给 AI 的）

1. 新会话直接把上面```里那一整段粘过去即可。
2. 设备如果停在 bootloader / fastbootd：**长按电源键 ~15 秒**强制重启，会自动回系统。
3. 后台战役如果还在跑（`/data/local/tmp/l64c.log`），可以先不管；
   要停就 `adb shell pkill -9 -x l64`。

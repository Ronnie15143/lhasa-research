# 直接粘贴给外部模型的开场（配套文件：CODEX_PACKAGE.md）

下面的文本是给外部模型的**开场 + 请求**。把 `CODEX_PACKAGE.md` 的内容一并贴给它（或作为附件），
然后贴这段作为提问。已尽量去掉"让它泛泛而谈"的空间。

---

```
我在做一台我自己拥有的设备的逆向（Xiaomi 18 Fold，lhasa，XRing O3，Android 17 / HyperOS OS4.0.21.0，
内核 6.18.21-android17，SPL 2026-08-01，bootloader 锁定）。我附上了一份完整的技术包（CODEX_PACKAGE.md），
里面有：设备与加固配置的硬事实、已经打通的解锁链（写 android_esp → 自造 GBL → gbl_efi_avb.write_lock_state）、
已经用证据排除的 11 条路（每条带地址/文件）、uid 2000 的可达面实测清单、以及我手上现成的原语
（uhid 的 order-1 全控 kmalloc-256、AF_UNIX 的 order-1 全控 8192B 页、mm->mmap_base 任意写、可执行 ashmem、
已解出的 KASLR slide）。

我卡住的地方很具体：**唯一能写目标分区（android_esp_block_device）的 SELinux 域是 update_engine**，
而 uid 2000 能触到的内核内存破坏面我已经逐个审计并排除。请只针对下面 5 个问题回答，不要重复
技术包里已经关闭的路，也不要给"官方解锁/换设备"这类建议：

Q1 在这种配置下（无 userns / 无 io_uring / 无 bpf / 无 keyring / 无 perf / 无 SYSVIPC / 无 POSIX_MQUEUE，
HARDENED_USERCOPY + BUG_ON_DATA_CORRUPTION + CFI + INIT_ON_ALLOC + PAN/MTE、KASAN 关闭），
   uid 2000 还剩哪些**具体**的内存破坏面是我没列的？给子系统 + 触发 syscall/设备 + 对象所在 slab +
   为什么能绕开这些加固。我特别没审过：tty flip buffer、procfs/sysfs 写路径、shmem/tmpfs、dma-buf 与
   mali fd 传递、binder fd 传递、pidfd_getfd、process_vm_writev、epoll/timerfd 的 fd 生命周期。

Q2 我只有一个 uid 0 的**文本写**原语（把一个字符串写进任意路径）。有没有办法用它写出一个
   bootloader 的 FAT 驱动能接受、且包含任意 ELF 内容的 ESP 镜像？（难点：FAT 引导扇区/FAT 表必然含 0x00）
   或者有没有办法让这个原语变成"按偏移写/追加写"（/proc/self/fd/N、loop backing file、device offset 之类）？

Q3 update_engine 是唯一能写目标分区的域。在"shell 能 start 任意 init 服务"的前提下，
   有没有不依赖 payload 签名的办法让它写我给的字节？（AIDL 里 merge/cleanup/suspend 类方法、
   --payload_path 能否注入、/data/ota_package 可写性、是否 dlopen /data 下的库）

Q4 已有四样东西：(a) 本进程 mm->mmap_base 任意写、(b) 可执行 ashmem、(c) uhid 的 order-1 全控对象、
   (d) AF_UNIX 的 order-1 全控页。在**没有任何 UAF/OOB** 的前提下，能不能组合出"让内核替我写块设备"的效果？
   我认为 PAN/PXN 让"内核执行用户页"不成立，请指出这个判断哪里有漏洞。

Q5 以你的经验，这类"BL 锁定 + 无 userns + 厂商加固"的设备，实际被攻破时最常走哪条路？
   按"最可能先出成果"排序（厂商 binder 服务 / OTA 客户端 / fastbootd 用户态 / vold / gsid /
   keystore / gatekeeper …），并给第一步该查什么。
```

# C1 复核：`mt_get_feature` 缺 report-ID 校验**不构成越界**（本轮反汇编逐条核）

> 2026-10-22 16:05 · 对象：`UAF_HUNT_SHORTLIST.md` 的 C1（6.18.22 #267）
> 结论：**不要按 C1 去做 PoC**。它缺的那道校验，在本机被 #268 的守卫吃掉了。

## 1. 本机代码事实

`mt_get_feature @ 0xffffffc080f8d240`：

```
+0x14  ldr  w9,  [report+0x84c]        ; report->size (bits)
+0x18  ldr  w10, [report+0x30]         ; report->id
+0x30  cinc w22, w9, ne                ; size = ceil(bits/8) + (id != 0)   ← 按"被请求的报告"精确算
+0x40  bl   hid_alloc_report_buf       ; 紧桶 kmalloc，长度 = w22
+0x64  bl   hid_hw_raw_request(hdev, id, buf, w22, 2, 1)
+0x84  bl   __hid_report_raw_event(hdev, 2, buf, w22, w22, 0)
```

`__hid_report_raw_event @ 0xffffffc080f656fc`（**本机已有 #268 的守卫**）：

```
+0x48  ldrb w10, [data]                ; reportnum = data[0]  ← 设备给的、可被 uhid 伪造的 ID
+0x58  ldr  x24, [bucket+0x18]         ; report = 按*返回的* ID 查到的报告
+0x68  ldr  w9,  [x24+0x84c]           ; 该报告的 bits
...    w22 = min(rsize_cap, ((bits-1)>>3)) + (id != 0)     ; rsize
+0xb0  sub  x23, x3, x19               ; size - (id?1:0)
+0xb4  cmp  x23, w22
+0xb8  b.hs +0x824                     ; size-idbytes >= rsize 才进解析
+0xbc  ...  dev_warn("Event data for report %d is incorrect (%d vs %zu)")
+0xf4  mov  w0, #-0x16                 ; -EINVAL，直接返回
```

## 2. 为什么"ID 不匹配 ⇒ 读越界"不成立

C1 的越界设想是：让设备对请求 R1 回一个 **报告 ID = R2**（R2 更大）的应答，
于是 `__hid_report_raw_event` 按 R2 的 `rsize` 解析只有 `len(R1)` 字节的缓冲区。

但本机在 `+0xb4/+0xb8` 就把它挡掉了：
`size - (id?1:0) < rsize(R2)` ⇒ 走 `+0xbc` 的 `_dev_warn` 然后 **返回 -EINVAL**，
**解析循环（`+0x824` 起）根本进不去**。
而 `+0x824` 是这一路唯一的出口（`b.hs`），没有第二条到解析循环的边。

反过来，若 R2 的 `rsize <= size - idbytes`，解析就是**在缓冲区内**的，不会越界；
字段位偏移本来就由内核自己解析过的描述符决定，字段不会越过该报告的 `rsize`。

`#268` 那道 memset（`+0x14c bl __pi_memset`）也确实被夹死：
它只在 `rsize > size - idbytes` 时才执行，而这个条件正好是 `+0xb4` 已经判为"不足"的分支，
两处互斥 ⇒ memset 是死代码。这与 `UAF_HUNT_SHORTLIST.md` 里对 #268 的结论一致。

## 3. 那 #267 到底留下什么

只剩**语义/逻辑**层面的东西：`mt_get_feature` 会把"不是我要的那份报告"的数据
当成自己那份报告继续用（读完 `hid_report_raw_event` 之后按固定偏移取字段），
在 `INIT_ON_ALLOC_DEFAULT_ON=y` 下未被设备写到的字节是 0
⇒ 最坏是"设备能影响驱动的某些标量（采样率/接触数上限）"，
**没有内存破坏、没有越界读写**。对我们的目标（内核任意写）无价值。

## 4. 下一步该怎么办（替代 C1）

1. `uinput` 那条（C2）已确认与 `/dev/uhid` **同标签同权限**（`uhid_device`，shell 在 `uhid(3011)` 组），
   且 `input_ff_upload / input_ff_erase / uinput_ff_upload_from_user / uinput_dev_erase_effect`
   全在 Image 里（可静态审）——这是目前**唯一"可达 + 可静态审计 + FF 上传/擦除天然有多对象生命周期"**
   的面，优先做。
2. `ashmem` 小米变体（C3）：Rust 驱动（`Rust-for-Linux` 的 `Miscdevice` 抽象），
   预期漏洞密度低；只在 uinput 也不出结果时再看。
3. `xr_fbt`：可达性成立但**驱动在模块里、vmlinux 0 符号**，
   要审必须先取到模块镜像（本地 OTA zip 只有 `firmware-update/*`，需要完整 OTA URL 或 `vendor_dlkm.img`）。
   `mali0` 同理并且已排除：`gpu_device` 的 allow 域不含 shell（这也解释了 `l71` 的 `EPERM`）。
4. 别忘了另一条腿：**SELinux 域审计**（`ESP_WRITE_DOMAIN_AUDIT.md`）。
   如果存在"能写 ESP 的域且 shell 可触达"，就完全不需要内核漏洞。

## 5. 给下一轮的纪律

- 本文件之后，把 C1 从候选里**移出**（不是降级），避免有人照着它的第 5 步去 panic 设备。
- 任何"缺某道校验 ⇒ 可越界"的候选，**必须先证明该路径真的能进到解析/拷贝循环**，
  再谈溢出方向；本机 `__hid_report_raw_event` 已经证明有硬守卫。

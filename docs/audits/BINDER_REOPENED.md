# binder 写路径重新打开（实测推翻 HANDOVER_2 §3）

> 2026-10-22 16:50 · 设备实测（`/data/local/tmp/l73`，uid 2000）

## 1. 实测证据

```
=== l73 binder write-path probe (uid=2000) ===
  binder mmap=0x786057b000
  BC_ENTER_LOOPER (0x0000630c)               ret=0   OK                write_consumed=4
  bare 0x0c (HANDOVER_2's mistake)           ret=-1  Invalid argument  write_consumed=0
  BC_EXIT_LOOPER (0x0000630d)                ret=0   OK                write_consumed=4
  BC_TRANSACTION handle=0 size=0             ret=0   OK                write_consumed=68
  BC_TRANSACTION handle=0 size=64 (in VMA)   ret=0   OK                write_consumed=68
```

结论：

1. **HANDOVER_2 §3「写路径要求缓冲落在 binder 自己的 VMA 内、区外 EINVAL」是测量伪影。**
   当年写的是裸命令字 `0x0c`，内核比的是 ioctl 编码值 `0x0000630c` ⇒ 落进
   `default: "unknown command %u"` → `-EINVAL`、`write_consumed=0`。上面第 2 行完整复现了这个伪影，
   第 1/3/4/5 行用正确编码后 **write_consumed = 4 / 68**，说明命令被解析并派发。
2. `BC_TRANSACTION` 被完整消费（4 字节命令 + 64 字节 `binder_transaction_data` = 68），
   **事务路径对 uid 2000 可达**。
3. 「区内未填充页 → EFAULT」也不是 binder 自己的 VMA 判定，而是 `get_user` 撞上
   `binder_vm_fault`（只返 SIGBUS）走 fault fixup —— 两条都属于"用户指针正常语义"。

> 顺带一个自己的坑：`struct binder_write_read` 里 `binder_size_t` 在 64 位下是 `__u64`，
> 我第一版按 `uint32_t` 声明，内核读到全 0 ⇒ 每个命令都"ret=0 但 consumed=0"。
> 用 32 位字段时这个 ioctl 会**静默成功**，很容易误判成"命令被吃了"。

## 2. 这条修正意味着什么

binder 从"只有只读探索价值"变成**主攻面**：

- 可发 `BC_TRANSACTION`（含任意 `data_size` / `offsets_size` / `flat_binder_object` 数组）；
- 可发 `BC_FREE_BUFFER` / `BC_INCREFS` / `BC_ACQUIRE` / `BC_REPLY` / `BC_DEAD_BINDER_DONE` 等；
- 服务侧可达性取决于 SELinux 给 shell 的 `binder call` 白名单（审计原文：shell 只被授了 9 个域的 call），
  但**发出去这一步本身**（解析、offsets 校验、buffer 分配、失败清理）都在内核里跑，全部可达。

## 3. 已知候选与口径

`BINDER_ALLOC_AUDIT.md` 的 F1（全局 `binder_freelist` 的 LRU/出 LRU 不对称 ⇒ 在用页被 shrinker
`zap+__free_pages`）是**地址级可证的真缺陷**，但口径只能是**拒绝服务**：写落点是常量非映射地址、
每次命中会 `PANIC_ON_OOPS` 重启、而且 shrinker 放回的是 order-0 页（现有 uhid/AF_UNIX 原语都是 order-1）。
⇒ 不当提权路线用。

## 4. 审计结果（本轮闭环）

`BINDER_TXN_AUDIT.md` 的结论：**事务路径没有 uid 2000 可触发的 OOB / UAF**，而且是结构性的：

- `offsets` 数组在进循环前**一次性拷进内核 buffer**（`0x1c8128-0x1c8140`），循环只读内核副本（`0x1c81d0`）⇒ 没有 TOCTOU；
- 每个对象都有 `type→object_size` 派生的边界（`offp ≤ data_size-object_size`，`0x1c83e4`）+ 单调不减（`0x1c83f0`）
  + `offp & 3`（`0x1c8234`）+ `data_size-offp ≥ 4`（`0x1c8244`）；`data_size/offsets/extra` 的溢出在 alloc 里查（`0x1cafe0-0x1cb030`）；
- 对象内容按 `min(data_size-offp, 40)` 截断拷进 **40B 零化栈缓冲**（`0x1c81c0-0x1c8314`），四种 type 都按完整
  `object_size` 回写（FD 24 / BINDER·HANDLE 24 / PTR 40 / FDA 32）⇒ 无 stale-bytes 泄露；
- 失败只在一处释放（`0x1ca038`），release 循环上界是 `failed_at`，三个 pre-loop 失败块显式归零
  ⇒ "offsets 未校验就进释放"的经典形状**不存在**；
- `binder_thread_read` 不回吐 buffer 内容（只写 64B `binder_transaction_data`，ptr 指向接收方自己的 mmap）⇒ 无 OOB read。

两条对前提的修正：

1. `security_binder_transaction` 在 `binder_alloc_new_buf` **之前**（`0x1c85a4 < 0x1c80c4`），所以"handle=0 也能跑满解析"不成立；
   **但**本机 servicemanager 在，设备实测 shell 的 `service list` 能返 543 个服务 ⇒ handle=0 的事务确实过 SELinux、
   能把分配 + 拷贝 + 对象翻译 + 投递整条路径跑满。**PoC 不需要先找一个可 call 的服务。**
2. `t->flags = tr->flags`（`0x1c7e18`）**没有掩码**（`0x1c2bc4-0x1c2c1c` 只做 64B copy_from_user）
   ⇒ `TF_CLEAR_BUF(0x20)` 用户可控，`binder_alloc_clear_buf`（`0xffffffc0804370c0`）**实测可达**。
   它补上了 `BINDER_ALLOC_AUDIT §6` 那个"未取到"的 F4 前提，但和 F1 组合只是把"读空页槽"升级成
   "往已回收页 memset 0" ⇒ 口径仍是 **DoS / 数据破坏**，不是提权。

⇒ **binder 两条线都不给提权**：分配器 F1 = DoS，事务路径 = 干净。唯一还没挖的是 PTR/FDA 的
`binder_validate_ptr / validate_fixup / defer_copy / fixup_parent` 四个 helper（本机 binder 不是上游原样，
有分块懒拷贝 + 对象用户态二次读 + fd_fixups + secctx 追加），记为深水区、不当当前主线。

## 5. 下一步（已派专项）


真正的目标变成 **事务路径的 OOB/UAF**：`offsets` 数组与 `flat_binder_object`（BINDER_TYPE_BINDER /
HANDLE / FD / PTR）的解析、`binder_alloc_new_buf` 的 size 计算、失败时
`binder_transaction_buffer_release` 的回收遍历、以及 `binder_thread_read` 的回吐。
历史 CVE 大多长在这里。判据仍然要求：对象桶 + 触发序列 + 命中信号 + 能否用现有原语 reclaim。

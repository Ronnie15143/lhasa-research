# BINDER_ALLOC_AUDIT — binder（新）页面分配器与 buffer 生命周期静态审计

- 目标：小米 18 Fold（lhasa，XRing O3），内核 `6.18.21-android17-5-g284297031c53`，4K 页，SELinux Enforcing，
  `kasan=off`、`CONFIG_PANIC_ON_OOPS=y`、`CONFIG_BUG_ON_DATA_CORRUPTION=y`、`CONFIG_RANDOM_KMALLOC_CACHES` 未设、`CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`。
- 攻击者：`adb shell` uid 2000，无 cap，Seccomp 0，`/dev/binder` 与 `/dev/binderfs/binder` 可 open。
- 方法：**纯静态**。全部结论来自本机镜像 `rom/vmlinux-4.0.21.0.elf`（139213 符号）+ `rom/Image-4.0.21.0.bin`
  （`file_off = link_addr - 0xffffffc080000000`）反汇编，以及镜像内 `.BTF` 的精确结构布局。**未在设备上执行任何 PoC**。
- 已关闭方向（不重复）：CVE-2026-64560（`64560_DEAD_ON_LHASA.md`）、hid-multitouch（`HID_MT_C1_RECHECK.md`）、uinput（`UINPUT_FF_AUDIT.md`）。

---

## 0. 结论摘要

1. **本机 binder 的页面分配器是一套全新的、与上游老 `binder_update_page_range` 完全不同的实现**
   （`binder_page_alloc/insert/lookup/free_page` + **全局** `binder_freelist` LRU + shrinker，
   `binder_update_page_range` 符号在本机**确实不存在**）。老模型「buffer 独占自己的页」被换成
   「页在 buffer 之间共享、页的可回收状态记在一条全局 LRU 上」，**页面归属只靠簿记**，没有任何反查结构。
2. **HANDOVER_2 §3 那条「binder 写路径要求命令缓冲落在自己的 VMA 内（区外 EINVAL / 区内未填充页 EFAULT）」是测量伪影，必须撤销。**
   写路径只做两件事：`untag(ptr)` + `ptr < TASK_SIZE(0x00007fffff0000)` 检查（`binder_ioctl_write_read+0x164`，
   `0xffffffc0801c2864`），随后直接 `get_user` 取命令字（`0xffffffc0801c28a8`，`ldtr w19,[x8]`）。
   当时观察到的 `EINVAL` 全部来自 **命令字用错**（写了裸 `0x0c`，而内核比较的是 **ioctl 编码值** `0x0000630c`，见 §3.2/§3.3），
   落进 `default: ... "unknown command %u"`（字符串 `0xffffffc0819bcd21`）→ `-EINVAL`；`write_consumed` 保持 0，与实测现象一致。
   `区内未填充页 → EFAULT` 这一半是对的，但原因是 `get_user` 打在未填充的 `VM_MIXEDMAP` 页上，
   撞 `binder_vm_fault`（`0xffffffc081017444: mov w0,#2` = `VM_FAULT_SIGBUS`）→ fault fixup → `-EFAULT`，
   **不是** binder 自己的 VMA 判定。结论：**binder 写路径对 uid 2000 完全可达**，之前"形成调用环"的判断不成立。
3. **找到一个地址级可证的生命周期缺陷（F1）**：全局回收 LRU 的「加入」区间与「摘除」区间不一致，导致
   **一个仍被 allocated buffer 部分覆盖的页可以留在 LRU 上**，shrinker 会把它 `zap + __free_pages` 掉；
   而 binder 的三条 copy/clear 路径对 `pages[idx] == NULL` **没有任何检查**，直接用它算 `page_to_virt`。
   后果：目标进程 SIGBUS / 数据损坏（确定），内核 oops → **panic 重启**（确定，`PANIC_ON_OOPS=y`），
   以及一个**窄竞态下的 ≤4095 字节可控写**（写进已回到 buddy 的页）。可利用性判断见 §4.5：**按 DoS 计，不按 LPE 计**。
4. 其它 3 项（`BUG_ON(!list_lru_add/del)`、`-EBUSY`+GUP 路径、`clear_on_free` 无锁 memset）逐条给地址，
   其中 `-EBUSY` 路径静态判定为**不可达（防御性死代码）**，`clear_on_free` 的用户可控性**未取到**（见 §6）。

**候选清单（一行一条）**

```
目标 proc 的 binder_alloc pages[] / 全局 binder_freelist（order-0 page + kmalloc-32 LRU 节点）
  · open(/dev/binder)+mmap → BC_TRANSACTION x3（size 0x800 / 0x900 / 0xf00，服务端 FIFO free）→ BC_TRANSACTION（size 0xff0）→ 本进程制造内存压力触发 reclaim
  · page-UAF（在用的页被 zap+free）→ pages[idx]==NULL 无检查解引用（oops/panic）+ 窄窗口 <=4095B 可控写
  · 入 LRU：binder_alloc_free_buf+0x1f4(0x8180908, 补 next 边界页) / +0x38c(0x8180aa0, 补自身边界页)  vs  出 LRU：binder_alloc_new_buf+0x2f4(0x81cb294)/+0x2fc(0x81cb29c)；binder_alloc_free_page 0x8101df90(清 pages 槽)/0x8101dfd4(zap_page_range_single)/0x8101e0d8(__free_pages)；无检查解引用 0x812c4bc / 0x8183290 / 0x81122e4 / 0x80437134
  · 目标进程读到自己 buffer 时 SIGBUS；或 dmesg "Unable to handle kernel paging request" in binder_alloc_copy_* → panic 重启
```

---

## 1. 结构（BTF 精确偏移，全部来自本机镜像）

`rom/btf_dump.py` 只给字节偏移，本审计另外打印了 **原始 bit 偏移**（`kflag=1`），因此位域语义是精确的。

### 1.1 `struct binder_alloc`（152 B）

| off | 字段 | 备注 |
|---|---|---|
| 0x00 | mutex | alloc 级互斥（free_buf / prepare_to_free / deferred_release 持有；**alloc 的页分配阶段不持**） |
| 0x28 | mm | `binder_alloc_init` 里 = `current->mm`（`0xffffffc080415ef4-0x415ef8`） |
| 0x30 | vm_start | `binder_alloc_mmap_handler` 写入（`0xffffffc08041d62c`） |
| 0x38 | buffers | list_head，按地址排序的 buffer 链（含空闲） |
| 0x48 | free_buffers | rb_root（best-fit） |
| 0x50 | allocated_buffers | rb_root（按 `user_data` 排序，`prepare_to_free`/copy 用） |
| 0x58 | free_async_space | 一半 buffer_size（`0xffffffc08041d744-0x41d754`） |
| 0x60 | pages | `struct page **`，kvmalloc（`0xffffffc08041d638-0x41d658`），**按 `(addr-vm_start)>>12` 索引** |
| 0x68 | freelist | **指向全局 `binder_freelist`（`0xffffffc08297ce88`）**，`binder_alloc_init` `0xffffffc080415f2c-0x415f34` |
| 0x70 | buffer_size | mmap 长度，**>4MB 截断到 4MB**（`0xffffffc08041d608-0x41d624`） |
| 0x78 | pid | |
| 0x80 | pages_high | 历史高水位（`binder_alloc_new_buf+0x524` 更新） |
| 0x88 | mapped | `bool`，mmap 时 `stlrb 1`（`0xffffffc08041d758`）、`binder_alloc_vma_close` `stlrb 0`（`0xffffffc0802784c8`） |
| 0x89 | oneway_spam_detected | |
| 0x90 | android_oem_data1 | 厂商字段（全静态扫描未见引用） |

### 1.2 `struct binder_buffer`（104 B）与位域（**bit 级**）

| off | 字段 | 备注 |
|---|---|---|
| 0x00 | entry | list_head（地址序） |
| 0x10 | rb_node | 在 free_buffers / allocated_buffers 之间搬 |
| 0x28 | bit0 `free` / bit1 `clear_on_free` / bit2 `allow_user_free` / bit3 `async_transaction` / bit4 `oneway_spam_suspect` / bit5..31 `debug_id` | 见 §3.5 的置位/清位点 |
| 0x30 | transaction | 非空 <=> 仍挂在事务上（free 前必须摘掉） |
| 0x38 | target_node | async 事务的 node（释放时要从 node->async_todo 摘） |
| 0x40/0x48/0x50 | data_size / offsets_size / extra_buffers_size | |
| 0x58 | user_data | 用户态指针（`vm_start + 偏移`），**8 字节对齐**（不是页对齐） |
| 0x60 | pid | |

### 1.3 新增的「页元数据节点」（kmalloc-32，`page->private` 指向它）

`binder_page_alloc`（`0xffffffc08027d4d8`）：

```asm
0xffffffc08027d4fc  mov  w0, #0xdc2              ; GFP_KERNEL|__GFP_ZERO, order 0
0xffffffc08027d50c  bl   __alloc_pages_noprof
0xffffffc08027d524  mov  w2, #0x20               ; kmalloc(32)
0xffffffc08027d52c  bl   __kmalloc_cache_noprof
0xffffffc08027d53c  stp  x20, x19, [x8, #0x10]   ; node->alloc = alloc ; node->page_index = idx
0xffffffc08027d540  str  x8, [x8]                ; INIT_LIST_HEAD(&node->lru)
0xffffffc08027d544  str  x8, [x8, #8]
0xffffffc08027d548  str  x8, [x0, #0x28]         ; page->private = node
```

即 `struct { list_head lru; struct binder_alloc *alloc; unsigned long page_index; }`（与 BTF `binder_shrinker_mdata` 32 B 一致）。
**节点里没有 `struct page *`**：页是从 `alloc->pages[page_index]` 反查的（这点决定了 §4 的缺陷）。

### 1.4 四件套语义

| 函数 | 地址 | 语义（反汇编结论） |
|---|---|---|
| `binder_page_alloc(alloc, idx)` | `0xffffffc08027d4d8` | `alloc_pages(GFP_KERNEL\|ZERO,0)` + kmalloc(32) 节点 + `page->private = node`；失败 `__free_pages`（`0x27d5cc`）并返回 NULL |
| `binder_page_insert(alloc, vaddr, page)` | `0xffffffc0803913cc` | `lock_vma_under_rcu(mm,vaddr)`（`0x3913f8`）→ 失败则 `down_read(mm->mmap_lock)`+`mtree_load`（`0x3914a4-0x3914b8`）；**只检查 `alloc->mapped`**（`0x391404`，否则 `-ESRCH`）→ `vm_insert_page(vma,vaddr,page)`（`0x39141c`）；随后放 VMA 引用（`0x391420-0x391450`）。**不校验该 vma 就是 binder 的 vma** |
| `binder_page_lookup(alloc, vaddr)` | `0xffffffc08027d654` | `down_read(mm->mmap_lock)` + `mapped` 检查 + `get_user_pages_remote(mm,vaddr,1,0x20,&page,NULL)`（`0x27d6bc`）；成功返回 page，否则 NULL |
| `binder_free_page(page)` | `0xffffffc080285078` | `kfree(page->private)` + `__free_pages(page,0)` —— **无条件按"驱动自有页"处理** |

注意：`binder_page_lookup` 的 gup_flags 立即数是 **0x20**（`0x27d6b4/bc`）。该值在 6.18 的 `FOLL_*` 语义下未被本次静态分析确证
（若要靠它拿引用计数，语义会与 `binder_free_page` 的 `__free_pages` 冲突）。见 §6「未取到」。

### 1.5 全局 LRU + shrinker（这是与老实现最大的差别）

- `binder_freelist`：`.data` 里的**全局 `struct list_lru`**（`0xffffffc08297ce88`），**所有进程共用一个**。
- shrinker 在 `binder_init+0x14` 注册：`0xffffffc08221cae4 -> binder_alloc_shrinker_init`（`0xffffffc08101e314`）。
- `binder_shrink_scan`（`0xffffffc08101e390`）：
  `list_lru_walk_node(&binder_freelist, 0, binder_alloc_free_page, NULL, &sc->nr_to_scan)`（`0x1e3b0-0x1e3d0`）。
- `binder_shrink_count`（`0xffffffc08031b4b8`）= `list_lru_count_node(&binder_freelist,0)`。
- `binder_alloc_free_page(item, list, lock, cb)`（`0xffffffc08101deec`）**逐个 LRU 节点**做：

```
x20 = item[0x10]              ; ->alloc          (0xdf0c)
x22 = item[0x18]              ; ->page_index     (0xdf28)
mmget_not_zero(alloc->mm)                        (0xdf20)
vma = lock_vma_under_rcu(mm, alloc->vm_start + idx*0x1000)    (0xdf3c)
      失败: down_read_trylock(mm->mmap_lock) + mtree_load      (0xdf54/0xdf68)
      还是失败 -> return 3（整条跳过，不入账）
mutex_trylock(&alloc->mutex) 失败 -> 跳过          (0xdf74)
if (vma && !alloc->mapped) -> 解锁 + 跳过          (0xdf80-0xdf88)
page = pages[idx]; pages[idx] = NULL  (stlr)      (0xdf90-0xdfa0)   ★先摘槽
list_lru_isolate(list, item); spin_unlock         (0xdfb0/0xdfb8)
if (vma) zap_page_range_single(vma, addr, 0x1000, NULL)  (0xdfd4)    ★撤 PTE
mutex_unlock / 放 vma 引用 / mmput_async          (0xdfdc-0xe0c4)
kfree(page->private); __free_pages(page,0)        (0xe0cc/0xe0d8)    ★页回 buddy
return 1
```

**关键**：shrinker 从不反查「这个 page_index 是否被某个 allocated buffer 覆盖」。LRU 是**唯一**的"可回收"判据。

### 1.6 生命周期时序（正常路径，含锁）

| 阶段 | 谁做 | 锁 | 地址 |
|---|---|---|---|
| `mmap` | `binder_mmap` -> `binder_alloc_mmap_handler` | `binder_alloc_mmap_lock`（全局） | 0x8041d4d4 / 0x8041d5c4 |
| 建 VMA | 清 `VM_MAYWRITE`，置 `VM_DONTCOPY\|VM_MIXEDMAP`，`vm_ops=binder_vm_ops`，`vm_private_data=proc`；`VM_WRITE` 直接 `-EPERM` | — | 0x8041d534 / 0x8041d544-0x41d56c |
| 建页表数组 | `pages = kvmalloc(nr_pages*8, GFP_KERNEL\|ZERO)`；**此时一页都不映射** | 同上 | 0x8041d638-0x41d658 |
| 初始空闲 buffer | 覆盖整个 mapping，`user_data=vm_start`，进 free_buffers | 同上 | 0x8041d664-0x41d740 |
| `alloc` | `binder_alloc_new_buf`（**唯一调用点 `binder_transaction+0x4d4` = 0x81c80c4**） | mutex 只覆盖"切 buffer + 摘 LRU"；**建页在 unlock 之后** | 0x81cafa0 / 0x81cb3dc |
| `copy-in` | `binder_alloc_copy_user_to_buffer` | 无 | 0x812c410（调用点 0x81c8140） |
| `free` | `binder_free_buf` -> `binder_transaction_buffer_release` -> `binder_alloc_free_buf` | alloc->mutex（`clear_buf` 除外） | 0x81880cc / 0x81826f8 / 0x8180714 |
| 回收 | 全局 shrinker | alloc->mutex(trylock) + mmap_lock(read/per-VMA) | §1.5 |
| `close/unmap` | `binder_alloc_vma_close` 置 `mapped=0`；`binder_alloc_deferred_release` 兜底释放所有页 | mutex | 0x82784c4 / 0x828641c |

**`binder_alloc_deferred_release`（`0xffffffc08028641c`）是"正向结论"**：它在 mutex 下
（a）`mapped` 仍为真就 `BUG()`（`0x286448 -> brk#0x800`），（b）遍历 `pages[]` 逐个
`list_lru_del` + `kfree(page->private)` + `__free_pages`（`0x2868f8-0x286968`），（c）`kvfree(pages)`（`0x2864f0`）。
所以**close(fd) 之后不会在全局 LRU 上留下悬空节点**（我最初的假设被否掉，这点写清楚以免下一轮重走）。

---

## 2. `binder_alloc_new_buf` 逐段拆解（`0xffffffc0801cafa0`）

```
+0x02c  ldarb w8,[alloc+0x88]; tbz -> 0x1cb70c (-ESRCH)        ; mapped 检查
+0x0a8  kzalloc(104, GFP_KERNEL|ZERO)                          ; 候选"余量 buffer"对象
+0x0c4  mutex_lock(&alloc->mutex)
+0x104..+0x14c  free_buffers 树 best-fit 搜索（chunk = vm_start+buffer_size-u 或 next_u-u）
+0x160..+0x1cc  split：new->user_data = u+size；list_add 到 buffer 之后；new->free=1
+0x1e8..+0x260  把余量 buffer 插进 free_buffers（rb_insert_color）
+0x27c..+0x2ac  ★第一遍（持锁）：区间 = [ALIGN_UP(u), ALIGN_DOWN(min(chunk_end, u+size+0xfff)))
+0x2dc..+0x2f4     pages[idx] 非空 -> list_lru_del(freelist, page->private)
+0x2f0  tbz w0,#0 -> 0x1cb5f8 = brk#0x800                      ; BUG_ON(!list_lru_del)
+0x318..+0x368  rb_erase(选中的 chunk)；清 bit0/bit2；按 is_async 置 bit3；插 allocated_buffers
+0x3b0  kfree(NULL)（exact-fit 路径）
+0x3c0..+0x3d8  buffer->data_size/offsets_size/extra_buffers_size/pid 落盘
+0x3dc  mutex_unlock                                            ; ★从这里开始不持锁
+0x3e0..+0x3ec  ★第二遍区间 = [ALIGN_DOWN(u), ALIGN_DOWN(u+size+0xfff)) = [ALIGN_DOWN(u), ALIGN_UP(u+size))
+0x400..+0x41c     pages[idx] 为空 -> 走 +0x4e4 建页
+0x4e4..+0x50c  mmget_not_zero(alloc->mm)（失败 -> -ENOMEM）
+0x514..+0x51c  page = binder_page_alloc(alloc, idx)
+0x528..+0x534  ret = binder_page_insert(alloc, page_addr, page)
+0x544  cmn w24,#0x10                                          ; ret == -EBUSY ?
+0x54c..+0x558    binder_free_page(page); page = binder_page_lookup(alloc, page_addr)
+0x564..+0x56c  pages[idx] = page  (stlr)                       ; 无锁发布
+0x570  mmput_async(alloc->mm)
+0x600..+0x614  建页失败：-ENOMEM -> binder_alloc_free_buf(alloc, buffer) 回收刚建的 buffer
```

三个可直接引用的结论：

1. **`data_size` 等元数据先发布、页后补**（`0x3c0` 在 `0x3dc` 之前，页在 `0x3dc` 之后），中间是"数组里有洞"的窗口。
2. **两遍区间不对称**：摘 LRU 用 `[ALIGN_UP(u), ALIGN_DOWN(u+size))`，建页用 `[ALIGN_DOWN(u), ALIGN_UP(u+size))`。
   后者多出**首、尾两个"部分覆盖页"**。这是 §4 主缺陷的一半。
3. 建页阶段不持 `alloc->mutex`，只靠 `mmget_not_zero` + `stlr` 发布；与 shrinker 的 `pages[idx]=NULL(stlr)` 对撞。

---

## 3. 用户可达入口全枚举（uid 2000，只靠 open + ioctl）

### 3.1 前提（已实测，不重验）

`open("/dev/binder")` 成功 -> 产生独立 `binder_proc`；`mmap(len<=4MB, PROT_READ)` 成功 -> `alloc->mapped=1`、`vm_start` 定死；
`binder_alloc_mmap_handler` 用 **`buffer_size != 0 -> -EBUSY`** 保证**一个 fd 只能 mmap 一次**（`0x8041d600-0x8041d604 -> 0x8041d81c`），
且 `binder_alloc_vma_close` 只置 `mapped=0`、**没有任何路径把它设回 1** => VMA 身份锁死，`vm_start` 不会被后续 mmap/mremap 改写。

### 3.2 ioctl 命令表（`binder_ioctl` @ `0xffffffc0801c5fa8`；比较指令地址 = 可引用证据）

| cmd | 编码 | cmp 地址 | 处理 | 能否推进 alloc/free |
|---|---|---|---|---|
| `BINDER_WRITE_READ` | `0xc0306201` | `0x81c6094` | `binder_ioctl_write_read(filp,arg,thread)`（`0x81c60a8`） | **★唯一通道**，见 §3.3 |
| `BINDER_SET_MAX_THREADS` | `0x40046205` | `0x81c6630` | `proc->max_threads = v`（`0x81c6668`，`inner_lock` 下） | 否 |
| 历史 `SET_IDLE_PRIORITY` | `0x40046206` | `0x81c61bc` | 落 `0x81c697c` 分支（未逐条追） | 否 |
| `BINDER_SET_CONTEXT_MGR` | `0x40046207` | `0x80040bb4`（.cold） | `binder_ioctl_set_ctx_mgr(proc,NULL)`（`0x80040bc4`） | 否（有 mgr 时 -EBUSY） |
| `BINDER_SET_CONTEXT_MGR_EXT` | `0x4018620d` | `0x80040cb4`（.cold） | `binder_ioctl_set_ctx_mgr(proc,ext)`（`0x80040ce0`） | 否 |
| `BINDER_THREAD_EXIT` | `0x40046208` | `0x81c6428` | `binder_thread_release(proc,thread)`（`0x81c6450`） | 清 thread，不动 buffer |
| `BINDER_VERSION` | `0xc0046209` | `0x81c658c` | 向用户写 `w8=8`（protocol 8）（`0x81c65c4`） | 否 |
| `BINDER_GET_NODE_DEBUG_INFO` | `0xc018620b` | `0x80040bfc` | `binder_ioctl_get_node_debug_info`（`0x80040c2c`） | 只读 |
| `BINDER_GET_NODE_INFO_FOR_REF` | `0xc018620c` | `0x81c61dc` | 24 B 结构，要求 5 个字段为 0 后查 node | 只读 |
| `BINDER_GET_FREEZER_INFO` | `0xc00c620f` | `0x80040c54` | `binder_ioctl_get_freezer_info`（`0x80040c80`），12 B | 只读 |
| `BINDER_FREEZE` | `0x400c620e` | `0x81c66e8` | `binder_ioctl_freeze`（`0x81c681c`） | 否 |
| `BINDER_GET_EXTENDED_ERROR` | `0xc00c6211` | `0x81c667c` | 读 `proc+0xb0/0xb8` 12 B 并清零（`0x81c6698-0x81c66b4`） | 否 |
| `BINDER_ENABLE_ONEWAY_SPAM_DETECTION` | `0x40046210` | `0x81c65dc` | 置 proc 开关 | 否 |
| 未定位 | `0xc018620a` / `0x4004620f` | `0x81c61cc` / `0x81c6418` | handler 未定位（见 §6） | 否 |

### 3.3 `BINDER_WRITE_READ` 内部：命令字解码（**编码值，不是裸 nr**）

`binder_ioctl_write_read`（`0xffffffc0801c2700`，`binder_thread_write`/`binder_thread_read` 全内联，长度约 0x2FD0）：

```
+0x058  copy_from_user(&bwr, arg, 0x30)                        ; 0x81c2758
+0x09c  write_size==0 -> 跳写侧
+0x144  未 tag(current->flags) 时 untag(write_buffer)          ; 0x81c2844-0x81c2860
+0x164  cmp x8, 0x00007fffff0000 ; b.hs -> -EFAULT              ; ★唯一的"写缓冲合法性"检查 0x81c2864
+0x1a8  ldtr w19, [x8]                                         ; get_user(cmd) 0x81c28a8
+0x1e0  and w8,w19,#0xfe; cmp #0x15                             ; = _IOC_NR(cmd) 分组（0x81c28e0）
+0x228  stats: binder_stats.bc[_IOC_NR]++                        ; 0x81c28ec-0x81c2900
+0x2d8  0x40046304 组（INCREFS/ACQUIRE/RELEASE/DECREFS）         ; 0x81c29dc/0x81c2a78
+0x4f8  0x40406301 => is_reply; bl binder_transaction           ; 0x81c2bf8 / 0x81c2c10(cset) / 0x81c2c1c
+0x7b4  0x40086303 = BC_FREE_BUFFER                             ; 0x81c2eb4（不等则 0x81c54d0 继续判决树）
+0x7c4  0x40086309 = BC_ACQUIRE_DONE                             ; 0x81c2e94
+0x98c  0x400c6312                                              ; 0x81c2c8c
.cold   0x0000630c BC_ENTER_LOOPER / 0x0000630d BC_EXIT_LOOPER   ; 0x800416e8 / 0x80041824
        0x40046302 BC_ACQUIRE_RESULT / 0x4008630a BC_ATTEMPT_ACQUIRE ; 0x80041264 / 0x80041874
        0x400863 后续组 0x6313/0x6314/0x6315                    ; 0x80041378 / 0x800414c0 / 0x80041a28
unknown command -> -EINVAL（字符串 "binder: %d:%d unknown command %u" @ 0x819bcd21）
```

**这两条是本节最重要的结论：**

- **写缓冲只受"用户地址 + < TASK_SIZE"约束**（`0x81c2864`），任何可读用户内存（栈/堆/bss/anon/文件映射）都行；
  HANDOVER_2 §3「必须落在自己 VMA 内」不成立。当时所有 `EINVAL` 都来自写了 `0x0c`（应写 `0x0000630c`）：
  `0x0c` 的 `_IOC_NR` 是 0x0c，按 `and #0xfe; cmp #0x15` 分组后落到"未匹配" -> `default` -> `-EINVAL`，
  且 `write_consumed` 保持 0（与实测现象完全一致）。
- `区内未填充页 -> EFAULT` 的解释是 `get_user` 打在未填充的 `VM_MIXEDMAP` 页上 ->
  `binder_vm_fault` 返回 `VM_FAULT_SIGBUS`（`0xffffffc081017444: mov w0,#2`）-> fault fixup -> `-EFAULT`。
  **注意：`binder_vm_fault` 只返回 SIGBUS，从不建页**（`mov w0,#2; ret`，12 字节函数），
  这也解释了为什么「用户自己 fault 出一个页」这条路走不通（见 §4.4）。

### 3.4 单独一次 ioctl 能推进到哪一步

| 路径 | 可达性 | 依据 |
|---|---|---|
| `binder_alloc_new_buf`（建页） | **不能进自己的 alloc**；**能进任意其它 proc 的 alloc** | 唯一调用点 `binder_transaction+0x4d4`（`0x81c80c4`），buffer 建在 `target_proc->alloc`（`x0 = x22+0x1e8`）；`target_proc` 由 `tr->target.handle` 解析，handle 0 = context mgr（本机 servicemanager 已持有 => 本进程 `SET_CONTEXT_MGR` 必 `-EBUSY`） |
| `binder_alloc_free_buf` | 能进**自己的** alloc，但需 `allocated_buffers` 里存在 `user_data` 精确匹配且 bit2 置位的 buffer | `BC_FREE_BUFFER` -> `binder_alloc_prepare_to_free`（`0x817ba64`）：按 `allocated_buffers` 树查 `user_data`（`0x817ba90-0x817ba98`），要求 bit0(free)==0 且 **bit2(allow_user_free)==1**（`0x817baa0`），然后清 bit0/bit2（`0x817baa4-0x817bab0`）返回 buffer |
| 自己 alloc 里出现 buffer | **只有收包（reply / 自己作为 target）** 一条路；无 node => 只能靠对系统服务发事务后收到的 reply | reply 走同一 `binder_transaction`，`target_proc` = 自己 |
| `binder_alloc_clear_buf` | 需 `buffer->clear_on_free`（bit1），来源见 §6（未取到） | `0x8180b58` |

=> **实际攻击面：uid 2000 可以用自己的 `BINDER_WRITE_READ` 去"驱动别人 alloc 的分配/释放"**，
`data_size / offsets_size / extra_buffers_size` 完全自选（上限 = 目标 `buffer_size`，<=4MB），
`extra_buffers_size` 由 `BC_TRANSACTION_SG` 提供（`tr.sg.buffer_size - tr.data_size`）。
这已足够构造 §4 的触发序列，**不需要任何 binder 上下文、不需要 context manager、不需要 CAP**。

### 3.5 释放路径的顺序（问题 3 的"次序"项）

`binder_free_buf`（`0x81880cc`）：

```
spin_lock(proc->inner_lock) ; 摘 buffer->transaction（txn->buffer=NULL）     0x818138-0x81813c
if (bit3 async && buffer->target_node) { 摘 node->async_todo + 唤醒 }        0x818164-0x818238
binder_transaction_buffer_release(proc, thread, buffer, ALIGN8(data)+offs, is_dead)
                                                                            0x818268
binder_alloc_free_buf(&proc->alloc, buffer)                                  0x818274
```

`binder_alloc_free_buf`（`0x8180714`）内部顺序：
`clear_on_free? -> clear_buf(无锁) -> mutex_lock -> 尺寸/状态自检 -> 页入 LRU（主区间） -> 与 next 合并（并补 next 边界页入 LRU）
-> 与 prev 合并（并补自身边界页入 LRU） -> free=1 -> 插入 free_buffers -> mutex_unlock`。
**页在 buffer 释放时既不 unmap 也不 free，只是"进 LRU"**——这是新模型的核心事实（老模型是 `binder_update_page_range(0,...)` 直接 zap+free）。

---

## 4. ★ 主缺陷 F1：回收 LRU 的不变量破裂（page-UAF）

### 4.1 三处"入 LRU"与唯一一处"出 LRU"的区间（地址级）

| 位置 | 代码 | 区间 |
|---|---|---|
| `binder_alloc_free_buf+0xdc..+0x134` | `0x81807f0` `and x21,x9,#~0xfff`（x9=u+0xfff）／`0x81807f4` `and x22,x8,#~0xfff`（x8=u+size） | **主区间** `[ALIGN_UP(u), ALIGN_DOWN(u+size))` |
| 合并 next 时 | `0x81808c8` `and x22,x23,#~0xfff`（x23=next_u）-> `0x8180908` `list_lru_add` | 补 `ALIGN_DOWN(next_u)` 这一页 |
| 合并 prev 时 | `0x8180a60` `and x21,x23,#~0xfff`（x23=u）-> `0x8180aa0` `list_lru_add` | 补 `ALIGN_DOWN(u)` 这一页 |
| `binder_alloc_new_buf+0x2dc..+0x2f4` | `0x81cb294` `and x26,x8,#~0xfff`（x8=u+0xfff = ALIGN_UP(u)）／`0x81cb29c` `and x28,x9,#~0xfff` | **摘除**区间 `[ALIGN_UP(u), ALIGN_DOWN(u+size))` |

三者"入"的并集 = 「完全被空闲区覆盖的页」+「两侧合并后才完全空闲的边界页」——**在合并的那一刻都是正确的**。
问题在"出"：摘除区间只覆盖**完全被新 buffer 覆盖的页**，`ALIGN_DOWN(u)` 与 `ALIGN_DOWN(u+size)` 这两个**部分覆盖页被漏掉**。
于是：**只要一个曾被合并补入 LRU 的边界页，后来被一次 split 切成"一部分在用、一部分空闲"，它就留在 LRU 上，同时已经有一部分落在 allocated buffer 里。**

> 精度声明：两条 merge-add 的**触发谓词**我只读到"buffer_u 非页对齐 + 与邻居相邻 + 后续 buffer 的 size != 0x1000"这一层
> （`0x8180888-0x81808b8`、`0x8180a38-0x8180a50`、`0x81808bc→0x8180b1c`、`0x8180a54→0x8180b30`），
> 谓词里参与比较的具体是 next 还是 next-next 的 `user_data`，两种读法我都能在反汇编上自洽，
> **未上机判定**。但 §4.2 给的尺寸组合（T2_u=V+0x800 非对齐、T2_size=0x900≠0x1000）在两种读法下都会触发 add，
> 因此该触发序列不依赖这个未定项。

### 4.2 触发序列（uid 2000，全部经 `BINDER_WRITE_READ`）

设目标服务（handle 0 / 任一可达服务）的 `vm_start = V`（页对齐），buffer 从底部顺序分配：

| 步 | 动作 | 目标 alloc 状态 |
|---|---|---|
| 1 | `BC_TRANSACTION` size **0x800**（`T1`，u=V）-> 服务端收到并 free | `T1` 释放；主区间空；无合并 |
| 2 | `BC_TRANSACTION` size **0x900**（`T2`，u=V+0x800）-> 仍 allocated | — |
| 3 | `BC_TRANSACTION` size **0xf00**（`T3`，u=V+0x1100）-> 仍 allocated | — |
| 4 | 服务端按 FIFO free `T2`：主区间空；`next=T3`(size 0xf00 != 0x1000) 且 prev=`T1` free 且相邻 => `0x8180aa0` 把 **`ALIGN_DOWN(V+0x800)=V` 页加入 LRU** | 页0 在 LRU，且页0 此时**完全**处于空闲区 `[V, V+0x1100)`（合法） |
| 5 | `BC_TRANSACTION` size **0xff0**（`T4`）-> best-fit 命中空闲块 `[V, V+0x1100)`，从底部切：`T4=[V, V+0xff0)`，余量 `[V+0xff0, V+0x1100)` | `T4` 的去 LRU 区间 = `[ALIGN_UP(V)=V, ALIGN_DOWN(V+0xff0)=V)` = **空** => 页0 **仍在 LRU**，但 `T4` 已占用页0 的 `0xff0/0x1000` ★不变量破裂 |
| 6 | 本进程 mmap+touch 数百 MB 制造 direct reclaim（或 `drop_caches`）-> `binder_shrink_scan` 扫到页0 节点 | `binder_alloc_free_page`：`pages[0]=NULL`，`zap_page_range_single(vma, V, 0x1000)`，`kfree(node)`，`__free_pages(page,0)` => **`T4` 的 0xff0 字节数据所在页回到 buddy，且 PTE 被撤** |

只要 `T4` 的 size 满足 `ALIGN_DOWN(V+size)==ALIGN_UP(V)`（即 `size<0x1000` 且 `u` 页对齐），步 5 的 del 区间必为空；
把 size 取到 **0xff0** 可让"在用部分"接近整页（0xff0/0x1000），这是这类页里能拿到的最大比例。
用 `extra_buffers_size`（`BC_TRANSACTION_SG`）可以在**不增加 data_size**的前提下把 size 拉到 0xff0，`offsets` 也可选。

### 4.3 命中信号（kasan=off、panic_on_oops=1、slabinfo 可读）

| 信号 | 说明 |
|---|---|
| **目标进程直接崩** | 目标读自己的收件 buffer（`[V, V+0xff0)`）撞已撤 PTE => `SIGBUS`（`binder_vm_fault` 返回 SIGBUS），服务进程 crash/重启 |
| **内核 oops -> panic 重启** | 之后任何一次 binder 触碰该 buffer 的页都会走 `pages[idx]==NULL` 的**无检查**路径：`binder_alloc_copy_user_to_buffer`（`ldr x10,[x10,x9,lsl#3]` @ `0x812c4bc`）、`copy_to_buffer`（`0x81122e4`）、`copy_from_buffer`（`0x8183290`）、`binder_alloc_clear_buf`（`0x80437134`）-> `page_to_virt(NULL)` 得到 `0xff00ffd0_xxxxxxxx` 级别非映射地址 -> `Unable to handle kernel paging request` -> `panic_on_oops` => **重启** |
| dmesg 关键词 | `Unable to handle kernel paging request at virtual address ff00ffd0...`，调用栈落在 `binder_alloc_copy_* / binder_transaction / binder_transaction_buffer_release` |
| slabinfo | 目标 alloc 的 order-0 页被归还，无 slab 计数变化（binder 页来自 buddy，不是 slab）；可观测的是 binder 相关 `kmalloc-32`（LRU 节点）减少 |
| 不可用 | `kasan=off` => 没有 KASAN 报告；`/proc/self/maps` 只能看到 PTE 消失后的 SIGBUS |

### 4.4 为什么其它"制造 PTE 但 binder 不知道"的路都不通（反面证据，避免下一轮重走）

| 想法 | 结论 | 证据 |
|---|---|---|
| 用户自己 fault 出页 -> `vm_insert_page` 返回 `-EBUSY` -> GUP 拿用户页 | 不通 | `binder_vm_fault` 只 `mov w0,#2`（`VM_FAULT_SIGBUS`），`0xffffffc081017444` |
| 用可写映射 fault | 不通 | `binder_mmap` 见 `VM_WRITE` 直接 `-EPERM`（`0x8041d534-0x8041d538`），并清 `VM_MAYWRITE`（`0x8041d55c`） |
| 二次 mmap 造第二个 VMA 覆盖同一地址 | 不通 | `buffer_size != 0 -> -EBUSY`（`0x8041d604 -> 0x8041d81c`） |
| munmap/mremap 后重映射 | 不通 | 任何 close 都 `stlrb 0` 置 `mapped=0`（`0x82784c8`），且无路径置回 1；`alloc_new_buf` 入口 `mapped==0` 直接 `-ESRCH`（`0x81cafd8-0x81cafdc`） |
| `madvise(DONTNEED)` 撤 PTE 后重插 | 无收益 | 页仍属驱动、`pages[idx]` 仍非空；不产生 UAF |
| 同页被两个 buffer 共享而"另一个"仍 allocated | **这正是 F1 的形态** | §4.2 |

### 4.5 可利用性判断（F1）

- **DoS：确定**。要么目标服务 SIGBUS 崩（可反复），要么 binder 自己踩 NULL 页槽 -> panic 重启（`PANIC_ON_OOPS=y`，一次就够）。
- **LPE：不作为结论**，理由逐条：
  1. `pages[idx]==NULL` 的后果是 `page_to_virt(NULL)` = 常量非映射地址（`0xff00ffd0...`），**不是可控地址** => 拿不到任意写；
  2. 想"写进已释放页"必须在 `ldr pages[idx]`（`0x812c4bc`）与 `__arch_copy_from_user`（`0x812c570`）之间让 shrinker 完成 `zap + __free_pages`，
     窗口微秒级，且**每次失败都会 panic 重启**（一台机一个 boot 基本只能试一次）；
  3. 现有回收原语都是 **order-1**（`/dev/uhid` UHID_CREATE2 -> kmalloc-256 objperslab=32/pagesperslab=2；`send(AF_UNIX,11872)` -> 整页 8192），
     而 shrinker 用的是 **`__free_pages(page,0)`（order-0）**，页先落 pcp 的 order-0 链表，order-1 申请不直接取它 => 命中率再降一档；
  4. `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` => 被回收页再分配时内容被清零，"先写后用"的数据型利用也受限；
  5. 可写的"在用比例"上限是 0xff0/0x1000（首/尾部分页），拿不到"整页可控"。
- 结论口径：**这是一条可被 uid 2000 稳定触发的内核 page-UAF/DoS，得分口径按"拒绝服务"记，不按"服务器/内核权限"记。**

---

## 5. 其它候选（逐条给地址与判定）

### F2 `BUG_ON(!list_lru_add)` / `BUG_ON(!list_lru_del)`

- `binder_alloc_free_buf`：`0x8180834->0x8180b6c`、`0x8180908->0x8180b74`、`0x8180aa0->0x8180b88`，目标都是 `brk #0x800`。
- `binder_alloc_new_buf`：`0x81cb2f0->0x81cb5f8` = `brk #0x800`（即 `if (!list_lru_del(...)) BUG();`）。
- 语义（反汇编 `list_lru_del` @ `0xffffffc0801cb9c0`）：`w0 = (item->next != item)`（`0x1cba80-0x1cba84`），
  **对"自链"的 item 返回 false => 直接 BUG**；`list_lru_add`（`0xffffffc080180c78`）对非空 item 同样返回 false。
- **判定：可达但有前提**。F1 的路径不会踩它（页在 LRU 上，del 成功）。要踩它需要"`pages[idx]` 非空但节点不在 LRU"且该页落在后续 buffer 的 del 区间里；
  静态层面构造过"同一页被两次 merge-add"的候选（free B 时 prev-merge 补 `ALIGN_DOWN(B_u)`，同时 next-merge 补 `ALIGN_DOWN(C_u)` 且两者同页），
  但**没有上机验证**。`CONFIG_BUG_ON_DATA_CORRUPTION` 下命中即 panic。**按未验证记录**。

### F3 `-EBUSY` + GUP 分支（`binder_alloc_new_buf+0x59c..+0x5c0`）

- 代码：`ret==-EBUSY` -> `binder_free_page(page)`（`0x81cb54c`）-> `binder_page_lookup`（`0x81cb558`）-> 用 GUP 回来的页填 `pages[idx]`（`0x81cb564`）。
- 风险：若 GUP 回来的是**用户页**，`page->private` 不是 kmalloc 节点，之后 `binder_free_page`/shrinker 的 `kfree(page->private)` => **任意 kfree**。
- **判定：静态判为不可达（防御性死代码）**。要让它触发必须有"binder 没插过、但 PTE 已存在"的页，而 §4.4 的 5 条路全部被封。
  唯一理论来源是 shrinker 的 `zap` 失败但 `pages[idx]` 已置 NULL——`zap` 只在 `vma==NULL` 时跳过，而 `vma==NULL` 时该地址已无 PTE。

### F4 `clear_on_free` 路径（`binder_alloc_clear_buf` @ `0xffffffc0804370c0`）

- 调用点 `0x8180b58`，**在 `mutex_lock`（`0x8180744`）之前**，即**无 alloc->mutex**；`size` 取自 `buffer->entry.next->user_data - user_data`（`0x4370f4-0x4370fc`），
  然后 `pages[idx]` **无 NULL 检查**（`0x437134`），`page_to_virt` 后 `__pi_memset(kaddr,0,chunk)`（`0x437170`）。
- **判定：缺陷形态与 F1 同源（NULL 页槽 + 无锁遍历），是否可达取决于 `buffer->clear_on_free`(bit1) 能否被攻击者置位**。
  `binder_transaction` 里是 `buffer->bit1 = (t->flags>>5)&1`（`0x81c8104-0x81c8118`），`t->flags` 在 `0x6c`（BTF 确认），
  **没能把 `t->flags` 的 bit5 追到用户可控的 `tr->flags`**（函数体内未找到对 `[t+0x6c]` 的写）。见 §6「未取到」。

### F5 buffer 双重释放（问题 3 的第 2 问）

- **没找到可利用的双重释放**：
  `binder_alloc_prepare_to_free`（`0x817ba64`）要求 bit2（`0x817baa0`）且清 bit0/bit2（`0x817baa4-0x817bab0`）；
  第一次 `binder_alloc_free_buf` 会把 buffer 从 `allocated_buffers`（`rb_erase` @ `0x818084c`）搬进 `free_buffers`，
  第二次 `BC_FREE_BUFFER` 在 `allocated_buffers` 里查不到 => 只打 "BC_FREE_BUFFER no match for buffer at offset %lx"（字符串 `0x81976e3b`）。
- 内部路径（`binder_transaction+0x2468`、`binder_proc_transaction+0x514`、`binder_alloc_new_buf+0x674` 三处 `binder_alloc_free_buf`）都是"失败回滚"，
  `binder_alloc_free_buf` 自身还有 `buffer->free`(bit0) / `buffer->transaction!=NULL` / `total>size` 三重自检（`0x8180794-0x81807a0`）。
  这条按"未发现"记录，不作为结论。

### F6 proc/thread todo/wait 队列 vs close(fd)（问题 3 的第 3 问）

- **未展开**。已确认的结构性事实：`binder_release -> binder_defer_work(RELEASE)`（延迟到 workqueue），
  `binder_alloc_deferred_release` 在 mutex 下断言 `!mapped`（`0x8286448 -> brk`）并清理 LRU 节点；
  ioctl 期间 filp 引用计数保证 release 不会并发。
  `binder_thread_release`（`0x827921c`）/`binder_proc_transaction`（`0x81c6b04`）的队列细节本轮**没有逐条读**（预算原因），不写结论。

---

## 6. 未取到 / 试过什么（按要求明确标注）

| 项 | 尝试 | 结果 |
|---|---|---|
| `binder_page_lookup` 的 `gup_flags=0x20` 含义 | 反汇编调用点（`0x27d6b4/bc`）+ 找 `FOLL_*` 定义 | **未取到**（镜像内无 `FOLL_*` 枚举，BTF 里也没有）。只记录立即数 0x20 与"返回页被当自有页 `__free_pages`"这一矛盾点 |
| `t->flags` bit5（`TF_CLEAR_BUF`）是否用户可控 | 在 `binder_transaction`（`0x1c7bf0-0x1cafa0`）内搜 `str w*, [x*,#0x6c]`；搜 `orr ..., #0x20` | **未取到**：函数体内没有对 `[t+0x6c]` 的写；`binder_proc_transaction+0x2f4`（`0x81c6df8`）那处是相邻 debug 计数自增，不是 flags 语义 |
| ioctl `0xc018620a` / `0x4004620f` 的 handler | 追判决树（`0x81c61cc -> 0x81c6584`、`0x81c6418 -> 0x81c697c`） | **未定位**（判决树在 `.cold` 里交错，未穷举到叶子） |
| `binder_free_page` 是否可能在 `page->private` 为用户值时被调用 | 追 `-EBUSY` 分支的 5 条前提 | 判为**不可达**（§4.4），但这是静态推断，未上机 |
| `binder_thread_release` / todo-wait 竞态 | 只读了 `binder_free_buf` 的 async_todo 摘链（`0x818164-0x818238`） | **未展开** |
| 6.18.22 补丁里是否有 binder C 版安全修复 | `research/ChangeLog-6.18.22.txt` 全文 grep `binder` | **只有 1 条** `rust_binder: use AssertSync for BINDER_VM_OPS`（非安全、C 版不受影响）=> 没有可直接套的 Nday |

---

## 7. 给下一步的建议（PoC 计划，**未执行**）

1. **第一步只验证"写路径可达"**（推翻旧结论，零风险）：`bwr.write_size=4; write_buffer=<任意可读用户内存>`，
   命令字用 **`0x0000630c`（BC_ENTER_LOOPER）**，期望 `ret=0, write_consumed=4`；
   再用 `0x40406300` + 64 B `binder_transaction_data`（handle 0，data_size=8）验证读到 `BR_FAILED_REPLY/BR_DEAD_REPLY`
   （证明 `binder_transaction` 真的跑了）。
2. **第二步按 §4.2 发 4 条事务**，事务 code 用服务端必定拒绝的随机值（服务端解析失败也会 `BC_FREE_BUFFER`，free 顺序即 FIFO）。
3. **第三步触发 reclaim**：本进程（或另一进程）`mmap` 并 touch 大量内存制造 direct reclaim；`/proc/sys/vm/drop_caches` 对 shell 一般不可写，不要依赖。
4. **命中判据**（按优先级）：① dmesg `Unable to handle kernel paging request ... binder_alloc_copy` / panic 计数；
   ② 目标服务进程 SIGBUS/重启；③ 再发一条事务后它读自己 buffer 失败。
   **注意每次 oops 都会重启，先准备 KASLR slide 重解（`cap_pair.sh`+`solve_live.py`）与日志持久化。**
5. 若只想拿 DoS 结论：第 3 步的压力从**另一个进程**施加，避免自己被目标服务拖死。

---

## 8. 一页速查（地址索引）

| 名称 | 地址 |
|---|---|
| `binder_ioctl` / `binder_ioctl_write_read` | `0xffffffc0801c5fa8` / `0xffffffc0801c2700` |
| `binder_transaction` / `binder_free_buf` / `binder_alloc_new_buf` | `0xffffffc0801c7bf0` / `0xffffffc0801880cc` / `0xffffffc0801cafa0` |
| `binder_alloc_free_buf` / `binder_alloc_prepare_to_free` | `0xffffffc080180714` / `0xffffffc08017ba64` |
| `binder_transaction_buffer_release` / `binder_free_transaction` | `0xffffffc0801826f8` / `0xffffffc0801c5b6c` |
| `binder_page_alloc` / `insert` / `lookup` / `free_page` | `0xffffffc08027d4d8` / `0xffffffc0803913cc` / `0xffffffc08027d654` / `0xffffffc080285078` |
| `binder_alloc_clear_buf` / `copy_user_to_buffer` / `copy_to_buffer` / `copy_from_buffer` | `0xffffffc0804370c0` / `0xffffffc08012c410` / `0xffffffc08011223c` / `0xffffffc0801831ec` |
| `binder_alloc_free_page`(shrinker) / `binder_shrink_scan` / `binder_shrink_count` | `0xffffffc08101deec` / `0xffffffc08101e390` / `0xffffffc08031b4b8` |
| `binder_mmap` / `binder_alloc_mmap_handler` / `binder_alloc_vma_close` / `binder_vm_fault` | `0xffffffc08041d4d4` / `0xffffffc08041d5c4` / `0xffffffc0802784c4` / `0xffffffc081017444` |
| `binder_alloc_deferred_release` / `binder_alloc_init` | `0xffffffc08028641c` / `0xffffffc080415ed0` |
| `binder_freelist`（全局 LRU） / `binder_shrinker` | `0xffffffc08297ce88` / `0xffffffc08297ceb8` |
| 写缓冲唯一检查 / get_user(cmd) | `0xffffffc0801c2864` / `0xffffffc0801c28a8` |
| `binder_alloc_new_buf` 唯一调用点 / 数据拷贝点 | `0xffffffc0801c80c4` / `0xffffffc0801c8140` |

# 性能优化实践

本文档面向的目标场景：**万级连接/秒**下做到无锁竞争、低 GC 压力、低延迟毛刺。所有结论可对照对应源码复核。

## §1 无锁读：Copy-on-Write 快照

**问题**：`rules.Engine` 早期用单一 `sync.RWMutex` 保护全部 ACL 字段。热重载或健康检查触发**写锁**时，所有新建连接被阻塞 → CPU 抖动 + 延迟毛刺。

**方案**：`ruleSet` 不可变快照 + `atomic.Pointer` 原子交换（`internal/rules/engine.go`）。

```go
type ruleSet struct { /* 全部 ACL 数据：maps / chnroute.Trie / suffixTrie ... */ }
type Engine struct {
	rules atomic.Pointer[ruleSet]
}
```

- 读者只需一次 `e.rules.Load()` 拿到当前快照指针，之后**无锁**读取；快照只读、绝不修改。
- 写者（`Load` / `Reload`）构建**全新** `ruleSet`，全部解析成功后 `e.rules.Store(rs)` 一次性原子换入；解析失败则旧快照继续生效，只报错。
- 热路径方法 `IsPortBlocked` / `IsIPBlocked` / `IsDomainBlocked` / `MatchProxyRule` / `ProxyRules` 全部遵循"Load 后无锁取值"。

**类似模式**（同一套思想，不同载体）：

- `chnroute.Trie.root` 为 `atomic.Pointer[trieData]`，热重载走 `Pull` 原子换根（`internal/chnroute/trie.go`）。
- `config/dns/router/tun` 的配置快照均为 `atomic.Pointer`：`dns.Handler.cfg`（`dnsConfig`）、`route.Router.cfg`（`routerConfig`）、`tun.TUNHandler.config`、`engine.Config`，热重载时 `Store` 换新。

## §2 缓冲池

| 池 | 位置 | 大小 | 用途 |
| --- | --- | --- | --- |
| `bufferPool` | `internal/relay/tcp.go` | 32 KiB | TCP relay 的 `io.CopyBuffer` 缓冲 |
| `UDPBufPool` / `udpBufPool` | `relay` / `udp` | 65535 字节 | UDP 数据报缓冲 |
| `PacketPool` | `internal/relay/tcp.go` | 4096 字节 | DNS 查询短包缓冲 |
| `clientHelloBufPool` | `internal/tun/handler.go` | 4096 字节 | `ReadClientHello` 预读首包 |

- **TCP relay**：32 KiB 池化缓冲 + `tcpSplice` 内核零拷贝（两端都是 `*net.TCPConn` 时 `dst.ReadFrom(src)` 走 `splice(2)`，避免用户态拷贝，低 CPU）。
- **TUN ReadClientHello**：从 `clientHelloBufPool` 取池化缓冲预读，但返回给调用方的是**精确尺寸独立拷贝**（`out := make([]byte, exact)`），池复用不污染调用方、也不与调用方生命周期耦合。
- **UDP**：`udpBufPool` 65535 满尺寸；`buf.NewPacket` 分配 packet buffer、`Release` 归还；非托管缓冲 `buf.As` 的 `Release` 是 no-op。给 TUN 发已有数据必须用 `buf.As` 而非 `buf.With`（`With` 不设置 end 导致 `Bytes()` 返回空切片，会把 UDP/DNS 回包写成空数据报）。

## §3 并发去重

- **DNS singleflight**（`internal/dns/handler.go`）：`Handler.group singleflight.Group`，key 为 `qname + "|" + qtype`，同一域名同类型并发查询只发一次上游；共享结果由各 caller 修正自己的 DNS transaction ID。
- **UDP 会话创建**（`internal/udp/handler.go`）：`createGroup.Do(key, createUDPSession)` 串行化同一目标的会话建立，避免**并发首包重复拨号**与连接泄漏；TUN 侧 `getOrCreateRemote` 还用"锁外拨号 + 二次检查"避免重复建连。

## §4 减少每包 / 每连接开销

- **UDP 每包免解析 IP**：`udp.Handler` 构造时把 `clientIP` 用 `net.ParseIP` 解析一次存入 `clientIPParsed`，`HandlePacket` 每包直接复用，避免每包分配（`internal/udp/handler.go`）。
- **热路径日志降级**：高频日志从 `slog.Info` 改为 `slog.Debug`，在高查询/连接率下是纯开销：
  - DNS `"handling DNS query"`（`internal/dns/handler.go`）；
  - TUN `"new connection"`、`"extracted domain"`（`internal/tun/handler.go`）。
  - 规则 `"rules loaded"` 等在加载时打，不在热路径。

## §5 DNS 单次解析

`isDNSCleanAndPrefer`（`internal/dns/handler.go`）把**污染检查 + IP 优选**合并为**一次 `Unpack`**（原来 `Unpack` 两次）：

```go
func (h *Handler) isDNSCleanAndPrefer(ctx, wire, qname) (out []byte, preferCached, clean bool)
```

- 单次 `msg.Unpack(wire)` 后先遍历 Answer 做 chnroute 污染检查；
- 未污染且启用 IP 优选时才进入 `filterIPPreference` 过滤最快 IP 并重新 `Pack`；
- 返回 `(输出 wire, 是否命中优选缓存, 是否干净)`，调用方据此决定缓存/回退国外 DNS。

## §6 TUN 协议栈特性与性能基准（Benchmark）

SmartProxy 支持 5 种 TUN 协议栈实现，可在不同设备环境与权限要求下灵活选用：
- **`gvisor`（全平台默认）**：Google 开源的成熟用户态 Go 栈。并发多协程驱动，TCP 握手约 25 µs（云端）/ 52 µs（真机），全平台无需 CGO 编译即可运行，生态兼容性好，适合网页高频并发短连接场景。
- **`lwip`（移动端推荐）**：轻量级 C 语言协议栈（Lightweight IP）。单连接内存开销极低（握手路径 345~490 B，约为 gVisor 的 1/5），TCP 建连与 `system`/`mixed` 同档（实测 ~2.4 µs 云端 / ~5.9 µs 真机），UDP 端到端吞吐在非 Root 栈中最高（真机 430 MB/s，约 gVisor 的 2.8 倍），发包方向真·零拷贝（0 allocs/op），非常适合 Android 客户端长期后台驻留防 OOM/LMK 杀进程。
- **`system`**：利用 Linux 内核网络栈直接处理 TCP，性能强但需系统 root / `CAP_NET_ADMIN` 特权。
- **`mixed`**：混合协议栈（TCP 走 System 内核栈，UDP 走 gVisor 用户态栈），需系统特权。
- **`go`**：纯 Go 原生简易栈，主要用于开发参考与测试。

### 实测基准数据对比

为了解各协议栈在真实场景下的开销特征与性能边界，在**两套典型硬件与运行时环境**下执行了标准化基准压测：
1. **云端 CI 环境**：GitHub Actions Runner (`ubuntu-latest`, AMD EPYC 9V45 96-Core / Linux x86_64, Go 1.27.1)
2. **移动端真机环境**：Android 设备 (ARM64 / aarch64 8-Core, Termux, Go 1.25+ / Clang CGO)

测试执行命令：
```bash
# 协议栈吞吐与握手全套基准压测
CGO_ENABLED=1 go test -tags "with_gvisor,with_lwip" -bench="BenchmarkStack_" -benchmem -benchtime=500x -run=^$ ./internal/tun/
```

### 1. UDP 吞吐量对比 (`BenchmarkStack_UDP_Backpressure`)

> **测试场景**：向协议栈连续灌入 1400 字节标准 UDP 报文（`10.0.0.2:45678 → 8.8.8.8:53`，1500 MTU 内不分片），测到报文穿过协议栈被交回 handler 为止。列出单包端到端耗时 (ns/op)、按 1400 B/包折算的吞吐 (MB/s)、单包堆内存占用 (B/op) 与 Go 堆分配次数 (allocs/op)。
>
> **口径**：每批最多 64 个报文在途，等这一批**全部出栈**再发下一批，栈因此不会被灌爆。这个窗口远小于链路上任何一级内部缓冲（`pipeTun.readCh` 4096、gVisor channel endpoint 4096、lwIP `inputChan` 1024、`go` 栈 socketpair 约 150 包），栈没办法把耗时藏进队列；同步只在每批的首尾各一次，摊到 64 个包上可以忽略。同一用例把迭代数从 128 提到 8192，ns/op 只在 1.5 倍内波动 —— 对比文末对照表里无背压版本 85 倍的漂移。
>
> **表里包含什么**：注入开销按各栈自己的方式计入（`gvisor` 走 `InjectInbound`、`go` 走 socketpair 的 `unix.Write`、其余走 `tun.readCh`），handler 侧的读取对五个栈相同。所以这张表回答的是「一个报文走完这个栈要花多少时间」，不是纯协议栈内核的耗时。

#### 环境 A：CI 云端测试环境 (Linux x86_64 4-Core)
| 协议栈 | 架构分类 | 权限要求 | 单包耗时 (ns/op) | 吞吐 (MB/s) | 堆内存消耗 (B/op) | Go 堆分配 (allocs/op) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`system`** | 主机原生内核协议栈 | 需 Root | **1,136 ns** | **1,232 MB/s** | 422 B | 2 allocs |
| **`lwip`** | 用户态 C 语言栈 (Lightweight IP) | **非 Root 兼容** | **1,839 ns** | **761 MB/s** | 1,923 B | 4 allocs |
| **`gvisor`** | 用户态 Go 语言栈 (Google gVisor) | **非 Root 兼容** | 2,913 ns | 481 MB/s | 558 B | 3 allocs |
| **`mixed`** | 混合栈 (Kernel TCP + gVisor UDP) | 需 Root | 3,086 ns | 454 MB/s | 474 B | 2 allocs |
| **`go`** | 纯 Go 原生简易协议栈 | 需 Root | 4,087 ns | 343 MB/s | 4,808 B | 1 alloc |

#### 环境 B：移动端真机测试环境 (Android ARM64 8-Core)
| 协议栈 | 架构分类 | 权限要求 | 单包耗时 (ns/op) | 吞吐 (MB/s) | 堆内存消耗 (B/op) | Go 堆分配 (allocs/op) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`lwip`** | 用户态 C 语言栈 (Lightweight IP) | **非 Root 兼容** | **3,260 ns** | **430 MB/s** | 1,950 B | 4 allocs |
| **`system`** | 主机原生内核协议栈 | 需 Root | **3,537 ns** | **396 MB/s** | 436 B | 2 allocs |
| **`mixed`** | 混合栈 (Kernel TCP + gVisor UDP) | 需 Root | 6,640 ns | 211 MB/s | 637 B | 2 allocs |
| **`gvisor`** | 用户态 Go 语言栈 (Google gVisor) | **非 Root 兼容** | 9,217 ns | 152 MB/s | 654 B | 3 allocs |
| **`go`** | 纯 Go 原生简易协议栈 | 需 Root | 11,639 ns | 120 MB/s | 4,842 B | 1 alloc |

> **数据分析与客观说明**：
> - **`lwip` 与 `system` 同档，两者之外断崖**：真机上 `lwip`(430 MB/s) 与 `system`(396 MB/s) 并列第一，CI 上则是 `system`(1,232 MB/s) 领先 `lwip`(761 MB/s)，两个环境的相对次序会翻转，但都远高于其余三个。**`mixed` 的 UDP 走 gVisor 用户态栈**，所以它贴着 `gvisor`(211 / 152 MB/s) 而不是贴着 `system` —— 这正是混合栈的定义，也是它 UDP 性能上限的来源。`go` 栈最慢（120 MB/s），与它「仅供开发参考」的定位一致。
> - **lwIP 的入栈方向有一次 C→Go 载荷拷贝**：`goUdpRecv` 用 `C.GoBytes` 把载荷拷进 Go 堆（lwIP 的 pbuf 在回调返回后即释放，这里必须拷），所以它的 B/op（1,950 B ≈ 1400 B 载荷 + 开销）明显高于 `system`/`mixed`/`gvisor`（436~654 B）。§3 讲的零拷贝是**出栈（发包）方向**的优化，方向不同，不要混为一谈。
> - **测试性质**：这是内存层面的端到端处理开销，不代表实际广域网物理传输速度，实际下载/上传带宽取决于物理网卡、蜂窝/Wi-Fi 射频、运营商限速与节点 RTT。

#### 对照：无背压用例 (`BenchmarkStack_UDP_Throughput`)

同一批栈上跑的无背压版本 —— 循环体只把报文投进缓冲通道就返回，500 次迭代填不满任何一级队列，测到的是**基准把报文喂进 TUN 的成本**，不是栈的 UDP 处理能力。保留它有两个用处：说明「没有背压的吞吐数字有多不可信」，以及给出各家注入方式本身的成本。

| 环境 | 协议栈 | 无背压 (ns/op) | 折算吞吐 |
| :--- | :--- | :--- | :--- |
| A (CI) | `lwip` / `system` / `mixed` | 26.7 / 51.8 / 27.6 ns | 52.4 / 27.0 / 50.8 GB/s |
| A (CI) | `gvisor` / `go` | 2,697 / 519.1 ns | 519 / 2,697 MB/s |
| B (真机) | `lwip` / `system` / `mixed` | 54.5 / 43.6 / 45.1 ns | 25.7 / 32.1 / 31.0 GB/s |
| B (真机) | `gvisor` / `go` | 6,768 / 1,929 ns | 207 / 726 MB/s |

三个实现完全不同的栈给出几十 GB/s 的同一量级数字，本身就不成立；把迭代数从 500 提到 2000 / 20000，同一个用例还会涨到 164 / 595 ns（由生产者-消费者竞争支配，与栈无关）。`gvisor` 那一行倒是有几千 ns，因为它注入用的 `InjectInbound` 本身就要过一遍栈 —— 所以它在这组里歪打正着落在同一量级，但这只是巧合，不能当作它「不用背压也准」的理由。

### 2. TCP 握手开销对比 (`BenchmarkStack_TCP_Handshake`)

> **测试场景**：客户端向 TUN 注入一个 SYN，测得从注入到收到 SYN/ACK 的往返开销（用例不发第三步 ACK）。
>
> 本节数据于 2026-10-03 重测：此前的基准把收尾开销（`LWIPStack.Close()` 在 tun 未先关闭时等满 500ms 读循环退出超时）算进了 `ns/op`，见文末「基准口径与已知局限」。

#### 环境 A：CI 云端测试环境 (Linux x86_64 4-Core)
| 协议栈 | 架构分类 | 权限要求 | 握手耗时 (ns/op) | 堆内存消耗 (B/op) | Go 堆分配 (allocs/op) | 适用场景分析 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`system`** | 主机内核原生协议栈 | 需 Root | **2,272 ns (~2.3 µs)** | 376 B | 5 allocs | 特权环境服务器极速转发 |
| **`mixed`** | 混合栈 (Kernel TCP + gVisor UDP) | 需 Root | **2,392 ns (~2.4 µs)** | 374 B | 5 allocs | 特权环境服务器 |
| **`lwip`** | 用户态 C 语言栈 (Lightweight IP) | **非 Root 兼容** | **2,426 ns (~2.4 µs)** | **488 B** | **5 allocs** | **移动端推荐**：建连与 system/mixed 同档，内存约为 gVisor 的 1/4 |
| **`gvisor`** | 用户态 Go 语言栈 (Google gVisor) | **非 Root 兼容** | **25,489 ns (~25.5 µs)** | 2,043 B | 27 allocs | **通用默认**：网页高频短连接并发建连迅速，纯 Go 无 CGO |
| **`go`** | 纯 Go 原生简易协议栈 | 需 Root | 378,792 ns (~379 µs) | 527 B | 5 allocs | 开发测试参考 |

#### 环境 B：移动端真机测试环境 (Android ARM64 8-Core)
| 协议栈 | 架构分类 | 权限要求 | 握手耗时 (ns/op) | 堆内存消耗 (B/op) | Go 堆分配 (allocs/op) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`mixed`** | 混合栈 (Kernel TCP + gVisor UDP) | 需 Root | **3,811 ns (~3.8 µs)** | **374 B** | **5 allocs** |
| **`system`** | 主机原生内核协议栈 | 需 Root | 3,977 ns (~4.0 µs) | 371 B | 5 allocs |
| **`lwip`** | 用户态 C 语言栈 (Lightweight IP) | **非 Root 兼容** | **5,880 ns (~5.9 µs)** | **482 B** | **5 allocs** |
| **`gvisor`** | 用户态 Go 语言栈 (Google gVisor) | **非 Root 兼容** | **51,674 ns (~51.7 µs)** | 2,047 B | 27 allocs |
| **`go`** | 纯 Go 原生简易协议栈 | 需 Root | 708,738 ns (~709 µs) | 669 B | 5 allocs |

> **数据分析与客观说明**：
> - **gVisor 的定位仍然是「通用默认」**：单次 TCP 握手约 25 µs（云端）/ 52 µs（真机），在网页浏览这类伴随大量首屏并发短连接的场景下够用，且全 Go 实现、无 CGO 编译依赖。
> - **lwIP 建连不慢，此前文档里的「~1 ms」不成立**：SYN 到达后 lwIP 在**同一轮处理内**直接发出 SYN/ACK，不经过任何定时器轮询 —— 适配层的 25ms ticker 只驱动 `sys_check_timeouts()`（重传、TIME_WAIT、keepalive 等），不在建连路径上。实测单次握手 2.4 µs（x86_64）/ 5.9 µs（ARM64 真机），与 `system`/`mixed` 同档。连接建立之后单连接内存占用极小（345~490 B，约为 gVisor 的 1/4），GC 压力低（5 次分配 vs 27 次分配）。
> - **协议栈选型建议**：
>   - **默认推荐 `gvisor`**：全 Go 实现，零 CGO 编译依赖，跨平台成熟稳定，全平台通用首选。
>   - **移动端推荐 `lwip`**：极低内存 Footprint、极低 GC 压力、建连与特权栈同档、UDP 端到端吞吐在非 Root 栈中最高，非常契合 Android 客户端长期后台驻留，有效避免系统低内存清理（LMK 杀进程）。
>   - **特权环境可选 `system` / `mixed`**：在 Linux 服务器等具备 root / `CAP_NET_ADMIN` 权限且需要极致吞吐的环境下可选用。
### 3. lwIP 协议栈深度优化与零拷贝架构

在 v2.2 中，SmartProxy 对 lwIP 用户态协议栈进行了端到端的深度调优，使得其在移动端获得了超高吞吐并实现发包零堆分配：
1. **TUN 物理输出真·零拷贝 (`unsafe.Slice`)**：
   - 优化前：每次下行报文触发 `goPacketOutput` 时通过 `C.GoBytes` 分配 Go 堆内存切片，20MB/s 高速下载下每秒产生超 15,000 次堆分配，导致 GC 频繁停顿。
   - 优化后：由于 `OutputFn` 紧接着同步执行系统调用 `tun.Write(packet)` 写入虚拟网卡，生命周期无需跨 goroutine 留存，改用 `unsafe.Slice` 直接借用 C 连续内存，彻底消除堆内存分配（0 allocs/op）。
   - **注意方向**：这是**出栈（发包）**方向的优化。反方向的**入栈（收包）**仍有一次 `C.GoBytes` 载荷拷贝（`goUdpRecv` / `goTcpRecv`，lwIP 的 pbuf 在回调返回后即释放，这里省不掉），UDP 基准里 lwIP 的 B/op 高于其他栈就是这个原因，见 §1 的分析。
2. **TCP 时间戳与大窗口扩展 (RFC 7323)**：
   - 启用 `#define LWIP_TCP_TIMESTAMPS 1` 与 `#define LWIP_WND_SCALE 1`（接收缩放比例 `TCP_RCV_SCALE 4`，滑动窗口 560KB）。
   - 毫秒级高精 RTT 采样，避免在百兆/千兆速率下因 TCP 序列号回绕（PAWS）产生误判重传或丢包。
3. **单 Pbuf 传输防分片 (`LWIP_NETIF_TX_SINGLE_PBUF 1`)**：
   - 避免 lwIP 在分段发包时将数据拆碎为 pbuf 链表，让底层网卡发包逻辑稳定命中 `p->next == NULL` 的直出单段快路径。
4. **TCP NoDelay 与 UDP 游戏小包优先调度隔离**：
   - 入栈 lwIP 显式调用 `tcp_nagle_disable(newpcb)`，出栈与 `countingConn` 监控代理全链路透传 `SetNoDelay(true)`，彻底消除 40ms/200ms ACK 延迟等待；
   - 与大文件下载无冲突：中继层采用 32KB/64KB 块缓冲通过 `io.CopyBuffer` 批量复制，自然发出满尺寸 MSS 报文，兼具极速建连与满带宽吞吐；
   - 为 UDP 分配独立的 `udpCmdChan` 并赋予抢占式调度优先级，避免游戏/DNS 报文在后台进行大流量 TCP 下载时产生队头阻塞（Head-of-Line Blocking）。

### 4. 基准口径与已知局限

- **收尾开销已移出计时窗口**：`testing` 的计时一直到 benchmark 函数返回才停止，用裸 `defer` 注册的收尾会被算进 `ns/op`。此前 `LWIPStack.Close()` 在 tun 未先关闭时要等满 500ms 的「读循环退出」超时（`stack_lwip.go`），于是 `500ms / b.N` 被当成了单次握手耗时：

  | `-benchtime` | 报出的 ns/op |
  | --- | --- |
  | 200x | 2,513,561 |
  | 1000x | 505,263 |
  | 5000x | 104,303 |
  | 20000x | 29,696 |

  ns/op 掉 85 倍而乘回去的总时长恒为 0.5 s —— 这是与握手次数无关的固定开销在被摊，不是 lwIP 的建连代价。现在各用例在 `b.ResetTimer()` 之前 `defer benchTeardownGuard(b)`，它比各 `Close` 的 defer 注册得晚、按 LIFO 先执行，计时在收尾前停住。上文 TCP 握手一节的数据均为修复后重测。

- **握手用例不完成三次握手**：`BenchmarkStack_TCP_Handshake_*` 只注入 SYN 并等待 SYN/ACK，不含第三步 ACK。
- **UDP 有两组用例，别混用**：§1 正文的带背压组（`BenchmarkStack_UDP_Backpressure_*`）才是各栈的 UDP 处理能力；文末对照表里的无背压组（`BenchmarkStack_UDP_Throughput_*`）测的是注入成本，MB/s 列不能用于栈间比较。
- **带背压组的窗口是 64**：它回答的是「栈稳态下每包多少时间」，不是理论峰值吞吐；窗口取大取小都会让数字略变。另外每批的首尾各有一次同步（一批 64 个包摊一次），相对 1~12 µs 的单包处理可以忽略。
- **`go` 栈的握手用例跑不了大迭代数**：把 `-benchtime` 提到 5000x，它会在第 2511 次迭代上报 `timeout waiting for TCP response`（用例每轮新建连接、只轮转 16 个源端口），因此握手数据一律取 500x。同理，§1 的 UDP 分组用 128x~8192x 验证过 N 无关性，但对外发布的值统一取 500x 以便与 CI 对照。
- **数据来源与抖动**：环境 A 为 CI（commit `4e12271` 的运行）单次结果，同一用例不同 CI 运行的离散度可达 ~1.5 倍（lwIP 握手在两次运行里分别是 2.4 µs 与 3.6 µs）；环境 B 为 Android 真机 7 次运行的**中位数**，批内离散度 1.2~1.6 倍，不同批次之间可达 2~3 倍（受调度与 CPU 调频影响）。两端都看数量级即可，别读第三位有效数字。

## §7 检查清单（优化后验证）

| 检查 | 命令 |
| --- | --- |
| 编译通过 | `go build ./...` |
| 竞态检测 | `go test -race ./...` 全绿、无数据竞争 |
| 格式规范 | `gofmt -l .` 无输出 |
| 基准可复现 | `go test -tags "with_gvisor,with_lwip" -bench="BenchmarkStack_" -benchmem -benchtime=500x -run=^$ ./internal/tun/` |
| UDP 背压基准 N 无关 | `go test -tags "with_gvisor,with_lwip" -bench="BenchmarkStack_UDP_Backpressure" -benchmem -benchtime=8192x -run=^$ ./internal/tun/`，结果应与 500x 同量级 |

改动热路径（ACL 查询、relay、UDP/DNS 转发）后应回归以上各项（含基准可复现项）；新增共享状态时优先考虑"不可变快照 + atomic 换新"，避免引入锁竞争。

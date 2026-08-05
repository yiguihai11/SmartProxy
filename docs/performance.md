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

## §6 检查清单（优化后验证）

| 检查 | 命令 |
| --- | --- |
| 编译通过 | `go build ./...` |
| 竞态检测 | `go test -race ./...` 全绿、无数据竞争 |
| 格式规范 | `gofmt -l .` 无输出 |

改动热路径（ACL 查询、relay、UDP/DNS 转发）后应回归以上三项；新增共享状态时优先考虑"不可变快照 + atomic 换新"，避免引入锁竞争。

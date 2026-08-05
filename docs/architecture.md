# 总体架构

本文从整体上描述 SOCKS5 Smart Router 的架构：设计目标、模块依赖、两条入口链路、连接生命周期与关键设计决策。细节请分别参考各专题文档（见 [README.md](README.md)）。

## 1. 设计目标

| 目标 | 具体含义 |
| --- | --- |
| 高性能 | 低锁竞争 + 低 GC：热路径无锁读（`atomic.Pointer` + COW 快照）、`sync.Pool` 复用缓冲，目标支撑万级连接/秒。热路径日志降级为 `Debug`（`internal/tun/handler.go` 注释："每连接一条，万级连接/秒下打 INFO 是纯开销"）。 |
| 智能分流 | 国内 IP/域名直连、国外走代理；80/443 等端口先尝试直连，失败后自动回退代理（`Router.SmartConnectWithFallback`）。 |
| 规则驱动 | ACL 文件（`acl.txt`）用 `allow` / `block` / `proxy` 三类动作控制放行、阻断与强制代理，命中 `proxy` 规则时指定代理别名。 |
| 热重载 | `config.json`、`acl.txt`、`chnroute.txt` 三份文件可热更新，运行时近似实时生效、零停机（事件驱动 fsnotify，见 [hot-reload.md](hot-reload.md)）。 |

## 2. 模块依赖图

依赖自上而下单向流动，入口层只依赖引擎，引擎层依赖组件，组件之间不互相循环引用：

```
cmd/smartproxy
   │  装配 engine / config watcher / 信号处理
   ▼
internal/engine
   │  持有并装配下列组件；转发层负责两条入口分发
   ├──▶ internal/tun        （TUN 设备 + gvisor 栈 + 回调）
   ├──▶ internal/socks5     （SOCKS5 协议编解码）
   ├──▶ internal/udp        （UDP ASSOCIATE 会话）
   ▼
internal/route  internal/rules  internal/upstream  internal/dns
   │                │                │                │
   ▼                ▼                ▼                ▼
internal/relay  internal/chnroute  internal/dpi  internal/netutil
   │                                     │
   ▼                                     ▼
internal/safego                       internal/config（watcher）
internal/logbuf
```

- 依赖关系要点：`route` 依赖 `chnroute`（判定国内）、`upstream`（拨号）、`rules`（规则匹配）；`dns` 依赖 `chnroute`、`upstream`（代理查询）、`relay`（缓冲池）；`tun` 与 `socks5` 共用 `route` / `rules` / `upstream` / `dns`；所有模块的 goroutine 均经 `safego.Go` 包装。
- `internal/admin` 依赖 `logbuf`（日志查询）、`relay`（字节计数）、`udp`（会话统计）、`route`（黑名单）、`upstream`（代理健康）、`dns`（缓存）、`chnroute`（路由状态）。

## 3. 两条入口链路

### 3.1 SOCKS5 入口

```
TCP 连接 → internal/socks5.Handshake（30s deadline，握手成功后清除 deadline）
        → socks5.ReceiveRequest → 按 Command 分发
        ├── CONNECT        → engine.handleConnect → route / upstream
        └── UDP ASSOCIATE  → engine.handleUDPAssociate → internal/udp.Handler
```

- 握手与读请求共用一个 30s `deadline`；`internal/engine/engine.go` 中握手成功后显式 `conn.SetDeadline(time.Time{})` 清除，"不影响后续长连接 relay"。
- 每个连接一个独立 goroutine（`safego.Go("engine.handleClient", ...)`），并设置 TCP `KeepAlive` 与 `NoDelay`。
- CONNECT 走 `handleConnect`：先做端口/IP 阻断检查，再判断是否启用智能分流；智能模式读取首包提取域名后进入与 TUN 相同的分流逻辑（`tun.ReadClientHello` + `tun.ExtractDomain` 复用自 `internal/tun`）。
- UDP ASSOCIATE 创建独立 UDP 监听 socket，交给 `internal/udp.Handler` 管理会话（详见 [socks5.md](socks5.md)）。

### 3.2 TUN 入口

```
sing-tun gvisor 用户态栈
   ├── TCP 新连接  → TUNHandler.NewConnectionEx
   │                   └─ handleSmartConnect：ReadClientHello（3s）→ ExtractDomain（dpi）
   │                       → 域名规则 → IsDomesticByIP → EstablishConnection / SmartConnectWithFallback
   │                       → relay.TCPRelay
   └── UDP 新会话  → TUNHandler.NewPacketConnectionEx
                       ├─ port 53 → handleDNS（internal/dns.HandleDNS）
                       └─ 其他    → handleGenericUDP（getOrCreateRemote + remoteUDPReader）
```

- gvisor 栈回调控件由 `sing-tun` 库调度到独立 goroutine 调用（TCP：`stack_gvisor_tcp.go:94` 的 `go f.handler.NewConnectionEx(...)`；UDP：`udpnat/service.go:116` 的 `go func(){...}`），项目内再包一层 `safego.Go` 做 panic 恢复与命名。
- TUN 是透明代理，没有 SOCKS5 应答层；"伪成功回复"只在 SOCKS5 入口存在（见 [tun.md](tun.md) §4.1）。

## 4. 连接生命周期

### 4.1 SOCKS5 CONNECT（非智能模式）

1. 客户端 TCP 连入，`Handshake` 协商认证（无认证或用户名/密码）。
2. `ReceiveRequest` 解析目标 `Host:Port`；命令分发到 `handleConnect`。
3. 端口/IP 阻断检查：命中则回 `ReplyNotAllowed`（80/443 例外：先回 `ReplySuccess` 再 `SendEnhancedBlock`）。
4. `Router.EstablishConnection`：按 `SelectProxy` 结果走 direct / 指定代理 / 默认上游。
5. 成功后回 `ReplySuccess`，随后 `relayTCP` → `relay.TCPRelay` 双向转发直至任一方断开或 ctx 取消。
6. `handleClient` 退出时 `defer conn.Close()` 释放连接。

### 4.2 TUN TCP（handleSmartConnect）

1. `ReadClientHello` 读首包（3s 超时，池化缓冲 + 精确拷贝）。
2. `ExtractDomain` 从 TLS SNI 或 HTTP Host 提取域名；命中静态域名阻断 → `SendEnhancedBlock`。
3. `IsDomesticByIP`：国内 → `EstablishConnection` 直连，首包先写上游再 `TCPRelay`。
4. 国外/未知 → `SmartConnectWithFallback`：先直连，失败/读写校验失败 → 记入动态黑名单 → 回退默认代理；直连验证成功则保留直连（`prefixedConn` 回放已读的 1 字节）。
5. 全链路 `defer conn.Close()` + 各提前返回分支显式回调 `onClose(nil)`。

### 4.3 TUN UDP

1. `NewPacketConnectionEx`：端口/IP 阻断检查 → `handleGenericUDP`（port 53 走 `handleDNS`）。
2. `handleGenericUDP`：按 `destination.String()` 建 `tunUdpSession`，`udpSend` goroutine 循环 `ReadPacket`。
3. `getOrCreateRemote` double-checked：锁内查 map 命中即复用；未命中锁外拨号（最长 10s，不阻塞其他目标），二次检查防重复建连。
4. `remoteUDPReader` goroutine 回包（`buf.As` 包装，避免空数据报），`tunUdpSession` 空闲由 `startUDPCleaner`（5s 周期）回收。
5. 任一 goroutine 结束/ctx 取消/cleaner 触发 → 关闭所有 remote 连接并 `remoteWg.Wait()`。

## 5. 关键设计决策

| 决策 | 实现 | 效果 |
| --- | --- | --- |
| 无锁读 | `internal/rules` 的 `Engine.rules` 是 `atomic.Pointer[ruleSet]`，reload 构建新快照后 `Store`；`chnroute.Trie` 用 `atomic.Pointer[trieData]` 换根；`config`/`dns`/`route`/`tun` 的配置均用 `atomic.Pointer` | 热路径读零锁；重载不影响在途连接 |
| `sync.Pool` 缓冲 | `relay.bufferPool`（32KiB TCP 拷贝）、`relay.UDPBufPool`（64KiB UDP）、`relay.PacketPool`（4096）、`tun.clientHelloBufPool`（4096）、`udp.udpBufPool`（65535） | 降低分配与 GC 压力，支撑万级连接/秒 |
| singleflight | `dns.Handler.group` 合并同一域名+类型的并发查询；`udp.Handler.createGroup` 串行化同一目标的会话创建 | 避免重复查询/重复拨号 |
| `safego` | 所有业务 goroutine 经 `safego.Go(name, fn)` 启动，内部 `recover` 记录日志与栈 | panic 不拖垮进程，便于 goroutine 定位 |
| TCP 零拷贝 | `relay.tcpSplice` 优先 `*net.TCPConn.ReadFrom` 走内核 `splice(2)`，不满足时回退 `io.CopyBuffer` | 大流量下 CPU 占用显著下降 |
| 热重载近似实时 | fsnotify 事件驱动监听目录，`Write`/`Create` 即触发对应 reloader（非 mtime 轮询） | 配置变更毫秒级生效 |

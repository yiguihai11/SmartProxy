# 智能路由

智能路由负责在规则引擎判定之后决定"这条连接走直连还是代理"。实现位于 `internal/route/`（`router.go`、`blacklist.go`），具体选路与出站委托给 `internal/upstream` 的 `Manager`。

## §1 路由决策总览

```
目标 (host, port, domain)
  │
  ├─ 规则引擎判断: allow? → 直连
  │               block? → 阻断
  │               proxy alias? → 走指定上游
  │
  ├─ 国内/国外分流: IsDomestic(IP) (chnroute Trie)
  │    命中 → 直连
  │    未命中 → 代理
  │
  └─ Smart Connect (80/443): 先直连, 失败回退代理
```

入口有两处，逻辑等价：

- **SOCKS5**：`internal/engine/engine.go` 的 `handleConnect`——非 smart 端口走 `EstablishConnection`；smart 端口先回 `ReplySuccess`，`ReadClientHello(3s)` 读首包再分流。
- **TUN**：`internal/tun/handler.go` 的 `handleSmartConnect`——读首包 → `ExtractDomain` → 国内 `EstablishConnection` / 国外 `SmartConnectWithFallback`。

## §2 国内外分流

`Router.IsDomestic(ip)` / `IsDomesticByIP(ip)` / `isDomesticHost(host)` 都落到 `chnroute.Trie.Contains`。命中国内 CIDR → 直连；未命中 → 走默认上游代理。**DNS 污染检测也用同一份 chnroute**（`internal/dns/handler.go` 的 `isDNSCleanAndPrefer`：响应 A/AAAA 落在国内集合之外即视为污染）。

## §3 Smart Connect 探测

`SmartConnectWithFallback`（`internal/route/router.go`）实现"先直连、失败回退代理"：

```
SelectProxy(host, port, domain, engine)
  ├─ "direct"      → 直连（规则强制），写首包，保持直连
  ├─ 指定 alias    → selected.Connect，写首包（代理）
  └─ "fallback"
       ├─ 黑名单命中？ → 直接 ConnectDefault（代理）
       ├─ dialTCP(smartTimeout)
       │    └─ 失败 → simplifyError → 加入黑名单 → ConnectDefault
       ├─ Write(firstPkt)
       │    └─ 失败 → 加入黑名单 → ConnectDefault
       └─ Read 1 字节验证（SetReadDeadline(smartTimeout)）
            失败 → 加入黑名单 → ConnectDefault
            成功 → prefixedConn 包装，保持直连
```

- 直连成功还需**读取验证**：`io.ReadFull` 读 1 字节证明目标确实响应；这 1 字节用 `prefixedConn` 塞回 relay 首包，避免丢数据（`TestPrefixedConn_*` 覆盖）。
- `smartTimeout` 默认 3s（`config.SmartProxy.Timeout`），dial / write / read 三个阶段共用。
- `simplifyError` 把 `net.OpError` 规约为 `i/o timeout` / `connection refused` / `no route to host` 等简短原因，用于日志与黑名单 reason。
- 非 smart 路径 `EstablishConnection`：先规则选路（direct / alias），否则 `isDomesticHost` → 直连，最后兜底 `upstreamMgr.Connect`（返回状态 `proxy` / `direct` / `failed`）。

## §4 动态黑名单

`internal/route/blacklist.go` 提供 `Blacklist`（domain 与 ip 各一份，按 `host:port` 为 key）。行为：

- **直连任意环节失败（dial / write / read verify）即加入黑名单**，以 `blacklistTTL`（默认 300s）为过期时间，并记录失败 reason。
- 之后同一 host:port 或 domain:port 进入 smart connect 时，`IsBlacklisted` 命中 → **直接走代理**，不再尝试直连。
- `IsBlacklisted` 惰性删除过期项；`StartCleanup`（默认每 60s）用 `cleanExpired` 清扫。
- 容量上限 `blacklistMaxSize = 10000`，超限时淘汰 expiry 最早的一条（`evictOldestLocked`）。
- `BlacklistSnapshot()` / `RemoveFromBlacklist()` 供 admin 接口查询与手动解除。

## §5 选路策略

`upstream.Manager`（`internal/upstream/manager.go`）持有策略与所有代理：

- `SelectProxy(targetIP, port, domain, engine)`：先让规则引擎 `MatchProxyRule`，返回 `("direct", nil)`、`("", proxy)`（指定 alias）或 `("fallback", nil)`；alias 不存在时降级为 fallback。
- `orderedProxies()` 按策略 `strategy` 重排默认代理：`failover`（默认，顺序尝试）、`round_robin`（原子计数器轮询起点）、`random`（shuffle）、`latency`（可用优先 + 按健康检查 EMA 延迟升序，无延迟按 1h 计）。
- `ConnectDefault` 逐个尝试 `IsAvailable()` 的代理，失败 `RecordFailure` 后继续下一个，全部失败返回错误。

## §6 关键数据结构

`Router` 用 `atomic.Pointer[routerConfig]` 保存可热更新配置：

```go
type routerConfig struct {
    smartTimeout time.Duration
    blacklistTTL time.Duration
}
```

`UpdateConfig(smartTimeout, blacklistTTL)` 构建新 `routerConfig` 后 `r.cfg.Store(...)` 原子替换，读侧每次 `r.cfg.Load()`。config 热重载时（`internal/config/watcher.go` → `eng.Router.UpdateConfig`）即时生效、无需重启。cleanup 循环用 `safego.Go` 启动，`StopCleanup` 通过关闭 channel + `WaitGroup` 安全退出。

# 上游代理管理

上游代理模块管理所有出站代理：配置装载、连接建立（TCP/UDP）、健康检查熔断、选路策略与 DNS UDP 会话复用池。实现位于 `internal/upstream/`（`manager.go`、`proxy.go`、`health.go`、`udp_pool.go`）。

## §1 职责边界

规则引擎（`internal/rules`）只回答"这个目标走哪个 alias"；"怎么连、是否健康、从哪些代理里选"全部由本模块负责。`Manager` 是唯一入口：

- 启动时从 `config.Upstream` 装载 `alias → *Proxy` 与默认代理列表。
- 维护选路策略（`strategy`）、健康检查器（`HealthChecker`）、DNS UDP 复用池（`UDPAssociatePool`）。
- `Reload` 重建配置、重启健康检查与 UDP 池。

## §2 支持的代理协议

`internal/upstream/proxy.go` 的 `ProxyScheme`：

| scheme | 说明 |
| --- | --- |
| `socks5` / `socks5h` | SOCKS5，客户端把目标域名直接编码进请求（由代理远程解析） |
| `socks4` | SOCKS4，本地解析目标为 IPv4 后握手，回码 `0x5a` |
| `http` | HTTP CONNECT 隧道，带 Basic `Proxy-Authorization` |
| `https` | HTTP CONNECT over TLS（`tls.Client` + `HandshakeContext`） |

UDP ASSOCIATE 仅 `socks5` / `socks5h` 支持。

## §3 连接建立

- **TCP**：`Proxy.Connect(ctx, host, port)` 按 scheme 分发（`socks5Connect` / `socks4Connect` / `httpConnect`）；`dial` 统一 10s 超时、TCP keepalive 30s + NoDelay。`Manager.ConnectDefault` 按 `orderedProxies()` 顺序逐个尝试可用代理，失败 `RecordFailure` 后继续下一个。
- **UDP**：`socks5UDPAssociate` 握手后发 `{0x05,0x03,0x00,0x01,0,0,0,0,0,0}`，读 bind 地址（`0.0.0.0` / `::` 时替换为代理 Host）后 `DialUDP`，返回 `UDPProxyConn{UDPConn, tcpConn}`。`Manager.UDPAssociate` / `UDPAssociateSelected` 先按规则选指定代理，否则在默认代理里找 SOCKS5 支持者。

## §4 健康检查熔断状态机

`internal/upstream/health.go` 的 `ProxyHealth` 三态：

```
StateClosed ──失败 ≥ FailuresThreshold──► StateOpen
    ▲                                      │  OpenCoolDown 到期
    │         成功 ≥ SuccessesThreshold    ▼
    └──────────────── StateHalfOpen ◄─────┘
        （半开期间任意失败 → 立即回 StateOpen）
```

- `IsAvailable()`：Closed / HalfOpen 为可用，Open 不可用。
- `checkLoop` 每代理一个 goroutine（启动时随机错峰 0–2s），按 `cfg.Interval`（默认 60s）经 HTTP GET `cfg.URL` 探活（2xx–3xx 算成功），延迟做 EMA 平滑（`(lat*3+new)/4`）。
- `AutoDisableSingle`：仅一个代理时自动关闭健康检查。
- 手动 disable/enable：admin `/health/proxy` → `Manager.SetProxyHealth(alias, available)` → `SetManualState`。

## §5 选路策略

`Manager.SelectProxy(targetIP, port, domain, engine)` 先让规则引擎 `MatchProxyRule`：

- `("direct", nil)`：规则强制直连。
- `("", proxy)`：命中指定 alias；alias 缺失时返回 `("fallback", nil)`。
- `("fallback", nil)`：无规则命中，走默认代理列表。

`orderedProxies()` 按 `strategy` 重排默认代理：`failover`（默认，顺序）、`round_robin`（`atomic.Uint64` 轮询起点）、`random`（shuffle）、`latency`（可用优先 + 按 EMA 延迟升序，无延迟按 1h 计）。

## §6 DNS UDP ASSOCIATE 复用池

`internal/upstream/udp_pool.go` 的 `UDPAssociatePool`，`Manager` 构造时 `NewUDPAssociatePool(4)` 默认 4 条：

- `Acquire` 优先取池中连接：先做 **TTL 淘汰**（创建超 15s 大概率已被代理侧断开，直接丢弃），再做 **TCP 控制信道 5ms 快速探测**（读超时 = 连接正常；读到数据或出错 = 丢弃）。
- 池空则 `provider` 新建；`Release` 归还（超过 `maxSize` 直接关），`Discard` 丢弃损坏连接，`Close` 全关。
- DNS 走代理查询（`Manager.AcquireDNSUDP`）即复用它，避免每条 DNS 查询都重建 UDP 会话。

## §7 Reload

`Manager.Reload(cfg)`（config 热重载时由 `internal/config/watcher.go` 调用）：

1. 锁内 `rebuildFromConfig` 重建 aliasMap / defaultProxies / strategy。
2. `dnsUDPPool.Close()` 后新建 `NewUDPAssociatePool(4)`。
3. 所有代理 `health.reset()`。
4. `healthChecker.Reload(cfg.HealthCheck, newProxies)`：`Stop()`（cancel + `wg.Wait()` 等 checkLoop 退出）→ 换配置与代理列表 → 重新 `Start()`。

## §8 其他

- `Proxies()` 返回 `[]ProxyInfo`（含健康快照）供 admin 接口展示。
- 保留别名 `direct` 不可被覆盖；URL 为空、无 alias 或创建失败（`NewProxy` 报错）的代理跳过并告警。

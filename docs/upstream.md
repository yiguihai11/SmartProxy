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
- **UDP**：默认走 `socks5UDPAssociate` —— 握手后发 `{0x05,0x03,0x00,0x01,0,0,0,0,0,0}`，读 bind 地址（`0.0.0.0` / `::` 时替换为代理 Host）后 `DialUDP`，返回 `UDPProxyConn{UDPConn, tcpConn}`。`Manager.UDPAssociate` / `UDPAssociateSelected` 先按规则选指定代理，否则在默认代理里找 SOCKS5 支持者。

### UDP ASSOCIATE 被拒时的裸 UDP 兜底（`udp_addr`）

某些上游（如 shadowsocks-android 插件模式）主实例只启 `tcp_only`：它的 SOCKS5 服务对 UDP ASSOCIATE 回 **rep=0x07**（CommandNotSupported），但同端口的 UDP 上却常有配套的裸 UDP relay（udp_only 兜底实例，不要求 ASSOCIATE、读到带 SOCKS5 UDP 头的帧就转发）。为支持这类上游，`Proxy` 增加 `udp_addr`（配置键 `upstream.proxies[i].udp_addr`，由 `SetUDPAddr` 校验）：

- **`udp_addr` 为空**（默认）：标准 SOCKS5 UDP ASSOCIATE；若上游回 rep=0x07，自动兜底为**裸 UDP** 直连 `Host:socks-port`（打 WARN 日志，便于排查）。
- **纯端口 `"1080"`**：强制裸 UDP，直连 `Host:1080`（跳过握手）。
- **`host:port` / `":port"`**：强制裸 UDP，直连该精确地址（host 为空用代理 Host），如 `127.0.0.1:1080`、`[::1]:1080`。

实现：`rawUDPAssociate(raddr)` 直接 `net.DialUDP` 返回 `UDPProxyConn{UDPConn}`（`tcpConn` 为 nil，`Close` 已做空指针保护）；`resolveUDPAddr` 把 `udp_addr` 解析为 `*net.UDPAddr`（纯端口→Host+端口，host:port→原样）。注意两点：① `DialUDP` 恒成功，目标无监听时包会静默丢弃（黑洞），故 rep=0x07 兜底路径打 WARN；② 兜底只在**本代理**的 ASSOCIATE 被拒时发生，不改变 `Manager.UDPAssociate` 多代理 failover 语义。DNS 代理查询（`Manager.AcquireDNSUDP`）同走此路径，一处修改同时覆盖 DNS UDP。

**已端到端实测验证**：用官方 shadowsocks-rust v1.23.4 二进制搭出与 Android 兜底实例同形态的环境——`ssserver`（`"mode": "tcp_and_udp"`）+ `sslocal`（`"mode": "udp_only"`，本地 UDP 监听）——`Proxy{UDPAddr: "127.0.0.1:<udp端口>"}` 裸中继发出带 SOCKS5 UDP 头的 DNS 查询帧，收到真实 DNS 响应（TXID 匹配）。实测 trace 确认链路：sslocal 收到裸帧即 `created udp association for <peer>`（按源地址现场建关联、免 ASSOCIATE）→ `udp relay <peer> -> <target> (proxied)` → `connected udp remote <ssserver>` → ssserver `udp relay ... -> <target>` → 响应原路返回。回归测试见 `internal/upstream/rawrelay_e2e_test.go`（`go test -tags e2e`，需 `SS_SERVER_BIN`/`SS_LOCAL_BIN` 环境变量指向真实二进制）。

> 两个实测中发现的配置坑，供复现时参考：① shadowsocks-rust 官方 release 的 CLI 把端口并入 `-s`/`-b` 地址参数（无 `-p`/`-l`），用 JSON 配置最稳；② `ssserver` 默认 `mode: TcpOnly` **不开 UDP**，必须显式 `"mode": "tcp_and_udp"`，否则 UDP 载荷在服务端被静默丢弃。

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

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
| `ss` | Shadowsocks（经典 AEAD，内置实现，无需外部 `sslocal`）。URL 形如 `ss://base64(method:password)@host:port`，也兼容明文 `ss://method:password@host:port`。TCP + UDP 均支持，见 §3.1 |

UDP 支持：`socks5` / `socks5h`（标准 UDP ASSOCIATE，或 `udp_addr` 裸中继）与 `ss`（内置 SS UDP relay，见 §3.1）。

## §3 连接建立

- **TCP**：`Proxy.Connect(ctx, host, port)` 按 scheme 分发（`socks5Connect` / `socks4Connect` / `httpConnect` / `ssConnect`）；`dial` 统一 10s 超时、TCP keepalive 30s + NoDelay。`Manager.ConnectDefault` 按 `orderedProxies()` 顺序逐个尝试可用代理，失败 `RecordFailure` 后继续下一个。
- **UDP**：默认走 `socks5UDPAssociate` —— 握手后发 `{0x05,0x03,0x00,0x01,0,0,0,0,0,0}`，读 bind 地址（`0.0.0.0` / `::` 时替换为代理 Host）后 `DialUDP`，返回 `UDPProxyConn{UDPConn, tcpConn}`。`Manager.UDPAssociate` / `UDPAssociateSelected` 先按规则选指定代理，否则在默认代理里找 UDP 支持者（`SupportsUDP()`：`socks5` / `socks5h` / `ss`）。

### §3.1 内置 Shadowsocks（`ss://`）

`internal/upstream/ss.go` 用 [sing-shadowsocks](https://github.com/sagernet/sing-shadowsocks)（sing-box 生态，仍维护中的纯 Go 库）直接以 shadowsocks 协议连接远程 SS 服务器，**不再依赖外部 `sslocal` 进程**（之前 Termux 上要先跑一个 sslocal 才能用 SS）。支持经典 AEAD 加密：`aes-128/192/256-gcm`、`chacha20-ietf-poly1305`、`xchacha20-ietf-poly1305`；AEAD-2022（SIP022）：`2022-blake3-aes-128/256-gcm`、`2022-blake3-chacha20-poly1305`；以及不加密的 **`none`**（`plain` 是同义词）。`newSSMethod` 显式校验 method 名称（`shadowaead.New` 对未知方法不报错、会留 nil constructor，这里显式拦截拼写错误）。SIP003 插件的 `?plugin=` 参数**只解析不执行**，见下小节。

> `none`/`plain` 与 AEAD 的差异及 wire 格式，见下「`none`/`plain`（不加密）」小节。

- **凭据解析**（`parseSSUserinfo`）：userinfo 优先按 shadowsocks URI 规范做 base64 解码（RawURL / URL / RawStd / Std 四种都试），失败则按明文 `method:password` 处理，第一个 `:` 之后整段为密码（含冒号也保留）。注意 `url.Parse` 会在第一个冒号处切分并把后续冒号 percent-encode，实现用 `Username()/Password()` 取回解码后的密码再重组。`none`/`plain` 不需要密码，可写免密码形式 `ss://none@host:port`（无冒号）；解码仅在结果含 `:`（即 `method:password` 结构）时接受，避免 `none` 这种恰好是合法 base64 的明文方法名被误解码。
- **TCP**：`ssConnect` 走 `dial`（fwmark + keepalive）→ `ssMethod.DialConn(conn, dest)` 得到加密流，透明对接上层。
- **UDP**：`ssUDPAssociate` 直接 `net.DialUDP` 到 SS 服务器端口，用 `ssMethod.DialPacketConn` 得到逐包携带目标地址的 packet conn（sing 的 `clientPacketConn` 每包自含 destination），因此**单条 UDP 连接即可服务任意目标**，与 SOCKS5 上游的复用模型一致。适配器 `ssUDPConn` 把上游一侧的 SOCKS5-UDP 帧（RSV|FRAG|ATYP|ADDR|PORT|payload）翻译成 SS UDP 包：`Write` 解析帧→`WritePacket`（预留 headroom + AEAD tag 容量，避免 sing `buf` panic）；`Read` 从 `ReadPacket` 拿到 payload + 来源地址→补 SOCKS5 响应头返回完整帧。`udp_addr` 对 `ss` 不适用（SS UDP 本来就是内置 relay，无需裸中继兜底）。

UDP 复用池（§6）对 `ss` 同样生效：`ssUDPConn` 实现了 `ProbeTCP()`（无 TCP 控制信道，返回 nil 视为健康，靠 TTL 淘汰兜底），池的 `Acquire/Release/Discard` 已从 `*UDPProxyConn` 泛化为 `net.Conn` + 可选 `tcpProbeConn` 接口。

#### AEAD-2022（SIP022）

`2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` / `2022-blake3-chacha20-poly1305` 的 key 语义与经典 AEAD 不同：**不是密码，而是 base64 编码的二进制 PSK**（16B / 32B），多用户时多个 PSK 用 `:` 连接。`newSSMethod2022` 用 `decodeBase64Key` 依次尝试 Std / URL / Raw 变体解码（兼容 ss-android 导出时可能不带 `==` padding 的 key），再交给 `shadowaead_2022.New`；空、非 base64、长度不足的 key 在 `NewProxy` 时即报错。

- **密码框填的就是 base64 key**（如 `MDEyMzQ1Njc4OWFiY2RlZg==`），不是明文密码；多 PSK 用 `:` 连接。
- **UDP 是会话式**（客户端/服务端各持独立会话：首包携带 sessionId + packetId、滑动窗口去重、HeaderType 方向不对称、带最多 ~900B 的 padding），不是经典 AEAD 的自包含包，服务端必须用 `shadowaead_2022.Service` 解包。因此 `ssUDPConn.Write` 改用 `N.CalculateFrontHeadroom` 动态预留 2022 的会话/padding 头（对经典 AEAD 与 `none` 同样正确）。
- 进程内测试覆盖 TCP/UDP 往返（`ss_test.go` 的 `TestSSConnectTCP`、`TestSSUDPConnRoundTrip2022`）。

#### SIP003 插件：`?plugin=`（只解析）

ss-android 导出的链接可带 `?plugin=id;key=val;key=val`（SIP003 插件，如 `obfs-local`、`v2ray-plugin`）。SmartProxy **只解析保留该参数、不执行插件进程**（插件是外部二进制，需要本地跑 obfs-local 等）。`NewProxy` 把 `?plugin=` 解析进 `Proxy.Plugin`；配置了插件的上游在 `ssConnect`/`ssUDPAssociate` 时返回明确错误（提示去掉 `?plugin=`，或自行在服务端完成混淆）。dashboard 代理对话框把该参数显示为只读，保存时原样保留，避免误删。

#### `none`/`plain`（不加密）

shadowsocks-rust 中 `plain` 与 `none` 是**同一个** `CipherKind::NONE` 的别名（`shadowsocks-crypto` `kind.rs`：`"plain" | "none" => Ok(NONE)`），规范名是 `none`。与经典 AEAD 的差异：

| 方面 | AEAD（如 `aes-128-gcm`） | `none`/`plain` |
| --- | --- | --- |
| key | 密码经 HKDF 派生（key_len 16/32） | key_len 0，**不需要密码**（rust 端给了密码也只 warning） |
| TCP wire | `[salt][AEAD(addr)]` 分块，每块带 nonce + 16B tag | 明文地址头 + 明文 payload，无 salt、无分块框架（rust 走 `CryptoStream::new_none` 快速路径） |
| UDP wire | 每包 `[salt][AEAD(addr\|payload)]`（随机 salt，自包含） | 每包明文 `[addr][payload]`，双向对称 |
| 完整性 | AEAD 认证 | 无 |

- **互通性**：sing-shadowsocks 的 `shadowsocks.NewNone()` 产出与 rust 端完全相同的 wire 格式，客户端直接互通；`ssUDPConn` 适配器逐包携带目标地址的模型对 `none` 同样适用（无 tag，`WritePacket` 只明文序列化地址）。TCP/UDP 均有进程内测试覆盖。
- **用途与风险**：零保密性、零完整性，中间人可读改全部流量。只用于调试、测试，或隧道本身已被 TLS/SSH 加密、不想叠加加密开销的场景；不要单独用于生产。smartproxy 与官方 shadowsocks-android 一样把 `none` 放进下拉（官方 App 的 `arrays.xml` 第一个就是 `NONE`），并标注「明文不加密 ⚠」。

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

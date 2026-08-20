# 引擎端到端回归测试(TCP/UDP 直连 · 代理 · ACL · TUN 隧道)

`internal/engine/direct_e2e_test.go`、`proxy_e2e_test.go` 与 `tun_e2e_test.go` 是**基础能力
回归测试**:不改逻辑的前提下,每次动到路由 / UDP 会话 / ACL / 上游转发 / TUN 入口相关代码,
都必须跑绿。

```bash
# 必须带 -tags with_gvisor:TUN 用例依赖 sing-tun 的 gvisor 栈,没这个 tag 只编译 stub
go test -tags with_gvisor ./internal/engine/ -run TestEngine -count=1   # 功能
go test -tags with_gvisor -race ./internal/engine/ -run TestEngine -count=1  # 竞态
```

## 覆盖矩阵

| 场景 | TCP | UDP | 断言依据 |
|---|---|---|---|
| 直连(ACL force-direct) | `TestEngineDirectTCP`(+1MB 大包) | `TestEngineDirectUDP` | 引擎侧 `relay.DirectBytesUp` / `udp.DirectBytesUp` 增长,proxy 计数不动 |
| 直连 · IPv6 目标 | `TestEngineDirectTCP_IPv6` | `TestEngineDirectUDP_IPv6` | 客户端经 `::1` 接入、目标 ATYP=0x04,断言同上 |
| 代理 · ACL 规则命中 | `TestEngineProxyTCP_RuleSelected` | `TestEngineProxyUDP_RuleSelected` | 主引擎 proxy 计数增长 **且** 上游引擎 direct 计数增长 |
| 代理 · 默认策略兜底 | `TestEngineProxyTCP_DefaultStrategy` | `TestEngineProxyUDP_DefaultStrategy` | 同上(空 ACL/chnroute + `strategy: up`) |
| 代理 · IPv6 目标 | `TestEngineProxyTCP_IPv6` | `TestEngineProxyUDP_IPv6` | 客户端经 `::1` 接入、目标 ATYP=0x04 走上游(上游 B 是 IPv4 SOCKS5 不受影响) |
| ACL `block ip` | `TestEngineACL_BlockIP` | 同用例 UDP 分支 | TCP 回 `ReplyNotAllowed(0x02)`;UDP 帧被静默丢弃 |
| ACL `block port` | `TestEngineACL_BlockPort` / `_IPv6` | — | TCP 回 `0x02`(端口匹配族无关,`IsPortBlocked` 纯端口 map) |
| ACL `block cidr` | `TestEngineACL_BlockCIDR` | 同用例 UDP 分支 | TCP 回 `0x02`;UDP 帧静默丢弃(走 blockedCIDR trie) |
| ACL `block domain` 精确+后缀 | `TestEngineACL_BlockDomain` | 同用例 UDP DOMAIN 帧 | TCP 回 `0x02`;UDP DOMAIN 型帧丢弃;拦截在 dial 前、域名无需可解析 |
| ACL `allow` 优先于 proxy | `TestEngineACL_AllowOverridesProxy` / `_IPv6` | — | 配了走上游规则但 allow 命中 → 走直连 |
| ACL `allow cidr` 优先 | `TestEngineACL_AllowCIDR` | — | `proxy ip` 被 `allow cidr` 覆盖 → 直连 |
| ACL `allow port` 优先 | `TestEngineACL_AllowPort` | — | `proxy port` 被 `allow port` 覆盖 → 直连 |
| ACL `allow domain` 优先 | `TestEngineACL_AllowDomain` | — | `proxy domain` 被 `allow domain` 覆盖 → 回落默认上游(非直连,见下) |
| proxy 按端口 | `TestEngineProxy_Port` | — | A proxy 计数涨 + B direct 涨(`proxyPorts` map) |
| proxy 按精确 IP | `TestEngineProxy_IP` | — | 同上(`proxyIPs` map) |
| proxy 按域名 | `TestEngineProxy_Domain` | — | 域名 CONNECT(ATYP=0x03)命中 `proxyDomains`;A/B 双计数 |
| TUN 隧道 · 直连 | `TestEngineTUN_DirectTCP` | `TestEngineTUN_DirectUDP` | 真实建 tun,SO_BINDTODEVICE 客户端进隧道;TCP 走 relay 计数(连接关闭才结算),UDP 走 tun handler 自身转发、**只断回包内容** |
| TUN 隧道 · 代理 | `TestEngineTUN_ProxyTCP` | `TestEngineTUN_ProxyUDP` | tun 引擎把流量交给 SOCKS5 上游引擎 B;B 侧 `relay/udp.DirectBytesUp` 增长 |
| TUN 隧道 · block | `TestEngineTUN_BlockTCP` | `TestEngineTUN_BlockUDP` | TCP 拨号失败;UDP 无回包读超时 |

> TUN 用例需要 `/dev/net/tun` + CAP_NET_ADMIN,不满足自动 Skip(GitHub Actions 托管
> runner 通常没有)。本机 Linux 是它们的真实执行环境——改了 tun 入口代码后本机跑这组,
> CI 只负责保证 gvisor 栈在 with_gvisor 下能编译。

## 为什么断言计数器,而不只是「echo 通了」

「echo 通了」证明不了路径——流量可能走了错误的转发路径照样回包。这里用 relay/udp 包的
**全局字节计数器**采样 delta 断言真实路径:

- 直连:relay/udp `DirectBytesUp` 增长,`ProxyBytesUp` 不动;
- 代理(双引擎串联:引擎 B 是引擎 A 的 SOCKS5 上游):A 的 `ProxyBytesUp` 增长(B 收到并
  直连目标),B 的 `DirectBytesUp` 增长(A 确实把数据交给了上游)。

## domain 规则的入口缺口(已修,别再改回去)

`block/proxy domain` 规则依赖「目标域名」参与规则匹配,但两个入口曾经**恒传空串**,
导致 domain 规则在那两条路上永不命中:

1. **SOCKS5 TCP 非 smart 路径**(`internal/engine/engine.go` `handleConnect`):CONNECT
   ATYP=0x03 时 `host` 就是域名,以前 `EstablishConnection(host, port, "", ...)` 丢了它。
   已修:`host` 非 IP 时作为 `domain` 传入,并在 dial 前补 `IsDomainBlocked(host)` 检查
   (80/443 回 `SendEnhancedBlock`,其余回 `ReplyNotAllowed`,与 IP/port 分支语义一致)。
2. **UDP 入口**(`internal/udp/handler.go`):UDP 帧 DOMAIN 型目标(ATYP=0x03)把域名放进
   `ip`,但 `SelectProxy(ip, port, "", ...)` 同样丢 domain。已修:解析时单独保留 `domain`,
   新会话前加 `IsDomainBlocked`,并传给 `createUDPSession → SelectProxy`。

TUN 入口(`tun/handler.go`)与 smart 路径(`ExtractDomain`/`ExtractSNI`)本来就传 domain,未动。
回归钉:见 `TestEngineACL_BlockDomain`(精确+后缀, TCP/UDP)与 `TestEngineProxy_Domain`。

域名规则的架构约束(写测试时踩过):域名不是 IP,`isDomesticHost` 判不了「国内」,
`allow domain` 命中后回落的默认路径是**默认上游而非直连**——纯直连引擎收到域名 CONNECT
会因 `ConnectDefault` 无上游而失败。所以域名走上游的用例,上游必须显式配
`proxy domain <域名> direct` 才能担当目标。

## 断言方法论(两条铁律,违反必出假绿/假红)

1. **TCP relay 计数器在连接关闭后才结算。** `relay.tcp` 的 `relayDirection` 在 copy 循环
   退出(连接关闭)后才累加计数;echo 连接常开时,读回复后立刻采样是 delta=0。必须**先关闭
   客户端连接**再断言,并用 `awaitIncrease` 轮询等待计数增长。UDP 计数器逐包同步累加,
   读完回包即已入账,无需等待。

2. **计数器是进程级全局,双引擎测试互相污染。** A 把流量交给 B 时,A 的 proxy 计数与 B 的
   direct 计数在同一窗口内同时增长。因此双引擎测试**只做单引擎正断言**:A 侧只断
   `ProxyBytesUp` 增长(`assertProxiedTraffic`),B 侧只断 `DirectBytesUp` 增长
   (`assertUpstreamDirect`);绝不能跨引擎断「==0」。单引擎场景(纯直连、ACL allow 且上游
   闲置)才能同时断正负(`assertDirectTraffic`)。

## UDP「流量不走」的根因(本组测试存在的意义)

直连 UDP 曾出现「客户端发帧无回包、引擎 WARN 源地址不匹配」:SOCKS5 UDP ASSOCIATE 回复
广告的 BND 地址用 `getOutboundIPv4()`,loopback 客户端按 BND 把包发到非 loopback 出站 IP,
源地址对不上源校验的 `clientIP(127.0.0.1)` → 全部丢包;VPN 手机上该函数返回 TUN 网段 IP,
更彻底走不通。修复:`handleUDPAssociate` 广告「客户端实际连到的本地地址」(`tcpLocal.IP`),
见 `internal/engine/engine.go`。TUN 隧道路径无此问题。改任何 UDP 会话相关代码,先跑这组测试。

## TUN 用例的两个内核坑(改 `tun_e2e_test.go` 前必读)

TUN 用例的客户端「经隧道拨服务器」会遇到两层独立的内核过滤,都是静默丢包、表现成
i/o timeout。**改这个文件时别把对策删掉**,否则就是「直连/代理全超时」的下一次踩坑:

1. **gVisor martian 回环过滤**(拨 127.0.0.1 必死)。sagernet gvisor fork 在非回环 NIC 上
   丢弃源/目的落在 127.0.0.0/8 的包(`AllowExternalLoopbackTraffic` 默认 false)。所以测试
   目标恒为**非回环的本地别名** `198.18.0.2`(RFC 2544 benchmark 段,加到 lo):gVisor 放过、
   引擎 dial 走 local 表直达 echo、SO_BINDTODEVICE 客户端照常进隧道。

2. **内核 martian 源过滤**(`accept_local` 门控,和 rp_filter 无关)。gVisor 回包源地址 =
   客户端 SYN 目的地址 = 198.18.0.2,而它是 lo 上的本地别名。内核在 tun 上收到「源是本机
   另一接口的本地地址」的包,在路由阶段(prerouting 之后)当伪造源丢弃——SYN-ACK 能看见、
   连接永远建不起来。对策:`startTUNEngine` 给自建 tun 设 `net.ipv4.conf.<tun>.accept_local=1`
   (cleanup 恢复)。生产环境踩不到(服务器永远是远端真实 IP)。别用「route via lo 让它可达
   但不本地」替代——实测内核只对 LOCAL 表命中做本地投递,该方案 0.0.0.0 listener 收不到包。

3. **`-race` 下自动 Skip**:sing-tun 的 `GVisor.Start` 先 attach endpoint(dispatch 循环
   拉起)再装 transport handler,gvisor 的 `Stack.transportProtocolHandlers` 无锁 map,
   启动窗口期递送必撞数据竞态——竞态两侧都在 gvisor/sing-tun 依赖内,本仓库代码只是调用方。
   因此 TUN 用例在 `go test -race` 下被 `requireTUN` 跳过(Go 隐式 `race` 构建标签判定),
   其余用例与 CI 回归照常全跑。不要试图「修好」它——那是上游 bug,等 sing-tun 修了再放开。

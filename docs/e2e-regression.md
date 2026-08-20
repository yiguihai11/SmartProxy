# 引擎端到端回归测试(TCP/UDP 直连 · 代理 · ACL)

`internal/engine/direct_e2e_test.go` 与 `internal/engine/proxy_e2e_test.go` 是**基础能力回归
测试**:不改逻辑的前提下,每次动到路由 / UDP 会话 / ACL / 上游转发相关代码,都必须跑绿。

```bash
go test ./internal/engine/ -run TestEngine -count=1   # 功能
go test -race ./internal/engine/ -run TestEngine -count=1  # 竞态
```

## 覆盖矩阵

| 场景 | TCP | UDP | 断言依据 |
|---|---|---|---|
| 直连(ACL force-direct) | `TestEngineDirectTCP`(+1MB 大包) | `TestEngineDirectUDP` | 引擎侧 `relay.DirectBytesUp` / `udp.DirectBytesUp` 增长,proxy 计数不动 |
| 代理 · ACL 规则命中 | `TestEngineProxyTCP_RuleSelected` | `TestEngineProxyUDP_RuleSelected` | 主引擎 proxy 计数增长 **且** 上游引擎 direct 计数增长 |
| 代理 · 默认策略兜底 | `TestEngineProxyTCP_DefaultStrategy` | `TestEngineProxyUDP_DefaultStrategy` | 同上(空 ACL/chnroute + `strategy: up`) |
| ACL `block ip` | `TestEngineACL_BlockIP` | 同用例 UDP 分支 | TCP 回 `ReplyNotAllowed(0x02)`;UDP 帧被静默丢弃 |
| ACL `block port` | `TestEngineACL_BlockPort` | — | TCP 回 `0x02` |
| ACL `allow` 优先于 proxy | `TestEngineACL_AllowOverridesProxy` | — | 配了走上游规则但 allow 命中 → 走直连 |

## 为什么断言计数器,而不只是「echo 通了」

「echo 通了」证明不了路径——流量可能走了错误的转发路径照样回包。这里用 relay/udp 包的
**全局字节计数器**采样 delta 断言真实路径:

- 直连:relay/udp `DirectBytesUp` 增长,`ProxyBytesUp` 不动;
- 代理(双引擎串联:引擎 B 是引擎 A 的 SOCKS5 上游):A 的 `ProxyBytesUp` 增长(B 收到并
  直连目标),B 的 `DirectBytesUp` 增长(A 确实把数据交给了上游)。

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

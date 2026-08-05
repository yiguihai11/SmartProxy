# DNS 处理

DNS 模块负责 DNS 查询的反污染、缓存、并发合并与 IP 优选。实现位于 `internal/dns/`（`handler.go`、`cache.go`、`preference.go`），入口在 `internal/udp/handler.go`（SOCKS5 UDP ASSOCIATE 的 53 端口）与 `internal/tun/handler.go`（TUN handleDNS）。

## §1 数据流

```
DNS 查询 (qname, qtype, targetIP:53)
  │
  ├─ 域名规则拦截 (blocked) → BuildFakeResponse
  ├─ 缓存命中 → 返回
  ├─ singleflight 合并同 qname+qtype
  ├─ 国内目标 (IsDomestic): queryUDPVerifyID (直连) → 污染检查
  │    └─ 污染 → 走国外 DNS 回退 (queryViaProxyVerifyID)
  ├─ 国外目标: queryViaProxyVerifyID (走代理 UDP)
  └─ IP 优选 (Preference): 对多 A/AAAA 记录并行探测选最快
```

`HandleDNS(ctx, queryWire, targetIP, targetPort, engine)`（`internal/dns/handler.go`）主流程：

1. `cfg.enabled` 为 false 返回 nil（上层走 passthrough，见 §7）。
2. `msg.Unpack(queryWire)`，`qname` 去尾点并转小写。
3. `engine.IsDomainBlocked(qname)` → `buildFakeResponse`（拦截发生在缓存之前）。
4. `cache.Get(qname, qtype)` 命中 → 修正当前 caller 的 transaction ID 后返回。
5. `singleflight.Do("qname|qtype")`：同一 qname+qtype 的并发查询只查一次，其余共享结果并各自修正 TXID。
6. 国内目标 `queryUDPVerifyID`（直连 UDP，`_VerifyID` 校验响应 TXID 一致）；失败 → 走国外 DNS 代理回退。国外目标 `queryViaProxyVerifyID`（走上游 UDP ASSOCIATE）。

## §2 反污染

`isDNSClean(wire)`：Unpack 后遍历 Answer 中所有 A/AAAA，用 chnroute 判断每个 IP 是否在国内集合内；**出现任何一个国外 IP 即判定污染**。chnroute 未加载（`IsEmpty()`）时直接放行。

## §3 单次解析优化（核心）

`isDNSCleanAndPrefer(ctx, wire, qname) (out, preferCached, clean)` 对国内 DNS 响应**只 Unpack 一次**，用同一份 `*dns.Msg` 依次完成污染检查与 IP 优选：

```
Unpack 一次 → 污染检查（A/AAAA 是否都在 chnroute 内）
              ├─ 污染 → (wire, false, false)            触发国外 DNS 回退
              └─ 未污染:
                   ├─ 未启用 IP 优选 → (wire, false, true)  原样返回、不缓存
                   └─ 启用 → filterIPPreference(msg, wire)
                             ├─ 有最优 IP → (重打包 wire, true, true)  可缓存
                             └─ 探测全失败 → (origWire, false, true)   不缓存
```

`applyIPPreference` 保留为**薄包装**（Unpack + 调 `filterIPPreference`），仅供测试/独立调用；热路径不再二次 Unpack。`TestIsDNSCleanAndPrefer` 覆盖三条路径：未启用优选（干净、不缓存、原样返回）、污染响应（不干净）、优选启用分支。

## §4 IP 优选（preference.go）

`Preference.PreferIPs(ctx, ips)`：并行探测候选 IP，选延迟最低者。模式来自配置 `dns.speed_check_mode`：

| 模式 | 探测方式 |
| --- | --- |
| `ping` | 调 `ping -c1 -W0.5`（v6 用 ping6），正则解析 `time=... ms` |
| `tcp:80,443` | 对每个端口 `Dial`（超时 2s），取首个连通耗时 |

`filterIPPreference` 只处理多 IP：对 A/AAAA 分别选最优，重打包仅保留最优记录 + 其他类型记录。**探测全部失败时返回原始响应且不缓存**（`cached=false`），下次查询重试——这是刻意设计（见 memory: dns-ip-preference-logic），不调整。

## §5 缓存

`internal/dns/cache.go` 的 `Cache`：LRU（`container/list`）+ `map[cacheKey]cacheEntry`，`cacheKey = {qname, qtype}`。`Set` 用 `defaultTTL`（配置 `dns.cache.ttl`，默认 300s）或调用方指定 ttl；`Get` 命中时 LRU 前置、惰性删除过期项。后台 `cleanLoop` 每分钟清扫过期项。`CacheGet/CacheSet/CacheLen/CacheClear/...` 暴露给上层（udp handleDNS 命中缓存时直接回包）。

## §6 域名劫持

`buildFakeResponse(queryWire)`：Unpack 查询 → `SetReply` → 为每个 Question 造一条 A（`cfg.blockedIP`）或 AAAA（`cfg.blockedIP6`）记录（TTL 60s）→ 重新 Pack。对被 block 的域名返回伪造响应；解析失败原样返回 query。`HandleDNS` 的域名拦截发生在缓存之前（`TestHandleDNS_BlockBeforeCache` 验证 block 覆盖缓存）。

## §7 入口与 passthrough

- **SOCKS5 UDP ASSOCIATE**（`internal/udp/handler.go` 的 `handleDNS`）：`HandlePacket` 中 `port==53` 时若 `dnsHandler.Enabled()` 走 `handleDNS`，否则 **DNS passthrough 模式**——`handleGenericUDP` 直接把原始 UDP 包转发（不做解析/缓存）。
- `handleDNS` 先做域名拦截与缓存（都只对 UDP payload 生效），`isPrivateIP(realIP)` 的目标走直连查询；否则 `HandleDNS`。
- **TUN**（`internal/tun/handler.go` 的 `handleDNS`）：对每个包 `SetReadDeadline(30s)` 且**每包重置**空闲计时，读包 → `HandleDNS` → 回包。

## §8 查询辅助与公开 API

- `queryUDP(ctx, wire, host, port)`：直连 UDP 查询，复用 `relay.PacketPool` 缓冲、按 `cfg.queryTimeout` 设 deadline；`queryUDPVerifyID` 在其上多校验一步响应 TXID。
- `queryViaProxy(ctx, wire, dnsHost, dnsPort)`：走 `Manager.AcquireDNSUDP` 拿到 UDP 会话 → 前置 SOCKS5 UDP 头（`encodeSOCKS5Addr` 编码 ATYP）→ 写查询 → 按响应 ATYP 剥离头部取 DNS payload；成功 `ReleaseDNSUDP`、失败 `DiscardDNSUDP`。`queryViaProxyVerifyID` 同样校验 TXID。
- 对外可访问器：`QueryUDP`、`IsDNSClean`、`BuildFakeResponse`、`CacheGet/CacheSet/CacheLen/CacheClear/CacheRemove/CacheEntries`、`Enabled`、`IsDomestic`、`UpdateConfig`（热重载时由 config watcher 调用）。

# SmartProxy

[![Go Report Card](https://goreportcard.com/badge/gitlab.com/yiguihai/smartproxy)](https://goreportcard.com/report/gitlab.com/yiguihai/smartproxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

高性能智能路由代理：TUN 全局透明代理 + 标准 SOCKS5 服务双入口，自动国内外分流、DNS 反污染与 IP 优选、DPI 域名识别、多上游负载与健康检查、配置热重载。

## 🚀 核心特性

- **双入口**：系统级 TUN 透明代理（gvisor 栈）+ SOCKS5 服务端，ACL 统一放行/阻断/分流
- **多上游**：SOCKS5/SOCKS5H/SOCKS4/HTTP(S) 与**内置 Shadowsocks（`ss://`，TCP+UDP）** 上游，健康检查熔断 + failover / round_robin / random / latency 选路；TCP 与 UDP 各自独立熔断，UDP 走主动 DNS 探测
- **智能分流**：基于 chnroute Trie 的国内外分流；80/443「先直连、失败回退代理」；直连失败自动加入动态黑名单
- **DNS 反污染**：污染检测、IP 优选（ping/tcp 探测）、缓存 + singleflight 并发合并
- **规则引擎（ACL）**：`allow`/`block`/`proxy` × `port`/`ip`/`cidr`/`domain`（含 `*.` 通配），Copy-on-Write 无锁快照
- **DPI**：从首包提取 TLS SNI / HTTP Host，IP 阶段即可按域名分流
- **热重载**：config.json / acl.txt / chnroute.txt 均支持事件驱动热更新，无需重启
- **高性能**：COW 无锁读、sync.Pool 缓冲复用、TCP splice 零拷贝、并发全链路 race 测试
- **全平台**：Linux / Windows / Darwin 可编译；Android/iOS 通过 fd 模式接入（见下文）

## 🛠️ 快速开始

```bash
make build            # 编译当前平台（默认带 with_gvisor，含 TUN 支持）
make build-all        # 交叉编译所有支持平台
```

启动需要三个文件：`config.json`、`chnroute.txt`、`acl.txt`：

```bash
./build/smartproxy config.json
```

## 📝 配置示例

```json
{
  "listen": { "host": "::", "port": 1080 },
  "upstream": {
    "default": "failover",
    "proxies": [{ "alias": "ss-local", "url": "socks5://127.0.0.1:1081" }]
  },
  "routing": { "chnroute_file": "chnroute.txt", "acl_file": "acl.txt" },
  "dns": { "enabled": true, "foreign": { "ipv4": "8.8.8.8:53" } }
}
```

完整字段见 [docs/config.md](./docs/config.md)，示例见 [config.json](./config.json)。

> 每个上游可用 `proxies[].mode` 标记能力：`tcp_and_udp`（默认）/ `tcp_only` / `udp_only`，与 shadowsocks 一致。`socks5`/`socks5h` 的 UDP 先走标准 UDP ASSOCIATE，**任意失败**（含 rep=0x07）自动兜底裸 UDP relay 到 `host:port`；`udp_only` 节点（无 TCP 监听器，如 shadowsocks 的 UDP fallback 实例）UDP 直接裸中继到自身地址。详见 [docs/upstream.md](./docs/upstream.md) §3.2。

## 📖 ACL 规则速览

每行一条：`<action> <type> <value> [alias]`，`#` 注释，大小写不敏感。

| action | 说明 |
|--------|------|
| `allow` | 显式放行，跳过后续 block/proxy 检查 |
| `block` | 拒绝并断开连接 |
| `proxy` | 走指定上游代理，`alias` 对应 `upstream.proxies[].alias` |

| type | 说明 | 示例 |
|------|------|------|
| `port` | 精确端口 | `80` |
| `ip` | IP（含 `/` 自动按 CIDR） | `1.2.3.4` |
| `cidr` | CIDR 前缀 | `10.0.0.0/8` |
| `domain` | 域名（`*.` 通配子域，不含父域） | `*.google.com` |

优先级：`allow` → `block` → `proxy` → 直连。`allow` 会阻止 `proxy` 命中；`proxy` 按出现顺序先匹配先胜出。

```text
proxy domain *.google.com primary      # Google 走 primary 代理
block domain *.adnetwork.com           # 拦截广告
proxy port 22 direct                   # SSH 强制直连（"direct" 为特殊别名）
```

详见 [docs/rules-engine.md](./docs/rules-engine.md)。

## 📚 开发文档

| 文档 | 内容 |
|------|------|
| [架构总览](./docs/architecture.md) | 模块依赖、双入口链路、连接生命周期 |
| [TUN 开发文档](./docs/tun.md) | sing-tun 集成、gvisor 栈、缓冲池、fd 模式、库接口对照 |
| [规则引擎](./docs/rules-engine.md) | ACL 语法、优先级、COW 无锁快照 |
| [智能路由](./docs/smart-routing.md) | 国内外分流、Smart Connect、动态黑名单 |
| [SOCKS5 协议](./docs/socks5.md) | 握手 / CONNECT / UDP ASSOCIATE |
| [DNS 处理](./docs/dns.md) | 反污染、IP 优选、域名劫持 |
| [上游管理](./docs/upstream.md) | 健康检查熔断、选路策略 |
| [DPI](./docs/dpi.md) | TLS SNI / HTTP Host 提取 |
| [中继与缓冲池](./docs/relay.md) | 数据面转发与内存复用 |
| [热重载](./docs/hot-reload.md) | fsnotify 事件驱动热更新 |
| [配置参考](./docs/config.md) | 全部配置字段 + 命令行/daemon |
| [Admin API](./docs/admin-api.md) | 全部管理端点说明 |
| [性能优化](./docs/performance.md) | 无锁读、COW、缓冲池实践 |

## 📱 Android / iOS 集成（fd 模式）

通过 `gomobile bind` 将引擎编译为 AAR / XCFramework。移动端使用 **fd 模式**：TUN 文件描述符由系统 VPN API 提供，Go 侧不再创建设备，路由也由 OS 管理。

```bash
make android   # → build/smartproxy.aar
make ios       # → build/Socks5Router.xcframework
```

核心调用：

```kotlin
class ProxyVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val tun = Builder()
            .setMtu(1500).addAddress("172.19.0.1", 30).addRoute("0.0.0.0", "0")
            .addDnsServer("1.1.1.1").establish() ?: return START_NOT_STICKY
        protect(tun.fd)                                   // 防回环，先于启动
        Mobile.startRouter(configJson, tun.fd)            // 启动 Go 引擎（异步）
        return START_STICKY
    }
    override fun onDestroy() { Mobile.stopRouter(); super.onDestroy() }
}
```

fd 模式下：`tun.file_descriptor` 不读 JSON（仅由 `startRouter(json, fd)` 传入）、`auto_route` 强制 `false`、`inet4/6_address` 必须与 `VpnService.Builder` 一致。

## ⚖️ 开源协议

MIT

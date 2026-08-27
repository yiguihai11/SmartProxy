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
- **Web 管理面板**：纯 Go dashboard（config / ACL / chnroute / 日志在线编辑），fsnotify 热重载即时生效，HTTPS + 可选 Basic Auth
- **Android 客户端**：Kotlin + Compose 全功能 App —— VPN 隧道 / 仅代理（SOCKS5）双服务模式、按应用实时流量与单条封禁、per-app 分流、DNS 注入、排除路由、开机自启
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

> 每个上游的 TCP/UDP 能力**自动辨识，无需配置**：`socks5`/`socks5h`/`ss` 才可能支持 UDP，`http`/`https`/`socks4` 恒为 `tcp_only`。对 UDP-capable 节点，探测与真实流量共同推导出三态 mode（`tcp_and_udp`/`tcp_only`/`udp_only`，由 TCP/UDP 双熔断自动推出，`udp_only` 即「TCP 挂了但 UDP 正常」）与 UDP 能力标记（`standard`=标准 ASSOCIATE / `raw`=裸中继 / `none`=无 UDP）。`socks5`/`socks5h` 的 UDP 先走标准 UDP ASSOCIATE，**任意失败**（含 rep=0x07）自动兜底裸 UDP relay 到 `host:port`；已辨识为 raw 的节点后续直连裸中继、跳过注定失败的 ASSOCIATE，但每 10 分钟重检一次 ASSOCIATE，上游升级后自动回到 standard。详见 [docs/upstream.md](./docs/upstream.md) §3.2。

## 🖥️ Web 管理面板

引擎启动即起管理服务（`listen.admin_port`，默认 9090，HTTPS + 可选 Basic Auth）。浏览器打开：

- 桌面端：`https://127.0.0.1:9090`（或 `/dashboard`）
- Android VPN 隧道模式：`https://smartproxy.lan:9090`（引擎接管 DNS，静态记录把域名解析到手机）
- Android 仅代理模式：`https://127.0.0.1:9090`（本机开面板；QR 跨设备扫到的是扫描机自己）

| 端点 | 能力 |
|------|------|
| `/` `/dashboard` | 纯 Web UI（config / ACL / chnroute / 日志在线编辑） |
| `GET/PUT /config` | 读改配置，fsnotify 热重载即时生效 |
| `/acl` `/acl/add` | ACL 规则编辑、追加 |
| `/chnroute` | chnroute 上传校验落盘 |
| `/logs` `/logs/clear` | 环形缓冲日志 + level 过滤 |
| `/stats` `/blacklist` `/cache` `/route` `/health` | 运行统计、动态黑名单、缓存、选路、健康检查 |

全量端点见 [docs/admin-api.md](./docs/admin-api.md)。

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

## 📱 Android 客户端

全功能独立 App（Kotlin + Jetpack Compose，`android/`）。引擎经 `gomobile bind` 编译为 AAR 集成；APK 由 GitHub Actions 构建，四 ABI（arm64-v8a / armeabi-v7a / x86_64 / x86），版本号取自 git tag。

**两种服务模式**（抽屉 → 服务模式）：
- **VPN 隧道**（默认）：`VpnService` 建 TUN，引擎以 **fd 模式**接管全部流量，全局透明代理。
- **仅代理（SOCKS5）**：不建 VpnService，只跑引擎 SOCKS5（`:1080`，默认全接口双栈，局域网可达）。⚠️ 无 VpnService 就没有系统「后台占网络」护身符——Android 15+ 后台会按 uid 掐掉网络，本地 SOCKS 连接出现「前台正常、后台超时」（SS 安卓同款现象）；App 在仅代理模式启动时会引导开启「忽略电池优化」豁免。

**功能**：
- 首页：连接状态、IPv4/IPv6 开关、开机自启、管理面板入口（URL / 二维码 / 复制）。开关语义随服务模式切换：VPN 隧道 = 拦截（tun 接管该族流量）；仅代理 = SOCKS5 监听（双开/只 v6 = `::`、只 v4 = `0.0.0.0`）。
- 抽屉：代理应用（per-app 分流与「禁止联网」，仅 VPN 隧道模式显示）、DNS 服务器注入（仅 VPN）、排除路由（仅 VPN + API 33+）、服务模式、联网状态、日志查看。
- 联网状态：按应用的实时连接与网速，页面打开才采集；单条连接可封禁（掐断现存连接 + 写 ACL）。
- 日志：应用内查看 `SmartProxyVpn` 标签；Go 引擎日志在 logcat 的 `GoLog` 标签（应用内有意排除）。

**构建**：

```bash
make android   # → build/smartproxy.aar（引擎库）
# APK：GitHub Actions android-build 自动出包，或本地 cd android && ./gradlew assembleRelease
```

核心调用：`Mobile.startRouter(configPath, tunFd, tunEnabled)`。fd 模式下传 TUN fd + `true`；仅代理模式传 `0, false`。fd 模式下 `tun.file_descriptor` 不读 JSON（仅由 `startRouter` 传入）、`auto_route` 强制 `false`、`inet4/6_address` 必须与 `VpnService.Builder` 一致。

**CI**：
- `go-test`：全部包测试 + 并发热点 race + `go vet` + 编译（每次 Go 改动）。
- `android-build`：Gradle `assembleRelease` 出四 ABI APK。
- `update-chnroute`：每月 1/15/30 号自动拉取 china-ip-list 更新 `chnroute.txt` 并推回 main。

## ⚖️ 开源协议

MIT

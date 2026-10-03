# SmartProxy

[![go-test](https://github.com/yiguihai11/SmartProxy/actions/workflows/go-test.yml/badge.svg?branch=main&label=go-test)](https://github.com/yiguihai11/SmartProxy/actions/workflows/go-test.yml)
[![android-build](https://github.com/yiguihai11/SmartProxy/actions/workflows/android-build.yml/badge.svg?branch=main&label=android-build)](https://github.com/yiguihai11/SmartProxy/actions/workflows/android-build.yml)
[![update-chnroute](https://github.com/yiguihai11/SmartProxy/actions/workflows/update-chnroute.yml/badge.svg?branch=main&label=update-chnroute)](https://github.com/yiguihai11/SmartProxy/actions/workflows/update-chnroute.yml)
[![CodeQL](https://github.com/yiguihai11/SmartProxy/actions/workflows/codeql.yml/badge.svg?branch=main&label=CodeQL)](https://github.com/yiguihai11/SmartProxy/security/code-scanning)
[![CircleCI](https://circleci.com/gh/yiguihai11/SmartProxy.svg?style=shield)](https://app.circleci.com/pipelines/github/yiguihai11/SmartProxy)
[![Go Version](https://img.shields.io/github/go-mod/go-version/yiguihai11/SmartProxy)](https://github.com/yiguihai11/SmartProxy/blob/main/go.mod)
[![codecov](https://img.shields.io/codecov/c/github/yiguihai11/SmartProxy)](https://codecov.io/gh/yiguihai11/SmartProxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SmartProxy 是一个用 Go 语言编写的高性能透明代理与智能路由系统。支持 TUN 虚拟网卡与标准 SOCKS5 服务双入口，内置国内外流量自动分流、DNS 反污染与 IP 优选、DPI 协议特征提取、多上游负载与健康探测、配置实时热重载，并提供功能完整的 Android 客户端。

---

## 📌 核心功能与设计

- **双入口接入**：
  - **TUN 透明代理**：支持 `gvisor`、`lwip`、`system`、`mixed`、`go` 五种协议栈，支持常规桌面模式与移动端 fd 托管模式。
  - **SOCKS5 服务端**：支持标准 TCP CONNECT 与 UDP ASSOCIATE，支持多地址/双栈监听。
- **智能分流与回退**：
  - 基于 chnroute 前缀树（Trie）实现国内外 IP 路由决策。
  - Web 端口（80/443）支持“先直连、失败回退代理”机制，直连超时自动加入动态黑名单，减少白名单漏判造成的阻断。
- **规则引擎 (ACL)**：
  - 支持 `allow` / `block` / `proxy` 操作，涵盖端口、单 IP、CIDR 网段与域名（含 `*.` 通配符）。
  - 核心规则集使用不可变快照与原子指针（Copy-on-Write），读操作无需获取互斥锁。
- **DNS 反污染与 IP 优选**：
  - 国内 DNS 直连配合 chnroute 校验防止污染，异常时回退到远端无污染 DNS。
  - 针对多 A/AAAA 记录可启用 TCP/Ping 延迟探测与 IP 优选。
  - 采用 singleflight 机制合并突发并发查询，降低重复请求开销。
- **DPI 协议探测**：
  - 从连接首包中主动识别 TLS ClientHello (SNI) 与 HTTP Host 头部，即使无域名解析也可基于域名规则分流。
- **多上游节点管理**：
  - 协议支持：SOCKS5、SOCKS5H、SOCKS4、HTTP(S) 及 Shadowsocks (`ss://`，TCP+UDP)。
  - 调度策略：支持 `failover`（主备容灾）、`round_robin`（轮询）、`random`（随机）与 `latency`（延迟优先）。
  - 健康检查：TCP 与 UDP 具备独立的主动探测与熔断恢复状态机。
- **配置与数据热重载**：
  - `config.json`、`acl.txt`、`chnroute.txt` 监听文件系统变更事件（fsnotify），就地原子换新，无需重启服务。
- **内置 Web 控制台**：
  - 启动即随附轻量管理面板（默认 9090 端口，HTTPS + 可选身份认证），支持在线编辑配置、规则调整与日志实时流过滤。
- **跨平台与 Android 客户端**：
  - 支持 Linux、macOS、Windows；通过 Android Jetpack Compose 客户端提供无缝的移动端体验（VPN 隧道与仅代理双模式）。

---

## 📊 TUN 协议栈架构与选型

SmartProxy 支持 5 种 TUN 协议栈实现，可在不同设备环境与权限要求下灵活选用：
- **`gvisor`（全平台默认）**：Google 开源的成熟用户态 Go 栈。并发多协程驱动，TCP 握手约 25–38 µs（实测），全平台无需 CGO 编译即可运行，生态兼容性好，适合通用网页高频短连接场景。
- **`lwip`（移动端推荐）**：轻量级 C 语言协议栈（Lightweight IP）。单连接内存开销极低（~490 B，比 gVisor 省 76%），TCP 建连实测 3.6 µs（云端）/ 4.6 µs（真机），与 `system`/`mixed` 同量级，发包真·零拷贝（0 allocs/op），非常适合 Android 客户端长期后台驻留防 OOM/LMK 杀进程。
- **`system`**：利用 Linux 内核网络栈直接处理 TCP，性能强但需系统 root / `CAP_NET_ADMIN` 特权。
- **`mixed`**：混合协议栈（TCP 走 System 内核栈，UDP 走 gVisor 用户态栈），需系统特权。
- **`go`**：纯 Go 原生简易栈，主要用于开发参考与测试。

> 📖 **完整基准测试报告**：云端 CI 与 Android ARM64 移动端真机环境下的详细 UDP 吞吐量对比、TCP 握手开销对比、零拷贝架构实现及技术设计细节，请参阅 **[性能白皮书 (docs/performance.md)](./docs/performance.md#6-tun-协议栈特性与性能基准benchmark)**。

---

## 🛠️ 快速上手

### 1. 编译构建

要求 Go 1.25 或更高版本：

```bash
# 编译当前平台（默认包含 gvisor 协议栈）
make build

# 交叉编译多平台发布包（Linux / Darwin / Windows）
make build-all
```

如需在 Linux/桌面端启用 lwIP 协议栈，需安装 GCC 并包含编译标签：

```bash
go build -tags "with_gvisor,with_lwip" -o build/smartproxy ./cmd/smartproxy
```

### 2. 启动运行

准备好配置文件（可参考项目自带的 `config.json`、`chnroute.txt` 与 `acl.txt`）：

```bash
./build/smartproxy config.json
```

---

## 📝 配置示例

```json
{
  "listen": {
    "host": "::",
    "port": 1080,
    "admin_port": 9090
  },
  "tun": {
    "enabled": false,
    "name": "smartproxy0",
    "stack": "gvisor",
    "mtu": 1500,
    "inet4_address": "172.19.0.1/30"
  },
  "upstream": {
    "default": "failover",
    "proxies": [
      {
        "alias": "primary",
        "url": "socks5://127.0.0.1:1081"
      },
      {
        "alias": "backup",
        "url": "ss://aes-128-gcm:password@1.2.3.4:8388"
      }
    ]
  },
  "routing": {
    "chnroute_file": "chnroute.txt",
    "acl_file": "acl.txt"
  },
  "dns": {
    "enabled": true,
    "foreign": {
      "ipv4": "8.8.8.8:53"
    }
  }
}
```

完整配置字段说明详见 [docs/config.md](./docs/config.md)。

---

## 🖥️ Web 管理控制台

服务启动后，内置 Web 控制台默认监听 `https://127.0.0.1:9090`（支持自定义端口与可选 Basic Auth 认证）。

- **桌面端访问**：`https://127.0.0.1:9090`
- **Android VPN 隧道模式**：`https://smartproxy.lan:9090`（内置 DNS 静态映射）
- **主要能力**：
  - `/` 或 `/dashboard`：可视化仪表盘，查看运行状态与活动连接。
  - `GET/PUT /config`：实时查看与在线保存配置，保存后自动触发热重载生效。
  - `/acl`：在线编辑与追加 ACL 访问控制规则。
  - `/chnroute`：更新并校验国内 IP 路由表。
  - `/logs`：环形内存日志查看，支持按日志级别（DEBUG/INFO/WARN/ERROR）过滤。
  - `/stats` / `/blacklist` / `/health`：查看吞吐统计、动态黑名单列表与上游健康状况。

详细 API 端点规范参见 [docs/admin-api.md](./docs/admin-api.md)。

---

## 📖 ACL 规则语法

规则文件按行解析，格式为 `<action> <type> <value> [alias]`：

- **动作 (action)**：`allow`（放行直连）、`block`（阻断拦截）、`proxy`（经指定代理节点）。
- **类型 (type)**：`port`（端口）、`ip`（单个 IP）、`cidr`（IP 网段）、`domain`（域名，支持 `*.example.com` 子域匹配）。
- **优先级**：`allow` > `block` > `proxy` > 默认路由分流。

```text
# 常用规则示例
block domain *.adservice.com         # 拦截广告域名
proxy domain *.google.com primary    # 指定域名走 primary 代理
proxy cidr 198.51.100.0/24 backup    # 指定海外网段走 backup
allow port 22                        # SSH 流量放行直连
```

详细用法参见 [docs/rules-engine.md](./docs/rules-engine.md)。

---

## 📱 Android 客户端

项目提供原生 Android 客户端（源码位于 `android/`），基于 Kotlin + Jetpack Compose 构建，Go 核心引擎通过 `gomobile bind` 编译为 AAR 静态集成。

### 下载与安装
可通过 [GitHub Releases](https://github.com/yiguihai11/SmartProxy/releases/latest) 下载对应 CPU 架构的签名安装包：
- **`arm64-v8a`**：主流现代 Android 真机（推荐）
- **`armeabi-v7a`**：旧款 32 位 ARM 设备
- **`x86_64` / `x86`**：Android 模拟器或 x86 平板

### 双工作模式
1. **VPN 隧道模式（默认）**：
   - 系统级 `VpnService` 创建 TUN 虚拟接口，Go 引擎以 fd 托管模式接管设备全部流量。
   - 支持按应用代理（Per-App Split Tunneling）、应用禁止联网、自定义 DNS 注入、路由排除。
2. **仅代理模式（SOCKS5）**：
   - 不创建系统 VPN，仅启动本地 SOCKS5 代理监听服务，供特定应用（如浏览器、Telegram）手动配置连接。
   - 具备后台保活指引，降低 Android 后台限制导致的连接超时问题。

### 移动端构建
```bash
# 1. 编译 Go 核心引擎 AAR (需配置 Android NDK 与 Go 环境)
make android

# 2. 编译 Android APK (可直接通过 Gradle 构建)
cd android && ./gradlew assembleRelease
```

---

## 📚 详细设计文档

| 专题文档 | 主要内容 |
| :--- | :--- |
| [架构总览](./docs/architecture.md) | 模块拓扑、双入口流程、生命周期设计 |
| [TUN 开发文档](./docs/tun.md) | 协议栈接入、sing-tun 集成、fd 托管模式与缓冲区设计 |
| [性能与基准测试](./docs/performance.md) | 无锁 COW 快照、缓冲复用、5 大网络栈实测基准数据 |
| [规则引擎](./docs/rules-engine.md) | ACL 匹配原理、前缀树与通配符实现 |
| [智能分流机制](./docs/smart-routing.md) | chnroute 决策、动态黑名单与失败快速回退 |
| [SOCKS5 协议实现](./docs/socks5.md) | 握手、CONNECT、标准与裸 UDP 中继机制 |
| [DNS 处理与反污染](./docs/dns.md) | 污染检测、IP 延迟探测优选与并发合并 |
| [上游代理管理](./docs/upstream.md) | 健康检查、双向独立熔断与多策略选路 |
| [DPI 协议探测](./docs/dpi.md) | TLS SNI 与 HTTP Host 首包解析原理 |
| [热重载机制](./docs/hot-reload.md) | fsnotify 监听与原子快照交换实现 |
| [配置完整参考](./docs/config.md) | 全量 JSON 字段、默认值及环境变量说明 |
| [Admin API 参考](./docs/admin-api.md) | Web 面板所有 RESTful 端点调用规范 |

---

## ⚖️ 开源协议

本项目采用 [MIT 许可证](https://opensource.org/licenses/MIT) 开源。

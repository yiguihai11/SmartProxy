# SOCKS5 Smart Router 开发文档

SOCKS5 Smart Router（下称"本工程"）是一个基于 Go 的智能分流路由器，同时提供 SOCKS5 服务器入口与 TUN 透明代理入口，支持 ACL 规则、智能回退（smart proxy）、DNS 污染检测/IP 优选、上游代理健康检查与动态热重载。本目录为它的完整开发文档。

## 阅读指南

| 文档 | 内容 | 适合对象 |
| --- | --- | --- |
| [architecture.md](architecture.md) | 总体架构：设计目标、模块依赖图、两条入口链路、连接生命周期、关键设计决策 | 所有开发者 |
| [tun.md](tun.md) | TUN 模块专题：sing-tun 集成、gvisor 栈回调、连接处理、缓冲池、UDP 会话、fd 模式、坑点、接口对照表 | TUN / 网络栈开发者 |
| [rules-engine.md](rules-engine.md) | ACL 规则引擎：allow/block/proxy 语法、COW 快照、无锁读 | 规则维护者、分流策略开发者 |
| [smart-routing.md](smart-routing.md) | 智能分流：80/443 先直连失败回退代理、动态黑名单、IP 优选 | 分流策略开发者 |
| [socks5.md](socks5.md) | SOCKS5 服务器：握手、CONNECT、UDP ASSOCIATE 协议实现 | 协议 / 服务端开发者 |
| [dns.md](dns.md) | DNS 模块：污染检测、缓存、IP 优选、singleflight、代理 DNS | DNS / 网络开发者 |
| [upstream.md](upstream.md) | 上游代理：健康检查、选择策略（failover/round_robin/random/latency）、UDP 池；内置 SS 与 obfs，含「SS 地址头须与首块数据合成一次写以过 GFW」的实测坑点 | 代理链路开发者 |
| [ss-rust-lessons.md](ss-rust-lessons.md) | 从 shadowsocks-rust 源码提炼的设计经验：TCP 转发、socket 选项、DNS/HE、重放防护、URL 解析、UDP 中继、负载均衡，逐条对照 SmartProxy 标 已应用/可借鉴/需改造 | 代理链路开发者 |
| [dpi.md](dpi.md) | 流量探测：TLS SNI / HTTP Host 提取 | 分流策略开发者 |
| [relay.md](relay.md) | 双向转发：TCP splice 零拷贝、缓冲池、字节计数 | 转发 / 性能开发者 |
| [hot-reload.md](hot-reload.md) | 热重载：config.json / acl.txt / chnroute.txt 的事件驱动 watcher | 运维、全部开发者 |
| [config.md](config.md) | 配置文件全字段说明与默认值 | 使用者、运维 |
| [performance.md](performance.md) | 性能特性：低锁竞争、低 GC、万级连接/秒、缓冲复用 | 性能调优者 |
| [admin-api.md](admin-api.md) | Admin HTTP 接口：/stats /health /config /acl /chnroute 等全部端点 | 运维、后台开发者 |
| [android-dev-plan.md](android-dev-plan.md) | Android 版开发计划：两层次架构（VpnService 流量模式 + Go 引擎目标分流）、三种流量模式（仅代理/仅绕过/放行自身）、App 选择页（查询/排序/提示）、里程碑 | Android 开发者 |
| [android-cli.md](android-cli.md) | Android 构建与 CI 安装：gomobile AAR + Gradle 签名 release + APK 上传（全在 GitHub Actions） | Android 开发者 |

## 第三方依赖版本说明

本目录所有文档中对第三方库 API 的描述，均已对照 `go.mod` 中锁定版本的源码逐一核实（模块缓存位于 `$GOPATH/pkg/mod` 下对应版本目录）。若本地升级依赖版本，相关描述可能失效，请以新版本源码为准。

| 依赖 | 版本 | 主要涉及文档 |
| --- | --- | --- |
| github.com/sagernet/sing-tun | v0.8.10 | tun.md（§8 接口对照表） |
| github.com/sagernet/sing | v0.8.10 | tun.md、relay.md（common/buf、common/network、common/metadata） |
| github.com/miekg/dns | v1.1.72 | dns.md |
| golang.org/x/sync | v0.20.0 | dns.md（singleflight） |
| github.com/fsnotify/fsnotify | v1.7.0 | hot-reload.md（事件驱动 watcher） |

## 模块总览

`internal/` 下各模块的职责与依赖关系如下（对应 [architecture.md](architecture.md) 的模块依赖图）：

```
internal/
├── engine        # 引擎中枢：装配所有组件、启动/停止、两条入口的连接分发
├── tun           # TUN 设备 + gvisor 用户态网络栈 + TCP/UDP/DNS 回调
├── socks5        # SOCKS5 服务端：握手、CONNECT、UDP ASSOCIATE
├── udp           # SOCKS5 UDP ASSOCIATE 会话处理（转发/超时回收）
├── route         # 路由决策：直连/代理选择、智能回退、动态黑名单
├── rules         # ACL 规则引擎（allow/block/proxy，COW 快照 + 原子指针）
├── upstream      # 上游代理管理（健康检查、选择策略、DNS UDP 池）
├── dns           # DNS 处理（污染检测、缓存、IP 优选、singleflight）
├── chnroute      # 国内 IP 段 Trie（atomic.Pointer 原子换根）
├── dpi           # 流量探测（TLS SNI / HTTP Host）
├── relay         # 双向转发（TCP splice 零拷贝、缓冲池、字节计数）
├── netutil       # 网络工具（端口判断、增强阻断、Host:Port 解析）
├── admin         # admin 控制接口（Unix socket / HTTP，日志与状态查询）
├── config        # 配置加载/校验、热重载 watcher（fsnotify 事件驱动）
├── logbuf        # 日志环形缓冲（admin 日志查询的数据源）
└── safego        # 安全 goroutine 包装（panic 恢复 + goroutine 命名）
```

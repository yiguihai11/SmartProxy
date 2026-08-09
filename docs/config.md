# 配置参考

## §1 配置来源与加载

- 配置通过 **`config.json`** 提供，运行时可用 `-config <path>` 指定（默认 `config.json`）；加载失败（文件不存在、JSON 语法错误）直接导致启动失败（`cmd/smartproxy/main.go`）。
- 字段定义在 `internal/config/config.go`，默认值见 `DefaultConfig()`；`config.Load` 先反序列化到 `DefaultConfig()` 实例，再调 `applyDefaults()` 补全未填字段（`internal/config/loader.go`）。
- **所有字段大小写敏感**，与 JSON 键严格一致（如 `log_level` 不能写成 `LogLevel`）。

## §2 完整字段参考

### 顶层 `Config`

顶层 JSON 键：`log_level`、`listen`、`tun`、`upstream`、`routing`、`dns`、`smart_proxy`；`log_level` 默认 `"INFO"`（DEBUG / INFO / WARN / ERROR）。各子结构字段见下表。

### `listen`

| Go 字段 | JSON 键 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `Host` | `host` | `"::"` | SOCKS5 监听地址（IPv6 通配） |
| `Port` | `port` | `1080` | SOCKS5 监听端口 |
| `Auth` | `auth` | 无 | 可选认证 `{username, password}` |
| `RelaxedUDPOriginCheck` | `relaxed_udp_origin_check` | `true` | 放行非预期来源 IP 的 UDP 包 |
| `UDPAssociateIdleTimeout` | `udp_associate_idle_timeout` | `60` | UDP 会话空闲超时（秒） |
| `AdminSocket` | `admin_socket` | `""` | Admin 面板 unix socket 路径（可选） |
| `AdminPort` | `admin_port` | `0` | Admin 面板 TCP 端口（0 表示禁用）；`admin_port` > 0 时即使 `admin_socket` 为空也会启动面板 |
| `AdminAuth` | `admin_auth` | 无 | Admin 认证 `{enabled, username, password}` |
| `AdminRefreshInterval` | `admin_refresh_interval` | `3` | Admin 数据刷新间隔（秒） |
| `AdminHTTPS` | `admin_https` | `true` | TCP 端口启用 HTTPS：同一端口上明文 HTTP 请求被 301 重定向到 `https://`，TLS 握手正常走 HTTPS。设 `false` 恢复纯 HTTP。默认自动生成自签证书（见下） |
| `AdminCertFile` | `admin_cert_file` | `""` | 自定义证书 PEM 路径（可选）。为空时用自签证书；设置时须与 `admin_key_file` 一起设置 |
| `AdminKeyFile` | `admin_key_file` | `""` | 自定义私钥 PEM 路径（可选），须与 `admin_cert_file` 一起设置 |
| `AdminCertSANs` | `admin_cert_sans` | `[]` | 附加到自动生成自签证书 SAN 的主机名/IP 列表（如 `["192.168.1.1"]`），用于覆盖通过局域网 IP 访问面板时的"主机名不匹配"告警（见下）。配置了 `admin_cert_file`/`admin_key_file` 时忽略 |

**Admin HTTPS 自签证书**：`admin_https=true` 且未配 `admin_cert_file`/`admin_key_file` 时，启动自动生成一张 ECDSA P-256 自签证书（CN=`smartproxy`，SAN=localhost/127.0.0.1/::1 **+ `admin_cert_sans` 中列出的主机名/IP**，397 天有效期），best-effort 写入**配置文件同目录**的 `admin.crt` + `admin.key`，重启复用同一证书（浏览器只需告警/信任一次）。**若已存在的证书缺少当前请求的 SAN（比如改过 `admin_cert_sans`），会自动重新生成**。写盘失败则仅内存持有。unix socket（`admin_socket`）仍为纯 HTTP，仅供本机访问。**注意：Admin TLS 配置在启动时生效，改动需重启；`admin_auth` 仍可热重载。**

> 局域网 IP 场景：默认自签证书只覆盖 localhost/127.0.0.1/::1，直接用 `https://192.168.1.1:9090` 访问会报"证书对该地址无效"。在 `admin_cert_sans` 里写上该 IP 即可让自动生成的证书覆盖它，消除主机名不匹配告警；"不受信任"告警则需把 `admin.crt` 装进访问设备的受信任根证书库（Android 7.0+ 装 CA 证书、Chrome 即信任；装证书要求先设锁屏 PIN）。

### `tun`

| Go 字段 | JSON 键 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `Enabled` | `enabled` | `false` | 是否创建 TUN 设备 |
| `Name` | `name` | `"tun0"` | TUN 设备名 |
| `MTU` | `mtu` | `1500` | 设备 MTU |
| `Inet4Address` | `inet4_address` | `["172.19.0.1/30"]` | IPv4 前缀列表 |
| `Inet6Address` | `inet6_address` | `[]` | IPv6 前缀列表 |
| `AutoRoute` | `auto_route` | `false` | 是否自动配置路由。**服务器上保持 `false`**：`true` 会全局劫持 0.0.0.0/0 出站（含 SSH），导致卡顿/环路；`false` 时自动安装"源选择性路由"，仅 TUN 子网流量走 tun0，服务器自身不受影响（见 `tun.md` §6） |
| `OutputMark` | `output_mark` | `0` | 自身出站打标值（SO_MARK），`0`=关闭（默认）。**`>0` 且 `auto_route: true`、非 fd 模式时生效**：自动加 `ip rule fwmark <值> lookup main`（自身绕过 TUN 劫持）+ nftables 输出链给 `route_exclude_ports` 打标（SSH 等绕过），实现"全量捕获但不卡自身/SSH"。需 root / CAP_NET_ADMIN（见 `tun.md` §6.2） |
| `RouteExcludePorts` | `route_exclude_ports` | `[22]` | 打 `OutputMark` 排除的本地端口（默认 SSH 22），仅 `auto_route=true` + `output_mark>0` 时生效 |
| `Stack` | `stack` | `"gvisor"` | 协议栈实现（默认 gvisor） |
| `FileDescriptor` | （`json:"-"`） | `0` | 外部 TUN fd 模式，非 JSON 字段，由程序注入 |

### `upstream`

| Go 字段 | JSON 键 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `Default` | `default` | `"failover"` | 默认代理选择策略 |
| `HealthCheck` | `health_check` | 见下 | 健康检查配置 |
| `Proxies` | `proxies` | `[]` | 代理列表，每项 `{alias, url}` |

`proxies` 每项 `ProxyEntry` 字段：`alias`（缺省自动命名 `proxy<N>`）、`url`（协议 URL，如 SS / VMess）；**没有 type 字段，也没有 mode 字段** —— 每个上游的 TCP/UDP 能力由 scheme + 双熔断**自动辨识**（见 `docs/upstream.md` §3.2）。`health_check` 子字段：

| 字段 | JSON 键 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `Alias` | `alias` | `proxy<N>` | 代理别名（规则引擎引用） |
| `URL` | `url` | — | 协议 URL：`socks5://` / `socks5h://`（可带 user:pass）、`socks4://`、`http(s)://`（CONNECT）、`ss://`（内置 shadowsocks，见 `docs/upstream.md` §3.1）。`ss://` 支持 `ss://base64(method:password)@host:port`、明文 `ss://method:password@host:port`，或不加密方法的免密码形式 `ss://none@host:port`。方法可为经典 AEAD、AEAD-2022（密码框填 base64 PSK，多 PSK 用 `:` 连接）、或 `none`/`plain`。可带 `?plugin=obfs-local;obfs=http|tls;obfs-host=...`（内置 simple-obfs 混淆，仅 TCP）或 `?plugin=v2ray-plugin;mode=websocket|grpc|quic[;tls];host=...`（内置 v2ray 传输，可带 `path`/`mux`/`serviceName`/`certRaw`）；其它插件不内置会拒绝 |

| Go 字段 | JSON 键 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `Enabled` | `enabled` | `false` | 是否启用健康检查 |
| `URL` | `url` | `"http://wifi.vivo.com.cn/generate_204"` | 探测 URL |
| `Interval` | `interval` | `60` | 探测间隔（秒） |
| `Timeout` | `timeout` | `5` | 单次探测超时（秒） |
| `FailuresThreshold` | `failures` | `2` | 连续失败多少次判为下线 |
| `SuccessesThreshold` | `successes` | `1` | 连续成功多少次判为恢复 |
| `OpenCoolDown` | `open_cool_down` | `30` | 熔断冷却（秒） |
| `AutoDisableSingle` | `auto_disable_if_single_proxy` | `true` | 仅一个代理时自动停用健康检查 |
| `UDPProbeDNS` | `udp_probe_dns` | `"1.1.1.1:53"` | 主动 UDP 健康探测的 DNS 服务器：对支持 UDP 的上游，把真实 DNS 查询经其 UDP relay 发到该地址，收到合法响应即判定 UDP 可用 |
| `UDPProbeDomain` | `udp_probe_domain` | `"dns.google"` | UDP 健康探测查询的域名（A 记录） |

> TCP 与 UDP 健康是**两个独立熔断器**：TCP 探活喂 TCP 电路（`/health` 的 `health`），DNS UDP 探测喂 UDP 电路（`/health` 的 `udp_health`），互不影响。探测方向由 scheme 决定：`socks5`/`socks5h`/`ss` 两种都探，其余协议（`http`/`https`/`socks4`）只探 TCP。每个代理的**生效 mode 由这两个熔断自动推出**（`tcp_and_udp`/`tcp_only`/`udp_only`，后者即「TCP 挂了但 UDP 正常」），无需配置。UDP 路由（`UDPAssociate` failover）按 `udp_health` 熔断，TCP 路由按 `health` 熔断。详见 `docs/upstream.md` §3.2 / §4。

### `routing`

| Go 字段 | JSON 键 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `ChnrouteFile` | `chnroute_file` | `"chnroute.txt"` | 国内 IP 段列表文件 |
| `ACLFile` | `acl_file` | `"acl.txt"` | ACL 规则文件 |

### `dns`

| Go 字段 | JSON 键 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `Enabled` | `enabled` | `true` | 是否接管 DNS 转发 |
| `QueryTimeout` | `query_timeout` | `3` | DNS 查询超时（秒） |
| `Foreign` | `foreign` | `{ipv4, ipv6}` | 国外 DNS 地址（`foreign.ipv4` 默认 `1.1.1.1:53`，`foreign.ipv6` 默认 `[2606:4700:4700::1111]:53`） |
| `Cache` | `cache` | `{size:10000, ttl:300}` | DNS 缓存：`cache.size` 条目数、`cache.ttl` 秒 |
| `SpeedCheckMode` | `speed_check_mode` | `""` | IP 优选（DNS IP preference）模式与端口（如 `icmp:80,443`），由 `dns.ParseSpeedCheckMode` 解析；留空表示不启用（`PreferNone`） |

> 域名被封时回填的 IP 已硬编码（IPv4 `0.0.0.0`、IPv6 `::`），不再由 `blocked_ip` / `blocked_ipv6` 配置。

### `smart_proxy`

| Go 字段 | JSON 键 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `Enabled` | `enabled` | `true` | 是否启用智能代理 |
| `Timeout` | `timeout` | `3` | 建连探测超时（秒） |
| `Ports` | `ports` | `[80, 443]` | 智能代理目标端口 |
| `BlacklistTTL` | `blacklist_ttl` | `300` | 失败黑名单 TTL（秒） |

## §3 校验规则 Validate()

`(*Config).Validate()`（`internal/config/config.go`）集中做语义校验，违反任何一条即返回聚合错误：

| 约束 | 说明 |
| --- | --- |
| `listen.port` 在 1~65535 | 否则报错 |
| `dns.query_timeout > 0` | 必须为正 |
| `smart_proxy.timeout > 0` | 必须为正 |
| `smart_proxy.blacklist_ttl > 0` | 必须为正 |
| `dns.cache.size > 0` | 必须为正 |
| 每个 `upstream.proxies[i].url` 非空 | 空 URL 报错 |
| 健康检查启用时 | `health_check.url` 非空、`interval > 0`、`timeout > 0` |

`Validate()` 的调用点与失败后果：

- **热重载 / Admin 写配置**：`configReload`（`cmd/smartproxy/main.go`）与 admin PUT `/config`（`internal/admin/admin.go`）都会先 `Validate`；热重载校验失败**保留旧配置**、脏配置不进内存，admin 写配置校验失败返回 400、**不落盘**。
- **进程启动**：`config.Load` 只做 `applyDefaults`，**不显式调用 `Validate()`**；严重非法配置（`chnroute_file` / `acl_file` 缺失、TUN 前缀非法）在 `engine.New` / `engine.Start` 初始化阶段报错导致启动失败（`internal/engine/engine.go`）。

## §4 命令行参数与守护进程模式

### 命令行参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-config <path>` | `config.json` | 配置文件路径 |
| `-daemon` | `false` | 以守护进程方式运行（仅非 Windows） |
| `-pid <path>` | — | pid 文件路径（可选，配合 `-daemon`） |
| `-log <path>` | — | 日志文件路径（可选，配合 `-daemon`） |
| `-quiet` | `false` | 抑制终端日志输出（配合 `-daemon` 常用） |

**配置文件路径也可作为第一个位置参数传入**（`./smartproxy config.json`），仅在 `-config` 仍为默认值 `config.json` 时生效（`flag.Parse()` 后检查 `flag.NArg() > 0 && cfgPath == "config.json"`）。

### 守护进程模式（daemon）

`cmd/smartproxy` 通过 **github.com/sevlyar/go-daemon** 实现 POSIX 守护化，仅非 Windows 生效：`daemon_posix.go`（构建标签 `!windows`）实现 `registerDaemonFlags` / `handleDaemon`；`daemon_windows.go` 为桩实现，两个函数均空，**不注册任何 flag**。`handleDaemon` 在 `flag.Parse()` 之后调用，机制：

1. 传 `-daemon` 时 `daemon.Context.Reborn()` 创建子进程，**父进程 `os.Exit(0)` 退出**（曾因只 `return` 导致父进程在前台继续跑服务、子进程端口冲突的竞态，已修复）；子进程继续执行 config 加载、engine 启动等正常流程。
2. `WorkDir = "./"`、`Umask = 027`；`-pid` 指定 pid 文件（权限 0644），进程退出时由 `Release()` 清理。
3. 日志：`-quiet` 且未给 `-log` → 重定向 `/dev/null`；给了 `-log` → 写入该文件（权限 0640）。进程内日志：`-quiet` 时 slog 的 base handler 为 `nil`，不写终端但仍进入 logbuf 环形缓冲，Admin 面板可读（`NewSlogHandlerLevel` 对 nil handler 有防护）。

> daemon 模式是**进程启动方式**，与热重载（`hot-reload.md`）无关；守护化后仍在同一进程内提供 TUN / SOCKS5 / Admin 服务。注意：`-quiet` flag 在 `daemon_posix.go` 注册（`!windows`），变量 `quiet` 声明在 `main.go`（跨平台共享，避免 Windows 构建 undefined）。

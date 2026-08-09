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

UDP 支持：`socks5` / `socks5h`（标准 UDP ASSOCIATE，失败自动兜底裸 UDP，见 §3.2）与 `ss`（内置 SS UDP relay，见 §3.1）。**带 SIP003 插件的 `ss` 节点默认 UDP 关闭**（等效手动关闭，可手动释放开启探测，见 §1 SIP003 小节）。**每个上游的 TCP/UDP 能力自动辨识、无需配置**：生效 mode（`tcp_and_udp` / `tcp_only` / `udp_only`）由 scheme + 双熔断动态推出，UDP 能力标记（`standard` / `raw` / `none`）由探测与真实流量推导，见 §3.2。

## §3 连接建立

- **TCP**：`Proxy.Connect(ctx, host, port)` 按 scheme 分发（`socks5Connect` / `socks4Connect` / `httpConnect` / `ssConnect`）；`dial` 统一 10s 超时、TCP keepalive 30s + NoDelay。`Manager.ConnectDefault` 按 `orderedProxies()` 顺序逐个尝试可用代理，失败 `RecordFailure` 后继续下一个。
- **UDP**：默认走 `socks5UDPAssociate` —— 握手后发 `{0x05,0x03,0x00,0x01,0,0,0,0,0,0}`，读 bind 地址（`0.0.0.0` / `::` 时替换为代理 Host）后 `DialUDP`，返回 `UDPProxyConn{UDPConn, tcpConn}`。`Manager.UDPAssociate` / `UDPAssociateSelected` 先按规则选指定代理，否则在默认代理里找 UDP 支持者（`SupportsUDP()`：`socks5` / `socks5h` / `ss`）。

### §3.1 内置 Shadowsocks（`ss://`）

`internal/upstream/ss.go` 用 [sing-shadowsocks](https://github.com/sagernet/sing-shadowsocks)（sing-box 生态，仍维护中的纯 Go 库）直接以 shadowsocks 协议连接远程 SS 服务器，**不再依赖外部 `sslocal` 进程**（之前 Termux 上要先跑一个 sslocal 才能用 SS）。支持经典 AEAD 加密：`aes-128/192/256-gcm`、`chacha20-ietf-poly1305`、`xchacha20-ietf-poly1305`；AEAD-2022（SIP022）：`2022-blake3-aes-128/256-gcm`、`2022-blake3-chacha20-poly1305`；以及不加密的 **`none`**（`plain` 是同义词）。`newSSMethod` 显式校验 method 名称（`shadowaead.New` 对未知方法不报错、会留 nil constructor，这里显式拦截拼写错误）。SIP003 插件的 `?plugin=` 参数**内置执行**（obfs-http / obfs-tls，见下小节）。

> `none`/`plain` 与 AEAD 的差异及 wire 格式，见下「`none`/`plain`（不加密）」小节。

- **凭据解析**（`parseSSUserinfo`）：userinfo 优先按 shadowsocks URI 规范做 base64 解码（RawURL / URL / RawStd / Std 四种都试），失败则按明文 `method:password` 处理，第一个 `:` 之后整段为密码（含冒号也保留）。注意 `url.Parse` 会在第一个冒号处切分并把后续冒号 percent-encode，实现用 `Username()/Password()` 取回解码后的密码再重组。`none`/`plain` 不需要密码，可写免密码形式 `ss://none@host:port`（无冒号）；解码仅在结果含 `:`（即 `method:password` 结构）时接受，避免 `none` 这种恰好是合法 base64 的明文方法名被误解码。
- **TCP**：`ssConnect` 走 `dial`（fwmark + keepalive）→ `ssMethod.DialEarlyConn(conn, dest)` **延迟地址握手**——地址头不在建连时发，而是与首个数据写合成一次发（none+obfs 过 GFW 的关键，见下方「过 GFW 的线格式」小节），透明对接上层。
- **UDP**：`ssUDPAssociate` 直接 `net.DialUDP` 到 SS 服务器端口，用 `ssMethod.DialPacketConn` 得到逐包携带目标地址的 packet conn（sing 的 `clientPacketConn` 每包自含 destination），因此**单条 UDP 连接即可服务任意目标**，与 SOCKS5 上游的复用模型一致。适配器 `ssUDPConn` 把上游一侧的 SOCKS5-UDP 帧（RSV|FRAG|ATYP|ADDR|PORT|payload）翻译成 SS UDP 包：`Write` 解析帧→`WritePacket`（预留 headroom + AEAD tag 容量，避免 sing `buf` panic）；`Read` 从 `ReadPacket` 拿到 payload + 来源地址→补 SOCKS5 响应头返回完整帧。`ss` 的 UDP 恒为标准能力（内置 relay 无需裸中继兜底，无 `raw` 概念），生效 mode 仍由双熔断按 §3.2 自动推出。

UDP 复用池（§6）对 `ss` 同样生效：`ssUDPConn` 实现了 `ProbeTCP()`（无 TCP 控制信道，返回 nil 视为健康，靠 TTL 淘汰兜底），池的 `Acquire/Release/Discard` 已从 `*UDPProxyConn` 泛化为 `net.Conn` + 可选 `tcpProbeConn` 接口。

#### AEAD-2022（SIP022）

`2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` / `2022-blake3-chacha20-poly1305` 的 key 语义与经典 AEAD 不同：**不是密码，而是 base64 编码的二进制 PSK**（16B / 32B），多用户时多个 PSK 用 `:` 连接。`newSSMethod2022` 用 `decodeBase64Key` 依次尝试 Std / URL / Raw 变体解码（兼容 ss-android 导出时可能不带 `==` padding 的 key），再交给 `shadowaead_2022.New`；空、非 base64、长度不足的 key 在 `NewProxy` 时即报错。

- **密码框填的就是 base64 key**（如 `MDEyMzQ1Njc4OWFiY2RlZg==`），不是明文密码；多 PSK 用 `:` 连接。
- **UDP 是会话式**（客户端/服务端各持独立会话：首包携带 sessionId + packetId、滑动窗口去重、HeaderType 方向不对称、带最多 ~900B 的 padding），不是经典 AEAD 的自包含包，服务端必须用 `shadowaead_2022.Service` 解包。因此 `ssUDPConn.Write` 改用 `N.CalculateFrontHeadroom` 动态预留 2022 的会话/padding 头（对经典 AEAD 与 `none` 同样正确）。
- 进程内测试覆盖 TCP/UDP 往返（`ss_test.go` 的 `TestSSConnectTCP`、`TestSSUDPConnRoundTrip2022`）。
- **已用真实 shadowsocks-rust v1.23.4 `ssserver` 端到端验证**（`ss2022_e2e_test.go`，`go test -tags e2e`，需 `SS_SERVER_BIN` 指向真实 ssserver）：sing 2022 客户端直连 ssserver（不经 sslocal），TCP 明文往返（含 2022 握手 timestamp 校验）与 UDP 会话式往返均互通。注意这与 `rawrelay_e2e_test.go`（`socks5` 上游 + rep=0x07 兜底裸 UDP 到 sslocal 监听端口，Case A）是**两条不同链路**：本测试是 `ss://` scheme 下 SmartProxy 自身即 sslocal、直接与 ssserver 通讯（Case B）。

#### SIP003 插件：内置 obfs-http / obfs-tls（`?plugin=`）

ss-android 导出的链接可带 `?plugin=id;key=val;key=val`（SIP003 插件）。SmartProxy **内置 simple-obfs 的 `obfs-local`（http/tls 两种混淆）客户端**，无需外部二进制：`internal/upstream/obfs.go` 逐字节移植 simple-obfs 的 `obfs_http.c` / `obfs_tls.c` 客户端侧，`ssConnect` 在 TCP 建连后、SS 加密层之下再套一层混淆。

- **obfs-http**：首写前置 HTTP GET 请求头（`Content-Length`=首包长，`Host` 在端口非 80 时带 SS 服务器端口，`User-Agent: curl/7.<random>.<random>`、`Sec-WebSocket-Key` 随机——与 obfs-local 一致）；首读剥掉服务端 `HTTP/1.1 101` 响应头（按 `\r\n\r\n` 找边界）；后续读写明文直通。服务器端 `check_http_header` 只校验请求行含 `HTTP/1.1` 与 `Upgrade: websocket`，不校验 `Host`（`obfs-host` 缺省用 SS 服务器主机）。
- **obfs-tls**：首包藏进 TLS ClientHello 的 **session_ticket 扩展**（138B 固定头 + ticket 扩展 + 数据 + SNI + 66B 其余扩展）；读侧状态机解服务端 `ServerHello`（96B，验证 `0x16`）+ `ChangeCipherSpec`（6B）+ `EncryptedHandshake` 头（5B，len 即首块长），后续按 `0x17` 帧解帧；后续写每包前置 `0x17 0x03 0x03` + len 帧头。
- **UDP 默认关闭（可手动开启探测）**：obfs 只混淆 TCP（SIP003 语义，simple-obfs/v2ray-plugin 两端均无 UDP 通道），所以带插件的节点**默认把 UDP 电路手动置 down**——等效用户手动点了 UDP 关闭（构造时 `udpHealth.SetManualState(false)`）：面板显示 `tcp_only` + UDP down（manual 虚线框）、路由不选它做 UDP、健康检查也不探测它。但插件节点**不是硬 TCP-only**：`SchemeSupportsUDP()` 恒 true，SS UDP 仍绕过插件直连服务器 UDP 端口（`ssUDPAssociate`），所以部署若确实把 SS UDP 单独暴露在公网，在面板点 UDP 徽章释放回 auto（`action=auto`）后探测会跑起来，成功即把节点打成 UDP 可用（`tcp_and_udp`）。默认关闭只是"先当它没有"，不是协议上禁止。
- **内置插件**：`obfs-local`（http/tls 混淆，仅 TCP，见 `obfs.go`）与 `v2ray-plugin` / `xray-plugin`（websocket/grpc/quic 传输、可带 TLS，见 `v2ray.go`）**都已内置**，无需外部二进制；其它插件二进制不内置，`ssConnect`/`ssUDPAssociate` 时返回明确错误提示去掉该参数。
- **dashboard**：代理对话框的 SS 区块插件拆成两级选择（对齐 shadowsocks-android 的 Plugin + Configure 分离）：先选插件类型「无 / simple-obfs / v2ray-plugin」，再选具体模式——simple-obfs 为 Obfuscation wrapper（http / tls），v2ray-plugin 为 Transport mode（websocket-http / websocket-tls / quic-tls / grpc / grpc-tls，命名对齐 v2ray-plugin-android）；随后显示对应参数（obfs 的 `obfs-host`、http 额外 `obfs-uri`——无 `http-method`，对齐 simple-obfs-android 的 obfs / obfs-host / obfs-uri 三字段配置；v2ray 的 `host`/`path`/`mux`/`serviceName`/`certRaw`），保存时组装成 `obfs-local;obfs=...;obfs-host=...` 或 `v2ray-plugin;mode=...;tls;...`（`quic-tls` 不写 `tls` flag，QUIC 服务端强制 TLS，与安卓一致）；编辑时按 `;key=val` 拆回表单。另支持粘贴完整 `ss://` 链接自动导入（base64 / 明文 / 无密码三种 userinfo），或在 SS 区块点 **Scan QR** 扫码导入（`/jsqr.js` 内联 jsQR + 原生 `BarcodeDetector`）：扫码/图片/Paste 解码结果走同一条 `parseSSLink` → 表单填充链路。相机总是尝试调用（由浏览器决定是否允许——`getUserMedia`/`BarcodeDetector` 只在 HTTPS 或 localhost 等安全上下文放行）；普通 HTTP 远程访问（如 `http://192.168.1.1`）时浏览器会拒绝相机，自动落到**图片上传/粘贴**通道（纯 jsQR、任何协议可用）。
- **e2e 验证**（`obfs_e2e_test.go`，`go test -tags e2e`，需 `SS_SERVER_BIN` + `OBFS_SERVER_BIN`）：SmartProxy 带 `?plugin=` 直连真实 simple-obfs `obfs-server`（http/tls）→ 真实 ssserver，TCP 明文往返一致；UDP 直连 SS 服务器端口往返一致。

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

#### 过 GFW 的线格式：地址头必须与首块数据合成一次写

> 这是真实踩过的坑（2026-08，用户设备实测）：同一个 `ss://none` + obfs-http 节点，**安卓 shadowsocks-rust/ss-android 能过 GFW，SmartProxy 却被 RST**。关掉智能代理、用不敏感域名直连确认节点本身是好的——问题确凿出在 GFW。此节记录根因、修复，以及向 shadowsocks-rust 学到的设计。

**根因（pcap 实锤）**：旧实现 `ssConnect` 用 `Method.DialConn`（**eager 握手**）——TCP 建连后立即把 SS 地址头单独发出。在 obfs-http 层，这构成一个 `Content-Length == 地址头长度`、body 只有裸地址头的 GET：

```
GET / HTTP/1.1\r\nHost: upay.10010.com\r\n...\r\nContent-Length: 12\r\n\r\n
03 08 v2ex.com 01 bb          ← 裸 SS 地址头（12B）作为整个 body
...（TLS ClientHello 517B 在 ~20ms 后的另一个包里）
```

`Content-Length: 12` 且 body 恰为**一个孤立的 shadowsocks 地址头**，是「shadowsocks-in-http-obfs」的精确 DPI 指纹 → GFW 直接 RST。

**参考客户端怎么做**：sslocal/ss-android **延迟地址握手**——建连后什么都不发，等首个数据写（TLS ClientHello）到达时把 `[地址头][首块数据]` 合成**一次写**，obfs body 变成 `Content-Length: 529`、内容像一个 TLS 握手的前缀：

```
GET / HTTP/1.1\r\n...\r\nContent-Length: 529\r\n\r\n
03 08 v2ex.com 01 bb  +  TLS ClientHello(517B)   ← 一个 TCP 段里
```

抓包对比**逐字节一致**（修复后 SmartProxy 与 sslocal 参考 pcap：`Content-Length=529`、`bodylen=529`、TLS 从 body 偏移 12 开始、addr 头 `03 08 76326578...01bb`）。地址头从不在线上单独出现 → DPI 无从认指纹。

**修复（`internal/upstream/ss.go` 的 `deferredSSConn`）**：

1. `ssConnect` 改 `DialEarlyConn`（延迟握手）：AEAD/2022 的首个 `Write` 触发 sing 的 `writeRequest(payload)`，内部天然把 salt+addr+payload 合成一次加密写；`none`/`plain` 的 `noneConn.Write` 是**两次独立写**（先地址头再 payload），必须手动把 `[addr][payload]` 合成一次 `writeAll`。
2. **双向 relay 的竞态**（最隐蔽的坑）：SmartProxy 的 TCP relay 同时跑 c2r / r2c 两个 goroutine，r2c 读侧会**抢先**在首个数据写之前触发握手——裸地址头又单独上线。rust 是事件驱动天然没有这竞态；Go 的阻塞读无法区分「服务端还没回应」与「先读后写协议」。于是复刻 shadowsocks-rust `establish_tcp_tunnel` 的 500ms 语义（issue #232）：`deferredSSConn.Read` 的首读带 **500ms 读 deadline** 等服务端数据——数据只有写侧先发合并握手后才会到，TLS/HTTP 场景写侧毫秒级先发、读侧直接拿到数据**不 flush**；只有 500ms 超时（客户端真的一字节不发，如 FTP/SMTP 等服务端先发言的协议）才 flush 裸地址头并重试读。
3. **返回值陷阱**：合并写后必须返回 `len(b)`（调用方 payload 长度）而非 `len(merged)`，否则 `io.CopyBuffer` 把 `n != len(b)` 当成 `io.ErrShortWrite` 切断 relay。

**学到的设计（"ss 太厉害，要向它学习"）**：

- **与参考实现逐字节对齐，而不是"能互通就行"**。能互通 ≠ 过 GFW：任何 wire 差异都可能成为 DPI 指纹。修这类问题先抓双方 pcap 逐段对比，别猜。
- **地址头延迟到首块数据**是 shadowsocks 客户端的一致选择（rust 的 `make_first_packet_buffer`、sing 的 `DialEarlyConn`），既省一个 RTT 又消掉「孤立地址头」指纹。
- **先读后写协议（FTP/SMTP）用 500ms 首字节预读兜底**（rust #232）：既不让写优先场景退化（写侧毫秒级先到），又保证读优先场景不死锁。这个"带超时的首次决策"模式值得复用。

**验证**：`internal/upstream/ss_deferred_test.go`（写合并 / 读 flush / 先写后读直通 / 端到端 `Content-Length` 回归）；真机抓包见 `/tmp/ref/ref-v2ex.pcap`（参考）与 `/tmp/cap/fix2.pcap`（修复后）；最终用户设备 Termux 实测 `ip.cn` / `v2ex.com` 均 `connected via` 该节点。参考实现源码：`shadowsocks-rust/crates/shadowsocks-service/src/local/utils.rs`（`establish_tcp_tunnel`）。

### 上游能力自动辨识与裸 UDP 兜底

`mode` **不再是配置字段**（`ProxyEntry` 已删除）。每个上游的 TCP/UDP 能力由两部分自动推导：**生效 mode**（反映当前可用性，随探测变动）+ **UDP 能力标记**（反映协议层能力，sticky last-known-good）。

#### 生效 mode：scheme + 双熔断

`EffectiveMode()` 由 scheme 静态基态与 TCP/UDP 双熔断动态推出：

- **`http` / `https` / `socks4`**：确定不支持 UDP，恒为 `tcp_only`，从不探测 UDP。
- **带 SIP003 插件的 `ss`**：scheme 仍可探测 UDP，但**默认把 UDP 电路手动置 down**（等效手动关闭，见 §1 SIP003 小节）——未释放前恒为 `tcp_only` 且不探测；用户释放回 auto 后才探测，探测成功即恢复 UDP 可用。
- **`socks5` / `socks5h` / 纯 `ss`**（`SchemeSupportsUDP()`）：

  | TCP 熔断 | UDP 熔断 | 生效 mode |
  |---|---|---|
  | up | up | `tcp_and_udp` |
  | up | down | `tcp_only` |
  | down | up | `udp_only`（自动推出：无 TCP 监听器或 TCP 挂了但 UDP 正常） |
  | down | down | `tcp_and_udp`（双挂，熔断快照表达故障） |

路由用 `IsTCPOnly()` / `IsUDPOnly()` 读此派生值：`udp_only` 时 UDP 直连裸中继、跳过 TCP 路由与 TCP 健康探测，TCP 挂了也不会熔断它的 UDP。

#### UDP 能力标记（`udpCapability`）

每个 UDP-capable 代理维护一个 `UDPCapability`：`unknown` / `standard` / `raw` / `none`，由**探测端到端成功**推导并 sticky：

- **`standard`**：标准 SOCKS5 UDP ASSOCIATE 控制通道建立成功。
- **`raw`**：ASSOCIATE 失败后兜底裸 UDP relay 到 `Host:port` 成功（等价于 shadowsocks-android 的 UDP fallback 实例 / 插件模式的裸 relay —— 不要求 ASSOCIATE、读到带 SOCKS5 UDP 头的帧就转发）。判定按连接类型：`UDPProxyConn.tcpConn != nil` → standard，`tcpConn == nil`（走了 rawFallback）→ raw。
- **`none`**：UDP 探测端到端失败（ASSOCIATE 与 raw 都失败）且当前标记为 `unknown`/`none` 时置入。**探测失败只在 fresh/unknown 节点上写 `none`**，已辨识为 standard/raw 的节点失败只熔断 `udpHealth`、不翻回标记（故障由熔断快照表达）。
- **sticky 转移**：只允许 `unknown→standard`、`unknown→raw`、`unknown→none`、`raw→standard`（允许升级为 ASSOCIATE）；**禁止 `standard→raw` 降级**（避免瞬时失败导致永久降级）。
- **raw 重检自愈**：raw 节点平时仍直连裸中继（路由优化），但每 `rawRecheckInterval`（10 分钟）允许重试一次标准 ASSOCIATE——成功即升级 `standard`，失败则回落裸中继、标记保持 raw 并重置计时（不抖动、不再逐个连接重复失败握手）。该重检同时服务健康探测与真实流量，故健康检查关闭（单代理 auto-disable）时也能靠真实流量完成升级。

能力写入点：① 健康探测的 `checkProxyUDP` 成功（真实 DNS 查询端到端往返）后按连接类型 `classifyUDPCapability` 写入，失败时 `noteUDPCapabilityFailure`（仅 unknown/none 置 none）；② 真实流量在标记仍为 `unknown` 时的首次成功（`UDPAssociate` 成功路径），作为探测未开启时的补充。`ss` 无 raw 概念，恒 `standard`。

**路由优化**：已知 `raw` 的节点后续 UDP 直连裸中继，**跳过注定失败的 ASSOCIATE 握手**（`socks5UDPAssociate` 顶部 `if p.IsUDPOnly() || p.UDPCapability() == UDPCapRaw { rawUDPAssociate }`）。其余节点先走标准 ASSOCIATE，**任意失败**（拨号/握手/请求失败、回任何非 0x00 的 rep（含 0x07 CommandNotSupported）、bind 地址解析或拨号失败）自动兜底裸 UDP。

实现：`rawUDPAssociate(raddr)` 直接 `net.DialUDP` 返回 `UDPProxyConn{UDPConn}`（`tcpConn` 为 nil，`Close` 已做空指针保护）；`rawFallback(cause)` 在 ASSOCIATE 任一步失败后解析 `Host:port` 兜底。注意两点：① `DialUDP` 恒成功，目标无监听时包会静默丢弃（黑洞），故兜底路径打 WARN；② 兜底只在**本代理**的 ASSOCIATE 失败时发生，不改变 `Manager.UDPAssociate` 多代理 failover 语义。DNS 代理查询（`Manager.AcquireDNSUDP`）同走此路径，一处修改同时覆盖 DNS UDP。

**已端到端实测验证**：用官方 shadowsocks-rust v1.23.4 二进制搭出与 Android 兜底实例同形态的环境——`ssserver`（`"mode": "tcp_and_udp"`）+ `sslocal`（`"mode": "udp_only"`，本地 UDP 监听）——该节点无 TCP 监听器，TCP 探测失败即把 TCP 熔断打 open，生效 mode 自动推出 `udp_only`，`UDPAssociate` 经 raw 快路径裸中继发出带 SOCKS5 UDP 头的 DNS 查询帧，收到真实 DNS 响应（TXID 匹配）。实测 trace 确认链路：sslocal 收到裸帧即 `created udp association for <peer>`（按源地址现场建关联、免 ASSOCIATE）→ `udp relay <peer> -> <target> (proxied)` → `connected udp remote <ssserver>` → ssserver `udp relay ... -> <target>` → 响应原路返回。回归测试见 `internal/upstream/rawrelay_e2e_test.go`（`go test -tags e2e`，需 `SS_SERVER_BIN`/`SS_LOCAL_BIN` 环境变量指向真实二进制）。

> 两个实测中发现的配置坑，供复现时参考：① shadowsocks-rust 官方 release 的 CLI 把端口并入 `-s`/`-b` 地址参数（无 `-p`/`-l`），用 JSON 配置最稳；② `ssserver` 默认 `mode: TcpOnly` **不开 UDP**，必须显式 `"mode": "tcp_and_udp"`，否则 UDP 载荷在服务端被静默丢弃（这是 shadowsocks-rust 自身的配置，与 SmartProxy 的自动辨识无关）。

## §4 健康检查熔断状态机

`internal/upstream/health.go` 的 `ProxyHealth` 三态：

```
StateClosed ──失败 ≥ FailuresThreshold──► StateOpen
    ▲                                      │  OpenCoolDown 到期
    │         成功 ≥ SuccessesThreshold    ▼
    └──────────────── StateHalfOpen ◄─────┘
        （半开期间任意失败 → 立即回 StateOpen）
```

- **TCP 与 UDP 是两个独立熔断器**：每个 `Proxy` 持有 `health`（TCP）与 `udpHealth`（UDP）两个 `ProxyHealth`。TCP 探活只喂 `health`，DNS UDP 探测只喂 `udpHealth`，开合互不影响——TCP 挂了不会熔断 UDP（`udp_only` 场景），UDP 挂了也不会熔断 TCP。对应地，TCP 路由按 `IsAvailable()`（`health`）过滤，UDP 路由按 `IsUDPAvailable()`（`udpHealth`）过滤。
- `IsAvailable()` / `IsUDPAvailable()`：Closed / HalfOpen 为可用，Open 不可用。
- `checkLoop` 每代理一个 goroutine（启动时随机错峰 0–2s），按 `cfg.Interval`（默认 60s）：
  - **探测方向由 scheme 决定**（`SchemeSupportsUDP()`）：`socks5` / `socks5h` / `ss` 两种都探；`http` / `https` / `socks4` 只探 TCP、恒 `tcp_only`。
  - **TCP 探活**：HTTP GET `cfg.URL` 探活（2xx–3xx 算成功），喂 `health`。**所有节点都跑**，无 `udp_only` 豁免（`udp_only` 由「TCP 熔断 open + UDP 正常」自动推出，TCP 探测失败正是其来源）。
  - **UDP 探活**：经 `probeUDP` 发真实 DNS 查询——`p.UDPAssociate(dnsServer, 53)` → 写带 SOCKS5 UDP 头的 DNS A 查询帧 → 收响应帧并校验 TXID + QR 位，延迟做 EMA 平滑，喂 `udpHealth`。DNS 服务器与查询域名可配（`health_check.udp_probe_dns`，默认 `1.1.1.1:53`；`udp_probe_domain`，默认 `dns.google`）。探测复用正常 relay 路径（标准 ASSOCIATE + 裸兜底 / udp_only 裸中继 / ss UDP），所以测的就是真实 UDP 流量走的链路；成功时按连接类型分类并写入 UDP 能力标记，失败时 fresh 节点置 `none`（见 §3.2）。
- `AutoDisableSingle`：仅一个代理时自动关闭健康检查。
- 手动 disable/enable：admin `/health/proxy?alias=X&circuit=tcp|udp|both&action=enable|disable|auto` → `Manager.SetCircuitHealth` → `SetManualState` / `ClearManualState`。`circuit` 可单独作用某一路（如只 pin 掉 TCP、保留 UDP），省略即 `both`。**粘性手动覆盖**：电路被 `manual` pin 住后，探测结果只刷新延迟/最近尝试、**不挪动状态**，直到 `action=auto` 释放回自动控制；`enable`=强制 up、`disable`=强制 down、`auto`=释放。整节点按钮 Disable=双路 pin down，Enable=双路释放回 auto；想强制启用某个被探测打挂的电路则点它自己的徽章（force up）。快照新增 `manual` 字段标记 pin 状态，面板卡片 TCP/UDP 徽章即此入口，pin 住的电路用虚线边框标识。**热重载保活**：`Manager.Reload` 重建 Proxy 前按 alias 快照各电路的手动 pin，重载后仍存在的节点原样恢复（改 URL 不改 alias 也保持）——用户手动关闭的节点不会因配置热重载被静默重新启用；从配置里删掉的节点其 pin 随之消失。

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

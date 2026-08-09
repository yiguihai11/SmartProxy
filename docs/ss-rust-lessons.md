# 从 shadowsocks-rust 学到的设计经验

本文是「过 GFW 的 obfs 线格式坑」([upstream.md](upstream.md) 中 `deferredSSConn` 一节)的姊妹篇：不再只盯一条坑，而是把 shadowsocks-rust 源码里**前人踩过并总结出来的设计**整体扫一遍，逐条对照 SmartProxy 现状，标注 `已应用` / `可借鉴` / `需改造`。凡是标注 `已应用` 的，本仓库已经落地或由依赖（sing-shadowsocks / sing）代管；`可借鉴` 是抄了不亏、随时可加；`需改造` 是思路对但 Go 侧要自己动手。

分析基线：`/tmp/ss-rust`（shadowsocks-rust 主仓库），重点目录 `crates/shadowsocks/src/{relay,security,net,net/dns_resolver}` 与 `crates/shadowsocks-service/src`。行号均为分析时源码行。

---

## 一、TCP 转发

### 1.1 写状态机 + addr 与首块数据合成一次写 —— ✅ 已应用

参考客户端把 SS 地址头（ATYP+DST+PORT）和第一块 payload 拼进**同一次 write**，obfs-http 的 Content-Length 覆盖两者，body 看起来像正常 TLS 握手。我们的 `deferredSSConn`（`internal/upstream/ss.go`）已完整复刻：`DialEarlyConn` 延迟握手 + none/plain 手动合并 `[addr][payload]` 一次 `writeAll`。实测 pcap 与 sslocal 字节一致。

### 1.2 首块 500ms pre-read（issue #232）—— ✅ 已应用

rust 在 `establish_tcp_tunnel` 里对首块读取设 500ms 超时：先等对端数据，超时才单独发地址头（服务 FTP/SMTP 这类先读后写协议）。这正是我们 `deferredSSConn.Read` 的 500ms grace 语义——它解决了 Go 双向 relay 里 r2c 读协程抢先 flush 裸 addr 的问题。详见 [upstream.md](upstream.md)。

### 1.3 半关闭语义：对端 FIN 后自己只关写侧，不关闭整条连接 —— ✅ 已应用

ss-rust 双方向 copy 结束后对已读端 `shutdown(Read)`、对已写端 `shutdown(Write)`，让另一端还能收完剩余数据（TLS close_notify 依赖这个）。SmartProxy `internal/relay/tcp.go:147-150` 已做 `tcpDst.CloseWrite()` + `tcpSrc.CloseRead()`，语义一致。

### 1.4 握手失败静默丢弃（issue #292）—— 🔶 可借鉴

ss-rust 对端握手失败时直接把连接静默丢弃，不向客户端写错误响应——避免把"目标端口不存在 / 服务器被墙"这类探测信息回传给客户端，也避免让 GFW 从错误报文里学到握手失败后的行为特征。SmartProxy 目前握手失败会向客户端回 SOCKS5 错误码（对本地客户端友好，但对 SS 上游是泄露探测信号）。若以后要藏行为，可考虑对**上游 SS 握手**失败静默，对**本地 SOCKS5 入口**仍回错误码。两者视角不同，需区分对待。

### 1.5 数据面无空闲超时 —— ✅ 已应用

ss-rust 数据面（established 之后）**不设任何 idle timeout**，只靠 keepalive 保活、靠对端 FIN 收尾；idle 超时只用于握手阶段。SmartProxy 已全量遵循：所有 deadline 都是"握手/查询期作用 + 进数据面前清理"——`engine.go:231`（SOCKS5 握手后 `conn.SetDeadline(time.Time{})`，注释原文就是 "Clear the handshake deadline; it does not affect the subsequent long-lived relay connection"）、`proxy.go:515`（UDP ASSOCIATE 10s 握手 deadline 在进数据面前清掉）、`tun/handler.go:552`（DNS 查询 socket 每轮重设 30s，属有意闲置回收）。与 ss-rust 哲学一致，无隐患。

---

## 二、socket 选项（`crates/shadowsocks/src/net/`）

### 2.1 TCP_NODELAY 无条件设置 —— ✅ 已应用

rust 在 connect 后 / accept 后都无条件 `set_tcp_nodelay`（`net/sys/unix/mod.rs:114,140`）。SmartProxy 三处已做：accept 路径 `engine.go:204`、上游 dial `proxy.go:668`、直连 dial `route/router.go:339`。代理每跳转发小包，Nagle 必须关，已全覆盖。

### 2.2 KeepAlive：idle=interval=15s —— ✅ 已应用（2026-08-09）

rust 默认 `SO_KEEPALIVE` + `TCP_KEEPIDLE=15s` + `TCP_KEEPINTVL=15s`（`net/option.rs:20-22`，service 默认 `Duration::from_secs(15)`），**不设 KEEPCNT**。注意 rust 的 keepalive 只用于探测半死连接，**不用于出站数据面**（见 1.5）。

已对齐：三处 `SetKeepAlivePeriod(30s)` → `15s`（`engine.go` accept、`proxy.go` 上游 dial、`router.go` 直连 dial），并新增 `netutil.SetKeepAliveInterval`（`internal/netutil/tcpopts_linux.go`）在同一 socket 上补 `TCP_KEEPINTVL=15`。原因：Go 的 `SetKeepAlivePeriod` 只设 KEEPIDLE（`tcpsock.go` 仅调 `setKeepAliveIdle`），KEEPINTVL 恒走内核默认 75s，会让半死探测拖 5 倍。KEEPCNT 保持内核默认，与 rust 一致。

**注意 MPTCP 坑**（rust `unix/mod.rs:76-87` 注释 + mptcp_net-next #383/#353）：Linux MPTCP 内核不支持 KEEPIDLE/KEEPINTVL，只认纯 SO_KEEPALIVE，rust 会降级重试——若 SmartProxy 以后跑 MPTCP，`SetKeepAliveInterval` 的 SetsockoptInt 会失败，需按 rust 语义降级为只留 SO_KEEPALIVE。

### 2.3 SO_MARK（fwmark）—— ✅ 已应用

rust 在出站 TCP/UDP connect 前设 `SO_MARK`（`net/sys/unix/linux/mod.rs:61-78,324-341`），需 CAP_NET_ADMIN。SmartProxy `internal/fwmark/fwmark.go:53-65` 已在 `net.Dialer.Control` 里设置，时机正确（connect 前触发），TUN 自排除的 ip rule（fwmark→main）配套齐全。

### 2.4 SO_BINDTODEVICE —— 🔶 可借鉴

rust 在 SO_MARK 之后、connect 之前设 `SO_BINDTODEVICE`（`linux/mod.rs:351-371`），用于强制走指定网卡。Go 侧 `unix.SetsockoptString(fd, SOL_SOCKET, SO_BINDTODEVICE, iface)` 放在 Dialer.Control 即可。注意要求 CAP_NET_RAW（Linux 3.9+），失败不应 fatal。SmartProxy 暂无此需求，但作为"出口绑定网卡"能力可备。

### 2.5 TCP_FASTOPEN：监听侧 qlen=1024 —— ✅ 已应用（2026-08-09）

rust 在 `listen()` 之后设 `TCP_FASTOPEN=1024`（`net/tcp.rs:159-163`，`linux/mod.rs:171-202`），backlog 也是 1024。注释引用 LWN 508865：建议 5 但既然 backlog 是 1024 就开 1024 个握手槽。Go 无官方 API，已实现 `netutil.EnableTCPFastOpen`（`internal/netutil/tcpopts_linux.go`：`net.Listen` 之后经 `SyscallConn().Control` 设 `TCP_FASTOPEN=1024`，best-effort），并在 SOCKS5 入口 `engine.go` 监听建立后调用。对用 TFO 的客户端省首个 RTT，与数据面无关。**客户端侧不适用**，见 2.6。

### 2.6 客户端 TCP_FASTOPEN_CONNECT —— ❌ 不适用（两个结构性障碍）

**ss-rust 客户端没有用 `TCP_FASTOPEN_CONNECT`**（客户端 TFO 走第三方 `tokio_tfo`，grep 全仓库无 FASTOPEN_CONNECT）。评估在 Go 侧补这条时，确认它**对本协议族不适用**，两个无法绕过的障碍：

1. **net.Dialer 在握手完成前不返回**：`net.Dialer` 的 connect 是阻塞式的（`src/net/sock_posix.go` 中 connect 完成后才 `isConnected=true`），返回时 TCP 握手已完成，首个 `Write` 必然是 SYN-ACK 之后的普通数据段；而 SYN 在 `connect()` 里就已发出，只设 `TCP_FASTOPEN_CONNECT` 拿不到"数据在 SYN 里"的收益。
2. **SS 首块字节依赖首个用户 payload**：`deferredSSConn` 的核心是"addr+首块数据合成一次写"，但首块数据要等 relay 拿到第一个用户包才存在——TFO 却要求 connect 时刻就有数据可带。connect 时只有 SS 地址头已知，而裸 addr 正是被 RST 的 DPI 指纹；obfs-http 的 GET 头 `Content-Length` 必须等于首包长度（addr+payload），connect 时算不出来（`obfs.go:158` buildRequest）；obfs-tls 把首包藏进 ClientHello 的 session_ticket，同理。

要让 SS 吃到 TFO 的 RTT 收益需要"connect 与首块数据并行"（绕过 net.Dialer 的 connect-with-early-data），但首块数据本身不存在于 connect 时刻——**结构性无解**。监听侧 TFO（§2.5，接受客户端 TFO）仍然适用，且与数据面无关。

### 2.7 SO_SNDBUF / SO_RCVBUF —— 🔶 可借鉴

rust 在三个时机设：出站 connect 前、监听 socket bind 前、**accept 后立即**（`net/sys/mod.rs:49-57`、`net/tcp.rs:130-136`、`unix/mod.rs:132-138`）。Go 需 `unix.SetsockoptInt` 手动设。Linux 内核会把设值当初始值 + autotune 自动翻倍，小值不一定生效；accept 路径要紧跟 accept 后，否则窗口已协商完。SmartProxy 目前没设——上游与客户端间大带宽场景（> 默认 rcvbuf/sndbuf）才值得加，可做成配置项。

### 2.8 SO_REUSEADDR / SO_REUSEPORT —— ✅ 已应用 / 无需

rust 只在 listener 设 REUSEADDR，且**刻意排除 Windows**（`net/tcp.rs:138-146`：Windows 上 SO_REUSEADDR 允许 socket hijacking）。Go 的 `net.Listen` 非 Windows 默认已开 REUSEADDR，无需处理。REUSEPORT 仅 tproxy/redir 的 UDP 用（`local/redir/udprelay/sys/unix/linux.rs:74-82`），Go 不暴露、SmartProxy 单进程无此需求。

### 2.9 SetLinger(0) —— ✅ 已应用

rust 不直接设置但这是同类代理的共识做法；SmartProxy `internal/netutil/netutil.go:53` 已做 `SetLinger(0)`（立即 RST 关闭，避免 TIME_WAIT 堆积），符合预期。

### 2.10 IP_MTU_DISCOVER 禁 UDP 分片 + MTU 校验 —— 🔶 可借鉴

rust 出站 UDP 默认 `IP_PMTUDISC_DO` 禁分片（`linux/mod.rs:235-272,313-317`），只有显式 `allow_fragmentation=true` 才放开；且所有 send/recv 路径都做 `len > mtu` 校验（`net/udp.rs:201-303`）。Go 无现成 API，需 `unix.SetsockoptInt(fd, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)`（v6 用 `IPPROTO_IPV6`/`IPV6_MTU_DISCOVER`）。对 SmartProxy UDP relay：禁分片能避免"隧道内 1500+ 报文被 GFW 特征识别"，但要先确认隧道对端（服务器）也在做同样的 MTU 边界处理，否则超大报文会静默丢——这是**两端协同**的改动，故标需改造。

---

## 三、DNS 与连接建立（`crates/shadowsocks/src/net/dns_resolver/`）

### 3.1 getaddrinfo 放 blocking 线程池 —— ✅ 无需重复

rust 用 tokio `lookup_host` → 在 blocking 线程池调系统 getaddrinfo（`resolver.rs:229-233`），不阻塞事件循环。Go 的 `net.Resolver` / `net.Dialer` 原生就是异步阻塞模型，等价，无需重复实现。

### 3.2 A/AAAA 双取 —— ✅ 无需重复

rust hickory 版强制 `Ipv4AndIpv6` 策略（`hickory_dns_resolver.rs:151-153`），注释说明：若用 `Ipv4ThenIpv6`，第一个查询成功就返回，Happy Eyeballs 需要 A 和 AAAA 同时在手。Go `net.Resolver` 纯 Go 版会并发发起 A/AAAA 并做 RFC6724 排序，默认已覆盖。

### 3.3 resolv.conf 热重载 + 1s 防抖 —— 🔶 可借鉴

rust 用 notify 监听 `/etc/resolv.conf`，`Modify` 事件后**防抖 1 秒**再重建 resolver（`resolver.rs:154-227,204-206`），`ArcSwap` 原子切换。注释明确："/etc/resolv.conf may be modified multiple time in 1 second. Update once for all those Modify events"；且 `renamed or removed` 事件是未定义行为，需小心。SmartProxy 的 DNS 模块有自己的缓存与单飞（见 [dns.md](dns.md)），但 resolver 本身用 Go 默认，未做 resolv.conf 热重载——Docker/CNI 环境改 resolv.conf 后不重启不生效。可借鉴 rust 的防抖 + 原子换 resolver 思路（SmartProxy 已有 `atomic.Pointer` 换 chnroute/规则的成熟先例）。

### 3.4 Happy Eyeballs：族间 300ms 错峰 —— ✅ 无需重复

rust `lookup_then_connect!` 把地址按 v4/v6 分桶，非首选族延迟 `FIXED_DELAY = 300ms` 再启动（`mod.rs:71-228,96-99`，注释"Chrome and Firefox uses 300ms"），族内多 IP 串行尝试。它的 TODO（`mod.rs:100-105`）自述：这是"族间 300ms 错峰 + 族内串行"，不是 RFC 8305 标准的逐 IP 延迟。Go `net.Dialer` 内置 RFC 8305 Happy Eyeballs（`FallbackDelay` 默认 300ms），直接用即可。

### 3.5 每候选 IP 独立超时（rust 留下的 TODO）—— 🔶 可借鉴

rust 族内串行逐 IP 尝试但**没有对每个候选单独设超时**（`mod.rs:139-177`），注释与实现都承认：一个黑洞 IP 会拖死整条链路。Go `net.Dialer.Timeout` 覆盖整体（DNS+握手）而不是逐地址。若 SmartProxy 需要多出口 failover 的强健性，可考虑对每个候选 IP 包 `Dialer{Timeout: X}`——这是把 rust 的 TODO 补上，属于增强。

### 3.6 bind_local_addr 族映射 / dual-stack 降级 —— ✅ 无需重复

rust 手动处理 V4 bind→V6 connect（IPv4-mapped）、dual-stack bind 冲突降级 `IPV6_V6ONLY`（`net/sys/mod.rs:24-47,92-127`），甚至反过来引用 Go 的 `src/net/ipsock_posix.go` 做 IP 栈能力探测（`sys/mod.rs:140-183`）。Go `net.Dialer.LocalAddr` 原生做族映射与双栈探测，SmartProxy 直接用即可。

---

## 四、加密与重放防护（`crates/shadowsocks/src/security/replay/`）

### 4.1 AEAD-2022 重放防护 —— ✅ 已应用（sing 代管）

ss-rust 的 2022 AEAD 在**解密之后**做重放检查：时间戳 ±30s 窗口 + LRU 缓存最近 60s 内的 SALT，重复即丢弃（窗口外 + LRU 命中都算重放）。检查放**解密后**而非解密前（issue #442：早期版本先查重放再解密，重放包触发解密流程暴露时序侧信道）。SmartProxy 的 SS 加密走 `sing-shadowsocks` 依赖，2022 方法的完整性/重放防护由 sing 实现，已应用。

### 4.2 乱序丢包时的重放误报（#442 同类）—— 🔶 可借鉴

rust 对 UDP 乱序到达的边界处理：LRU 窗口 + 时间戳窗口组合，既要防重放又不能因乱序把正常包当重放丢。sing 侧已有相应处理。若 SmartProxy 未来自研 UDP 去重（目前 SS UDP 隧道语义靠对端），需记住这个权衡。

### 4.3 密钥派生（EIH / 多用户）—— ✅ 已应用（sing 代管）

AEAD-2022 的多用户身份、预共享密钥派生由 sing-shadowsocks 实现，SmartProxy 无需重复。

---

## 五、URL / 配置解析（`crates/shadowsocks/src/config.rs`）

### 5.1 SS URL 三形态 base64 解析顺序 —— ✅ 已应用

rust 按顺序尝试三种形态：URL-safe base64（带 `-` `_`）、standard base64（`+` `/`）、纯裸密码，逐级回退。SmartProxy 已在 `0dc37e0`（legacy QR 格式解析修复）覆盖该逻辑。

### 5.2 plugin 参数 splitn(2, ';') —— ✅ 已应用

rust 解析 `plugin=obfs-local;obfs=http;obfs-host=x` 时用 `splitn(2, ';')` 只拆第一个分号（plugin 路径可能含分号/特殊字符），其余原样保留。SmartProxy 在 `0dc37e0` 修过「plugin 含字面量分号被丢弃」，语义一致。

### 5.3 默认端口与 IP:port 边界 —— ✅ 已应用

rust 对 `ss://host` 无端口用默认、`[v6]:port` 解析边界等都有防御。SmartProxy 在 `0dc37e0`（ss:// 默认端口修复）覆盖。

---

## 六、UDP 中继

### 6.1 UDP association LRU + TTL + 容量上限 —— ✅ 已应用

ss-rust 对 UDP 关联做 LRU 驱逐 + TTL 过期 + 容量上限，会话空闲过期回收。SmartProxy `internal/udp/handler.go` 已实现等价模型：每个会话记 `lastActive`（`handler.go:80-81`），`StartCleaner` 按 `sess.timeout` 定期回收（`handler.go:445-446`），容量超限按 lastActive 驱逐最老会话（`handler.go:340`）。与 rust 模型一致。

### 6.2 响应续期：有出站响应就把 TTL 续上 —— ✅ 已应用

rust 在收到出站响应时刷新 association 的 TTL（活跃连接不被误回收）。SmartProxy `handler.go:392,409` 在收发两侧都 `lastActive.Store(now)`，语义一致。

### 6.3 SS UDP 池 15s TTL（无控制通道视为健康）—— ✅ 已应用

ss-rust 的 UDP 关联**不是控制通道协议**（不像 SOCKS5 ASSOCIATE 有握手），rust 把它们当作"建了就该一直活着"，靠 15s TTL 兜底。SmartProxy `internal/upstream/udp_pool.go:18` 注释明确"ss UDP / raw UDP have no control channel, so they are treated as healthy (TTL ...)"，且 `udp_pool.go:52` 用 15s TTL 驱逐，与 rust 一致。

### 6.4 per-association 独立 channel —— 🔶 可借鉴

rust 每个 UDP association 独占一个 channel，避免共享 socket 的锁竞争。SmartProxy 当前 UDP 会话用 `net.UDPConn` + 全局锁/路由查找，若并发打满可参考改为 per-assoc 队列。属性能优化，非必须。

---

## 七、负载均衡

### 7.1 评分模型：median + MAD + fail_rate —— 🔶 需改造（可选）

rust balancer 用**中位数 + 中位数绝对偏差（MAD）+ 失败率**综合评分，抗单次抖动。SmartProxy 的 `latency` 策略用 EWMA（α=1/4，`health.go:488-491`），`failover/round_robin/random` 已实现（`manager.go:161-185`）。差异：
- EWMA 对脉冲式抖动（单次慢包）敏感度高于 median+MAD。
- rust 把失败率计入评分，SmartProxy 是独立熔断电路（consecutiveFailures）决定可用性，再在可用集里按 latency 选。

若要对齐 rust，可把 latency 评分从 EWMA 换成"近 N 次采样 median"，失败率已由熔断覆盖无需重复。这是可选优化，非缺陷。

---

## 八、插件协议

### 8.1 SIP003：env + loopback 端口 —— 🔶 可借鉴

rust 的 obfs 插件走 SIP003：通过环境变量传配置，插件监听 127.0.0.1 随机端口，主程序把流量转发过去。SmartProxy 把 obfs 内联实现（`internal/upstream/obfs.go`），不走外部进程——省掉进程管理与转发开销，是**更优**的取舍。SIP003 的价值在于生态兼容（能挂任意现成插件），SmartProxy 若以后要接 v2ray-plugin 等才有意义。

### 8.2 SIP004 manager 协议 —— 🔶 参考

rust 提供 manager 接口（端口/IP 上报、节点增删），类似我们的 admin API。SmartProxy 已有 `internal/admin`（Unix socket + HTTP /stats /health /config），能力对齐，无需照搬协议。

---

## 九、可以直接抄的 issue 清单

| issue | 教训 | 对 SmartProxy |
| --- | --- | --- |
| [#232](https://github.com/shadowsocks/shadowsocks-rust/issues/232) | 首块 500ms pre-read | ✅ 已应用（deferredSSConn） |
| [#292](https://github.com/shadowsocks/shadowsocks-rust/issues/292) | 握手失败静默丢弃 | 🔶 可借鉴（区分上游/入口视角） |
| [#442](https://github.com/shadowsocks/shadowsocks-rust/issues/442) | 重放检查须在解密后 | ✅ sing 代管 |
| [#546](https://github.com/shadowsocks/shadowsocks-rust/issues/546) | keepalive 要同时设 KEEPIDLE+KEEPINTVL | 🔶 可借鉴（KEEPINTVL 需 x/sys） |
| [#179](https://github.com/shadowsocks/shadowsocks-rust/issues/179) | 零拷贝 / splice 相关 | ✅ relay/tcp.go 已用 splice |
| [#373](https://github.com/shadowsocks/shadowsocks-rust/issues/373) | UDP 相关边界 | 🔶 参考 |
| mptcp_net-next #383/#353 | MPTCP 不支持 KEEPIDLE/KEEPINTVL | 🔶 上 MPTCP 时处理 |
| LWN 508865 / rust #tokio#2685 | 监听侧 TFO backlog 应匹配握手槽 | 🔶 可借鉴（仅监听侧；客户端侧不适用，见 2.6） |

---

## 十、最值得抄的 5 条（按性价比排序）

（§1.5/§2.2/§2.5 经实测已落地为"已应用"，§2.6 经结构分析归为"不适用"，均已从候选里剔除。）

1. **resolv.conf 热重载 + 1s 防抖**（3.3）：Docker/CNI 环境不用重启即可感知 DNS 变更，复用现有 atomic.Pointer 换根模式。
2. **SO_BINDTODEVICE + UDP 禁分片**（2.4/2.10）：出口绑定与 UDP MTU 边界，按需上、注意两端协同。
3. **#292 握手失败静默（上游视角）**（1.4）：区分上游/入口视角，仅对上游 SS 握手失败静默。
4. **SO_SNDBUF/SO_RCVBUF**（2.7）：大带宽场景手动扩缓冲区，accept 后紧跟设置，可做配置项。
5. **每候选 IP 独立超时**（3.5）：补上 rust 自己留的 TODO，避免单黑洞 IP 拖死链路。

---

## 附：参考源码位置

- TCP 写状态机 / 首块合并：`crates/shadowsocks/src/relay/tcprelay/proxy_stream/client.rs`（make_first_packet_buffer）
- 500ms pre-read：#232，`crates/shadowsocks-service/src/local/utils.rs`（establish_tcp_tunnel）
- socket 选项：`crates/shadowsocks/src/net/option.rs`、`net/sys/unix/{linux/mod.rs,mod.rs}`、`net/sys/mod.rs`、`net/tcp.rs`、`net/udp.rs`
- DNS/HE：`crates/shadowsocks/src/net/dns_resolver/{mod.rs,resolver.rs,hickory_dns_resolver.rs}`
- 重放防护：`crates/shadowsocks/src/security/replay/`
- URL 解析：`crates/shadowsocks/src/config.rs`

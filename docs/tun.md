# TUN 模块（internal/tun）

本文是 TUN 透明代理的专题文档，覆盖 `internal/tun` 的职责边界、sing-tun 集成、gvisor 栈回调、TCP/UDP/DNS 连接处理、fd 模式、启动/关闭顺序、开发坑点，以及与 sing-tun v0.8.10 库源码的接口对照表。

> 版本说明：所有对 sing-tun / sing 库 API 的描述均对照 `go.mod` 锁定的 **v0.8.10** 源码核实（模块缓存 `$GOPATH/pkg/mod/github.com/sagernet/sing-tun@v0.8.10` 与 `sing@v0.8.10`）。升级依赖后请复核 §8 对照表。

## §1 职责边界

`internal/tun` 负责：

1. **创建/接管 TUN 设备**：普通模式自建 TUN（`singtun.New`，Linux 下打开 `/dev/net/tun`）；fd 模式包装 OS 提供的 fd（移动端、已有 VPN fd 场景）。
2. **gvisor 用户态网络栈**：创建并启动 sing-tun 的 gvisor stack，充当 TCP/UDP/DNS 流量的接收层。
3. **把流量接入路由与规则引擎**：实现 `singtun.Handler` 的三个回调方法，把 TCP/UDP/DNS 交给 `internal/route`、`internal/rules`、`internal/upstream`、`internal/dns` 处理。

入口为 `TUNHandler`（`internal/tun/handler.go`），编译期断言 `var _ singtun.Handler = (*TUNHandler)(nil)` 保证回调签名与库一致——若三个方法签名不匹配会直接编译失败。

## §2 sing-tun 集成

启动流程集中在 `TUNHandler.Start`：

```go
// InterfaceMonitor 必须非 nil：NativeTun.Start() 内部调用其 RegisterMyInterface，
// 缺省 nil 会 nil 指针 panic。用 sing 默认实现 + NOP logger 构建（不注册回调，惰性）。
networkMonitor, _ := singtun.NewNetworkUpdateMonitor(logger.NOP())
interfaceMonitor, _ := singtun.NewDefaultInterfaceMonitor(networkMonitor, logger.NOP(), singtun.DefaultInterfaceMonitorOptions{})

tunOpts := singtun.Options{
    Name:             cfg.Name,
    MTU:              uint32(cfg.MTU),
    Inet4Address:     inet4,
    Inet6Address:     inet6,
    AutoRoute:        cfg.AutoRoute,
    FileDescriptor:   cfg.FileDescriptor,
    InterfaceMonitor: interfaceMonitor,
}
t, err := NewTUN(tunOpts)                // singtun.New

// t.Start() 是接口置 UP + auto_route 规则安装的唯一入口（见 §6），必须调用
if err := t.Start(); err != nil { ... }

stackType := cfg.Stack
if stackType == "" {
    stackType = "gvisor"                 // 空串强制 gvisor
}

stackOpts := singtun.StackOptions{
    Context:     context.Background(),
    Tun:         t,
    TunOptions:  tunOpts,
    Handler:     h,                      // TUNHandler 实现 singtun.Handler
    UDPTimeout:  5 * time.Minute,        // 必须非零（见下）
    ICMPTimeout: 30 * time.Second,
}
s, err := NewTUNStack(stackType, stackOpts)  // singtun.NewStack
```

要点：

- `NewTUN` / `NewTUNStack` 是 `singtun.New` / `singtun.NewStack` 的别名（`handler.go` 底部 `var NewTUN = singtun.New; var NewTUNStack = singtun.NewStack`）。
- **空串强制 "gvisor"**：sing-tun 的 `NewStack` 对空串默认走 `mixed`/`system`（见 §8），本工程在 `Start()` 中把空串统一替换为 `"gvisor"`，保证默认栈就是 gvisor。
- **UDPTimeout/ICMPTimeout 必须非零**：sing-tun 的 gvisor UDP forwarder 在 `timeout == 0` 时内部 `udpnat.New` 会直接 panic（源码注释记录：此前漏设导致 TUN 无法启动）。本项目显式设为 `5min / 30s`。
- `AutoRoute` 在 fd 模式下由 `Engine.Start` 强制置为 `false`（不接管系统路由）。

## §3 gvisor 栈与回调

`singtun.Handler` 接口由三个方法组成（`tun.go:21`）：

```go
PrepareConnection(network, source, destination, routeContext, timeout) (DirectRouteDestination, error)
NewConnectionEx(ctx, conn, source, destination, onClose)      // N.TCPConnectionHandlerEx
NewPacketConnectionEx(ctx, conn, source, destination, onClose) // N.UDPConnectionHandlerEx
```

本项目 `PrepareConnection` 直接返回 `(nil, nil)`（不使用 direct route 机制）。

**回调已被库调度到独立 goroutine**，项目里的 `safego.Go` 并不是为了"异步"，其真正作用是 panic 恢复 + goroutine 命名：

- TCP：`stack_gvisor_tcp.go:94` 中 `go f.handler.NewConnectionEx(f.ctx, conn, source, destination, nil)`，每个 TCP 连接一个 goroutine。
- UDP：`udpnat/service.go:116` 中 `go func() { s.handlerEx.NewPacketConnectionEx(...) }()`，每个 UDP 会话一个 goroutine。

因此 `NewConnectionEx` / `NewPacketConnectionEx` 内的 `safego.Go("tun.handleSmartConnect", ...)` / `safego.Go("tun.handleGenericUDP", ...)` 是在库调度的基础上再加一层保护与命名。

## §4 连接处理

### 4.1 阻断语义

命中 `ruleEng.IsPortBlocked` / `IsIPBlocked` 时：

| 目标端口 | 动作 |
| --- | --- |
| 80 / 443 | `netutil.SendEnhancedBlock(conn, port)`：先 `SetLinger(0)` 再 `conn.Close()` → 对端收到 RST |
| 其他端口 | 直接 `conn.Close()` |

注意：**TUN 是透明代理，没有 SOCKS5 应答层**，"伪成功回复"（先回 `ReplySuccess` 再阻断）只存在于 SOCKS5 入口（`internal/engine/engine.go` 的 `handleConnect`）。TUN 路径命中阻断就是立即断开。

### 4.2 handleSmartConnect（TCP）

`NewConnectionEx` 里若 `SmartProxy.Enabled` 且目标端口在 `SmartProxy.Ports` 中，则进入智能分流；否则走 `Router.EstablishConnection` 直接建立连接。智能分流流程：

```
ReadClientHello(conn, 3s)      // 读首包
  → ExtractDomain(firstPkt)    // dpi.ExtractSNI / dpi.ExtractHTTPHost
  → ruleEng.IsDomainBlocked(domain)？ → SendEnhancedBlock
  → router.IsDomesticByIP(host)？
      ├── 是 → EstablishConnection 直连，首包先写上游 → relay.TCPRelay
      └── 否 → SmartConnectWithFallback（先直连，失败回退代理，动态黑名单）
```

首包必须透传给上游（`remote.Write(firstPkt)`），否则目标服务器等不到握手/请求头。

### 4.3 ReadClientHello 池化缓冲

`clientHelloBufPool` 是 `sync.Pool`，`New` 分配 4096 字节：

- 先 `io.ReadFull(conn, buf[:5])` 读 5 字节头。
- 若 `buf[0]` 在 `0x14~0x17`（TLS record）：读 `recordLen` 进池缓冲尾部。当 `recordLen <= 4091`（4096-5）时**无额外分配**，随后 `make([]byte, 5+recordLen)` 精确拷贝出结果。
- 超大 record（`recordLen > len(buf)-5`）：走 dedicated 分配（`make([]byte, recordLen)`），避免越界。
- 非 TLS（HTTP 等）：循环读直至命中 `\r\n\r\n` 或读满，再精确拷贝。
- 返回给调用方的是**精确大小的独立拷贝（cap == len）**，绝不直接返回池缓冲的子切片——保证池中缓冲不被调用方持有/污染，回池后可安全复用。

`ExtractDomain` 复用 `internal/dpi`（见 [dpi.md](dpi.md)），失败返回 `""`。

### 4.4 UDP 会话

`NewPacketConnectionEx` → `handleGenericUDP`（port 53 走 `handleDNS`）。

- **会话 key 用 `destination.String()`**（含地址 + 端口），不同目标互不串扰。
- `tunUdpSession` 记录 `lastActive` 与 `timeout`；`startUDPCleaner` 每 **5s** 扫描一次，超时未活跃的会话 `signalClose()` 并删除；`Close()` 时同样清理全部会话。
- `getOrCreateRemote` 采用 **double-checked locking**：
  1. 快路径：`mu.Lock()` 内查 `remotes` map，命中即返回，不做任何拨号。
  2. 慢路径：**锁外**拨号（`net.Dialer{Timeout: 10s}`），最长 10s 且不阻塞同一会话内其他目标的转发。
  3. 二次检查：拨号返回后再上锁，若并发已建好同一目标则复用已有连接并 `Close()` 刚建的多余连接。
- 发送侧：`udpSend` goroutine 循环 `conn.ReadPacket`，经 proxy 时把预构建的 SOCKS5 UDP header 前置后写入 `relay.UDPBufPool` 缓冲。
- 回包侧：`remoteUDPReader` goroutine 从远程读取，proxy 路径先解析 SOCKS5 header 剥掉（`atyp` 0x01/0x03/0x04 计算 `payloadStart`），再用 `buf.As` 包装后 `tunConn.WritePacket`（见 §7 坑点 8）。

### 4.5 handleDNS

- 仅 `destination.Port == 53` 的 UDP 会话进入。
- 每包 `SetReadDeadline(now + 30s)`，空闲 30s 超时自动退出（每收到一包即重置）。
- 循环：读包 → `h.dnsHandler.HandleDNS(ctx, payload, host, port, ruleEng)` → 响应非空则 `buf.As` 包装写回（DNS 响应也走 `buf.As`，见 §7 坑点 8）。

## §5 fd 模式

```go
isFdMode := cfg.FileDescriptor != 0
if isFdMode {
    if cfg.MTU <= 0 { cfg.MTU = 1500 }   // 默认 1500，并告警须与 OS 配置一致
    if cfg.Name == "" { cfg.Name = "tun" }
}
```

- sing-tun 的 `New`（`tun_linux.go`）在 `options.FileDescriptor != 0` 时走 else 分支：`tunFd: options.FileDescriptor` + `os.NewFile(uintptr(options.FileDescriptor), "tun")` 包装 OS 提供的 fd（移动端/宿主已创建 TUN 的场景）。
- `AutoRoute` 不生效（`Engine.Start` 强制 `false`），由 OS 侧管理路由。
- **MTU 一致性**：fd 模式下 MTU 以 OS VPN 配置为准，两侧必须一致，否则报文过大被丢弃。

## §6 启动/关闭顺序

启动（`TUNHandler.Start`）：

```
创建 InterfaceMonitor（NativeTun.Start 内部依赖 RegisterMyInterface，非 nil 否则 panic）
  → 创建 TUN（singtun.New，普通模式只配置 MTU + 地址，此时接口还是 DOWN）
  → t.Start()（关键：netlink.LinkSetUp 把接口置 UP；auto_route=true 时安装源策略路由/规则）
  → 创建 stack（singtun.NewStack，空串强制 "gvisor"）
  → s.Start()（gvisor 栈开始接收包，仅初始化 IP 栈，不碰 tun 接口状态）
  → t.Name() 记录接口名
```

> **`t.Start()` 必须调用**：`NativeTun.Start()`（`tun_linux.go:267`）是唯一做 `LinkSetUp`（接口 UP）和 `setRoute`/`setRules`（auto_route 真正实现）的地方；gvisor 栈的 `Stack.Start()` 不碰接口。此前漏调导致 tun0 一直是 DOWN、auto_route 路由一条不装，只能手动 `ip link set tun0 up`。fd 模式（`FileDescriptor != 0`）下 `NativeTun.Start()` 直接返回 nil，不受影响。

> **`Options.InterfaceMonitor` 必须非 nil**：`NativeTun.Start()` 内部调用 `InterfaceMonitor.RegisterMyInterface`，缺省 nil 会 nil 指针 panic。用 `singtun.NewNetworkUpdateMonitor(logger.NOP())` + `singtun.NewDefaultInterfaceMonitor(...)` 构建（本工程不注册回调，monitor 保持惰性）。

关闭（`Engine.Stop`，`stopOnce` 保护）：

```
cancel()（全局 ctx）
  → Router.StopCleanup()
  → listener.Close()
  → tunStack.Close()        // 先关 stack，停止转发
  → tunDev.Close()          // 再关 TUN 设备
  → TUNHandler.Close()      // 关闭 UDP cleaner + 清理源选择性路由
  → DNSHandler.Close()      // 关闭 DNS 缓存
  → adminServer.Stop()
```

`TUNHandler.Close` 关闭 `cleanerStopCh`（cleaner goroutine 退出前把 `udpSessions` 全部 `signalClose()` 并删除），并执行 `cleanSelectiveRoutes()` 删除源选择性路由的策略规则与专用路由表（见下）。

### §6.1 路由模式：auto_route 与源选择性路由

**`auto_route: true` 会劫持全部出站流量（0.0.0.0/0）**：sing-tun 的 `setRoute`/`setRules` 会装「`from all lookup <table>` + 默认路由 `dev tun0`」等策略规则，把服务器自身所有进程的出站包都引入 tun0。**不要在「还要被 SSH/对外提供服务的服务器」上开 `auto_route=true`**——SSH 响应等服务器自身流量会被 TUN 接管，导致卡顿甚至环路（TUN handler 再拨号上游又回到 tun0）。`auto_route=true` 只适合纯客户端/出口设备。

**服务器场景**：`auto_route=false` 时本工程**自动安装"源选择性路由"**（`internal/tun/selective_route.go`，仅 Linux）：

1. 随机挑一张未占用的路由表号（避开内核内置表 0-255，多实例不冲突），建一张专用路由表放默认路由：`default dev tun0`。
2. 加策略规则：`ip rule add from <tun子网> lookup <表> pref 100`（IPv4 与 IPv6 各装一条，配置了 inet6 时对称处理）。

效果：只有源地址为 TUN 子网（如 172.19.0.0/30）的流量走 tun0，服务器自身（含 SSH）完全不受影响。等价于 sing-tun auto_route 的"源规则"部分，但**不装 `from 0.0.0.0` 全量劫持**。TUN 关闭时 `Close()` 自动清理规则与路由表，无系统残留。fd 模式（移动端）由 OS VPN 管理路由，跳过安装。

> **IPv6 源限制**：源选择性路由要求客户端应用以 TUN 子网地址为源（IPv6 就是 `fc00::1`）。`curl --interface` 对 IPv4 会钉源、对 IPv6 不一定；若应用用别的源会掉进 sing-tun 自带的空表 `oif` 规则 → unreachable。

验证要点：启动后 `ip rule` 出现 `100: from 172.19.0.0/30 lookup <表>`（无 `from 0.0.0.0` 全量规则），`ip route show table <表>` 有一条 `default dev tun0`；关闭后 `ip rule` 恢复标准三条。

### §6.2 output_mark：自身出站打标 + auto_route 排除自身

**`tun.output_mark`（默认 `0` = 关闭）** 给路由器**自身所有出站连接**打 `SO_MARK`（`internal/fwmark/fwmark.go`，值可配置，默认 `0xffffff`）。实现：所有拨号点的 `net.Dialer.Control` 注入 `fwmark.Control`（DNS 查询/测速、UDP 转发、smart connect 探测、上游 SOCKS5 拨号、连通性探测等约 10 处）。

**`output_mark > 0` + `auto_route: true` + 非 fd 时**，TUN 启动自动安装"排除自身"（`internal/tun/self_exclude_linux.go`）：

```
ip rule（v4+v6）pref 8999: fwmark <mark> lookup main
   → 自身打标的包在 sing-tun 的 from all lookup 2022（pref 9000）之前落 main 表 → 绕过 TUN 劫持
nftables（inet smartproxy，type route output 链，只改 mark 不丢包）
   → 给 route_exclude_ports（默认 [22] SSH）的出站包打 mark → 同样绕过劫持
客户端包（无 mark）→ 继续命中 9000 劫持 → 全量捕获，无需钉源
```

- **效果**：`auto_route=true` 也能在服务器上安全使用——路由器自身拨号（防环）、SSH 22 端口（防卡）都被排除，客户端流量全量进 TUN。
- **安装失败必须中止启动**：`installSelfExclude` 出错即返回错误、`t.Close()`，否则就是无排除的全量劫持（服务器卡死）。
- **清理**：`Close()` 删除两条 ip rule + 整表删除 `inet smartproxy`（不碰其它 nftables 规则）。
- **权限**：`SO_MARK` / `ip rule` / nftables 均需 root / CAP_NET_ADMIN。
- **平台**：仅 Linux 生效；非 Linux 用 no-op 桩（`self_exclude_other.go`）。fd 模式（移动端）由 OS VPN 管理路由，不打标。
- **安全提示**：在服务器上启用 `auto_route=true + output_mark` 前，建议先确认 nft（`which nft`）存在、`route_exclude_ports` 覆盖了 SSH 端口，并备好回滚（删除 `inet smartproxy` 表 + 两条 pref 8999 规则即可恢复）。

## §7 开发注意事项（坑点）

1. **不要直接返回池化缓冲的子切片给调用方**，必须精确尺寸拷贝（`cap == len`）。见 §4.3：池缓冲回池后会被后续连接复用，返回子切片会造成数据竞争与内容污染。
2. **回调已被库调度到独立 goroutine**，`safego.Go` 的真正作用是 panic 恢复 + goroutine 命名。gvisor TCP 走 `stack_gvisor_tcp.go:94` 的 `go f.handler.NewConnectionEx(...)`；UDP 经 `udpnat` 走 `udpnat/service.go:116` 的 `go func(){...}`。不要在回调外层再套一层无意义的异步。
3. **onClose 分路径**：gvisor TCP 回调传 `nil`（`stack_gvisor_tcp.go:94`）；UDP 经 udpnat 传 `func(err error)`（NAT 用它删会话）。项目 `if onClose != nil` 的防御写法正是为此——UDP 漏回调会留下 NAT 会话泄漏。
4. **阻断连接也要回调 onClose**：所有提前 return 分支都调 `onClose(nil)`。新增分支时不要漏，尤其是 UDP（`NewPacketConnectionEx` 里每处阻断都 `onClose(nil)`）。
5. **UDP 会话 key 用 `destination.String()`**（含地址 + 端口），不同目标互不串扰；不要用仅地址或仅端口的 key。
6. **fd 模式 MTU 一致性**：mtu 以 OS VPN 配置为准，两侧必须一致（见 §5）。
7. **依赖检查**：TUN handler 对 `ruleEng` / `router` / `upstreamMgr` / `dnsHandler` 均有 nil 检查（移动端部分依赖可能未初始化），命中 nil 时记日志并关闭连接/包连接。
8. **给 TUN 发已有数据必须用 `buf.As`，不是 `buf.With`**：`sing/common/buf` 里 `With(data)` 不设置 `end`（`buffer.go:64`），`Bytes()` 返回 `data[start:end]` → `With` 包已有数据得到**空切片**，会把 UDP 回包/DNS 响应写成空数据报。`As(data)` 设置 `end = len(data)`（`buffer.go:56`）。`remoteUDPReader` 与 `handleDNS` 已用 `As`，并有回归测试 `TestRemoteUDPReader_WritesNonEmptyPayload`（`internal/tun/handler_test.go`）。
9. **`auto_route=true` 会劫持服务器全量出站（0.0.0.0/0，含 SSH）**：服务器上开必卡/环路，应设 `false` 走源选择性路由（详见 §6.1）。
10. **启动 monitor 用 `logger.NOP()` 即可**：`NewNetworkUpdateMonitor`/`NewDefaultInterfaceMonitor` 非 Android 上构造时不打开 netlink 通道，`Start()` 才订阅；本工程不 `Start()` 它们，仅用于满足 `RegisterMyInterface` 的非 nil 要求，无运行时开销。
11. **netlink 跨平台**：`sagernet/netlink` 包本身在 Windows/Darwin 无法编译（`xfrm.go` 用了 Linux 专属常量），netlink 逻辑必须全部隔离在 `//go:build linux` 文件，非 Linux 用 no-op 桩（`selective_route_other.go`）。

## §8 与 sing-tun 库源码的接口对照（v0.8.10）

| 项目用法 | 库定义 | 备注 |
| --- | --- | --- |
| `NewTUNStack = singtun.NewStack` | `NewStack(stack string, options StackOptions) (Stack, error)`（`stack.go`） | `"gvisor"` → `NewGVisor`；库对空串默认非 gvisor（`mixed`/`system`），本项目在 `Start()` 强制空串 → `"gvisor"` |
| `StackOptions{Context, Tun, TunOptions, Handler}` | `Handler Handler`（`stack.go`） | `TUNHandler` 实现它（编译期断言 `var _ singtun.Handler`） |
| `singtun.New(tunOpts)` | `New(options Options) (Tun, error)`，平台分文件（`tun_linux.go` / `tun_darwin.go` / `tun_windows.go` / `tun_other.go`） | Linux 打开 `/dev/net/tun`（`open()` + `TUNSETIFF`），需 root / CAP_NET_ADMIN |
| `Options.FileDescriptor` | 非 0 时 `os.NewFile(uintptr(options.FileDescriptor), "tun")`（`tun_linux.go:64,74`） | fd 模式依据；fd 模式下 `Start()`/`unsetRoute` 等跳过 OS 配置 |
| `Options.InterfaceMonitor` | `NativeTun.Start()` 调用 `InterfaceMonitor.RegisterMyInterface`（`tun_linux.go`） | 必须非 nil，否则 panic（见 §6） |
| `sagernet/netlink` | `github.com/sagernet/netlink@v0.0.0-20240612041022-b9a21c07ac6a` | 源选择性路由安装/清理（仅 Linux，见 §6.1） |
| `Handler` 三方法 | `PrepareConnection(...)` + `N.TCPConnectionHandlerEx`（`NewConnectionEx(ctx, conn, source, destination, onClose)`）+ `N.UDPConnectionHandlerEx`（`NewPacketConnectionEx(...)`） | `tun.go:21` 与 `sing/common/network/conn.go:105,138` |
| UDP 转发 | gvisor UDP 经 `udpnat.New(handler, ...)`（`stack_gvisor_udp.go`），nat 创建会话时 `go ...NewPacketConnectionEx(...)`（`udpnat/service.go:116`） | 每 UDP 会话一个 goroutine |
| `s.Start()` / `s.Close()` | `Stack.Start() error` / `Stack.Close() error`（`stack.go`） | `Engine.Stop` 顺序关闭 stack → tun → handler |
| `t.Name()` | `Tun.Name() (string, error)`（`tun.go:40`） | 记录接口名，失败仅告警 |

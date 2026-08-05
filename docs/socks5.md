# SOCKS5 服务端协议实现

服务端协议实现在 `internal/socks5/`（`server.go` 的握手/请求/回复、`constants.go` 的协议常量），业务接线在 `internal/engine/engine.go`；客户端侧（连上游代理）实现在 `internal/upstream/proxy.go`。

## §1 协议阶段

```
客户端                        服务端
  |-- version(0x05) + nmethods + methods -->|  协商
  |<-- version + chosen_method ------------|
  |-- version + method + auth payload ---->|  认证（配置了用户名密码时）
  |<-- version + 0x00/0x01 ---------------|  认证结果
  |-- version + cmd + rsv + atyp + addr -->|  请求：CONNECT / BIND / UDP ASSOCIATE
  |<-- version + reply + rsv + atyp + addr-|  回复
  |----------- data relay -----------------|  数据转发
```

## §2 握手（Handshake）

`internal/socks5/server.go` 的 `Handshake(rw, serverUser, serverPass)`：

1. 读 `version(0x05)` + `nmethods` + methods 列表；非 0x05 报错、`nmethods==0` 报错。
2. 配置了用户名密码时只接受 `UserPass(0x02)`，客户端未提供则回 `NoAccept(0xFF)`。
3. 未配置认证且客户端提供 `NoAuth(0x00)` → 直接回 `{0x05, 0x00}` 完成。
4. 走 UserPass 时读 `AuthVer(0x01)` + ulen + username + plen + password，与 `serverUser/serverPass` 比对后回 `{0x01, 0x00}`（通过）或 `{0x01, 0x01}`（失败）。

协议常量见 `internal/socks5/constants.go`：`Version5=0x05`、`NoAuth=0x00`、`UserPass=0x02`、`NoAccept=0xFF`、`AuthVer=0x01`、`AuthPassed=0x00`、`AuthFailed=0x01`、`RSV=0x00`。

## §3 请求与回复

`ReceiveRequest(r)` 读 `ver/cmd/rsv/atyp` 4 字节，按 ATYP 读地址与 2 字节端口：

| ATYP | 值 | 地址格式 |
| --- | --- | --- |
| IPv4 | `0x01` | 4 字节 |
| 域名 | `0x03` | 1 字节长度 + N 字节域名 |
| IPv6 | `0x04` | 16 字节 |

非法头返回 `ProtocolError{Reply}`，由调用方回对应错误码。`SendReply(w, reply, bindHost, bindPort)` 构造 `ver+reply+rsv+atyp+addr+port`，bindHost 为空时用 `0.0.0.0`。

命令与回复码（`constants.go`）：

| 命令 | 值 | 说明 |
| --- | --- | --- |
| CONNECT | `0x01` | 建立 TCP 隧道 |
| BIND | `0x02` | 不支持 |
| UDP ASSOCIATE | `0x03` | 由 `internal/udp` 处理 |

`ReplySuccess=0x00` … `ReplyAddrNotSupport=0x08`。`internal/engine/engine.go` 的 `replyForConnError` 把 `dial` 错误映射为 `ReplyConnRefused(0x05)` / `ReplyNetUnreachable(0x03)` / `ReplyHostUnreachable(0x04)`，超时映射为 `ReplyTTLExpired(0x06)`。

## §4 UDP ASSOCIATE

`handleUDPAssociate`（`internal/engine/engine.go`）：创建本地 UDP socket → 回 `ReplySuccess`（bind 地址为出站 IP，非 `0.0.0.0`）→ 交给 `internal/udp` 的 `Handler` 处理数据报。**SOCKS5 UDP 数据报头**：`RSV(2 字节) + FRAG(1) + ATYP(1) + ADDR + PORT(2) + DATA`；`FRAG != 0` 直接丢弃（不支持分片）。`handleUDPAssociate` 对空闲超时（默认 60s）用 10s ticker 检测，upstream 仍有活跃会话时不关闭。详见 `internal/udp/handler.go` 与 docs/dns.md。

## §5 引擎侧流程

`internal/engine/engine.go`：

```
handleClient
  ├─ conn.SetDeadline(30s)                ← 握手 deadline，完成后立即清除
  ├─ Handshake(conn, serverUser, serverPass)
  ├─ conn.SetDeadline(time.Time{})        ← 清除，避免影响后续长连接
  ├─ ReceiveRequest(conn)
  └─ switch Command:
       CONNECT       → handleConnect
       UDP_ASSOCIATE → handleUDPAssociate
       其他          → ReplyCmdNotSupported
```

- 连接建立时设置 TCP keepalive 30s + `NoDelay`，仅用于死链检测，**不主动关闭连接**。
- `handleConnect`：先查规则（`IsPortBlocked` / `IsIPBlocked`）；80/443 被 block 时回 `ReplySuccess` 后 `SendEnhancedBlock`，其余端口回 `ReplyNotAllowed`。
- 非 smart 端口 → `EstablishConnection` → `relayTCP`；smart 端口（80/443）→ 先回 `ReplySuccess` → `ReadClientHello(3s)` 提取域名 → 国内直连 / 国外 `SmartConnectWithFallback`。
- `relayTCP` 调用 `relay.TCPRelay`（`internal/relay/tcp.go`）：双方向 `safego.Go` 转发，TCP→TCP 走零拷贝 `splice`（`dst.ReadFrom(src)`），否则 `io.CopyBuffer` 用 32KB 池化缓冲。**数据 relay 阶段对客户端连接不再设 deadline**，长连接可无限期保持。

## §6 客户端侧实现（连上游代理）

`internal/upstream/proxy.go` 的 `socks5Connect`（上层连代理时使用）：`dial` 到代理（10s 超时，keepalive 30s + NoDelay）→ `socks5Handshake`（有凭据时协商 UserPass）→ 发 CONNECT 请求（目标域名直接编码进请求，由代理远程解析）→ 校验 `rep==0x00` → `skipSOCKS5Addr` 跳过回复地址 → 返回可用 `net.Conn`。

`socks5UDPAssociate`：握手后发 `{0x05,0x03,0x00,0x01,0,0,0,0,0,0}` → 读 bind 地址端口（`0.0.0.0`/`::` 时替换为代理 Host）→ `net.DialUDP` 连 bind 地址 → 返回 `UDPProxyConn{UDPConn, tcpConn}`，`Close` 时同时关 TCP 控制连接。仅 `socks5` / `socks5h` scheme 支持，详见 docs/upstream.md。

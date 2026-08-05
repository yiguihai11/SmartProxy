# 中继与缓冲池开发文档

中继层负责把一条连接的流量在客户端与远端之间双向搬运。TCP 中继在 `internal/relay/tcp.go`；**本仓库 `internal/relay` 没有独立的 `udp.go`**，UDP 会话转发实现在 `internal/udp/handler.go`（SOCKS5 UDP 会话）与 `internal/tun/handler.go`（TUN 侧 UDP），两者复用 relay 包导出的 `UDPBufPool`。

## §1 职责

- **TCP 中继**：`relay.TCPRelay(ctx, client, remote, proxy)` 启动 c2r / r2c 两个方向的中继 goroutine（`safego.Go` 托管），任一侧出错或 ctx 取消即关闭两侧连接。底层用 `io.CopyBuffer` 搬运，TCP→TCP 时优先走内核 `splice(2)` 零拷贝。
- **统计**：relay 包导出 `ActiveConns`、`ProxyBytesUp/Down`、`DirectBytesUp/Down` 等 `atomic.Int64` 计数器，供 Admin 面板展示。
- **UDP 会话**：`internal/udp/handler.go` 的 `Handler` 按 `客户端->目标` 二元组建立 `udpSession`，`pipeDownstream` 负责把远端回包写回客户端。

### TCPRelay 编排

```
TCPRelay(ctx, client, remote, proxy)
  ├─ safego.Go c2r：relayDirection(ctx, remote, client, "c2r", proxy)
  ├─ safego.Go r2c：relayDirection(ctx, client, remote, "r2c", proxy)
  ├─ safego.Go wait：wg.Wait() → close(done)
  └─ select { done 或 ctx.Done() }
       └─ ctx 取消时 client.Close() + remote.Close() + wg.Wait()
```

两个方向各一个 goroutine，字节计数按方向与 proxy 与否累加到 `ProxyBytesUp/Down`、`DirectBytesUp/Down`。任一端 `CloseWrite()` / `CloseRead()` 收尾，保证半关闭语义。

## §2 全局缓冲池

`internal/relay/tcp.go` 定义的缓冲池：

| 池 | 大小 | 用途 |
| --- | --- | --- |
| `bufferPool`（私有） | 32 KiB | TCP relay 的 `io.CopyBuffer` 缓冲（`relayDirection` 内 Get/Put） |
| `UDPBufPool`（公开） | 65535 字节 | UDP 数据报缓冲，TUN / engine 复用（`internal/tun/handler.go`、`internal/dns/handler.go` 都取用） |
| `PacketPool`（公开） | 4096 字节 | DNS 查询短包缓冲（`internal/dns/handler.go` 的 `queryUDP` / `queryViaProxy` 使用） |

UDP 数据报理论最大 65535 字节，故 UDP 池按满尺寸预分配；DNS 查询响应通常远小于 4 KiB，用 `PacketPool` 减小常驻内存。

## §3 tcpSplice：内核零拷贝

`relayDirection` 对每个方向先做类型断言：

- 两端都是 `*net.TCPConn` 时调用 `tcpSplice`，内部执行 `dst.ReadFrom(src)`。Go 1.25 标准库对"双方都是 TCPConn"的 `ReadFrom` 自动走 `splice(2)` 系统调用，且正确处理 deadline 与连接关闭。
- 收益：数据在**内核态**直接搬运，不经用户态缓冲复制，大幅降低 CPU 占用（万级连接/秒场景的关键优化）。
- 不满足 splice 条件（如客户端是 TLS 隧道内的 `net.Conn` 包装、TUN 栈的 gvisor 连接）或 splice 失败时，回退到 `bufferPool` 取的 32 KiB 缓冲 + `io.CopyBuffer`。

`tcpSplice` 返回 `(n, ok)`：`ok` 为真表示 splice 路径已完整搬运，直接跳到收尾；否则回退 buffered copy。

## §4 缓冲池使用契约

1. **Get 后必须 Put**：所有 `sync.Pool` 取用的缓冲，用完必须放回，否则池退化为纯分配。
2. **借用语义**：从池拿到的缓冲视为"借用"，其数据**不得交给生命周期更长的持有者**；如需长期持有必须先拷贝到独立切片。
3. **精确尺寸独立拷贝**：`internal/tun/handler.go` 的 `ReadClientHello` 是典型范式——从 `clientHelloBufPool`（`sync.Pool`，4096 字节）取池化缓冲预读首包，但返回给调用方的 `out := make([]byte, 精确长度)` 是**精确尺寸的独立拷贝**，池复用不污染调用方、也不被调用方保留的引用连累。
4. `io.CopyBuffer` 的缓冲 `buf := bufferPool.Get().([]byte)` 用毕 `bufferPool.Put(buf)`，仅在一个 `io.CopyBuffer` 调用周期内存活。

## §5 UDP 会话转发

`internal/udp/handler.go` 的转发链路：

```
HandlePacket → 解析 SOCKS5 UDP 头（atyp/端口/负载）
  → 命中已有会话：直接 remoteConn.Write（0-RTT 快路径）
  → 新会话：createGroup.Do(key, createUDPSession)   // singleflight 串行化拨号
      ├─ direct 路径：net.Dialer 直连 UDP，预构建 respHeader
      └─ proxy 路径：upstream.UDPAssociate，上游回复自带 SOCKS5 头
  → safego.Go(pipeDownstream)：循环 Read remote → WriteTo client
```

- **`pipeDownstream`**（`internal/udp/handler.go`）：每会话一个 goroutine，从 `udpBufPool` 取 65535 缓冲循环读取远端回包。direct 路径把预构建的 SOCKS5 `respHeader` 拼在数据前再写回客户端；proxy 路径上游回复自带 header，原样回传。
- **`remoteUDPReader`**（`internal/tun/handler.go`）：TUN 侧 UDP 回包读取，同样用 `relay.UDPBufPool`，按 proxy 路径解析 SOCKS5 header 后取 payload 部分经 `buf.As` 包给 TUN。
- 会话清理：`StartCleaner` 每 5s 回收超时会话（默认 60s，DNS 会话 5s）；会话数超 `maxUDPSessions`（500）时丢最旧会话。

## §6 与 sing common/buf 的关系

- `buf.NewPacket()` 分配一个 packet buffer（sing 的 `common/buf`），用毕 `buffer.Release()` 归还池。`tun/handler.go` 的 `udpSend` / `handleDNS` 循环中每次 ReadPacket 后都配对一个 `Release`。
- **非托管缓冲**：`buf.As(slice)` 把已有切片包成 `buf.Buffer`，不持有池所有权，`Release()` 是 no-op，可安全调用。
- **警告：给 TUN 发已有数据必须用 `buf.As` 而不是 `buf.With`**。`buf.With` 只设置 start 不设置 end，`Bytes()` 会返回**空切片**，把 UDP 回包 / DNS 响应写成**空数据报**。`internal/tun/handler.go` 的 `remoteUDPReader` 与 `handleDNS` 两处都专门加了注释说明这一点，改动时不要"顺手"换成 `With`。

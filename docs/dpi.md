# DPI（深度包检测）开发文档

DPI 模块位于 `internal/dpi/dpi.go`，仅依赖标准库（`encoding/binary`、`strings`）。职责是从 TCP 首包中解析出目标域名（TLS SNI 或 HTTP Host），**纯解析、零依赖、无状态**——不持有任何配置或会话，同一个函数可并发调用。

## §1 定位与调用链

- **纯解析**：输入一段原始 payload，输出域名字符串，不做网络 I/O、不做状态记录、不改动入参。
- **零依赖**：不依赖 sing、gvisor 等第三方库；协议偏移与长度全部手工解析。
- **无状态**：无结构体、无全局变量，所有函数为纯函数式顶层函数。
- **价值**：在"只知道 IP"的连接阶段也能按域名应用 ACL 规则。TUN 模式下，首包尚未完成 TLS 握手时，`internal/tun/handler.go` 的 `handleSmartConnect` 通过 `ReadClientHello` 预读首包，再用 `ExtractDomain` 提取域名做 `IsDomainBlocked` 判断与路由决策。

`ExtractDomain`（`internal/tun/handler.go`）：

```go
func ExtractDomain(firstPkt []byte) string {
	if len(firstPkt) == 0 { return "" }
	if sni := dpi.ExtractSNI(firstPkt); sni != "" { return strings.ToLower(sni) }
	if httpHost := dpi.ExtractHTTPHost(firstPkt); httpHost != "" { return strings.ToLower(httpHost) }
	return ""
}
```

先试 TLS SNI，失败再试 HTTP Host；两者都失败返回空串。

## §2 ExtractSNI：TLS Server Name Indication

`func ExtractSNI(payload []byte) string`，按 TLS 报文结构逐层剥离，**每一层都有长度校验，越界一律返回 `""`**。函数顶部还挂了一个 `defer recover` 兜底：即便未来某处校验遗漏导致越界 panic，也会被吞掉并返回 `""`（双重防御）。

解析链（全部基于入参 `payload` 直接切片，不复制）：

| 层级 | 字节内容 | 校验 |
| --- | --- | --- |
| TLS record 头（5 字节） | `payload[0]` 内容类型（必须 `0x16` handshake）、`[1:3]` 版本、`[3:5]` record 长度 | `len(payload) < 5` 或 `payload[0] != 0x16` → `""`；`len(payload) < 5+recordLen` → `""` |
| record 体 | `record := payload[5:5+recordLen]`，`record[0]` 必须是 `0x01`（ClientHello） | 否则 `""` |
| handshake 长度 | `record[1:4]` 为 3 字节大端长度，`append([]byte{0}, record[1:4]...)` 拼成 4 字节后 `Uint32` 取值 | `len(record) < 4` 或 `len(record) < 4+handshakeLen` → `""` |
| handshake 体 | `handshake := record[4:4+handshakeLen]`，从此处开始按固定偏移跳字段 | — |

handshake 体内部按固定偏移跳过（偏移全为常量）：

- `pos = 2`：跳过 **client_version（2 字节）**；
- 跳过 **random（32 字节）**——`pos+32` 越界检查；
- **session_id**：1 字节长度 + 内容；
- **cipher_suites**：2 字节长度 + 内容；
- **compression_methods**：1 字节长度 + 内容。

每一步 `pos` 都做 `pos+N > len(handshake)` 越界检查。随后读取扩展区：

- **extensions**：2 字节总长度，`pos+extensionsLen > len(handshake)` 越界则 `""`；
- 逐扩展遍历：每项 2 字节 `type` + 2 字节 `len`，`extPos += 4 + extLen`；
- `type == 0x0000`（`server_name`）即命中 SNI：
  - 2 字节 SNI 列表长度，越界检查；
  - 列表内首项：1 字节 `name_type`（必须 `0x00` host_name），否则 `""`；
  - 2 字节 hostname 长度 + hostname 本体，越界检查；
  - 返回 `strings.ToLower(hostname)`。

命中扩展时立即返回；遍历完整个扩展区都未命中则返回 `""`。

## §3 ExtractHTTPHost：HTTP Host 头

`func ExtractHTTPHost(payload []byte) string`，只解析 payload 前 **4096 字节**（`end = min(len(payload), 4096)`），防止超大首包白解析。同样有 `defer recover` 兜底。

解析流程：

1. 用 `indexBytes(data, []byte("\r\n\r\n"))` 定位 HTTP 头结束位置，找不到返回 `""`（HTTP 首包必须完整含空行）。
2. `splitBytes(head, []byte("\r\n"))` 切行；首行是请求行，`strings.Fields` 取第二个字段为 URI。
3. URI 若是 `http://` / `https://` 开头：从 `://` 之后取到下一个 `/` 为止作为 host，`LastIndexByte(':')` 去端口，返回小写。
4. 否则遍历后续行找 `Host:` 头（先 `strings.ToLower` 行再 `HasPrefix("host:")`，大小写不敏感；`len(line) < 6` 跳过短行）。取值 `strings.TrimSpace(line[5:])`，`LastIndexByte(':')` 去端口。
5. 返回 `strings.ToLower(hostVal)`。

去端口用 `LastIndexByte(':')`：对无端口 hostname 该调用返回 -1，原样保留。

## §4 零分配 / 边界安全原则

1. **不分配中间缓冲**：`ExtractSNI` 全程基于 `payload` 切片（`record`、`handshake`、`extensions`、`sniData` 等都是入参的子切片）；`ExtractHTTPHost` 的 `indexBytes` / `splitBytes` 也不复制数据。
2. **所有长度字段先校验再切片**：每个长度字段（recordLen、handshakeLen、sessionIDLen、cipherSuitesLen、extensionsLen、extLen、sniListLen、hostLen）读取后立即与剩余长度比对，越界返回 `""`，杜绝越界切片。
3. **任何解析失败返回 `""`**：调用方（`ExtractDomain`）以此判断"未能提取域名"，从而回退到仅按 IP 的路由策略。
4. **`defer recover` 兜底**：解析是纯函数、无副作用，即使未来协议变更引入边界 bug，也只会得到 `""` 而不是 panic 拖垮进程。

新增解析函数时应沿用同一模式：只用入参切片、长度字段先校验、失败返回 `""`、不改动入参。

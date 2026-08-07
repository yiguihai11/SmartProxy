package upstream

// 内置 simple-obfs(SIP003)客户端:obfs-http / obfs-tls。协议逐字节移植自
// shadowsocks/simple-obfs(https://github.com/shadowsocks/simple-obfs)的
// obfs_http.c / obfs_tls.c(客户端侧 obfs_request / deobfs_response)。
//
// 工作原理(与 obfs-local 相同,但无需外部二进制):
//   - 首写:obfs-http 在第一个 SS 包前拼一个 HTTP GET 头;obfs-tls 把第一个 SS 包
//     藏进 TLS ClientHello 的 session_ticket 扩展里。
//   - 后续写:obfs-http 明文直通;obfs-tls 每包加 5 字节 0x17 帧头。
//   - 读侧:首读剥掉服务端的 obfs 响应头(obfs-http 找 \r\n\r\n;obfs-tls 解析
//     ServerHello + CCS + EncryptedHandshake 头),obfs-tls 后续解 0x17 帧。
//
// 该插件只混淆 TCP;SS UDP 不经插件,直接发到服务器端口(见 ssUDPAssociate)。

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// obfsConfig 是一次 SIP003 插件解析结果。仅支持 simple-obfs 的 http/tls 两种混淆;
// 其它插件二进制(v2ray-plugin 等)SmartProxy 不内置,连接时报错。
type obfsConfig struct {
	id     string // 插件二进制名,如 "obfs-local"
	obfs   string // "http" | "tls"
	host   string // obfs-host(HTTP Host / TLS SNI)
	port   int    // SS 服务器端口,HTTP Host 头在非 80 时带上(与 obfs-local 一致)
	method string // http-method,默认 "GET"(仅 http)
	uri    string // obfs-uri,默认 "/"(仅 http)
}

// parsePluginOptions 解析 SIP003 的 ?plugin= 参数值,格式:
//
//	<binary>;key=value;key=value...
//
// 值里的 \ ; = 反斜杠转义(ss-android PluginOptions 导出格式)。未知 key 忽略,
// 兼容 fast-open / mptcp 这类 TCP 层选项。
func parsePluginOptions(s string) (*obfsConfig, error) {
	if s == "" {
		return nil, errors.New("empty plugin options")
	}
	parts, err := splitPluginOptions(s)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, errors.New("empty plugin options")
	}
	cfg := &obfsConfig{id: parts[0], method: "GET", uri: "/"}
	for _, kv := range parts[1:] {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "obfs":
			cfg.obfs = v
		case "obfs-host":
			cfg.host = v
		case "http-method":
			cfg.method = v
		case "obfs-uri":
			cfg.uri = v
		case "fast-open", "mptcp":
			// TCP 层选项,忽略
		}
	}
	if cfg.id != "obfs-local" {
		return nil, fmt.Errorf("unsupported SIP003 plugin %q: SmartProxy only ships obfs-local (http/tls)", cfg.id)
	}
	if cfg.obfs != "http" && cfg.obfs != "tls" {
		return nil, fmt.Errorf("unsupported obfs type %q (want http or tls)", cfg.obfs)
	}
	return cfg, nil
}

// splitPluginOptions 按未转义的 ';' 分段,处理反斜杠转义。
func splitPluginOptions(s string) ([]string, error) {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == ';':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	parts = append(parts, cur.String())
	return parts, nil
}

// wrapObfs 把已连上远端 SS 服务器的 TCP 连接包上 obfs 传输层,返回满足 net.Conn
// 的混淆连接。obfs-http 的首包/后续包为明文拼装;obfs-tls 首包藏进 ClientHello。
func wrapObfs(conn net.Conn, cfg *obfsConfig) (net.Conn, error) {
	switch cfg.obfs {
	case "http":
		return &httpObfsConn{Conn: conn, host: cfg.host, port: cfg.port, method: cfg.method, uri: cfg.uri, needStrip: true}, nil
	case "tls":
		return &tlsObfsConn{Conn: conn, host: cfg.host}, nil
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported obfs type %q", cfg.obfs)
	}
}

// writeAll 循环写满整个 buf(处理 TCP 短写)。
func writeAll(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

var crlfcrlf = []byte("\r\n\r\n")

// ---------------------------------------------------------------------------
// obfs-http
// ---------------------------------------------------------------------------

// httpObfsConn 实现 obfs-http 客户端传输层:
//   - Write:首写前置 HTTP GET 请求头(Content-Length=首包长,服务端实际只按 \r\n\r\n
//     剥离、不按 Content-Length 读边界),后续明文直通;
//   - Read:首读缓存到 \r\n\r\n,剥掉服务端 101 响应头后返回剩余数据,后续直通。
type httpObfsConn struct {
	net.Conn

	host   string
	port   int // 远程 SS 端口;==80 时 Host 不带端口
	method string
	uri    string

	sentHeader bool
	needStrip  bool   // 尚未剥掉服务端响应头
	buf        []byte // 未找到 \r\n\r\n 前的缓存
	leftover   []byte // 剥掉响应头后剩下的数据
}

const maxObfsHTTPHeader = 64 * 1024

func (c *httpObfsConn) buildRequest(contentLength int) []byte {
	var b strings.Builder
	b.WriteString(c.method)
	b.WriteByte(' ')
	b.WriteString(c.uri)
	b.WriteString(" HTTP/1.1\r\n")
	if c.host == "" {
		b.WriteString("Host: cloudfront.net\r\n")
	} else if c.port != 80 {
		b.WriteString("Host: " + c.host + ":" + fmt.Sprint(c.port) + "\r\n")
	} else {
		b.WriteString("Host: " + c.host + "\r\n")
	}
	// User-Agent: curl/7.<major>.<minor>,major/minor 随机(与 simple-obfs 一致)
	b.WriteString("User-Agent: curl/7." + fmt.Sprint(randIntN(51)) + "." + fmt.Sprint(randIntN(2)) + "\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	b.WriteString("Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n")
	b.WriteString("Content-Length: " + fmt.Sprint(contentLength) + "\r\n")
	b.WriteString("\r\n")
	return []byte(b.String())
}

func (c *httpObfsConn) Write(p []byte) (int, error) {
	if c.sentHeader {
		if err := writeAll(c.Conn, p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	c.sentHeader = true
	hdr := c.buildRequest(len(p))
	buf := make([]byte, 0, len(hdr)+len(p))
	buf = append(buf, hdr...)
	buf = append(buf, p...)
	if err := writeAll(c.Conn, buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *httpObfsConn) Read(p []byte) (int, error) {
	if c.needStrip {
		for {
			if idx := bytes.Index(c.buf, crlfcrlf); idx >= 0 {
				rest := c.buf[idx+4:]
				c.buf = nil
				c.needStrip = false
				n := copy(p, rest)
				c.leftover = append(c.leftover[:0], rest[n:]...)
				if n < len(p) && len(c.leftover) == 0 {
					m, err := c.Conn.Read(p[n:])
					n += m
					if err != nil && n == 0 {
						return n, err
					}
					if err != nil {
						return n, err
					}
				}
				return n, nil
			}
			if len(c.buf) > maxObfsHTTPHeader {
				return 0, errors.New("obfs-http: server response header too large")
			}
			tmp := make([]byte, 8192)
			m, err := c.Conn.Read(tmp)
			if m > 0 {
				c.buf = append(c.buf, tmp[:m]...)
			}
			if err != nil {
				return 0, fmt.Errorf("obfs-http: reading server response: %w", err)
			}
		}
	}
	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		if n < len(p) {
			m, err := c.Conn.Read(p[n:])
			n += m
			if err != nil && n == 0 {
				return n, err
			}
			if err != nil {
				return n, err
			}
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

// ---------------------------------------------------------------------------
// obfs-tls
// ---------------------------------------------------------------------------

// tlsObfsConn 实现 obfs-tls 客户端传输层:
//   - Write:首写构造 TLS ClientHello(首包藏进 session_ticket 扩展),后续每包
//     前置 5 字节 0x17 0x03 0x03 + uint16 len 帧头;
//   - Read:首读解析固定结构的 ServerHello(96B)+ CCS(6B)+ EncryptedHandshake 头
//     (5B,len 即首块数据长),之后按 0x17 帧解帧。
type tlsObfsConn struct {
	net.Conn
	host string

	sentHello bool

	// 读侧状态机
	state    tlsReadState
	hdr      []byte // 攒当前待读的定长头
	msgLen   int    // 首块数据长度(EncryptedHandshake.len)
	frameLen int    // 当前 0x17 帧 payload 长度
	out      []byte // 已解帧、待交付给上层的数据
}

type tlsReadState int

const (
	tlsStateHello     tlsReadState = iota // 96B ServerHello
	tlsStateCCS                           // 6B ChangeCipherSpec
	tlsStateEncHeader                     // 5B EncryptedHandshake 头
	tlsStateFirstChunk                    // msgLen 字节首块数据(明文直通)
	tlsStateFrame                         // 0x17 帧
)

// simple-obfs 的模板字节(从 C 源码逐字节提取,见 obfs_tls.c)。
var tlsCipherSuites = []byte{
	0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
	0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
	0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
	0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
}

// tlsOthersExt = ec_point_formats + elliptic_curves + sig_algos + etm + ems,
// 共 66 字节,顺序与 simple-obfs 的 tls_ext_others_template 一致。
var tlsOthersExt = []byte{
	0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02,
	0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
	0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e,
	0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02,
	0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
	0x00, 0x16, 0x00, 0x00,
	0x00, 0x17, 0x00, 0x00,
}

const (
	tlsHelloLen    = 138 // sizeof(struct tls_client_hello)
	tlsSNILen      = 9   // sizeof(struct tls_ext_server_name)
	tlsTicketLen   = 4   // sizeof(struct tls_ext_session_ticket)
	tlsOthersLen   = 66  // sizeof(struct tls_ext_others)
	tlsServerHello = 96  // sizeof(struct tls_server_hello)
	tlsCCSLen      = 6   // sizeof(struct tls_change_cipher_spec)
	tlsEncHeader   = 5   // sizeof(struct tls_encrypted_handshake)
	tlsMaxFrame    = 16384
)

// clientHello 构造 obfs-tls 的 TLS ClientHello(与 simple-obfs obfs_tls_request
// 逐字节一致):首包 firstChunk 藏进 session_ticket 扩展,SNI 放 host。
func (c *tlsObfsConn) clientHello(firstChunk []byte) []byte {
	host := c.host
	if host == "" {
		host = "cloudfront.net"
	}
	hostLen := len(host)
	bufLen := len(firstChunk)
	tlsLen := bufLen + tlsHelloLen + tlsSNILen + hostLen + tlsTicketLen + tlsOthersLen

	b := make([]byte, tlsLen)
	pos := 0

	// 记录头:content_type 0x16, version 0x0301, len = tlsLen-5
	b[pos] = 0x16
	b[pos+1] = 0x03
	b[pos+2] = 0x01
	binary.BigEndian.PutUint16(b[pos+3:], uint16(tlsLen-5))
	pos += 5
	// 握手头:type 0x01, 3 字节长 = tlsLen-9
	b[pos] = 0x01
	binary.BigEndian.PutUint16(b[pos+2:], uint16(tlsLen-9))
	pos += 4
	// 握手版本 0x0303
	b[pos], b[pos+1] = 0x03, 0x03
	pos += 2
	// random:unix 时间 + 28 随机字节
	binary.BigEndian.PutUint32(b[pos:], uint32(time.Now().Unix()))
	pos += 4
	_, _ = rand.Read(b[pos : pos+28])
	pos += 28
	// session_id:32 随机字节
	b[pos] = 32
	pos += 1
	_, _ = rand.Read(b[pos : pos+32])
	pos += 32
	// cipher_suites:56 固定字节
	binary.BigEndian.PutUint16(b[pos:], uint16(len(tlsCipherSuites)))
	pos += 2
	copy(b[pos:], tlsCipherSuites)
	pos += len(tlsCipherSuites)
	// comp_methods:1 字节 0x00
	b[pos] = 1
	pos += 1
	b[pos] = 0x00
	pos += 1
	// ext_len = ticket(4+bufLen) + SNI(9+hostLen) + others(66)
	extLen := tlsTicketLen + bufLen + tlsSNILen + hostLen + tlsOthersLen
	binary.BigEndian.PutUint16(b[pos:], uint16(extLen))
	pos += 2

	// session_ticket 扩展:type 0x0023, len=bufLen, 数据=首包
	binary.BigEndian.PutUint16(b[pos:], 0x0023)
	pos += 2
	binary.BigEndian.PutUint16(b[pos:], uint16(bufLen))
	pos += 2
	copy(b[pos:], firstChunk)
	pos += bufLen

	// SNI 扩展:type 0x0000, ext_len=hostLen+5, list_len=hostLen+3, type 0, name_len=hostLen
	binary.BigEndian.PutUint16(b[pos:], 0x0000)
	pos += 2
	binary.BigEndian.PutUint16(b[pos:], uint16(hostLen+3+2))
	pos += 2
	binary.BigEndian.PutUint16(b[pos:], uint16(hostLen+3))
	pos += 2
	b[pos] = 0x00
	pos += 1
	binary.BigEndian.PutUint16(b[pos:], uint16(hostLen))
	pos += 2
	copy(b[pos:], host)
	pos += hostLen

	// 其余扩展(固定 66 字节)
	copy(b[pos:], tlsOthersExt)
	return b
}

func (c *tlsObfsConn) Write(p []byte) (int, error) {
	if !c.sentHello {
		c.sentHello = true
		if err := writeAll(c.Conn, c.clientHello(p)); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	// 后续数据分 ≤16384 字节的 0x17 帧(与 simple-obfs obfs_app_data 一致)
	orig := len(p)
	for len(p) > 0 {
		chunk := len(p)
		if chunk > tlsMaxFrame {
			chunk = tlsMaxFrame
		}
		frame := make([]byte, 5+chunk)
		frame[0], frame[1], frame[2] = 0x17, 0x03, 0x03
		binary.BigEndian.PutUint16(frame[3:5], uint16(chunk))
		copy(frame[5:], p[:chunk])
		if err := writeAll(c.Conn, frame); err != nil {
			return 0, err
		}
		p = p[chunk:]
	}
	return orig, nil
}

// Read 把服务端 obfs 响应解帧后返回 SS 明文数据。
func (c *tlsObfsConn) Read(p []byte) (int, error) {
	for {
		if len(c.out) > 0 {
			n := copy(p, c.out)
			c.out = c.out[n:]
			return n, nil
		}
		tmp := make([]byte, 16384)
		n, err := c.Conn.Read(tmp)
		if n > 0 {
			if ferr := c.feed(tmp[:n]); ferr != nil {
				return 0, ferr
			}
		}
		if err != nil {
			if len(c.out) > 0 {
				n := copy(p, c.out)
				c.out = c.out[n:]
				return n, nil
			}
			return 0, err
		}
	}
}

// feed 把原始字节喂进读侧状态机,产出解帧后的数据追加到 c.out。
func (c *tlsObfsConn) feed(b []byte) error {
	i := 0
	for i < len(b) {
		switch c.state {
		case tlsStateHello:
			need := tlsServerHello - len(c.hdr)
			take := minInt(need, len(b)-i)
			c.hdr = append(c.hdr, b[i:i+take]...)
			i += take
			if len(c.hdr) == tlsServerHello {
				if c.hdr[0] != 0x16 {
					return errors.New("obfs-tls: bad server hello content type")
				}
				c.hdr = nil
				c.state = tlsStateCCS
			}
		case tlsStateCCS:
			need := tlsCCSLen - len(c.hdr)
			take := minInt(need, len(b)-i)
			c.hdr = append(c.hdr, b[i:i+take]...)
			i += take
			if len(c.hdr) == tlsCCSLen {
				c.hdr = nil
				c.state = tlsStateEncHeader
			}
		case tlsStateEncHeader:
			need := tlsEncHeader - len(c.hdr)
			take := minInt(need, len(b)-i)
			c.hdr = append(c.hdr, b[i:i+take]...)
			i += take
			if len(c.hdr) == tlsEncHeader {
				c.msgLen = int(binary.BigEndian.Uint16(c.hdr[3:5]))
				c.hdr = nil
				if c.msgLen > 0 {
					c.state = tlsStateFirstChunk
				} else {
					c.state = tlsStateFrame
				}
			}
		case tlsStateFirstChunk:
			take := minInt(c.msgLen, len(b)-i)
			c.out = append(c.out, b[i:i+take]...)
			c.msgLen -= take
			i += take
			if c.msgLen == 0 {
				c.state = tlsStateFrame
			}
		case tlsStateFrame:
			if c.frameLen == 0 {
				need := 5 - len(c.hdr)
				take := minInt(need, len(b)-i)
				c.hdr = append(c.hdr, b[i:i+take]...)
				i += take
				if len(c.hdr) == 5 {
					if c.hdr[0] != 0x17 {
						return errors.New("obfs-tls: bad app data frame header")
					}
					c.frameLen = int(binary.BigEndian.Uint16(c.hdr[3:5]))
					c.hdr = nil
					if c.frameLen > tlsMaxFrame {
						return errors.New("obfs-tls: frame too large")
					}
				}
			} else {
				take := minInt(c.frameLen, len(b)-i)
				c.out = append(c.out, b[i:i+take]...)
				c.frameLen -= take
				i += take
			}
		}
	}
	return nil
}

// randIntN 返回 [0,n) 的随机数(仅用于伪造 User-Agent 版本号,不需要加密随机)。
func randIntN(n int) int {
	var b [8]byte
	_, _ = rand.Read(b[:])
	v := int(binary.LittleEndian.Uint64(b[:]))
	if v < 0 {
		v = -v
	}
	return v % n
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

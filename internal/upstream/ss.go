package upstream

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ss:// 上游:SmartProxy 直接以 shadowsocks 协议连接远程 SS 服务器,不依赖外部
// sslocal 进程。TCP 走 Method.DialConn 得到加密隧道;UDP 走 Method.DialPacketConn,
// 用 sing-shadowsocks 逐包携带目标地址的模型,把上游一侧收发的 SOCKS5-UDP 帧
// 转换成 SS UDP 包。
//
// 支持经典 AEAD(密码派生 key)、AEAD-2022(base64 key)与不加密的 none/plain。

// ssSupportedMethods 列出支持的经典 AEAD + AEAD-2022 加密方式。sing-shadowsocks
// 的 shadowaead.New / shadowaead_2022.New 对未知方法不报错(会留下 nil constructor),
// 这里显式校验,避免拼写错误直到连接时才 panic。
var ssSupportedMethods = map[string]bool{
	// 经典 AEAD(SIP004,密码派生 key)
	"aes-128-gcm":             true,
	"aes-192-gcm":             true,
	"aes-256-gcm":             true,
	"chacha20-ietf-poly1305":  true,
	"xchacha20-ietf-poly1305": true,
	// AEAD-2022(SIP022,key 是 base64 编码的二进制 PSK,可多 PSK 用 : 连接)
	"2022-blake3-aes-128-gcm":       true,
	"2022-blake3-aes-256-gcm":       true,
	"2022-blake3-chacha20-poly1305": true,
}

// newSSMethod 构建 SS 加密实现:经典 AEAD(密码派生 key)、AEAD-2022(base64 key)
// 或不加密的 none/plain。none/plain 是同一个方法(shadowsocks-rust 的
// CipherKind::NONE 别名),wire 为明文地址头 + payload,不需要密码。
func newSSMethod(method, password string) (shadowsocks.Method, error) {
	switch method {
	case "none", "plain":
		return shadowsocks.NewNone(), nil
	}
	if !ssSupportedMethods[method] {
		return nil, fmt.Errorf("unsupported shadowsocks method %q (supported: none/plain, aes-128/192/256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305, 2022-blake3-aes-128/256-gcm, 2022-blake3-chacha20-poly1305)", method)
	}
	if strings.HasPrefix(method, "2022-") {
		return newSSMethod2022(method, password)
	}
	return shadowaead.New(method, nil, password)
}

// newSSMethod2022 构建 AEAD-2022 的 Method。2022 的 key 语义与经典 AEAD 不同:
// 不是密码派生,而是 base64 编码的二进制 PSK(长度 16/32 字节),多用户时多个
// PSK 用 : 连接。sing 的 shadowaead_2022.NewWithPassword 只认带 padding 的
// StdEncoding,这里额外兼容不带 padding 的变体(ss-android 导出可能不带 =)。
func newSSMethod2022(method, password string) (shadowsocks.Method, error) {
	if password == "" {
		return nil, fmt.Errorf("shadowsocks-2022 method %q requires a base64 key", method)
	}
	parts := strings.Split(password, ":")
	pskList := make([][]byte, 0, len(parts))
	for _, part := range parts {
		kb, err := decodeBase64Key(part)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks-2022 key %q: %w", part, err)
		}
		pskList = append(pskList, kb)
	}
	return shadowaead_2022.New(method, pskList, nil)
}

// decodeBase64Key 依次尝试 Std / URL(带 padding)与 Raw 变体解码 base64 key。
func decodeBase64Key(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if kb, err := enc.DecodeString(s); err == nil {
			return kb, nil
		}
	}
	return nil, errors.New("invalid base64 key")
}

// parseSSUserinfo 解析 ss:// URL 的 userinfo(method:password)。
// 标准格式是 base64(无 padding,URL-safe)编码;也兼容明文 method:password。
func parseSSUserinfo(user *url.Userinfo) (method, password string, err error) {
	if user == nil {
		return "", "", errors.New("ss:// URL is missing method:password credentials")
	}
	// url.Parse 会把 userinfo 在第一个冒号处切成 username/password,后续冒号
	// 会被 percent-encode。用 Username()/Password() 取回(密码已解码,冒号保留)。
	username := user.Username()
	pw, hasPw := user.Password()
	raw := username
	if hasPw {
		raw = username + ":" + pw
	}
	// shadowsocks URI 规范:userinfo 为 base64 编码(通常无 padding)。纯 base64 不含
	// 冒号,hasPw 为 false,raw 即编码串;含冒号则视为明文 method:password。
	// 注意:解码结果必须含 ':'(即 method:password 结构)才算有效编码 —— 否则像
	// "none" 这种恰好是合法 base64 的明文方法名会被解码成乱码字节。
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if decoded, derr := enc.DecodeString(raw); derr == nil {
			if strings.IndexByte(string(decoded), ':') >= 0 {
				raw = string(decoded)
			}
			break
		}
	}
	i := strings.IndexByte(raw, ':')
	if i < 0 {
		// 无冒号:方法名本身(如 "none"),不需要密码。AEAD 方法缺密码时由
		// newSSMethod / shadowaead.New 报错。
		return raw, "", nil
	}
	method = raw[:i]
	password = raw[i+1:]
	if method == "" {
		return "", "", errors.New("ss:// credentials missing method")
	}
	return method, password, nil
}

// ssPluginBlocked 报告该 ss 上游是否配置了 SIP003 插件。SmartProxy 只解析插件
// 参数、不执行插件进程,带插件的上游无法正常建连。
func (p *Proxy) ssPluginBlocked() error {
	if p.Plugin == "" {
		return nil
	}
	return fmt.Errorf("ss proxy %q uses SIP003 plugin %q which SmartProxy does not execute (parse-only support); strip ?plugin=... from the URL to connect without the plugin", p.URL, p.Plugin)
}

// ssConnect 建立到目标 host:port 的 SS 加密隧道(TCP)。
func (p *Proxy) ssConnect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	if err := p.ssPluginBlocked(); err != nil {
		return nil, err
	}
	if p.ssMethod == nil {
		return nil, fmt.Errorf("ss proxy %q has no method", p.URL)
	}
	conn, err := p.dial(ctx) // TCP 连 SS 服务器(fwmark + keepalive)
	if err != nil {
		return nil, err
	}
	dest := M.ParseSocksaddrHostPort(targetHost, uint16(targetPort))
	ssConn, err := p.ssMethod.DialConn(conn, dest)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ss handshake to %s failed: %w", p.URL, err)
	}
	return ssConn, nil
}

// ssUDPAssociate 建一条到 SS 服务器的 UDP relay 会话,返回一个满足 SmartProxy
// 上游 UDP 契约(net.Conn + 收发完整 SOCKS5-UDP 帧)的连接。
func (p *Proxy) ssUDPAssociate(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	if err := p.ssPluginBlocked(); err != nil {
		return nil, err
	}
	if p.ssMethod == nil {
		return nil, fmt.Errorf("ss proxy %q has no method", p.URL)
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
	if err != nil {
		return nil, err
	}
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	slog.Debug("ss UDP relay established", "proxy", p.URL, "serverAddr", raddr)
	return &ssUDPConn{NetPacketConn: p.ssMethod.DialPacketConn(udpConn)}, nil
}

// ssUDPConn 把 sing-shadowsocks 的 UDP packet conn 适配成 SmartProxy 上游 UDP 契约:
//   - Write 收完整 SOCKS5-UDP 帧(RSV|FRAG|ATYP|DST.ADDR|DST.PORT|payload),解析出
//     目标地址后经 WritePacket 发送(SS 协议每包自带目标地址);
//   - Read 从 ReadPacket 拿到 payload + 来源目标,补上 SOCKS5 UDP 响应头后返回完整帧。
//
// 由于 sing 的 clientPacketConn 逐包携带 destination,单条 UDP 连接即可服务任意目标
// (与 SOCKS5 上游一个 UDP socket 服务多目标一致),因此可安全放进 UDP 复用池。
type ssUDPConn struct {
	N.NetPacketConn
}

// Write 入参是完整 SOCKS5-UDP 帧;返回 len(b) 表示整帧已处理。
func (c *ssUDPConn) Write(b []byte) (int, error) {
	host, port, payload, err := parseSOCKS5UDPFrame(b)
	if err != nil {
		return 0, err
	}
	dest := M.ParseSocksaddrHostPort(host, uint16(port))
	// 按具体 packet conn 声明的 headroom 预留加密头与尾部标签:经典 AEAD 是
	// salt+addr 头 + 16B tag;2022 额外含 session/padding 头(可到 ~900B)。容量
	// 不足时 WritePacket 内部 ExtendHeader/Seal 会 panic。
	front := N.CalculateFrontHeadroom(c.NetPacketConn)
	if _, ok := c.NetPacketConn.(N.FrontHeadroom); !ok {
		// nonePacketConn 只实现废弃的 Headroom(),不实现 FrontHeadroom,Calculate 返回 0;
		// 它 WritePacket 时还会 ExtendHeader 一个地址头,补 MaxSocksaddrLength 保底。
		front = M.MaxSocksaddrLength
	}
	rear := N.CalculateRearHeadroom(c.NetPacketConn)
	buff := buf.NewSize(front + len(payload) + rear)
	buff.Resize(front, 0)
	if _, err := buff.Write(payload); err != nil {
		buff.Release()
		return 0, err
	}
	if err := c.WritePacket(buff, dest); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read 返回完整 SOCKS5-UDP 帧(SOCKS5 响应头 + 原始 payload)。
func (c *ssUDPConn) Read(b []byte) (int, error) {
	buff := buf.NewSize(65535)
	dest, err := c.ReadPacket(buff)
	if err != nil {
		buff.Release()
		return 0, err
	}
	payload := buff.Bytes()
	hdr, herr := encodeSocks5UDPHeader(dest)
	if herr != nil {
		buff.Release()
		return 0, herr
	}
	if len(b) < len(hdr) {
		buff.Release()
		return 0, io.ErrShortBuffer
	}
	n := copy(b[len(hdr):], payload)
	copy(b, hdr)
	buff.Release()
	return len(hdr) + n, nil
}

// RemoteAddr 上游侧没有可用的远程地址信息,返回 SS 服务器地址。
func (c *ssUDPConn) RemoteAddr() net.Addr {
	return c.LocalAddr()
}

// ProbeTCP ss UDP 无 TCP 控制信道,视为始终健康(TTL 淘汰兜底)。
func (c *ssUDPConn) ProbeTCP() error {
	return nil
}

// parseSOCKS5UDPFrame 解析 SOCKS5 UDP 帧,返回目标 host、port 与 payload。
func parseSOCKS5UDPFrame(frame []byte) (host string, port int, payload []byte, err error) {
	if len(frame) < 4 {
		return "", 0, nil, errors.New("SOCKS5 UDP frame too short")
	}
	if frame[2] != 0 { // FRAG
		return "", 0, nil, errors.New("SOCKS5 UDP fragmentation not supported")
	}
	atyp := frame[3]
	var headerLen int
	switch atyp {
	case 0x01:
		if len(frame) < 10 {
			return "", 0, nil, errors.New("short SOCKS5 UDP IPv4 frame")
		}
		host = net.IP(frame[4:8]).String()
		headerLen = 4 + 4
	case 0x04:
		if len(frame) < 22 {
			return "", 0, nil, errors.New("short SOCKS5 UDP IPv6 frame")
		}
		host = net.IP(frame[4:20]).String()
		headerLen = 4 + 16
	case 0x03:
		if len(frame) < 5 {
			return "", 0, nil, errors.New("short SOCKS5 UDP domain frame")
		}
		domainLen := int(frame[4])
		if len(frame) < 5+domainLen+2 {
			return "", 0, nil, errors.New("truncated SOCKS5 UDP domain frame")
		}
		host = string(frame[5 : 5+domainLen])
		headerLen = 4 + 1 + domainLen
	default:
		return "", 0, nil, fmt.Errorf("unsupported SOCKS5 address type: %d", atyp)
	}
	port = int(binary.BigEndian.Uint16(frame[headerLen : headerLen+2]))
	return host, port, frame[headerLen+2:], nil
}

// encodeSocks5UDPHeader 用 SS 返回的目标地址构造 SOCKS5 UDP 响应头(RSV|FRAG|ATYP|ADDR|PORT)。
func encodeSocks5UDPHeader(dest M.Socksaddr) ([]byte, error) {
	host := dest.Fqdn
	if host == "" {
		host = dest.Addr.String()
	}
	addr := encodeSocks5Addr(host, int(dest.Port))
	hdr := make([]byte, 3, 3+len(addr))
	hdr[0], hdr[1], hdr[2] = 0, 0, 0 // RSV, RSV, FRAG
	return append(hdr, addr...), nil
}

package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"smartproxy/internal/fwmark"
)

const proxyDialTimeout = 10 * time.Second

type ProxyScheme string

const (
	SchemeSOCKS5  ProxyScheme = "socks5"
	SchemeSOCKS5H ProxyScheme = "socks5h"
	SchemeSOCKS4  ProxyScheme = "socks4"
	SchemeHTTP    ProxyScheme = "http"
	SchemeHTTPS   ProxyScheme = "https"
	// SchemeSS 直接以 shadowsocks 协议连接远程 SS 服务器(经典 AEAD 加密,
	// 见 internal/upstream/ss.go)。URL 形如 ss://base64(method:password)@host:port,
	// 也兼容明文 ss://method:password@host:port。
	SchemeSS ProxyScheme = "ss"
)

type Proxy struct {
	URL      string
	Scheme   ProxyScheme
	Host     string
	Port     int
	Username string
	Password string
	// UDPAddr 可选:裸 UDP relay 地址(用于 shadowsocks-android 这类 "SOCKS5 只做 TCP、
	// UDP 由同/异端口的独立 udp_only 实例服务" 的上游)。语义:
	//   空          -> 默认走标准 UDP ASSOCIATE;被 rep=0x07(CommandNotSupported)拒绝时自动兜底到 Host:Port
	//   "1080"      -> 强制裸 UDP,地址用 Host:1080
	//   "host:port" -> 强制裸 UDP,直接用该地址(host 可为空,如 ":1080" 表示 Host:1080)
	UDPAddr string
	health  ProxyHealth

	// ssMethod 是 ss:// scheme 的加密实现(经典 AEAD),由 NewProxy 在解析
	// method:password 时构建一次;Method 不可变,可安全并发使用。
	ssMethod shadowsocks.Method
}

// SupportsUDP 报告该上游是否支持 UDP(通过 UDPProxyConn 或 ss UDP relay)。
func (p *Proxy) SupportsUDP() bool {
	switch p.Scheme {
	case SchemeSOCKS5, SchemeSOCKS5H, SchemeSS:
		return true
	}
	return false
}

func (p *Proxy) IsAvailable() bool {
	return p.health.IsAvailable()
}

func NewProxy(proxyURL string) (*Proxy, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}

	scheme := ProxyScheme(strings.ToLower(u.Scheme))
	port := 1080
	if u.Port() != "" {
		port = parsePort(u.Port())
	} else if scheme == SchemeHTTP || scheme == SchemeHTTPS {
		port = 80
	}

	p := &Proxy{
		URL:    proxyURL,
		Scheme: scheme,
		Host:   u.Hostname(),
		Port:   port,
	}
	if u.User != nil && scheme != SchemeSS {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}
	if scheme == SchemeSS {
		method, password, err := parseSSUserinfo(u.User)
		if err != nil {
			return nil, err
		}
		ssMethod, err := shadowaeadNew(method, password)
		if err != nil {
			return nil, fmt.Errorf("invalid ss:// credentials for %q: %w", proxyURL, err)
		}
		p.ssMethod = ssMethod
		p.Username, p.Password = method, password
	}
	slog.Info("upstream proxy loaded", "url", proxyURL)
	return p, nil
}

func parsePort(s string) int {
	var port int
	fmt.Sscanf(s, "%d", &port)
	return port
}

// SetUDPAddr 校验并设置裸 UDP relay 地址。格式:纯端口("1080")或 host:port("127.0.0.1:1080"、":1080")。
func (p *Proxy) SetUDPAddr(s string) error {
	if s == "" {
		p.UDPAddr = ""
		return nil
	}
	if _, port, err := net.SplitHostPort(s); err == nil {
		if pnum, perr := strconv.Atoi(port); perr != nil || pnum <= 0 || pnum > 65535 {
			return fmt.Errorf("invalid udp_addr %q: invalid port %q", s, port)
		}
		p.UDPAddr = s
		return nil
	}
	if port, err := strconv.Atoi(s); err == nil && port > 0 && port <= 65535 {
		p.UDPAddr = s
		return nil
	}
	return fmt.Errorf("invalid udp_addr %q: expected a port or host:port", s)
}

func (p *Proxy) Connect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	switch p.Scheme {
	case SchemeSOCKS5, SchemeSOCKS5H:
		return p.socks5Connect(ctx, targetHost, targetPort)
	case SchemeHTTP, SchemeHTTPS:
		return p.httpConnect(ctx, targetHost, targetPort)
	case SchemeSOCKS4:
		return p.socks4Connect(ctx, targetHost, targetPort)
	case SchemeSS:
		return p.ssConnect(ctx, targetHost, targetPort)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", p.Scheme)
	}
}

func (p *Proxy) UDPAssociate(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	switch p.Scheme {
	case SchemeSOCKS5, SchemeSOCKS5H:
		return p.socks5UDPAssociate(ctx, targetHost, targetPort)
	case SchemeSS:
		return p.ssUDPAssociate(ctx, targetHost, targetPort)
	default:
		return nil, fmt.Errorf("UDP not supported for %s", p.Scheme)
	}
}

func (p *Proxy) socks5Connect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := p.socks5Handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	addr := encodeSocks5Addr(targetHost, targetPort)
	req := make([]byte, 3, 3+len(addr))
	req[0] = 0x05
	req[1] = 0x01
	req[2] = 0x00
	req = append(req, addr...)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed: rep=%d", resp[1])
	}
	if err := skipSOCKS5Addr(conn, resp[3]); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// rawUDPAssociate 跳过 SOCKS5 握手,把上游直接当裸 UDP relay 使用。
// 依赖上游的 UDP 端口上有一个 "不校验来源、不要求 ASSOCIATE" 的 UDP relay
// (如 shadowsocks-android 的 udp_only 兜底实例),它读到带 SOCKS5 UDP 头的帧就会转发。
func (p *Proxy) rawUDPAssociate(raddr *net.UDPAddr) (*UDPProxyConn, error) {
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	slog.Debug("raw UDP relay established", "proxy", p.Host, "remoteAddr", raddr)
	return &UDPProxyConn{UDPConn: udpConn}, nil
}

// resolveUDPAddr 把 udp_addr 解析成具体地址:纯端口 -> 上游 Host + 端口;host:port -> 直接使用。
// 仅在 udp_addr 非空时调用。
func (p *Proxy) resolveUDPAddr() (*net.UDPAddr, error) {
	if p.UDPAddr == "" {
		return nil, nil
	}
	if host, port, err := net.SplitHostPort(p.UDPAddr); err == nil {
		if host == "" {
			host = p.Host
		}
		return net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	}
	if port, err := strconv.Atoi(p.UDPAddr); err == nil && port > 0 && port <= 65535 {
		return net.ResolveUDPAddr("udp", net.JoinHostPort(p.Host, strconv.Itoa(port)))
	}
	// SetUDPAddr 已做格式校验,这里兜底防御
	return nil, fmt.Errorf("invalid udp_addr %q", p.UDPAddr)
}

func (p *Proxy) socks5UDPAssociate(ctx context.Context, targetHost string, targetPort int) (*UDPProxyConn, error) {
	// 显式配置 udp_addr -> 强制裸 UDP,跳过握手
	if p.UDPAddr != "" {
		raddr, err := p.resolveUDPAddr()
		if err != nil {
			return nil, err
		}
		return p.rawUDPAssociate(raddr)
	}

	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := p.socks5Handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		conn.Close()
		// rep=0x07 (CommandNotSupported):上游明确不做 SOCKS5 UDP,但同端口很可能有
		// 配套的裸 UDP relay(如 shadowsocks-android tcp_only 主实例 + udp_only 兜底实例)。
		// 自动兜底为裸 UDP,并打警告日志便于排查(裸 UDP 是 fire-and-forget,目标无监听会静默丢包)。
		if resp[1] == 0x07 {
			slog.Warn("UDP ASSOCIATE rejected (rep=0x07), falling back to raw UDP relay",
				"proxy", p.Host, "udpAddr", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
			raddr, rerr := net.ResolveUDPAddr("udp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
			if rerr != nil {
				return nil, rerr
			}
			return p.rawUDPAssociate(raddr)
		}
		return nil, fmt.Errorf("UDP ASSOCIATE failed: rep=%d", resp[1])
	}
	bndAddr, bndPort, err := readSOCKS5BindAddr(conn, resp[3])
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})

	if bndAddr == "0.0.0.0" || bndAddr == "::" || bndAddr == "" || bndAddr == "[::]" {
		bndAddr = p.Host
	}

	slog.Debug("UDP ASSOCIATE response",
		"proxy", p.Host, "bindAddr", bndAddr, "bindPort", bndPort,
		"target", fmt.Sprintf("%s:%d", targetHost, targetPort))

	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bndAddr, fmt.Sprintf("%d", bndPort)))
	if err != nil {
		conn.Close()
		return nil, err
	}
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		slog.Error("UDP ASSOCIATE dial failed", "proxy", p.Host, "bindAddr", raddr, "error", err)
		conn.Close()
		return nil, err
	}
	slog.Debug("UDP ASSOCIATE established",
		"proxy", p.Host, "localAddr", udpConn.LocalAddr(), "remoteAddr", raddr)
	return &UDPProxyConn{UDPConn: udpConn, tcpConn: conn}, nil
}

func (p *Proxy) socks5Handshake(rw io.ReadWriter) error {
	methods := []byte{0x00}
	if p.Username != "" && p.Password != "" {
		methods = append(methods, 0x02)
	}
	authReq := []byte{0x05, byte(len(methods))}
	authReq = append(authReq, methods...)
	if _, err := rw.Write(authReq); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(rw, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] == 0xFF {
		return errors.New("SOCKS5 handshake failed")
	}
	if buf[1] == 0x02 {
		if p.Username == "" || p.Password == "" {
			return errors.New("SOCKS5 auth required but no credentials")
		}
		authReq := []byte{1, byte(len(p.Username))}
		authReq = append(authReq, []byte(p.Username)...)
		authReq = append(authReq, byte(len(p.Password)))
		authReq = append(authReq, []byte(p.Password)...)
		if _, err := rw.Write(authReq); err != nil {
			return err
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(rw, authResp); err != nil {
			return err
		}
		if authResp[1] != 0 {
			return errors.New("SOCKS5 authentication failed")
		}
	}
	return nil
}

func encodeSocks5Addr(host string, port int) []byte {
	ip := net.ParseIP(host)
	if ip == nil {
		domain := []byte(host)
		buf := make([]byte, 4+len(domain))
		buf[0] = 0x03
		buf[1] = byte(len(domain))
		copy(buf[2:], domain)
		binary.BigEndian.PutUint16(buf[2+len(domain):], uint16(port))
		return buf
	}
	if ip4 := ip.To4(); ip4 != nil {
		buf := make([]byte, 7)
		buf[0] = 0x01
		copy(buf[1:], ip4)
		binary.BigEndian.PutUint16(buf[5:], uint16(port))
		return buf
	}
	buf := make([]byte, 19)
	buf[0] = 0x04
	copy(buf[1:], ip.To16())
	binary.BigEndian.PutUint16(buf[17:], uint16(port))
	return buf
}

func skipSOCKS5Addr(r io.Reader, atyp byte) error {
	switch atyp {
	case 0x01:
		_, err := io.ReadFull(r, make([]byte, 4+2))
		return err
	case 0x03:
		lenB := make([]byte, 1)
		if _, err := io.ReadFull(r, lenB); err != nil {
			return err
		}
		_, err := io.ReadFull(r, make([]byte, int(lenB[0])+2))
		return err
	case 0x04:
		_, err := io.ReadFull(r, make([]byte, 16+2))
		return err
	default:
		return fmt.Errorf("unsupported address type: %d", atyp)
	}
}

func readSOCKS5BindAddr(r io.Reader, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case 0x03:
		lenB := make([]byte, 1)
		if _, err := io.ReadFull(r, lenB); err != nil {
			return "", 0, err
		}
		buf := make([]byte, int(lenB[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(portBuf)), nil
}

func (p *Proxy) dial(ctx context.Context) (net.Conn, error) {
	addr := net.JoinHostPort(p.Host, fmt.Sprintf("%d", p.Port))
	d := net.Dialer{Timeout: proxyDialTimeout, Control: fwmark.Control}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(30 * time.Second)
		tcp.SetNoDelay(true)
	}
	return conn, nil
}

func (p *Proxy) httpConnect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	if p.Scheme == SchemeHTTPS {
		tlsCfg := &tls.Config{ServerName: p.Host}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	// net.JoinHostPort brackets IPv6 literals (e.g. [2001:db8::1]:443);
	// a raw fmt.Sprintf("%s:%d", host, port) would produce a malformed request-target.
	target := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if p.Username != "" && p.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			conn.Close()
			return nil, err
		}
		buf = append(buf, tmp[:n]...)
		if strings.Contains(string(buf), "\r\n\r\n") {
			break
		}
		if len(buf) > 65536 {
			conn.Close()
			return nil, fmt.Errorf("HTTP proxy response headers too large")
		}
	}
	statusLine := strings.SplitN(string(buf), "\r\n", 2)[0]
	parts := strings.Fields(statusLine)
	if len(parts) < 2 {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy returned malformed status line: %q", statusLine)
	}
	if parts[1] != "200" {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy returned %s", parts[1])
	}
	return conn, nil
}

func (p *Proxy) socks4Connect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	targetIP, err := resolveIPv4(ctx, targetHost)
	if err != nil {
		conn.Close()
		return nil, err
	}
	userID := p.Username
	// make([]byte, 9+len(userID)) is zero-initialized, so the null terminator
	// after USERID is already in place (byte at index 8+len(userID)).
	req := make([]byte, 9+len(userID))
	req[0] = 0x04
	req[1] = 0x01
	binary.BigEndian.PutUint16(req[2:], uint16(targetPort))
	copy(req[4:8], targetIP.To4())
	copy(req[8:], userID)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x5a {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 connect failed: code=%d", resp[1])
	}
	return conn, nil
}

func resolveIPv4(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	addr, err := netip.ParseAddr(host)
	if err == nil {
		if addr.Is4() {
			a := addr.As4()
			return net.IP(a[:]), nil
		}
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no IPv4 address for %s", host)
	}
	a := addrs[0].As4()
	return net.IP(a[:]), nil
}

type UDPProxyConn struct {
	*net.UDPConn
	tcpConn net.Conn
}

func (u *UDPProxyConn) Close() error {
	if u.tcpConn != nil {
		u.tcpConn.Close()
	}
	return u.UDPConn.Close()
}

// ProbeTCP 供 UDP 复用池验证连接是否仍可用。SOCKS5 UDP ASSOCIATE 的 TCP 控制信道
// 做 5ms 快速探测:读超时 = 连接正常(控制信道本不该有数据);读到数据或出错 = 已损坏。
// 裸 UDP / ss UDP 无控制信道(tcpConn 为 nil),直接视为健康。
func (u *UDPProxyConn) ProbeTCP() error {
	if u.tcpConn == nil {
		return nil
	}
	u.tcpConn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	_, probeErr := u.tcpConn.Read(make([]byte, 1))
	if probeErr != nil {
		if netErr, ok := probeErr.(net.Error); ok && netErr.Timeout() {
			u.UDPConn.SetDeadline(time.Time{})
			u.tcpConn.SetDeadline(time.Time{})
			return nil
		}
		return probeErr
	}
	return errors.New("unexpected data on UDP ASSOCIATE control channel")
}

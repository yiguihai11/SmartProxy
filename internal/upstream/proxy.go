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
	// SchemeSS connects to the remote SS server directly with the shadowsocks protocol
	// (classic AEAD encryption, see internal/upstream/ss.go). The URL looks like
	// ss://base64(method:password)@host:port, and plaintext ss://method:password@host:port is also accepted.
	SchemeSS ProxyScheme = "ss"
)

// Mode values for Proxy.Mode, the same three-state status marker shadowsocks uses for
// its sslocal mode. An empty Mode means ModeTCPAndUDP (the default).
const (
	ModeTCPAndUDP = "tcp_and_udp"
	ModeTCPOnly   = "tcp_only"
	ModeUDPOnly   = "udp_only"
)

type Proxy struct {
	URL      string
	Scheme   ProxyScheme
	Host     string
	Port     int
	Username string
	Password string
	// Plugin is the ?plugin= parameter of an ss:// URL (SIP003, ss-android export format
	// id;key=val;key=val). SmartProxy ships built-in obfs-local (http/tls, see obfs.go)
	// and v2ray-plugin/xray-plugin (all 5 Android modes of websocket/grpc/quic, see
	// v2ray.go); on TCP connect it wraps the matching transport under the SS encryption layer, and unknown plugins return a clear error.
	Plugin string
	// Mode is a status marker for the upstream's capabilities, matching shadowsocks's
	// mode: "tcp_and_udp" (default), "tcp_only", "udp_only".
	//   tcp_and_udp: both TCP and UDP; UDP tries the standard SOCKS5 UDP ASSOCIATE and
	//     falls back to a raw UDP relay on its own host:port if that fails.
	//   tcp_only:    TCP only, never used for UDP.
	//   udp_only:    no TCP listener; UDP goes straight to a raw UDP relay on host:port.
	Mode   string
	health ProxyHealth

	// ssMethod is the encryption implementation for the ss:// scheme (classic AEAD or
	// none/plain), built once by NewProxy when parsing method:password; Method is immutable and safe for concurrent use.
	ssMethod shadowsocks.Method
}

// ModeName returns the effective mode, defaulting an empty Mode to tcp_and_udp.
func (p *Proxy) ModeName() string {
	if p.Mode == "" {
		return ModeTCPAndUDP
	}
	return p.Mode
}

// IsUDPOnly reports whether the upstream only relays UDP (no TCP listener).
func (p *Proxy) IsUDPOnly() bool { return p.Mode == ModeUDPOnly }

// IsTCPOnly reports whether the upstream only relays TCP (never UDP).
func (p *Proxy) IsTCPOnly() bool { return p.Mode == ModeTCPOnly }

// SupportsUDP reports whether this upstream can relay UDP (via UDPProxyConn or the ss UDP
// relay). A tcp_only upstream does not; an empty mode means tcp_and_udp and does.
func (p *Proxy) SupportsUDP() bool {
	if p.IsTCPOnly() {
		return false
	}
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
		ssMethod, err := newSSMethod(method, password)
		if err != nil {
			return nil, fmt.Errorf("invalid ss:// credentials for %q: %w", proxyURL, err)
		}
		p.ssMethod = ssMethod
		p.Username, p.Password = method, password
		// SIP003 plugin options: parsed and kept; at ssConnect time ssPlugin decides whether to run (built-in obfs-local) or error out.
		if plugin := u.Query().Get("plugin"); plugin != "" {
			p.Plugin = plugin
		}
	}
	slog.Info("upstream proxy loaded", "url", proxyURL)
	return p, nil
}

func parsePort(s string) int {
	var port int
	fmt.Sscanf(s, "%d", &port)
	return port
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
	if p.IsTCPOnly() {
		return nil, fmt.Errorf("proxy %s is tcp_only, cannot relay UDP", p.Host)
	}
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

// rawUDPAssociate skips the SOCKS5 handshake and uses the upstream directly as a raw
// UDP relay. It relies on a UDP relay on the upstream's UDP port that "does not check
// the source and does not require ASSOCIATE" (e.g. shadowsocks-android's udp_only fallback instance), which forwards any frame carrying a SOCKS5 UDP header.
func (p *Proxy) rawUDPAssociate(raddr *net.UDPAddr) (*UDPProxyConn, error) {
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	slog.Debug("raw UDP relay established", "proxy", p.Host, "remoteAddr", raddr)
	return &UDPProxyConn{UDPConn: udpConn}, nil
}

// rawFallback tries a raw UDP relay at the upstream's own host:port after the standard
// SOCKS5 UDP ASSOCIATE flow failed (dial, handshake, request, any non-zero rep including
// 0x07 CommandNotSupported, or a bad bind reply). Raw UDP is fire-and-forget — packets drop
// silently if no relay listens there — so a failure here means the node has no working UDP
// relay at all.
func (p *Proxy) rawFallback(cause error) (*UDPProxyConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
	if err != nil {
		return nil, fmt.Errorf("UDP ASSOCIATE failed (%v) and raw UDP relay unreachable: %w", cause, err)
	}
	slog.Warn("UDP ASSOCIATE failed, falling back to raw UDP relay",
		"proxy", p.Host, "udpAddr", raddr, "cause", cause)
	conn, err := p.rawUDPAssociate(raddr)
	if err != nil {
		return nil, fmt.Errorf("UDP ASSOCIATE failed (%v) and raw UDP relay failed: %w", cause, err)
	}
	return conn, nil
}

func (p *Proxy) socks5UDPAssociate(ctx context.Context, targetHost string, targetPort int) (*UDPProxyConn, error) {
	// A udp_only upstream has no TCP listener to handshake over — relay straight to its own
	// host:port as a raw UDP relay (the equivalent of shadowsocks-android's udp_only fallback instance).
	if p.IsUDPOnly() {
		raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
		if err != nil {
			return nil, err
		}
		return p.rawUDPAssociate(raddr)
	}

	conn, err := p.dial(ctx)
	if err != nil {
		return p.rawFallback(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := p.socks5Handshake(conn); err != nil {
		conn.Close()
		return p.rawFallback(err)
	}
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return p.rawFallback(err)
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return p.rawFallback(err)
	}
	if resp[1] != 0x00 {
		conn.Close()
		// Any rep, including 0x07 (CommandNotSupported): the upstream's SOCKS5 may serve TCP
		// only, but the same host:port usually hosts a matching raw UDP relay — fall back to it.
		return p.rawFallback(fmt.Errorf("UDP ASSOCIATE rejected: rep=%d", resp[1]))
	}
	bndAddr, bndPort, err := readSOCKS5BindAddr(conn, resp[3])
	if err != nil {
		conn.Close()
		return p.rawFallback(err)
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
		return p.rawFallback(err)
	}
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		slog.Error("UDP ASSOCIATE dial failed", "proxy", p.Host, "bindAddr", raddr, "error", err)
		conn.Close()
		return p.rawFallback(err)
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

// ProbeTCP lets the UDP reuse pool verify a connection is still usable. The SOCKS5 UDP
// ASSOCIATE TCP control channel is probed with a 5ms quick read: read timeout = healthy
// (the control channel should never carry data); data read or error = broken. Raw UDP / ss UDP have no control channel (tcpConn is nil), so they are always considered healthy.
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

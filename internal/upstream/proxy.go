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
)

type Proxy struct {
	URL      string
	Scheme   ProxyScheme
	Host     string
	Port     int
	Username string
	Password string
	health   ProxyHealth
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
	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
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
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", p.Scheme)
	}
}

func (p *Proxy) UDPAssociate(ctx context.Context, targetHost string, targetPort int) (*UDPProxyConn, error) {
	if p.Scheme != SchemeSOCKS5 && p.Scheme != SchemeSOCKS5H {
		return nil, fmt.Errorf("UDP ASSOCIATE not supported for %s", p.Scheme)
	}
	return p.socks5UDPAssociate(ctx, targetHost, targetPort)
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

	addr := p.encodeSOCKS5Addr(targetHost, targetPort)
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

func (p *Proxy) socks5UDPAssociate(ctx context.Context, targetHost string, targetPort int) (*UDPProxyConn, error) {
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

func (p *Proxy) encodeSOCKS5Addr(host string, port int) []byte {
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

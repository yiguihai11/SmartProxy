package upstream

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"smartproxy/internal/config"
)

func TestNewProxy_SOCKS5(t *testing.T) {
	p, err := NewProxy("socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if p.Scheme != SchemeSOCKS5 {
		t.Errorf("Scheme = %s, want socks5", p.Scheme)
	}
	if p.Host != "127.0.0.1" {
		t.Errorf("Host = %s, want 127.0.0.1", p.Host)
	}
	if p.Port != 1080 {
		t.Errorf("Port = %d, want 1080", p.Port)
	}
	if p.Username != "" {
		t.Errorf("Username = %s, want empty", p.Username)
	}
}

func TestNewProxy_SOCKS5H(t *testing.T) {
	p, err := NewProxy("socks5h://proxy.example.com:2080")
	if err != nil {
		t.Fatal(err)
	}
	if p.Scheme != SchemeSOCKS5H {
		t.Errorf("Scheme = %s, want socks5h", p.Scheme)
	}
	if p.Host != "proxy.example.com" {
		t.Errorf("Host = %s, want proxy.example.com", p.Host)
	}
	if p.Port != 2080 {
		t.Errorf("Port = %d, want 2080", p.Port)
	}
}

func TestNewProxy_SOCKS5_DefaultPort(t *testing.T) {
	p, err := NewProxy("socks5://10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Port != 1080 {
		t.Errorf("Port = %d, want 1080 (default)", p.Port)
	}
}

func TestNewProxy_HTTP(t *testing.T) {
	p, err := NewProxy("http://proxy:8080")
	if err != nil {
		t.Fatal(err)
	}
	if p.Scheme != SchemeHTTP {
		t.Errorf("Scheme = %s, want http", p.Scheme)
	}
	if p.Port != 8080 {
		t.Errorf("Port = %d, want 8080", p.Port)
	}
}

func TestNewProxy_HTTP_DefaultPort(t *testing.T) {
	p, err := NewProxy("http://proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if p.Port != 80 {
		t.Errorf("Port = %d, want 80 (default for HTTP)", p.Port)
	}
}

func TestNewProxy_HTTPS_DefaultPort(t *testing.T) {
	p, err := NewProxy("https://proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if p.Scheme != SchemeHTTPS {
		t.Errorf("Scheme = %s, want https", p.Scheme)
	}
	if p.Port != 80 {
		t.Errorf("Port = %d, want 80 (default for HTTPS)", p.Port)
	}
}

func TestNewProxy_SOCKS4(t *testing.T) {
	p, err := NewProxy("socks4://10.0.0.1:9050")
	if err != nil {
		t.Fatal(err)
	}
	if p.Scheme != SchemeSOCKS4 {
		t.Errorf("Scheme = %s, want socks4", p.Scheme)
	}
	if p.Port != 9050 {
		t.Errorf("Port = %d, want 9050", p.Port)
	}
}

func TestNewProxy_SOCKS4_DefaultPort(t *testing.T) {
	p, err := NewProxy("socks4://10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Port != 1080 {
		t.Errorf("Port = %d, want 1080 (default)", p.Port)
	}
}

func TestNewProxy_WithAuth(t *testing.T) {
	p, err := NewProxy("socks5://user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if p.Username != "user" {
		t.Errorf("Username = %s, want user", p.Username)
	}
	if p.Password != "pass" {
		t.Errorf("Password = %s, want pass", p.Password)
	}
}

func TestNewProxy_URLCaseInsensitive(t *testing.T) {
	tests := []string{
		"SOCKS5://127.0.0.1:1080",
		"Http://proxy:3128",
		"Socks4://10.0.0.1",
	}
	for _, url := range tests {
		p, err := NewProxy(url)
		if err != nil {
			t.Errorf("NewProxy(%q) error: %v", url, err)
			continue
		}
		if p.Scheme != ProxyScheme(strings.ToLower(strings.Split(url, "://")[0])) {
			t.Errorf("NewProxy(%q) scheme = %s", url, p.Scheme)
		}
	}
}

func TestNewProxy_InvalidURL(t *testing.T) {
	_, err := NewProxy("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"1080", 1080},
		{"0", 0},
		{"65535", 65535},
		{"invalid", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := parsePort(tt.input)
		if got != tt.want {
			t.Errorf("parsePort(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestEncodeSOCKS5Addr_IPv4(t *testing.T) {
	result := encodeSocks5Addr("192.168.1.1", 443)

	if len(result) != 7 {
		t.Fatalf("len = %d, want 7", len(result))
	}
	if result[0] != 0x01 {
		t.Errorf("ATYP = %d, want 1", result[0])
	}
	ip := net.IP(result[1:5])
	if ip.String() != "192.168.1.1" {
		t.Errorf("IP = %s, want 192.168.1.1", ip)
	}
	if port := binary.BigEndian.Uint16(result[5:7]); port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
}

func TestEncodeSOCKS5Addr_IPv6(t *testing.T) {
	result := encodeSocks5Addr("::1", 80)
	if len(result) != 19 {
		t.Fatalf("len = %d, want 19", len(result))
	}
	if result[0] != 0x04 {
		t.Errorf("ATYP = %d, want 4", result[0])
	}
	if port := binary.BigEndian.Uint16(result[17:19]); port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
}

func TestEncodeSOCKS5Addr_Domain(t *testing.T) {
	result := encodeSocks5Addr("example.com", 8080)
	if result[0] != 0x03 {
		t.Errorf("ATYP = %d, want 3", result[0])
	}
	domainLen := int(result[1])
	if domainLen != len("example.com") {
		t.Errorf("domainLen = %d, want %d", domainLen, len("example.com"))
	}
	domain := string(result[2 : 2+domainLen])
	if domain != "example.com" {
		t.Errorf("domain = %s, want example.com", domain)
	}
	port := binary.BigEndian.Uint16(result[2+domainLen:])
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
}

func TestUDPProxyConn_Close(t *testing.T) {

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}

	u := &UDPProxyConn{UDPConn: udpConn, tcpConn: nil}
	if err := u.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}
}

func TestUDPProxyConn_Close_WithTCP(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}

	_, tcpConn := net.Pipe()

	u := &UDPProxyConn{UDPConn: udpConn, tcpConn: tcpConn}
	if err := u.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}
}

func TestUDPAssociate_UnsupportedScheme(t *testing.T) {
	tests := []struct {
		url string
		msg string
	}{
		{"socks4://127.0.0.1", "SOCKS4"},
		{"http://127.0.0.1:8080", "HTTP"},
	}
	for _, tt := range tests {
		p, err := NewProxy(tt.url)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.UDPAssociate(context.Background(), "example.com", 80)
		if err == nil {
			t.Errorf("%s: expected error for UDP ASSOCIATE", tt.msg)
		}
	}
}

// TestPluginNode_UDPDownDefault verifies an SS node with a SIP003 plugin defaults to UDP
// down — equivalent to the user manually disabling the UDP circuit. It is not hard TCP-only:
// the scheme stays UDP-probeable, and releasing the circuit (action=auto) re-enables UDP
// probing so a deployment that exposes the SS UDP port directly can come up.
func TestPluginNode_UDPDownDefault(t *testing.T) {
	p, err := NewProxy("ss://none:pass@127.0.0.1:80?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dupay.10010.com")
	if err != nil {
		t.Fatal(err)
	}
	// Scheme remains UDP-capable: the node can be UDP-probed once the user releases it.
	if !p.SchemeSupportsUDP() {
		t.Error("SS+plugin must stay scheme UDP-capable (probeable after manual release)")
	}
	// Default: UDP circuit manually disabled → effective tcp_only, capability none, UDP down.
	if !p.udpHealth.IsManuallyDisabled() {
		t.Error("plugin node's UDP circuit should default to manually disabled")
	}
	if p.IsUDPAvailable() {
		t.Error("plugin node's UDP should be down by default")
	}
	if got := p.EffectiveMode(); got != ModeTCPOnly {
		t.Errorf("EffectiveMode: got %q, want %q", got, ModeTCPOnly)
	}
	if got := p.UDPCapability(); got != UDPCapNone {
		t.Errorf("UDPCapability: got %q, want %q", got, UDPCapNone)
	}
	// UDPAssociate still works at the transport level: SS UDP dials straight to the server
	// port and succeeds fire-and-forget even with no listener — it is the circuit that gates
	// routing, not the transport call.
	if _, err := p.UDPAssociate(context.Background(), "example.com", 53); err != nil {
		t.Errorf("UDPAssociate should reach the direct UDP relay, got: %v", err)
	}

	// Plain SS (no plugin) defaults UDP up: automatic circuit, capability unknown until probed.
	p2, err := NewProxy("ss://none:pass@127.0.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
	if p2.udpHealth.IsManuallyDisabled() {
		t.Error("plain SS UDP circuit should default to automatic, not manual-down")
	}
	if !p2.SchemeSupportsUDP() {
		t.Error("plain SS must support UDP")
	}
	if got := p2.UDPCapability(); got != UDPCapUnknown {
		t.Errorf("plain SS UDPCapability: got %q, want %q", got, UDPCapUnknown)
	}
}

func TestConnect_UnsupportedScheme(t *testing.T) {
	p := &Proxy{Scheme: "unknown", Host: "127.0.0.1", Port: 1080}
	_, err := p.Connect(context.Background(), "example.com", 80)
	if err == nil {
		t.Error("expected error for unsupported scheme")
	}
}

func startSOCKS5Mock(t *testing.T) (addr string, done func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()

				buf := make([]byte, 256)
				n, err := conn.Read(buf)
				if err != nil || n < 3 {
					return
				}

				conn.Write([]byte{0x05, 0x00})

				buf = make([]byte, 256)
				n, err = conn.Read(buf)
				if err != nil || n < 4 {
					return
				}
				atyp := buf[3]

				switch atyp {
				case 0x01:
					if n < 10 {
						return
					}
				case 0x03:
					if n < 5 {
						return
					}
					domainLen := int(buf[4])
					need := 4 + 1 + domainLen + 2
					if n < need {
						io.ReadFull(conn, make([]byte, need-n))
					}
				case 0x04:
					if n < 22 {
						return
					}
				}

				conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}()
		}
	}()

	return ln.Addr().String(), func() {
		ln.Close()
		wg.Wait()
	}
}

func TestSOCKS5Connect_viaMock(t *testing.T) {
	addr, done := startSOCKS5Mock(t)
	defer done()

	host, portStr, _ := net.SplitHostPort(addr)
	port := parsePort(portStr)

	p := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   host,
		Port:   port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := p.Connect(ctx, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestSOCKS5Connect_WithAuth_viaMock(t *testing.T) {

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 258)
		n, err := io.ReadFull(conn, buf[:2])
		if err != nil || n < 2 || buf[0] != 0x05 {
			return
		}
		nmethods := int(buf[1])
		io.ReadFull(conn, make([]byte, nmethods))

		conn.Write([]byte{0x05, 0x02})

		auth := make([]byte, 512)
		authVer := make([]byte, 1)
		io.ReadFull(conn, authVer)
		ulenB := make([]byte, 1)
		io.ReadFull(conn, ulenB)
		io.ReadFull(conn, make([]byte, int(ulenB[0])))
		plenB := make([]byte, 1)
		io.ReadFull(conn, plenB)
		io.ReadFull(conn, make([]byte, int(plenB[0])))
		_ = auth

		conn.Write([]byte{0x01, 0x00})

		hdr := make([]byte, 4)
		io.ReadFull(conn, hdr)
		atyp := hdr[3]
		switch atyp {
		case 0x01:
			io.ReadFull(conn, make([]byte, 4+2))
		case 0x03:
			domLen := make([]byte, 1)
			io.ReadFull(conn, domLen)
			io.ReadFull(conn, make([]byte, int(domLen[0])+2))
		case 0x04:
			io.ReadFull(conn, make([]byte, 16+2))
		}

		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := parsePort(portStr)

	p := &Proxy{
		Scheme:   SchemeSOCKS5,
		Host:     host,
		Port:     port,
		Username: "testuser",
		Password: "testpass",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := p.Connect(ctx, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func startHTTPMock(t *testing.T) (addr string, done func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				if err != nil || n == 0 {
					return
				}

				req := string(buf[:n])
				_ = req

				conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			}()
		}
	}()

	return ln.Addr().String(), func() {
		ln.Close()
		wg.Wait()
	}
}

func TestHTTPConnect_viaMock(t *testing.T) {
	addr, done := startHTTPMock(t)
	defer done()

	host, portStr, _ := net.SplitHostPort(addr)
	port := parsePort(portStr)

	p := &Proxy{
		Scheme: SchemeHTTP,
		Host:   host,
		Port:   port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := p.Connect(ctx, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestHTTPConnect_WithAuth_viaMock(t *testing.T) {
	addr, done := startHTTPMock(t)
	defer done()

	host, portStr, _ := net.SplitHostPort(addr)
	port := parsePort(portStr)

	p := &Proxy{
		Scheme:   SchemeHTTP,
		Host:     host,
		Port:     port,
		Username: "user",
		Password: "pass",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := p.Connect(ctx, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func startSOCKS4Mock(t *testing.T) (addr string, done func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				resp := make([]byte, 8)
				n, err := io.ReadFull(conn, resp)
				if err != nil || n < 8 {
					return
				}

				if resp[0] != 0x04 {
					return
				}

				buf := make([]byte, 1)
				for {
					_, err := conn.Read(buf)
					if err != nil || buf[0] == 0 {
						break
					}
				}

				reply := make([]byte, 8)
				reply[0] = 0x00
				reply[1] = 0x5a

				conn.Write(reply)
			}()
		}
	}()

	return ln.Addr().String(), func() {
		ln.Close()
		wg.Wait()
	}
}

func TestSOCKS4Connect_viaMock(t *testing.T) {
	addr, done := startSOCKS4Mock(t)
	defer done()

	host, portStr, _ := net.SplitHostPort(addr)
	port := parsePort(portStr)

	p := &Proxy{
		Scheme:   SchemeSOCKS4,
		Host:     host,
		Port:     port,
		Username: "testuser",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := p.Connect(ctx, "127.0.0.1", 443)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestSOCKS4Connect_HostnameRequiresDNS(t *testing.T) {

	addr, done := startSOCKS4Mock(t)
	defer done()

	host, portStr, _ := net.SplitHostPort(addr)
	port := parsePort(portStr)

	p := &Proxy{
		Scheme: SchemeSOCKS4,
		Host:   host,
		Port:   port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := p.Connect(ctx, "localhost", 80)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestSOCKS5Handshake_NoAuth(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	p := &Proxy{}

	go func() {
		buf := make([]byte, 258)
		n, err := io.ReadFull(server, buf[:2])
		if err != nil || n < 2 || buf[0] != 0x05 {
			return
		}
		nmethods := int(buf[1])
		io.ReadFull(server, make([]byte, nmethods))

		server.Write([]byte{0x05, 0x00})
	}()

	if err := p.socks5Handshake(client); err != nil {
		t.Errorf("socks5Handshake failed: %v", err)
	}
}

func TestSOCKS5Handshake_AuthSuccess(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	p := &Proxy{
		Username: "user",
		Password: "pass",
	}

	go func() {
		buf := make([]byte, 258)
		n, err := io.ReadFull(server, buf[:2])
		if err != nil || n < 2 || buf[0] != 0x05 {
			return
		}
		nmethods := int(buf[1])
		io.ReadFull(server, make([]byte, nmethods))

		server.Write([]byte{0x05, 0x02})

		auth := make([]byte, 512)
		n, err = server.Read(auth)
		if err != nil || n < 5 {
			return
		}
		_ = n

		server.Write([]byte{0x01, 0x00})
	}()

	if err := p.socks5Handshake(client); err != nil {
		t.Errorf("socks5Handshake failed: %v", err)
	}
}

func TestSOCKS5Handshake_AuthRequiredButNoCreds(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	p := &Proxy{}

	go func() {
		buf := make([]byte, 258)
		n, err := io.ReadFull(server, buf[:2])
		if err != nil || n < 2 || buf[0] != 0x05 {
			return
		}
		nmethods := int(buf[1])
		io.ReadFull(server, make([]byte, nmethods))

		server.Write([]byte{0x05, 0x02})
	}()

	if err := p.socks5Handshake(client); err == nil {
		t.Error("expected auth required error, got nil")
	}
}

func TestSOCKS5Handshake_AuthFailed(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	p := &Proxy{
		Username: "user",
		Password: "wrong",
	}

	go func() {
		buf := make([]byte, 258)
		n, err := io.ReadFull(server, buf[:2])
		if err != nil || n < 2 || buf[0] != 0x05 {
			return
		}
		nmethods := int(buf[1])
		io.ReadFull(server, make([]byte, nmethods))

		server.Write([]byte{0x05, 0x02})

		auth := make([]byte, 512)
		n, err = server.Read(auth)
		if err != nil || n < 5 {
			return
		}
		server.Write([]byte{0x01, 0x01})
	}()

	if err := p.socks5Handshake(client); err == nil {
		t.Error("expected auth failure error, got nil")
	}
}

func TestSOCKS5Handshake_Rejected(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	p := &Proxy{}

	go func() {
		buf := make([]byte, 258)
		n, err := io.ReadFull(server, buf[:2])
		if err != nil || n < 2 || buf[0] != 0x05 {
			return
		}
		nmethods := int(buf[1])
		io.ReadFull(server, make([]byte, nmethods))

		server.Write([]byte{0x05, 0xFF})
	}()

	if err := p.socks5Handshake(client); err == nil {
		t.Error("expected handshake rejection error, got nil")
	}
}

func TestReadSOCKS5BindAddr_IPv4(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {

		payload := []byte{10, 0, 0, 1, 0x1f, 0x90}
		server.Write(payload)
	}()

	host, port, err := readSOCKS5BindAddr(client, 0x01)
	if err != nil {
		t.Fatal(err)
	}
	if host != "10.0.0.1" {
		t.Errorf("host = %s, want 10.0.0.1", host)
	}
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
}

func TestReadSOCKS5BindAddr_Domain(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		domain := []byte("proxy.local")
		payload := make([]byte, 1+len(domain)+2)
		payload[0] = byte(len(domain))
		copy(payload[1:], domain)
		binary.BigEndian.PutUint16(payload[1+len(domain):], 3128)
		server.Write(payload)
	}()

	host, port, err := readSOCKS5BindAddr(client, 0x03)
	if err != nil {
		t.Fatal(err)
	}
	if host != "proxy.local" {
		t.Errorf("host = %s, want proxy.local", host)
	}
	if port != 3128 {
		t.Errorf("port = %d, want 3128", port)
	}
}

func TestReadSOCKS5BindAddr_IPv6(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {

		payload := make([]byte, 18)
		payload[15] = 0x01
		binary.BigEndian.PutUint16(payload[16:], 53)
		server.Write(payload)
	}()

	host, port, err := readSOCKS5BindAddr(client, 0x04)
	if err != nil {
		t.Fatal(err)
	}
	if host != "::1" {
		t.Errorf("host = %s, want ::1", host)
	}
	if port != 53 {
		t.Errorf("port = %d, want 53", port)
	}
}

func TestSkipSOCKS5Addr_IPv4(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {

		server.Write(make([]byte, 6))
	}()

	if err := skipSOCKS5Addr(client, 0x01); err != nil {
		t.Errorf("skipSOCKS5Addr(IPv4): %v", err)
	}
}

func TestSkipSOCKS5Addr_Domain(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		payload := []byte{5, 'l', 'o', 'c', 'a', 'l', 0, 53}
		server.Write(payload)
	}()

	if err := skipSOCKS5Addr(client, 0x03); err != nil {
		t.Errorf("skipSOCKS5Addr(Domain): %v", err)
	}
}

func TestSkipSOCKS5Addr_IPv6(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		server.Write(make([]byte, 18))
	}()

	if err := skipSOCKS5Addr(client, 0x04); err != nil {
		t.Errorf("skipSOCKS5Addr(IPv6): %v", err)
	}
}

func TestSkipSOCKS5Addr_Unsupported(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	if err := skipSOCKS5Addr(client, 0x05); err == nil {
		t.Error("expected error for unsupported ATYP")
	}
}

func TestHTTPConnect_Non200Response(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		conn.Read(buf)

		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := parsePort(portStr)

	p := &Proxy{
		Scheme: SchemeHTTP,
		Host:   host,
		Port:   port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = p.Connect(ctx, "example.com", 443)
	if err == nil {
		t.Error("expected error for non-200 HTTP response")
	}
}

func TestResolveIPv4_Literal(t *testing.T) {
	ip, err := resolveIPv4(context.Background(), "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "192.168.1.1" {
		t.Errorf("got %s, want 192.168.1.1", ip)
	}
}

func TestResolveIPv4_NetIP(t *testing.T) {
	ip, err := resolveIPv4(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("got %s, want 127.0.0.1", ip)
	}
}

func TestResolveIPv4_InvalidReturnsError(t *testing.T) {
	_, err := resolveIPv4(context.Background(), "this-is-not-a-valid-hostname-xyz.invalid")
	if err == nil {
		t.Error("expected error for unresolvable hostname")
	}
}

func BenchmarkNewProxy(b *testing.B) {
	urls := []string{
		"socks5://127.0.0.1:1080",
		"http://proxy:8080",
		"socks4://10.0.0.1",
		"socks5://user:pass@host:1080",
	}
	b.ResetTimer()
	for b.Loop() {
		for _, u := range urls {
			NewProxy(u)
		}
	}
}

func BenchmarkEncodeSOCKS5Addr(b *testing.B) {
	tests := []struct {
		host string
		port int
	}{
		{"192.168.1.1", 443},
		{"example.com", 8080},
		{"::1", 80},
	}
	b.ResetTimer()
	for b.Loop() {
		for _, t := range tests {
			encodeSocks5Addr(t.host, t.port)
		}
	}
}

func TestSOCKS4Connect_RequestFormat(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	userID := "user123"
	errCh := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		expected := 9 + len(userID) // VN+CD+PORT+IP+USERID+\0
		buf := make([]byte, expected+1)
		if _, err := io.ReadFull(conn, buf[:expected]); err != nil {
			errCh <- err
			return
		}
		// A correct request must have NO bytes after the USERID terminator.
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := conn.Read(buf[expected:])
		if n > 0 {
			errCh <- fmt.Errorf("request has %d trailing byte(s); want exactly %d bytes", n, expected)
			return
		}
		if buf[0] != 0x04 || buf[1] != 0x01 {
			errCh <- fmt.Errorf("bad VN/CD: %x %x", buf[0], buf[1])
			return
		}
		if string(buf[8:8+len(userID)]) != userID {
			errCh <- fmt.Errorf("bad USERID: %q", string(buf[8:8+len(userID)]))
			return
		}
		if buf[8+len(userID)] != 0 {
			errCh <- fmt.Errorf("request not null-terminated")
			return
		}
		conn.Write([]byte{0x00, 0x5a, 0, 0, 0, 0, 0, 0})
		errCh <- nil
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p := &Proxy{Scheme: SchemeSOCKS4, Host: host, Port: parsePort(portStr), Username: userID}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := p.Connect(ctx, "127.0.0.1", 443)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPConnect_IPv6Target(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		req := string(buf[:n])
		if !strings.Contains(req, "CONNECT [::1]:443 HTTP/1.1") {
			errCh <- fmt.Errorf("CONNECT line not IPv6-bracketed: %q", strings.SplitN(req, "\r\n", 2)[0])
			return
		}
		if !strings.Contains(req, "Host: [::1]:443") {
			errCh <- fmt.Errorf("Host header not IPv6-bracketed: %q", strings.SplitN(req, "\r\n", 2)[0])
			return
		}
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		errCh <- nil
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p := &Proxy{Scheme: SchemeHTTP, Host: host, Port: parsePort(portStr)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := p.Connect(ctx, "::1", 443)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

// ---- raw UDP relay: udp_only auto-raw, ASSOCIATE-failure fallback ----

// makeSOCKS5UDPFrame builds a SOCKS5 UDP datagram (RSV|FRAG|ATYP|DST.ADDR|DST.PORT|data).
func makeSOCKS5UDPFrame(host string, port int, payload []byte) []byte {
	ip := net.ParseIP(host).To4()
	if ip == nil {
		f := []byte{0x00, 0x00, 0x00, 0x03, byte(len(host))}
		f = append(f, host...)
		f = append(f, byte(port>>8), byte(port))
		return append(f, payload...)
	}
	f := []byte{0x00, 0x00, 0x00, 0x01}
	f = append(f, ip...)
	f = append(f, byte(port>>8), byte(port))
	return append(f, payload...)
}

// startUDPEcho binds a UDP socket on IPv4 loopback that echoes every received datagram.
func startUDPEcho(t *testing.T) (*net.UDPConn, int) {
	return startUDPEchoOn(t, net.IPv4(127, 0, 0, 1))
}

// startUDPEchoOn binds a UDP socket on the given IP (IPv4 or IPv6 loopback) that echoes every
// received datagram.
func startUDPEchoOn(t *testing.T, ip net.IP) (*net.UDPConn, int) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], addr)
		}
	}()
	return pc, pc.LocalAddr().(*net.UDPAddr).Port
}

// TestUDPAssociate_UDPOnlyAutoRaw verifies that a node whose TCP circuit is down
// (auto-derived udp_only — no TCP listener here) relays raw UDP straight to its own
// host:port, never touching the TCP-based SOCKS5 ASSOCIATE path (which could not work
// anyway — the node has no TCP listener).
func TestUDPAssociate_UDPOnlyAutoRaw(t *testing.T) {
	echo, port := startUDPEcho(t)
	defer echo.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	p := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   "127.0.0.1",
		Port:   port, // UDP echo bound here; no TCP listener, so only the auto raw-UDP path can work
	}
	// TCP circuit down + UDP circuit up → effective udp_only → raw fast path.
	p.health.SetManualState(false)
	p.udpHealth.SetManualState(true)
	conn, err := p.UDPAssociate(ctx, "example.com", 53)
	if err != nil {
		t.Fatalf("UDPAssociate(udp_only) error: %v", err)
	}
	defer conn.Close()

	payload := []byte("ping-udp-only-auto")
	frame := makeSOCKS5UDPFrame("8.8.8.8", 53, payload)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write error: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if !bytes.Contains(buf[:n], payload) {
		t.Fatalf("echo mismatch: got %x, want contains %x", buf[:n], payload)
	}
}

// TestUDPAssociate_Rep7Fallback verifies the auto-fallback: when the upstream
// rejects SOCKS5 UDP ASSOCIATE with rep=0x07, a raw UDP relay to Host:Port is
// established and frames flow end-to-end.
func TestUDPAssociate_Rep7Fallback(t *testing.T) {
	// A UDP echo and a rep=0x07 SOCKS5 server bound to the SAME port.
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	port := echo.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], addr)
		}
	}()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// SOCKS5 handshake: no auth
				buf := make([]byte, 258)
				if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
					return
				}
				nmethods := int(buf[1])
				if _, err := io.ReadFull(c, buf[:nmethods]); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				// ASSOCIATE request (exactly 10 bytes: 0.0.0.0:0)
				req := make([]byte, 10)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				// reply rep=0x07 CommandNotSupported
				c.Write([]byte{0x05, 0x07, 0x00, 0x01})
			}(conn)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: port}
	conn, err := p.UDPAssociate(ctx, "example.com", 53)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := []byte("fallback-hello")
	frame := makeSOCKS5UDPFrame("8.8.8.8", 53, payload)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf[:n], payload) {
		t.Fatalf("echo mismatch: got %x, want contains %x", buf[:n], payload)
	}
}

// TestUDPAssociate_RawFallbackOnDialFailure verifies that the raw UDP relay is the
// fallback for ANY socks5UDPAssociate failure — here the TCP dial itself fails (no
// TCP listener) but a raw UDP relay on the same host:port still answers, so the
// UDP path must succeed ("TCP is down, keep testing UDP").
func TestUDPAssociate_RawFallbackOnDialFailure(t *testing.T) {
	echo, port := startUDPEcho(t)
	defer echo.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Default mode (tcp_and_udp), no TCP listener on the proxy port: the standard
	// ASSOCIATE dial fails, and the raw UDP relay on host:port is the fallback.
	p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: port}
	conn, err := p.UDPAssociate(ctx, "example.com", 53)
	if err != nil {
		t.Fatalf("UDPAssociate with TCP down: %v (want raw UDP fallback)", err)
	}
	defer conn.Close()

	payload := []byte("dial-fallback-hello")
	frame := makeSOCKS5UDPFrame("8.8.8.8", 53, payload)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf[:n], payload) {
		t.Fatalf("echo mismatch: got %x, want contains %x", buf[:n], payload)
	}
}

// TestTCPOnlyNeverServesUDP verifies a tcp_only-effective upstream (UDP circuit open) is
// skipped by UDP routing via SupportsUDP. The relay layer itself no longer rejects
// UDPAssociate (routing decides; the health probe must be able to attempt UDP through a
// degraded node to detect recovery), so this asserts the routing predicate.
func TestTCPOnlyNeverServesUDP(t *testing.T) {
	p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: 1}
	p.health.SetManualState(true)
	p.udpHealth.SetManualState(false) // udp down -> effective tcp_only
	if p.SupportsUDP() {
		t.Fatal("expected effective tcp_only to be skipped by UDP routing")
	}
	if p.EffectiveMode() != ModeTCPOnly {
		t.Fatalf("EffectiveMode: got %q, want %q", p.EffectiveMode(), ModeTCPOnly)
	}
}

// TestEffectiveMode verifies mode is auto-derived: UDP-capable schemes refine the
// three-state mode by the independent TCP/UDP circuits, and non-UDP schemes are always
// tcp_only no matter the circuits. There is no configured base anymore.
func TestEffectiveMode(t *testing.T) {
	cases := []struct {
		name   string
		scheme ProxyScheme
		tcpUp  bool
		udpUp  bool
		want   string
	}{
		{name: "socks5, both up", scheme: SchemeSOCKS5, tcpUp: true, udpUp: true, want: ModeTCPAndUDP},
		{name: "socks5, tcp up udp down", scheme: SchemeSOCKS5, tcpUp: true, udpUp: false, want: ModeTCPOnly},
		{name: "socks5, tcp down udp up", scheme: SchemeSOCKS5, tcpUp: false, udpUp: true, want: ModeUDPOnly},
		{name: "socks5, both down", scheme: SchemeSOCKS5, tcpUp: false, udpUp: false, want: ModeTCPAndUDP},
		{name: "socks5h", scheme: SchemeSOCKS5H, tcpUp: true, udpUp: true, want: ModeTCPAndUDP},
		{name: "ss, tcp up udp down", scheme: SchemeSS, tcpUp: true, udpUp: false, want: ModeTCPOnly},
		// Non-UDP schemes are always tcp_only regardless of circuits.
		{name: "http, both up", scheme: SchemeHTTP, tcpUp: true, udpUp: true, want: ModeTCPOnly},
		{name: "http, tcp down udp up", scheme: SchemeHTTP, tcpUp: false, udpUp: true, want: ModeTCPOnly},
		{name: "https, both down", scheme: SchemeHTTPS, tcpUp: false, udpUp: false, want: ModeTCPOnly},
		{name: "socks4, both up", scheme: SchemeSOCKS4, tcpUp: true, udpUp: true, want: ModeTCPOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{Scheme: tc.scheme}
			p.health.SetManualState(tc.tcpUp)
			p.udpHealth.SetManualState(tc.udpUp)
			if got := p.EffectiveMode(); got != tc.want {
				t.Fatalf("EffectiveMode: got %q, want %q", got, tc.want)
			}
		})
	}

	// Routing predicates follow the effective mode, while the probe direction is
	// scheme-based (a degraded UDP-capable node is still UDP-probed for recovery).
	p := &Proxy{Scheme: SchemeSOCKS5}
	p.health.SetManualState(true)     // tcp up
	p.udpHealth.SetManualState(false) // udp down -> effective tcp_only
	if p.IsTCPOnly() != true {
		t.Error("IsTCPOnly: want true for effective tcp_only")
	}
	if p.SupportsUDP() != false {
		t.Error("SupportsUDP: want false for effective tcp_only")
	}
	if !p.SchemeSupportsUDP() {
		t.Error("SchemeSupportsUDP: socks5 must still be UDP-probed for recovery")
	}

	// Non-UDP schemes: never UDP-probed and never serve UDP, even with healthy circuits.
	ph := &Proxy{Scheme: SchemeHTTP}
	ph.health.SetManualState(true)
	ph.udpHealth.SetManualState(true)
	if ph.SchemeSupportsUDP() {
		t.Error("SchemeSupportsUDP: http must not be UDP-probed")
	}
	if ph.SupportsUDP() {
		t.Error("SupportsUDP: http must never serve UDP")
	}
	if ph.IsTCPOnly() != true {
		t.Error("IsTCPOnly: http must always be effective tcp_only")
	}
}

func TestSchemeSupportsUDP(t *testing.T) {
	cases := []struct {
		scheme ProxyScheme
		want   bool
	}{
		{SchemeSOCKS5, true},
		{SchemeSOCKS5H, true},
		{SchemeSS, true},
		{SchemeHTTP, false},
		{SchemeHTTPS, false},
		{SchemeSOCKS4, false},
	}
	for _, tc := range cases {
		if got := (&Proxy{Scheme: tc.scheme}).SchemeSupportsUDP(); got != tc.want {
			t.Errorf("SchemeSupportsUDP(%s): got %v, want %v", tc.scheme, got, tc.want)
		}
	}
}

// TestUDPCapability_Detection verifies the capability marker is learned from the health
// probe's end-to-end relay result: a raw-only node (ASSOCIATE rejected, raw relay answers)
// is marked raw; a standard ASSOCIATE node is marked standard.
func TestUDPCapability_Detection(t *testing.T) {
	t.Run("raw-only node", func(t *testing.T) {
		// A frame DNS server (answers raw UDP frames with a valid DNS response) and a SOCKS5
		// TCP server that rejects ASSOCIATE with rep=0x07, both on the SAME port.
		fdns, dnsPort := startFrameDNSServer(t)
		defer fdns.Close()
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", dnsPort))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					buf := make([]byte, 258)
					if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
						return
					}
					if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
						return
					}
					if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
						return
					}
					if _, err := io.ReadFull(c, buf[:10]); err != nil { // ASSOCIATE request
						return
					}
					c.Write([]byte{0x05, 0x07, 0x00, 0x01}) // rep=0x07 CommandNotSupported
				}(conn)
			}
		}()

		p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: dnsPort}
		cfg := config.HealthCheckConf{Enabled: true, Timeout: 2, FailuresThreshold: 1, SuccessesThreshold: 1}
		hc := NewHealthChecker(cfg, []*Proxy{p})
		defer hc.Stop()
		hc.checkProxyUDP(p)
		if got := p.UDPCapability(); got != UDPCapRaw {
			t.Fatalf("raw-only node: UDPCapability got %q, want %q", got, UDPCapRaw)
		}
	})

	t.Run("standard associate node", func(t *testing.T) {
		// A UDP relay (frame DNS server) plus a SOCKS5 TCP server that ANSWERS the ASSOCIATE
		// with a bind address pointing at that UDP relay.
		fdns, dnsPort := startFrameDNSServer(t)
		defer fdns.Close()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		tcpPort := ln.Addr().(*net.TCPAddr).Port
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					buf := make([]byte, 258)
					if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
						return
					}
					if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
						return
					}
					if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
						return
					}
					if _, err := io.ReadFull(c, buf[:10]); err != nil { // ASSOCIATE request
						return
					}
					// rep=0x00, ATYP=IPv4, bind 127.0.0.1:dnsPort
					reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(dnsPort >> 8), byte(dnsPort & 0xff)}
					c.Write(reply)
					io.Copy(io.Discard, c) // keep the control channel open
				}(conn)
			}
		}()

		p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: tcpPort}
		cfg := config.HealthCheckConf{Enabled: true, Timeout: 2, FailuresThreshold: 1, SuccessesThreshold: 1}
		hc := NewHealthChecker(cfg, []*Proxy{p})
		defer hc.Stop()
		hc.checkProxyUDP(p)
		if got := p.UDPCapability(); got != UDPCapStandard {
			t.Fatalf("standard associate node: UDPCapability got %q, want %q", got, UDPCapStandard)
		}
	})
}

// TestUDPCapability_RawRoutingOptimization verifies a known-raw node skips the doomed
// ASSOCIATE handshake entirely: UDP frames flow over the raw relay and no TCP connection is
// ever attempted.
func TestUDPCapability_RawRoutingOptimization(t *testing.T) {
	echo, port := startUDPEcho(t)
	defer echo.Close()

	var tcpAttempts int32
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&tcpAttempts, 1)
			conn.Close()
		}
	}()

	p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: port}
	p.setUDPCapability(UDPCapRaw) // known raw from a prior detection

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := p.UDPAssociate(ctx, "example.com", 53)
	if err != nil {
		t.Fatalf("UDPAssociate on known-raw node: %v", err)
	}
	defer conn.Close()

	payload := []byte("raw-optimized")
	frame := makeSOCKS5UDPFrame("8.8.8.8", 53, payload)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf[:n], payload) {
		t.Fatalf("echo mismatch: got %x, want contains %x", buf[:n], payload)
	}
	if got := atomic.LoadInt32(&tcpAttempts); got != 0 {
		t.Fatalf("raw fast path must not attempt any TCP/ASSOCIATE connection, got %d attempts", got)
	}
}

// TestUDPCapability_StickyOnFailure verifies a node already detected raw keeps its
// last-known-good marker through a later end-to-end failure — the udpHealth circuit reports
// the outage, not the marker.
func TestUDPCapability_StickyOnFailure(t *testing.T) {
	p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: deadUDPPort(t)}
	p.setUDPCapability(UDPCapRaw)
	cfg := config.HealthCheckConf{Enabled: true, Timeout: 1, FailuresThreshold: 1, SuccessesThreshold: 1}
	hc := NewHealthChecker(cfg, []*Proxy{p})
	defer hc.Stop()
	hc.checkProxyUDP(p) // probe fails end to end (dead port)
	if p.IsUDPAvailable() {
		t.Error("expected UDP circuit open after the failing probe")
	}
	if got := p.UDPCapability(); got != UDPCapRaw {
		t.Fatalf("known-raw marker must stick through a failure, got %q", got)
	}
}

// TestUDPCapability_NoneFromUnknown verifies a fresh (unknown) node whose UDP probe fails
// end to end is marked none — the "otherwise UDP unsupported" case.
func TestUDPCapability_NoneFromUnknown(t *testing.T) {
	p := &Proxy{Scheme: SchemeSOCKS5}
	if got := p.UDPCapability(); got != UDPCapUnknown {
		t.Fatalf("fresh proxy: UDPCapability got %q, want %q", got, UDPCapUnknown)
	}
	p.noteUDPCapabilityFailure()
	if got := p.UDPCapability(); got != UDPCapNone {
		t.Fatalf("fresh node failure: UDPCapability got %q, want %q", got, UDPCapNone)
	}
}

// TestUDPCapability_UpgradeRawToStandard verifies raw → standard upgrade is allowed (a node
// later supports ASSOCIATE) and standard → raw downgrade is forbidden (transient failures
// never permanently degrade a known standard node).
func TestUDPCapability_UpgradeRawToStandard(t *testing.T) {
	echo, port := startUDPEcho(t)
	defer echo.Close()

	u1, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer u1.Close()
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	raw := &Proxy{Scheme: SchemeSOCKS5}
	raw.setUDPCapability(UDPCapRaw)
	raw.classifyUDPCapability(&UDPProxyConn{UDPConn: u1, tcpConn: pipeA})
	if got := raw.UDPCapability(); got != UDPCapStandard {
		t.Fatalf("raw→standard upgrade: got %q, want %q", got, UDPCapStandard)
	}

	u2, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer u2.Close()
	std := &Proxy{Scheme: SchemeSOCKS5}
	std.setUDPCapability(UDPCapStandard)
	std.classifyUDPCapability(&UDPProxyConn{UDPConn: u2}) // tcpConn nil → raw type
	if got := std.UDPCapability(); got != UDPCapStandard {
		t.Fatalf("known standard must not downgrade to raw, got %q", got)
	}
}

// startAssociateTCP serves a SOCKS5 TCP listener on IPv4 loopback whose UDP ASSOCIATE follows
// the given policy; see startAssociateTCPOn.
func startAssociateTCP(t *testing.T, policy string, udpPort int) (tcpPort int, attempts *int32) {
	return startAssociateTCPOn(t, net.IPv4(127, 0, 0, 1), policy, udpPort)
}

// startAssociateTCPOn serves a SOCKS5 TCP listener on the given IP (IPv4 or IPv6 loopback)
// whose UDP ASSOCIATE follows policy:
//   - "standard": replies rep=0x00 with bind ip:udpPort (the UDP relay, ATYP matching the IP
//     family — 0x01 IPv4 or 0x04 IPv6), then keeps the control channel open;
//   - "reject": replies rep=0x07 CommandNotSupported.
//
// It returns the TCP port and a counter of accepted TCP connections (to assert when the raw
// fast path is skipped).
func startAssociateTCPOn(t *testing.T, ip net.IP, policy string, udpPort int) (tcpPort int, attempts *int32) {
	t.Helper()
	var n int32
	attempts = &n
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tcpPort = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&n, 1)
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 258)
				if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
					return
				}
				if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				if _, err := io.ReadFull(c, buf[:10]); err != nil { // ASSOCIATE request
					return
				}
				if policy == "standard" {
					// reply = VER|REP|RSV|ATYP|BND.ADDR|BND.PORT, ATYP matching the IP family
					var reply []byte
					if ip4 := ip.To4(); ip4 != nil {
						reply = []byte{0x05, 0x00, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], byte(udpPort >> 8), byte(udpPort & 0xff)}
					} else {
						reply = make([]byte, 4+16+2)
						reply[0], reply[1], reply[2], reply[3] = 0x05, 0x00, 0x00, 0x04
						copy(reply[4:], ip.To16())
						reply[4+16], reply[4+16+1] = byte(udpPort>>8), byte(udpPort&0xff)
					}
					if _, err := c.Write(reply); err != nil {
						return
					}
					io.Copy(io.Discard, c) // keep the control channel open
				} else {
					c.Write([]byte{0x05, 0x07, 0x00, 0x01}) // rep=0x07 CommandNotSupported
				}
			}(conn)
		}
	}()
	return tcpPort, attempts
}

// requireIPv6 skips the test when the loopback has no usable IPv6 (e.g. CI hosts without v6).
func requireIPv6(t *testing.T) {
	t.Helper()
	pc, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	pc.Close()
}

// TestUDPCapability_DetectionIPv6 verifies the UDP capability detection path works against an
// IPv6 node ([::1]): the raw relay round-trips over IPv6, and a standard ASSOCIATE reply with
// an IPv6 bind address (ATYP=0x04) is parsed and dialed correctly. It is the IPv6 mirror of
// TestUDPCapability_Detection + the raw fast-path round trip.
func TestUDPCapability_DetectionIPv6(t *testing.T) {
	requireIPv6(t)

	t.Run("raw-only node", func(t *testing.T) {
		// The SOCKS5 TCP reject listener and the UDP frame DNS server must share the SAME port
		// (like shadowsocks-android: TCP-only SOCKS5 + a raw UDP relay on the same host:port),
		// so the raw fallback's dial to Host:Port finds the UDP relay there.
		fdns, dnsPort := startFrameDNSServerOn(t, net.IPv6loopback)
		defer fdns.Close()
		ln, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(dnsPort)))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					buf := make([]byte, 258)
					if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
						return
					}
					if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
						return
					}
					if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
						return
					}
					if _, err := io.ReadFull(c, buf[:10]); err != nil { // ASSOCIATE request
						return
					}
					c.Write([]byte{0x05, 0x07, 0x00, 0x01}) // rep=0x07 CommandNotSupported
				}(conn)
			}
		}()

		p := &Proxy{Scheme: SchemeSOCKS5, Host: "::1", Port: dnsPort}
		cfg := config.HealthCheckConf{Enabled: true, Timeout: 2, FailuresThreshold: 1, SuccessesThreshold: 1}
		hc := NewHealthChecker(cfg, []*Proxy{p})
		defer hc.Stop()
		hc.checkProxyUDP(p)
		if got := p.UDPCapability(); got != UDPCapRaw {
			t.Fatalf("IPv6 raw-only node: UDPCapability got %q, want %q", got, UDPCapRaw)
		}
	})

	t.Run("standard associate node", func(t *testing.T) {
		fdns, dnsPort := startFrameDNSServerOn(t, net.IPv6loopback)
		defer fdns.Close()
		tcpPort, _ := startAssociateTCPOn(t, net.IPv6loopback, "standard", dnsPort)

		p := &Proxy{Scheme: SchemeSOCKS5, Host: "::1", Port: tcpPort}
		cfg := config.HealthCheckConf{Enabled: true, Timeout: 2, FailuresThreshold: 1, SuccessesThreshold: 1}
		hc := NewHealthChecker(cfg, []*Proxy{p})
		defer hc.Stop()
		hc.checkProxyUDP(p)
		if got := p.UDPCapability(); got != UDPCapStandard {
			t.Fatalf("IPv6 standard node: UDPCapability got %q, want %q", got, UDPCapStandard)
		}
	})

	t.Run("raw fast path round trip", func(t *testing.T) {
		echo, port := startUDPEchoOn(t, net.IPv6loopback)
		defer echo.Close()

		p := &Proxy{Scheme: SchemeSOCKS5, Host: "::1", Port: port}
		p.setUDPCapability(UDPCapRaw) // known raw → routing fast path, relay straight to ::1

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := p.UDPAssociate(ctx, "example.com", 53)
		if err != nil {
			t.Fatalf("IPv6 raw fast path UDPAssociate: %v", err)
		}
		defer conn.Close()

		payload := []byte("ipv6-raw")
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(buf[:n], payload) {
			t.Fatalf("IPv6 raw echo mismatch: got %x, want contains %x", buf[:n], payload)
		}
	})
}

// TestUDPCapability_RawRecheckUpgrade verifies the raw → standard recovery path: a known-raw
// node keeps using the raw fast path (no ASSOCIATE handshake) until its recheck is due, then
// re-attempts the standard ASSOCIATE path once. If the upstream now supports ASSOCIATE, the
// relay comes up standard and the marker upgrades.
func TestUDPCapability_RawRecheckUpgrade(t *testing.T) {
	// The node has a UDP echo relay and a SOCKS5 TCP listener that now ANSWERS ASSOCIATE.
	fdns, dnsPort := startFrameDNSServer(t)
	defer fdns.Close()
	tcpPort, attempts := startAssociateTCP(t, "standard", dnsPort)

	p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: tcpPort}
	p.setUDPCapability(UDPCapRaw) // first raw detection schedules the recheck in the future

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1) Recheck not due → raw fast path: no TCP/ASSOCIATE attempt, raw relay conn.
	conn1, err := p.UDPAssociate(ctx, "example.com", 53)
	if err != nil {
		t.Fatalf("UDPAssociate (fast path): %v", err)
	}
	if upc, ok := conn1.(*UDPProxyConn); !ok || upc.tcpConn != nil {
		t.Fatal("expected a raw relay conn (tcpConn == nil) before the recheck is due")
	}
	conn1.Close()
	if got := atomic.LoadInt32(attempts); got != 0 {
		t.Fatalf("raw fast path must not attempt ASSOCIATE before recheck is due, got %d TCP attempts", got)
	}

	// 2) Force the recheck due → the node re-attempts standard ASSOCIATE.
	p.rawRecheckAfter = time.Now().Add(-time.Minute)
	conn2, err := p.UDPAssociate(ctx, "example.com", 53)
	if err != nil {
		t.Fatalf("UDPAssociate (recheck): %v", err)
	}
	upc, ok := conn2.(*UDPProxyConn)
	if !ok || upc.tcpConn == nil {
		t.Fatal("expected a standard ASSOCIATE conn (tcpConn != nil) after the recheck")
	}
	if got := atomic.LoadInt32(attempts); got != 1 {
		t.Fatalf("recheck must attempt exactly one ASSOCIATE, got %d TCP attempts", got)
	}

	// 3) Classifying that standard relay upgrades the marker raw → standard.
	p.classifyUDPCapability(conn2)
	conn2.Close()
	if got := p.UDPCapability(); got != UDPCapStandard {
		t.Fatalf("raw→standard upgrade after successful recheck: got %q, want %q", got, UDPCapStandard)
	}
}

// TestUDPCapability_RawRecheckNoFlap verifies a failed recheck does not flip the marker and
// does not retry ASSOCIATE on every subsequent association: the failed ASSOCIATE falls back to
// the raw relay (marker stays raw) and the next recheck is scheduled a full interval away.
func TestUDPCapability_RawRecheckNoFlap(t *testing.T) {
	// The node has a UDP echo relay but its SOCKS5 still rejects ASSOCIATE (rep=0x07).
	fdns, dnsPort := startFrameDNSServer(t)
	defer fdns.Close()
	tcpPort, attempts := startAssociateTCP(t, "reject", dnsPort)

	p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: tcpPort}
	p.setUDPCapability(UDPCapRaw)
	p.rawRecheckAfter = time.Now().Add(-time.Minute) // recheck due

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := p.UDPAssociate(ctx, "example.com", 53)
	if err != nil {
		t.Fatalf("UDPAssociate (failed recheck, raw fallback): %v", err)
	}
	if upc, ok := conn.(*UDPProxyConn); !ok || upc.tcpConn != nil {
		t.Fatal("failed recheck must fall back to a raw relay conn (tcpConn == nil)")
	}
	conn.Close()
	if got := atomic.LoadInt32(attempts); got != 1 {
		t.Fatalf("recheck must attempt exactly one ASSOCIATE, got %d TCP attempts", got)
	}
	if got := p.UDPCapability(); got != UDPCapRaw {
		t.Fatalf("failed recheck must not flip the marker, got %q, want %q", got, UDPCapRaw)
	}

	// Immediately after the failed recheck, the raw fast path is active again (next recheck is
	// a full interval away) — no second doomed ASSOCIATE attempt.
	conn2, err := p.UDPAssociate(ctx, "example.com", 53)
	if err != nil {
		t.Fatalf("UDPAssociate (post-recheck fast path): %v", err)
	}
	conn2.Close()
	if got := atomic.LoadInt32(attempts); got != 1 {
		t.Fatalf("no flapping: raw fast path must not retry ASSOCIATE, got %d TCP attempts", got)
	}
}

// TestProxyInfo_UDPCapability verifies the capability marker and auto-derived mode are
// surfaced through Proxies() for the dashboard.
func TestProxyInfo_UDPCapability(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: "socks5://127.0.0.1:1080"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.dnsUDPPool.Close()
	m.aliasMap["p1"].setUDPCapability(UDPCapRaw)

	infos := m.Proxies()
	if len(infos) != 1 {
		t.Fatalf("expected 1 proxy info, got %d", len(infos))
	}
	if infos[0].UDPCapability != string(UDPCapRaw) {
		t.Errorf("ProxyInfo.udp_capability: got %q, want %q", infos[0].UDPCapability, UDPCapRaw)
	}
	if infos[0].Mode != ModeTCPAndUDP {
		t.Errorf("ProxyInfo.mode: got %q, want %q (fresh circuits)", infos[0].Mode, ModeTCPAndUDP)
	}
}

// TestNewProxy_PluginParsing covers the SIP003 ?plugin= extraction for BOTH the literal-';'
// form (plugin=obfs-local;obfs=http;obfs-host=...) and the percent-encoded form (%3B/%3D).
// Go's url.ParseQuery silently drops a query whose value contains a literal ';', which made
// pasted/plain config ss:// links lose their obfs plugin and connect raw; pluginFromRawQuery
// must parse both identically.
func TestNewProxy_PluginParsing(t *testing.T) {
	const want = "obfs-local;obfs=http;obfs-host=upay.10010.com"
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"literal-semicolon", "ss://none@127.0.0.1:80?plugin=obfs-local;obfs=http;obfs-host=upay.10010.com"},
		{"percent-encoded", "ss://none@127.0.0.1:80?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dupay.10010.com"},
		{"encoded-value-with-extra-param", "ss://none@127.0.0.1:80?foo=bar&plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dupay.10010.com"},
		{"no-plugin", "ss://none@127.0.0.1:80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProxy(tc.url)
			if err != nil {
				t.Fatalf("NewProxy(%s): %v", tc.url, err)
			}
			if tc.name == "no-plugin" {
				if p.Plugin != "" {
					t.Fatalf("expected no plugin, got %q", p.Plugin)
				}
				return
			}
			if p.Plugin != want {
				t.Fatalf("Plugin: got %q, want %q", p.Plugin, want)
			}
			kind, err := p.ssPluginKind()
			if err != nil {
				t.Fatalf("ssPluginKind: %v", err)
			}
			if kind != "obfs-local" {
				t.Fatalf("ssPluginKind: got %q, want obfs-local", kind)
			}
			cfg, err := p.ssPlugin()
			if err != nil {
				t.Fatalf("ssPlugin: %v", err)
			}
			if cfg == nil || cfg.obfs != "http" || cfg.host != "upay.10010.com" {
				t.Fatalf("ssPlugin: unexpected config %+v", cfg)
			}
		})
	}
}

// TestPluginFromRawQuery exercises the low-level parser directly, including edge cases the
// Go query parser rejects.
func TestPluginFromRawQuery(t *testing.T) {
	cases := []struct {
		rawQuery string
		want     string
	}{
		{"plugin=obfs-local;obfs=http;obfs-host=upay.10010.com", "obfs-local;obfs=http;obfs-host=upay.10010.com"},
		{"plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dupay.10010.com", "obfs-local;obfs=http;obfs-host=upay.10010.com"},
		{"a=1&b=2", ""},
		{"", ""},
		{"plugin=", ""},
	}
	for _, tc := range cases {
		if got := pluginFromRawQuery(tc.rawQuery); got != tc.want {
			t.Errorf("pluginFromRawQuery(%q) = %q, want %q", tc.rawQuery, got, tc.want)
		}
	}
}

// TestNewProxy_LegacyQRFormat covers the legacy ss:// QR form
// ss://base64(method:password@host:port) with no '@' in the URI. shadowsocks-rust
// (Config::from_url) and shadowsocks-android (Profile.findAllUrls legacyPattern) both accept
// it; the payload lives in the host position so url.Parse leaves it as Hostname. Both padded
// (StdEncoding) and unpadded (RawURLEncoding) variants must parse.
func TestNewProxy_LegacyQRFormat(t *testing.T) {
	// base64 of "none:pass@127.0.0.1:8388" (24 bytes → 32 chars, no padding) and of
	// "none:pass@1.2.3.4:8388" (22 bytes → 32 chars with StdEncoding's '==').
	const (
		unpadded = "ss://bm9uZTpwYXNzQDEyNy4wLjAuMTo4Mzg4"
		padded   = "ss://bm9uZTpwYXNzQDEuMi4zLjQ6ODM4OA=="
	)
	for _, tc := range []struct{ name, url string }{
		{"unpadded-rawurl", unpadded},
		{"padded-std", padded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProxy(tc.url)
			if err != nil {
				t.Fatalf("NewProxy(%s): %v", tc.url, err)
			}
			if tc.name == "padded-std" {
				if p.Host != "1.2.3.4" || p.Port != 8388 || p.Username != "none" || p.Password != "pass" {
					t.Errorf("padded: got %q:%d %q/%q, want 1.2.3.4:8388 none/pass", p.Host, p.Port, p.Username, p.Password)
				}
				return
			}
			if p.Host != "127.0.0.1" {
				t.Errorf("Host: got %q, want 127.0.0.1", p.Host)
			}
			if p.Port != 8388 {
				t.Errorf("Port: got %d, want 8388", p.Port)
			}
			if p.Username != "none" || p.Password != "pass" {
				t.Errorf("credentials: got %q/%q, want none/pass", p.Username, p.Password)
			}
		})
	}
	// A legacy payload with standard-alphabet '+' must survive url.Parse's host handling
	// (rawSSPayload reads the original string, not the mangled Hostname).
	plusURL := "ss://bm9uZTp+YUAxLjIuMy40OjgzODg=" // base64(std) of "none:~a@1.2.3.4:8388"
	p, err := NewProxy(plusURL)
	if err != nil {
		t.Fatalf("NewProxy(plus payload): %v", err)
	}
	if p.Host != "1.2.3.4" || p.Port != 8388 || p.Username != "none" || p.Password != "~a" {
		t.Errorf("plus payload: got %q:%d %q/%q, want 1.2.3.4:8388 none/~a", p.Host, p.Port, p.Username, p.Password)
	}
}

// TestNewProxy_SSDefaultPort verifies the ss:// scheme defaults to port 8388 when omitted,
// matching shadowsocks-rust Config::from_url (port.unwrap_or(8388)) and shadowsocks-android.
func TestNewProxy_SSDefaultPort(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"plaintext-userinfo", "ss://none@example.com"},
		{"base64-userinfo", "ss://bm9uZTpwYXNz@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProxy(tc.url)
			if err != nil {
				t.Fatalf("NewProxy(%s): %v", tc.url, err)
			}
			if p.Port != 8388 {
				t.Fatalf("Port: got %d, want 8388", p.Port)
			}
		})
	}
	// Other schemes keep their URI defaults: http 80, socks 1080.
	if p, err := NewProxy("http://example.com"); err != nil || p.Port != 80 {
		t.Fatalf("http default port: got %d (err %v), want 80", p.Port, err)
	}
	if p, err := NewProxy("socks5://example.com"); err != nil || p.Port != 1080 {
		t.Fatalf("socks5 default port: got %d (err %v), want 1080", p.Port, err)
	}
}

// TestNewProxy_NameFragment verifies the ss:// #fragment is captured as the node's
// friendly name, mirroring shadowsocks-android (profile.name = uri.fragment). The
// fragment is percent-decoded by url.Parse, so a URL-encoded Chinese name must
// round-trip to the readable form.
func TestNewProxy_NameFragment(t *testing.T) {
	t.Run("modern-encoded-name", func(t *testing.T) {
		// ss://none:ODI4...@host:80 with plugin and an encoded Chinese fragment (the
		// exact shape from exported ss:// links, e.g. "美国 加利福尼亚州 洛杉矶").
		url := "ss://bm9uZTpPREk0WmpBd1pHTXRORFF6@103.11.76.248:80?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dupay.10010.com#%E7%BE%8E%E5%9B%BD%20%E5%8A%A0%E5%88%A9%E7%A6%8F%E5%B0%BC%E4%BA%9A%E5%B7%9E%20%E6%B4%9B%E6%9D%89%E7%9F%B6%20%205gnetworks.au"
		p, err := NewProxy(url)
		if err != nil {
			t.Fatalf("NewProxy: %v", err)
		}
		want := "美国 加利福尼亚州 洛杉矶  5gnetworks.au"
		if p.Name != want {
			t.Errorf("Name: got %q, want %q", p.Name, want)
		}
		if p.Host != "103.11.76.248" || p.Port != 80 {
			t.Errorf("host/port: got %q:%d, want 103.11.76.248:80", p.Host, p.Port)
		}
		if p.Plugin == "" {
			t.Error("plugin should still parse alongside the fragment")
		}
	})

	t.Run("legacy-qr-name", func(t *testing.T) {
		// Legacy QR form with a #name fragment: ss://base64(method:pass@host:port)#名称.
		p, err := NewProxy("ss://bm9uZTpwYXNzQDEyNy4wLjAuMTo4Mzg4#%E7%BE%8E%E5%9B%BD%20%E8%8A%82%E7%82%B9")
		if err != nil {
			t.Fatalf("NewProxy: %v", err)
		}
		if p.Host != "127.0.0.1" || p.Port != 8388 {
			t.Errorf("host/port: got %q:%d, want 127.0.0.1:8388", p.Host, p.Port)
		}
		if p.Name != "美国 节点" {
			t.Errorf("Name: got %q, want %q", p.Name, "美国 节点")
		}
	})

	t.Run("no-fragment", func(t *testing.T) {
		p, err := NewProxy("ss://none:pass@127.0.0.1:80")
		if err != nil {
			t.Fatalf("NewProxy: %v", err)
		}
		if p.Name != "" {
			t.Errorf("Name: got %q, want empty", p.Name)
		}
	})

	t.Run("literal-percent-in-name", func(t *testing.T) {
		// A fragment whose decoded text contains a literal '%' (encoded as %25) must
		// survive: url.Parse already decodes it, so we must not re-unescape.
		p, err := NewProxy("ss://none:pass@127.0.0.1:80#100%25off")
		if err != nil {
			t.Fatalf("NewProxy: %v", err)
		}
		if p.Name != "100%off" {
			t.Errorf("Name: got %q, want %q", p.Name, "100%off")
		}
	})
}

// TestParseSSLegacy exercises the low-level legacy parser directly, including the variants
// a QR generator might emit.
func TestParseSSLegacy(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		wantMethod    string
		wantPassword  string
		wantHostPort  string
	}{
		{"unpadded", "bm9uZTpwYXNzQDEyNy4wLjAuMTo4Mzg4", "none", "pass", "127.0.0.1:8388"},
		{"padded-std", "bm9uZTpwYXNzQDEuMi4zLjQ6ODM4OA==", "none", "pass", "1.2.3.4:8388"},
		{"std-alphabet-plus", "bm9uZTp+YUAxLjIuMy40OjgzODg=", "none", "~a", "1.2.3.4:8388"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, pw, hp, err := parseSSLegacy(tc.payload)
			if err != nil {
				t.Fatalf("parseSSLegacy: %v", err)
			}
			if m != tc.wantMethod || pw != tc.wantPassword || hp != tc.wantHostPort {
				t.Errorf("parseSSLegacy(%q) = %q/%q/%q, want %q/%q/%q",
					tc.payload, m, pw, hp, tc.wantMethod, tc.wantPassword, tc.wantHostPort)
			}
		})
	}
	// non-base64 payload must error, not panic
	if _, _, _, err := parseSSLegacy("!!not-base64!!"); err == nil {
		t.Error("parseSSLegacy(non-base64) = nil error, want error")
	}
}

func TestNewProxy_UDPInTCPFlag(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"plain socks5", "socks5://127.0.0.1:1080", false},
		{"socks5 query 1", "socks5://user:pass@127.0.0.1:1080?udp_in_tcp=1", true},
		{"socks5h query true", "socks5h://proxy.example.com:2080?udp_in_tcp=true", true},
		{"socks5h query yes", "socks5h://proxy.example.com:2080?udp_in_tcp=yes", true},
		{"socks5 query on", "socks5://127.0.0.1:1080?udp_in_tcp=on", true},
		{"socks5 query 0 is off", "socks5://127.0.0.1:1080?udp_in_tcp=0", false},
		{"other query untouched", "socks5://127.0.0.1:1080?plugin=foo", false},
		{"http ignores flag", "http://proxy:8080?udp_in_tcp=1", false},
		{"socks4 ignores flag", "socks4://10.0.0.1:9050?udp_in_tcp=1", false},
		{"ss ignores flag", "ss://none:pass@1.2.3.4:8388?udp_in_tcp=1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewProxy(tt.url)
			if err != nil {
				t.Fatalf("NewProxy(%q): %v", tt.url, err)
			}
			if p.UDPInTCP != tt.want {
				t.Errorf("UDPInTCP = %v, want %v", p.UDPInTCP, tt.want)
			}
		})
	}
}

func TestUDPInTCP_TCPDisabledByDefault_ManualRecovery(t *testing.T) {
	p, err := NewProxy("socks5://user:pass@127.0.0.1:1080?udp_in_tcp=1")
	if err != nil {
		t.Fatal(err)
	}
	// The carrier TCP stream is plaintext framed UDP, so a udp_in_tcp node defaults to TCP
	// manually down → udp_only (mirrors the SIP003 plugin's UDP-down default). UDP routing
	// must still pick the node up.
	if got := p.EffectiveMode(); got != ModeUDPOnly {
		t.Errorf("EffectiveMode = %s, want %s", got, ModeUDPOnly)
	}
	if !p.IsUDPOnly() {
		t.Error("IsUDPOnly() = false, want true (TCP defaults manually disabled)")
	}
	if !p.SupportsUDP() {
		t.Error("SupportsUDP() = false, want true (UDP routing must pick the node up)")
	}
	// The disable is a manual circuit pin, not a hard-coded mode: the user can re-enable TCP
	// (SetCircuitHealth tcp enable) and the node returns to a full tcp_and_udp member of TCP
	// routing.
	p.health.SetManualState(true)
	if got := p.EffectiveMode(); got != ModeTCPAndUDP {
		t.Errorf("EffectiveMode after TCP enable = %s, want %s", got, ModeTCPAndUDP)
	}
	if p.IsUDPOnly() {
		t.Error("IsUDPOnly() after TCP enable = true, want false")
	}
	// Releasing to auto also recovers TCP (both circuits probe healthy on a fresh node).
	p.health.ClearManualState()
	if got := p.EffectiveMode(); got != ModeTCPAndUDP {
		t.Errorf("EffectiveMode after TCP auto = %s, want %s", got, ModeTCPAndUDP)
	}
	// Dynamic derivation still holds: TCP manually down while UDP up → udp_only.
	p.health.SetManualState(false)
	p.udpHealth.SetManualState(true)
	if got := p.EffectiveMode(); got != ModeUDPOnly {
		t.Errorf("EffectiveMode with TCP down = %s, want %s", got, ModeUDPOnly)
	}
}

func TestUDPInTCP_RoutesFramedEvenWhenTCPDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cmdSeen := make(chan byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// SOCKS5 greeting (no auth).
		var g [2]byte
		if _, err := io.ReadFull(conn, g[:]); err != nil {
			return
		}
		io.ReadFull(conn, make([]byte, int(g[1])))
		conn.Write([]byte{0x05, 0x00})
		// Request must be CMD=5 (hev FWD_UDP) — the framed path, not raw.
		req := make([]byte, 10)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		cmdSeen <- req[1]
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		time.Sleep(200 * time.Millisecond)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	p := &Proxy{Scheme: SchemeSOCKS5, Host: host, Port: port, UDPInTCP: true}
	// TCP circuit down + UDP up → IsUDPOnly() true. socks5UDPAssociate's raw fast path keys
	// on that, but a udp_in_tcp node must still dial TCP and frame its UDP.
	p.health.SetManualState(false)
	p.udpHealth.SetManualState(true)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := p.UDPAssociate(ctx, "8.8.8.8", 53)
	if err != nil {
		t.Fatalf("UDPAssociate: %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(*udpInTCPConn); !ok {
		t.Fatalf("UDPAssociate returned %T, want *udpInTCPConn (framed path)", conn)
	}
	select {
	case cmd := <-cmdSeen:
		if cmd != 0x05 {
			t.Errorf("mock saw CMD=%d, want 5 (FWD_UDP)", cmd)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mock server never saw the CMD=5 request (UDPAssociate took the raw path?)")
	}
}

func TestUDPInTCPConn_FrameRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uc := newUDPInTCPConn(client)

	// SOCKS5 UDP packet: RSV+FRAG(3) ATYP=IPv4(1) addr(4) port(2) payload.
	packet := []byte{0, 0, 0, 0x01, 192, 168, 1, 1, 0x00, 0x35}
	packet = append(packet, []byte("payload123")...)

	// net.Pipe is synchronous: the raw server side must run in a goroutine, reading the
	// client's frame and echoing it back.
	gotFrame := make(chan []byte, 1)
	go func() {
		frame := make([]byte, len(packet))
		if _, err := io.ReadFull(server, frame); err != nil {
			gotFrame <- nil
			return
		}
		gotFrame <- frame
		server.Write(frame)
	}()

	// Write: SOCKS5 UDP packet → hev frame (datlen|hdrlen|addr block|payload).
	if _, err := uc.Write(packet); err != nil {
		t.Fatal(err)
	}
	wantFrame := make([]byte, len(packet))
	binary.BigEndian.PutUint16(wantFrame[0:2], uint16(len(packet)-10))
	wantFrame[2] = 10 // hdrlen = 3 + addrblock(7)
	copy(wantFrame[3:], packet[3:])
	select {
	case f := <-gotFrame:
		if f == nil {
			t.Fatal("server read failed")
		}
		if !bytes.Equal(f, wantFrame) {
			t.Errorf("wire frame = %x, want %x", f, wantFrame)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive frame")
	}

	// Read: hev frame → SOCKS5 UDP packet.
	got := make([]byte, len(packet))
	if _, err := io.ReadFull(uc, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, packet) {
		t.Errorf("read packet = %x, want %x", got, packet)
	}
}

func TestSocks5UDPInTCP_viaMock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotFrame := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// SOCKS5 greeting (no auth).
		var g [2]byte
		if _, err := io.ReadFull(conn, g[:]); err != nil {
			return
		}
		io.ReadFull(conn, make([]byte, int(g[1])))
		conn.Write([]byte{0x05, 0x00})

		// Request must be CMD=5 (hev FWD_UDP).
		req := make([]byte, 10)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		if req[0] != 0x05 || req[1] != 0x05 {
			t.Errorf("request cmd = %d, want 5 (FWD_UDP)", req[1])
			return
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

		// Read one client frame, then echo it back.
		frame := make([]byte, 3+7+9)
		if _, err := io.ReadFull(conn, frame); err != nil {
			return
		}
		gotFrame <- frame
		conn.Write(frame)
		time.Sleep(50 * time.Millisecond)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	p := &Proxy{Scheme: SchemeSOCKS5, Host: host, Port: port, UDPInTCP: true}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := p.socks5UDPInTCP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(*udpInTCPConn); !ok {
		t.Fatalf("expected *udpInTCPConn, got %T", conn)
	}

	// Write a SOCKS5 UDP packet; the mock must receive the equivalent hev frame.
	packet := []byte{0, 0, 0, 0x01, 127, 0, 0, 1, 0x1f, 0x90}
	packet = append(packet, []byte("hello-udp")...)
	if _, err := conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	wantFrame := make([]byte, len(packet))
	binary.BigEndian.PutUint16(wantFrame[0:2], uint16(len(packet)-10))
	wantFrame[2] = 10
	copy(wantFrame[3:], packet[3:])
	select {
	case f := <-gotFrame:
		if !bytes.Equal(f, wantFrame) {
			t.Errorf("wire frame = %x, want %x", f, wantFrame)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mock server did not receive a frame")
	}

	// The echoed frame comes back as a SOCKS5 UDP packet.
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], packet) {
		t.Errorf("read back = %x, want %x", buf[:n], packet)
	}
}

func TestUDPInTCP_ProbeTCPIsNoop(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	uc := newUDPInTCPConn(client)
	if err := uc.ProbeTCP(); err != nil {
		t.Errorf("ProbeTCP() = %v, want nil (framed data must not be probe-read)", err)
	}
}

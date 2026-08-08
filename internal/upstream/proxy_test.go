package upstream

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
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

// startUDPEcho binds a UDP socket on 127.0.0.1 that echoes every received datagram.
func startUDPEcho(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
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

// TestUDPAssociate_UDPOnlyAutoRaw verifies that a udp_only upstream relays raw UDP
// straight to its own host:port, never touching the TCP-based SOCKS5 ASSOCIATE path
// (which could not work anyway — the node has no TCP listener).
func TestUDPAssociate_UDPOnlyAutoRaw(t *testing.T) {
	echo, port := startUDPEcho(t)
	defer echo.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	p := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   "127.0.0.1",
		Port:   port, // UDP echo bound here; no TCP listener, so only the auto raw-UDP path can work
		Mode:   ModeUDPOnly,
	}
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

// TestUDPAssociate_TCPOnlyRejected verifies a tcp_only upstream never serves UDP.
func TestUDPAssociate_TCPOnlyRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: 1080, Mode: ModeTCPOnly}
	if _, err := p.UDPAssociate(ctx, "example.com", 53); err == nil {
		t.Fatal("expected tcp_only proxy to reject UDPAssociate")
	}
}

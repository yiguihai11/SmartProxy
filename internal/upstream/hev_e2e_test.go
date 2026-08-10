package upstream

// End-to-end verification against a real hev-socks5-server binary.
//
// Run with:
//
//	HEV_SOCKS5_SERVER=127.0.0.1:18080 go test ./internal/upstream/ -run TestSocks5UDPInTCP_RealHevServer -v
//
// where 127.0.0.1:18080 is a running `hev-socks5-server` (any port; the server picks
// UDP-in-TCP automatically when it sees the CMD=5 FWD_UDP request). Skips when the env
// var is unset so the regular test suite stays green without the C binary.

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// startEchoTCPServer listens on a loopback port and echoes every accepted connection.
// Used as the end-to-end target reached through the hev node's CMD=1 CONNECT proxy.
func startEchoTCPServer(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// TestSocks5TCP_RealHevServer verifies the plain TCP proxying path (CMD=1 CONNECT) against a
// real hev-socks5-server — the capability a udp_in_tcp node still serves once its TCP circuit
// is enabled. Run with:
//
//	HEV_SOCKS5_SERVER=127.0.0.1:18080 go test ./internal/upstream/ -run TestSocks5TCP_RealHevServer -v
func TestSocks5TCP_RealHevServer(t *testing.T) {
	serverAddr := os.Getenv("HEV_SOCKS5_SERVER")
	if serverAddr == "" {
		t.Skip("HEV_SOCKS5_SERVER not set; skipping real hev-socks5-server TCP e2e test")
	}
	echoAddr := startEchoTCPServer(t)

	host, portStr, _ := net.SplitHostPort(serverAddr)
	port := parsePort(portStr)
	p := &Proxy{Scheme: SchemeSOCKS5, Host: host, Port: port}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := p.Connect(ctx, "127.0.0.1", echoAddr.Port)
	if err != nil {
		t.Fatalf("TCP connect through hev server (%s) to %s: %v", serverAddr, echoAddr, err)
	}
	defer conn.Close()

	payload := []byte("tcp-echo-through-hev-plaintext")
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("echo = %q, want %q", got, payload)
	}
}

// TestSocks5TCP_RealHevServer_Auth verifies the TCP CONNECT path against an auth-enabled hev
// server: correct creds connect and echo, wrong password is rejected at the handshake.
// Run with:
//
//	HEV_SOCKS5_SERVER_AUTH=127.0.0.1:18081 go test ./internal/upstream/ -run TestSocks5TCP_RealHevServer_Auth -v
func TestSocks5TCP_RealHevServer_Auth(t *testing.T) {
	serverAddr := os.Getenv("HEV_SOCKS5_SERVER_AUTH")
	if serverAddr == "" {
		t.Skip("HEV_SOCKS5_SERVER_AUTH not set; skipping auth TCP e2e test")
	}
	echoAddr := startEchoTCPServer(t)

	host, portStr, _ := net.SplitHostPort(serverAddr)
	port := parsePort(portStr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	good := &Proxy{Scheme: SchemeSOCKS5, Host: host, Port: port,
		Username: "socksuser", Password: "sockspass"}
	conn, err := good.Connect(ctx, "127.0.0.1", echoAddr.Port)
	if err != nil {
		t.Fatalf("auth TCP connect with correct creds: %v", err)
	}
	conn.Close()

	bad := &Proxy{Scheme: SchemeSOCKS5, Host: host, Port: port,
		Username: "socksuser", Password: "wrong"}
	if conn, err := bad.Connect(ctx, "127.0.0.1", echoAddr.Port); err == nil {
		conn.Close()
		t.Error("auth TCP connect with wrong password: want error, got success")
	}
}

func TestSocks5UDPInTCP_RealHevServer(t *testing.T) {
	serverAddr := os.Getenv("HEV_SOCKS5_SERVER")
	if serverAddr == "" {
		t.Skip("HEV_SOCKS5_SERVER not set; skipping real hev-socks5-server e2e test")
	}

	// A connected UDP echo server: replies from the same socket it received on, so the
	// hev server's relay session routes the response back over the same TCP frame stream.
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echoConn.WriteToUDP(buf[:n], raddr)
		}
	}()

	host, portStr, _ := net.SplitHostPort(serverAddr)
	port := parsePort(portStr)
	p := &Proxy{Scheme: SchemeSOCKS5, Host: host, Port: port, UDPInTCP: true}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := p.socks5UDPInTCP(ctx)
	if err != nil {
		t.Fatalf("socks5UDPInTCP(%s): %v", serverAddr, err)
	}
	defer conn.Close()

	payload := []byte("ping-from-smartproxy-over-hev-tcp")
	packet := []byte{0, 0, 0, 0x01}
	packet = append(packet, echoAddr.IP.To4()...)
	packet = append(packet, byte(echoAddr.Port>>8), byte(echoAddr.Port))
	packet = append(packet, payload...)

	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo (server=%s echo=%s): %v", serverAddr, echoAddr, err)
	}
	// The echoed frame is translated back into a SOCKS5 UDP packet: 00 00 00 ATYP ADDR PORT payload.
	got := buf[:n]
	if len(got) < 10 || got[3] != 0x01 {
		t.Fatalf("echo packet malformed: %x", got)
	}
	gotPayload := got[10:]
	if string(gotPayload) != string(payload) {
		t.Errorf("echo payload = %q, want %q", gotPayload, payload)
	}
}

// TestSocks5UDPInTCP_RealHevServer_Auth verifies the socks5 username/password entered in
// the panel is honored by the hev server's USER/PASS auth. Run with:
//
//	HEV_SOCKS5_SERVER=127.0.0.1:18080 HEV_SOCKS5_SERVER_AUTH=127.0.0.1:18081 \
//	  go test ./internal/upstream/ -run TestSocks5UDPInTCP_RealHevServer_Auth -v
//
// where 18080 is the no-auth server and 18081 an auth-enabled one
// (auth.username=socksuser / auth.password=sockspass).
func TestSocks5UDPInTCP_RealHevServer_Auth(t *testing.T) {
	serverAddr := os.Getenv("HEV_SOCKS5_SERVER_AUTH")
	if serverAddr == "" {
		t.Skip("HEV_SOCKS5_SERVER_AUTH not set; skipping auth e2e test")
	}

	host, portStr, _ := net.SplitHostPort(serverAddr)
	port := parsePort(portStr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Correct credentials must complete the CMD=5 handshake.
	good := &Proxy{Scheme: SchemeSOCKS5, Host: host, Port: port,
		Username: "socksuser", Password: "sockspass", UDPInTCP: true}
	conn, err := good.socks5UDPInTCP(ctx)
	if err != nil {
		t.Fatalf("auth socks5UDPInTCP with correct creds: %v", err)
	}
	conn.Close()

	// Wrong credentials must be rejected (handshake error), not silently fall back.
	bad := &Proxy{Scheme: SchemeSOCKS5, Host: host, Port: port,
		Username: "socksuser", Password: "wrong", UDPInTCP: true}
	if conn, err := bad.socks5UDPInTCP(ctx); err == nil {
		conn.Close()
		t.Error("auth socks5UDPInTCP with wrong password: want error, got success")
	}
}

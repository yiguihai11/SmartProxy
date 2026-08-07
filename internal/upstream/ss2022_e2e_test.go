//go:build e2e

package upstream

// End-to-end verification: SmartProxy's built-in shadowsocks client (ss:// scheme, i.e.
// "we are the sslocal") connects directly to a real shadowsocks-rust ssserver, verifying
// AEAD-2022 (SIP022) interoperability.
//
// Note the difference from rawrelay_e2e_test.go (raw UDP relay, Case A):
//   - rawrelay: the proxy protocol is socks5; after the SS server replies rep=0x07,
//     SmartProxy raw-UDP-sends directly to sslocal's listen port (equivalent to "send to sslocal");
//   - this test: the proxy protocol is ss; SmartProxy talks to ssserver directly using
//     the shadowsocks protocol (equivalent to "we are the sslocal"), with no sslocal / SOCKS5 in between.
//
// Prerequisite: SS_SERVER_BIN points to the built ssserver (must support AEAD-2022, >=v1.15).
//
// Run:
//
//	SS_SERVER_BIN=/path/ssserver go test -tags e2e ./internal/upstream/ -run TestSS2022E2E -v

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestSS2022E2E verifies sing-2022 client <-> rust-2022 server interop using a real ssserver:
//  1. ssserver starts with 2022-blake3-aes-128-gcm (mode=tcp_and_udp, base64 key)
//  2. SmartProxy connects to it directly via an ss:// URL (NewProxy's full parsing path)
//  3. TCP: connect to a local loopback echo, plaintext round-trip matches -> the 2022 TCP
//     handshake (including timestamp validation) interoperates
//  4. UDP: local loopback echo, via 2022 session-based UDP (first packet carries
//     sessionId+packetId) round-trips correctly
func TestSS2022E2E(t *testing.T) {
	serverBin := os.Getenv("SS_SERVER_BIN")
	if serverBin == "" {
		t.Skip("SS_SERVER_BIN not set")
	}

	const (
		method = "2022-blake3-aes-128-gcm"
		key    = "MDEyMzQ1Njc4OWFiY2RlZg==" // base64(16B) "0123456789abcdef", aes-128 uses a 16-byte key
	)
	serverPort := freeUDPPort(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssserver2022.json")
	cfg := fmt.Sprintf(`{
	  "server": "127.0.0.1",
	  "server_port": %d,
	  "password": %q,
	  "method": %q,
	  "mode": "tcp_and_udp"
	}`, serverPort, key, method)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ssServer := exec.Command(serverBin, "-c", cfgPath)
	ssServer.Stdout = os.Stderr
	ssServer.Stderr = os.Stderr
	if err := ssServer.Start(); err != nil {
		t.Fatalf("failed to start ssserver: %v", err)
	}
	t.Cleanup(func() {
		ssServer.Process.Kill()
		ssServer.Process.Wait()
	})
	time.Sleep(300 * time.Millisecond)

	// Local loopback target (TCP/UDP echo); the whole path does not depend on the external network
	tcpTarget, udpTarget := startLocalEchoServers(t)
	_, tcpPortStr, _ := net.SplitHostPort(tcpTarget)
	tcpPort, _ := strconv.Atoi(tcpPortStr)
	_, udpPortStr, _ := net.SplitHostPort(udpTarget)
	udpPort, _ := strconv.Atoi(udpPortStr)

	// The ss:// URL goes through full parsing: base64url(method:key) userinfo -> newSSMethod2022
	u := fmt.Sprintf("ss://%s@127.0.0.1:%d", b64url(method+":"+key), serverPort)
	p, err := NewProxy(u)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// --- TCP round-trip ---
	tcpPayload := []byte("hello over ss 2022 tcp e2e")
	tcpConn, err := p.Connect(ctx, "127.0.0.1", tcpPort)
	if err != nil {
		t.Fatalf("Connect (TCP) via 2022 failed: %v", err)
	}
	defer tcpConn.Close()
	tcpConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := tcpConn.Write(tcpPayload); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	echo := make([]byte, len(tcpPayload))
	if _, err := io.ReadFull(tcpConn, echo); err != nil {
		t.Fatalf("tcp read echo: %v", err)
	}
	if !bytes.Equal(echo, tcpPayload) {
		t.Fatalf("tcp echo mismatch: got %q want %q", echo, tcpPayload)
	}
	t.Logf("TCP round-trip OK (%d bytes) via real ssserver 2022", len(tcpPayload))

	// --- UDP round-trip ---
	udpConn, err := p.UDPAssociate(ctx, "127.0.0.1", udpPort)
	if err != nil {
		t.Fatalf("UDPAssociate via 2022 failed: %v", err)
	}
	defer udpConn.Close()

	udpPayload := []byte("hello over ss 2022 udp e2e")
	targetIP := net.ParseIP("127.0.0.1").To4()
	frame := []byte{0x00, 0x00, 0x00, 0x01} // RSV|RSV|FRAG|ATYP=IPv4
	frame = append(frame, targetIP...)
	frame = append(frame, byte(udpPort>>8), byte(udpPort))
	frame = append(frame, udpPayload...)

	udpConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := udpConn.Write(frame); err != nil {
		t.Fatalf("udp write frame: %v", err)
	}
	resp := make([]byte, 2048)
	n, err := udpConn.Read(resp)
	if err != nil {
		t.Fatalf("udp read echo: %v", err)
	}
	// Response frame = SOCKS5 UDP header (10B, IPv4 target) + original payload
	const hdrLen = 10
	if n <= hdrLen {
		t.Fatalf("udp response too short: %d bytes", n)
	}
	if !bytes.Equal(resp[hdrLen:n], udpPayload) {
		t.Fatalf("udp echo mismatch: got %q want %q", resp[hdrLen:n], udpPayload)
	}
	t.Logf("UDP round-trip OK (%d bytes) via real ssserver 2022 session", len(udpPayload))
}

// startLocalEchoServers starts local TCP + UDP loopback echo servers and returns their
// 127.0.0.1 listen addresses.
func startLocalEchoServers(t *testing.T) (tcpAddr, udpAddr string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo
			}(conn)
		}
	}()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], raddr) // echo
		}
	}()

	return ln.Addr().String(), pc.LocalAddr().String()
}

//go:build e2e

package upstream

// End-to-end verification: SmartProxy's built-in obfs-http / obfs-tls (SIP003 plugin)
// client connects directly to the real obfs-server of simple-obfs, which forwards to a
// real shadowsocks-rust ssserver, reproducing the standard SIP003 server-side setup:
//
//	[SmartProxy] --obfs+ss--> [obfs-server:OBFS_PORT] --plaintext ss--> [ssserver:SS_PORT] --echo target-->
//
// The whole TCP path goes through obfs (validating our wire interoperability with a real
// obfs-server); UDP bypasses the plugin and connects directly to the SS server port
// (obfs only obfuscates TCP, see the ssUDPAssociate comment).
//
// Prerequisites:
//   - SS_SERVER_BIN points to the built ssserver (shadowsocks-rust)
//   - OBFS_SERVER_BIN points to the built obfs-server (simple-obfs; install libev-dev/
//     libcork-dev/pkg-config first, then ./autogen.sh && ./configure --disable-documentation && make)
//
// Run:
//
//	SS_SERVER_BIN=/path/ssserver OBFS_SERVER_BIN=/path/obfs-server \
//	  go test -tags e2e ./internal/upstream/ -run TestObfsE2E -v

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestObfsE2E runs the following for both http and tls obfuscation:
//  1. ssserver starts with aes-128-gcm (mode=tcp_and_udp)
//  2. obfs-server listens on OBFS_PORT with --obfs http|tls, forwarding to 127.0.0.1:SS_PORT
//  3. SmartProxy connects to OBFS_PORT via an ss:// URL with ?plugin=obfs-local;obfs=...
//  4. TCP loopback echo round-trips unchanged -> the built-in obfs client interoperates
//     with a real obfs-server
//
// Then verify UDP: bypassing obfs and connecting directly to the SS server port,
// the round-trip matches.
func TestObfsE2E(t *testing.T) {
	serverBin := os.Getenv("SS_SERVER_BIN")
	obfsServerBin := os.Getenv("OBFS_SERVER_BIN")
	if serverBin == "" || obfsServerBin == "" {
		t.Skip("SS_SERVER_BIN / OBFS_SERVER_BIN not set")
	}

	const (
		method   = "aes-128-gcm"
		password = "smartproxy-obfs-e2e"
	)
	ssPort := freeUDPPort(t)

	// --- ssserver(TCP+UDP) ---
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssserver.json")
	cfg := fmt.Sprintf(`{
	  "server": "127.0.0.1",
	  "server_port": %d,
	  "password": %q,
	  "method": %q,
	  "mode": "tcp_and_udp"
	}`, ssPort, password, method)
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
	waitForTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ssPort)))

	// Local loopback target (TCP/UDP echo)
	tcpTarget, udpTarget := startLocalEchoServers(t)
	_, tcpPortStr, _ := net.SplitHostPort(tcpTarget)
	tcpPort, _ := strconv.Atoi(tcpPortStr)
	_, udpPortStr, _ := net.SplitHostPort(udpTarget)
	udpPort, _ := strconv.Atoi(udpPortStr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// --- TCP round-trip via obfs (http / tls) ---
	for _, obfs := range []string{"http", "tls"} {
		t.Run("obfs-"+obfs, func(t *testing.T) {
			obfsPort := freeUDPPort(t)
			obfsServer := exec.Command(obfsServerBin,
				"-s", "127.0.0.1",
				"-p", strconv.Itoa(obfsPort),
				"-r", fmt.Sprintf("127.0.0.1:%d", ssPort),
				"--obfs", obfs,
			)
			obfsServer.Stdout = os.Stderr
			obfsServer.Stderr = os.Stderr
			if err := obfsServer.Start(); err != nil {
				t.Fatalf("failed to start obfs-server: %v", err)
			}
			t.Cleanup(func() {
				obfsServer.Process.Kill()
				obfsServer.Process.Wait()
			})
			waitForTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(obfsPort)))

			// ss:// points to the obfs-server port, with SIP003 plugin
			plugin := url.QueryEscape(fmt.Sprintf("obfs-local;obfs=%s;obfs-host=www.bing.com", obfs))
			u := fmt.Sprintf("ss://%s@127.0.0.1:%d?plugin=%s", b64url(method+":"+password), obfsPort, plugin)
			p, err := NewProxy(u)
			if err != nil {
				t.Fatalf("NewProxy: %v", err)
			}

			payload := []byte("hello over " + obfs + " obfs + ss e2e")
			conn, err := p.Connect(ctx, "127.0.0.1", tcpPort)
			if err != nil {
				t.Fatalf("Connect via obfs-%s failed: %v", obfs, err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			echo := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, echo); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if !bytes.Equal(echo, payload) {
				t.Fatalf("echo mismatch: got %q want %q", echo, payload)
			}
			t.Logf("TCP round-trip OK (%d bytes) via real obfs-server (%s)", len(payload), obfs)
		})
	}

	// --- UDP bypasses obfs, connecting directly to the SS server port ---
	u := fmt.Sprintf("ss://%s@127.0.0.1:%d", b64url(method+":"+password), ssPort)
	p, err := NewProxy(u)
	if err != nil {
		t.Fatalf("NewProxy (udp): %v", err)
	}
	udpConn, err := p.UDPAssociate(ctx, "127.0.0.1", udpPort)
	if err != nil {
		t.Fatalf("UDPAssociate failed: %v", err)
	}
	defer udpConn.Close()

	udpPayload := []byte("hello over ss udp e2e (no obfs)")
	targetIP := net.ParseIP("127.0.0.1").To4()
	frame := []byte{0x00, 0x00, 0x00, 0x01}
	frame = append(frame, targetIP...)
	frame = append(frame, byte(udpPort>>8), byte(udpPort))
	frame = append(frame, udpPayload...)

	udpConn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := udpConn.Write(frame); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	resp := make([]byte, 2048)
	n, err := udpConn.Read(resp)
	if err != nil {
		t.Fatalf("udp read echo: %v", err)
	}
	const hdrLen = 10
	if n <= hdrLen {
		t.Fatalf("udp response too short: %d bytes", n)
	}
	if !bytes.Equal(resp[hdrLen:n], udpPayload) {
		t.Fatalf("udp echo mismatch: got %q want %q", resp[hdrLen:n], udpPayload)
	}
	t.Logf("UDP round-trip OK (%d bytes, bypassing obfs)", len(udpPayload))
}

// waitForTCP polls until a TCP connection can be established to addr (replaces a fixed
// sleep, avoiding process-startup jitter).
func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tcp %s not accepting connections in time", addr)
}

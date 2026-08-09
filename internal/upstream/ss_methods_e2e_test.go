//go:build e2e

package upstream

// Matrix verification for every shadowsocks encryption method SmartProxy supports:
// for each cipher it starts a real shadowsocks-rust ssserver, connects through the
// built-in client (ssConnect), and round-trips a payload to a local echo target via
// both an IP address (ATYP 0x01) and a domain name (ATYP 0x03).
//
// Prerequisite: SS_SERVER_BIN points to the built ssserver (>= v1.15 for AEAD-2022).
//
// Run:
//
//	SS_SERVER_BIN=/path/ssserver go test -tags e2e ./internal/upstream/ -run TestSSMethodsE2E -v

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

// TestSSMethodsE2E covers none/plain, classic AEAD (SIP004) and AEAD-2022 (SIP022).
func TestSSMethodsE2E(t *testing.T) {
	serverBin := os.Getenv("SS_SERVER_BIN")
	if serverBin == "" {
		t.Skip("SS_SERVER_BIN not set")
	}

	cases := []struct {
		method string
		key    string // password for classic, base64 binary key for 2022
	}{
		{"none", ""},
		{"aes-128-gcm", "smartproxy-methods-e2e"},
		{"aes-192-gcm", "smartproxy-methods-e2e"},
		{"aes-256-gcm", "smartproxy-methods-e2e"},
		{"chacha20-ietf-poly1305", "smartproxy-methods-e2e"},
		{"xchacha20-ietf-poly1305", "smartproxy-methods-e2e"},
		{"2022-blake3-aes-128-gcm", b64url(string(bytes.Repeat([]byte{0x11}, 16)))},
		{"2022-blake3-aes-256-gcm", b64url(string(bytes.Repeat([]byte{0x22}, 32)))},
		{"2022-blake3-chacha20-poly1305", b64url(string(bytes.Repeat([]byte{0x33}, 32)))},
	}

	tcpTarget, _ := startLocalEchoServers(t)
	_, portStr, _ := net.SplitHostPort(tcpTarget)
	tcpPort, _ := strconv.Atoi(portStr)

	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			serverPort := freeUDPPort(t)
			cfgPath := filepath.Join(t.TempDir(), "ssserver.json")
			cfg := fmt.Sprintf(`{
			  "server": "127.0.0.1",
			  "server_port": %d,
			  "password": %q,
			  "method": %q,
			  "mode": "tcp_only"
			}`, serverPort, tc.key, tc.method)
			if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(serverBin, "-c", cfgPath)
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatalf("failed to start ssserver: %v", err)
			}
			t.Cleanup(func() {
				cmd.Process.Kill()
				cmd.Process.Wait()
			})
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))
			if err := waitForTCPErr(addr); err != nil {
				// The reference server rejected the cipher and exited (e.g. aes-192-gcm and
				// xchacha20-ietf-poly1305 are not in shadowsocks-rust's cipher table). The
				// self-contained TestSSMethods_NoReferenceServer covers those instead.
				cmd.Wait()
				t.Skipf("%s: reference ssserver does not support this cipher (%v); covered by TestSSMethods_NoReferenceServer", tc.method, err)
			}

			// ss:// userinfo: none has no password, so the parser takes it as plaintext
			// (base64 of "none" has no ':' and would be returned undecoded); the other
			// methods use base64url(method:key).
			userinfo := "none"
			if tc.method != "none" {
				userinfo = b64url(tc.method + ":" + tc.key)
			}
			u := fmt.Sprintf("ss://%s@127.0.0.1:%d", userinfo, serverPort)
			p, err := NewProxy(u)
			if err != nil {
				t.Fatalf("NewProxy(%s): %v", u, err)
			}

			for _, target := range []struct {
				host string
				port int
			}{
				{"127.0.0.1", tcpPort}, // IP target, ATYP 0x01
				{"localhost", tcpPort}, // domain target, ATYP 0x03
			} {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				conn, err := p.Connect(ctx, target.host, target.port)
				cancel()
				if err != nil {
					t.Fatalf("Connect(%s:%d) via %s: %v", target.host, target.port, tc.method, err)
				}
				conn.SetDeadline(time.Now().Add(15 * time.Second))
				payload := []byte("round-trip " + tc.method + " -> " + target.host)
				if _, err := conn.Write(payload); err != nil {
					conn.Close()
					t.Fatalf("write: %v", err)
				}
				echo := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, echo); err != nil {
					conn.Close()
					t.Fatalf("read echo: %v", err)
				}
				conn.Close()
				if !bytes.Equal(echo, payload) {
					t.Fatalf("echo mismatch: got %q want %q", echo, payload)
				}
			}
			t.Logf("%s: round-trip OK (IP + domain)", tc.method)
		})
	}
}

// waitForTCPErr polls until a TCP connection to addr succeeds, returning an error instead
// of failing the test (unlike the shared waitForTCP helper).
func waitForTCPErr(addr string) error {
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return lastErr
}

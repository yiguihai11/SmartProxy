//go:build e2e

package upstream

// End-to-end verification: the built-in v2ray-plugin/xray-plugin (SIP003) client of
// SmartProxy connects directly to a real teddysun/v2ray-plugin server, which forwards
// to a real shadowsocks-rust ssserver -- replicating all 5 Android transport modes
// (websocket-http / websocket-tls / grpc / grpc-tls / quic-tls), verifying a TCP
// loopback echo per mode:
//
//	[SmartProxy] --v2ray-plugin--> [v2ray-plugin server:PUB] --plaintext ss--> [ssserver:SS_PORT] --echo target-->
//
// websocket defaults to mux=1 and uses the mux frame protocol; grpc/quic carry the
// raw byte stream. UDP does not go through the plugin; it connects directly to the SS
// server port (the same SIP003 semantics as obfs).
//
// Prerequisites:
//   - SS_SERVER_BIN points to a built ssserver (shadowsocks-rust)
//   - V2RAY_PLUGIN_BIN points to a built v2ray-plugin server binary
//
// Run:
//
//	SS_SERVER_BIN=/path/ssserver V2RAY_PLUGIN_BIN=/path/v2ray-plugin-bin \
//	  go test -tags e2e ./internal/upstream/ -run TestV2rayPluginE2E -v

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestV2rayPluginE2E runs a TCP loopback echo verification for each of the 5 Android transport modes.
func TestV2rayPluginE2E(t *testing.T) {
	serverBin := os.Getenv("SS_SERVER_BIN")
	pluginBin := os.Getenv("V2RAY_PLUGIN_BIN")
	if serverBin == "" || pluginBin == "" {
		t.Skip("SS_SERVER_BIN / V2RAY_PLUGIN_BIN not set")
	}

	const (
		method   = "aes-128-gcm"
		password = "smartproxy-v2ray-e2e"
		host     = "www.10010.com" // matches the server's -host; TLS modes use the same certificate
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

	// local TCP loopback target
	tcpTarget, _ := startLocalEchoServers(t)
	_, tcpPortStr, _ := net.SplitHostPort(tcpTarget)
	tcpPort, _ := strconv.Atoi(tcpPortStr)

	// self-signed certificate (needed by TLS modes: websocket-tls / grpc-tls / quic server)
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	certPEM, err := genE2ECert(certPath, keyPath, host)
	if err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	certRawB64 := base64.StdEncoding.EncodeToString(certPEM)

	modes := []struct {
		name string // test name
		mode string // passed to the plugin as -mode
		tls  bool   // whether to pass -tls (quic forces TLS, enabled by the plugin itself)
	}{
		{"websocket-http", "websocket", false},
		{"websocket-tls", "websocket", true},
		{"grpc", "grpc", false},
		{"grpc-tls", "grpc", true},
		{"quic-tls", "quic", false}, // quic forces tls; the client pins the self-signed cert via certRaw
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			pubPort := freeUDPPort(t)

			args := []string{
				"-server",
				"-localAddr", "127.0.0.1",
				"-localPort", strconv.Itoa(pubPort),
				"-remoteAddr", "127.0.0.1",
				"-remotePort", strconv.Itoa(ssPort),
				"-mode", m.mode,
				"-host", host,
				"-loglevel", "warning",
			}
			if m.tls || m.mode == "quic" {
				args = append(args, "-tls", "-cert", certPath, "-key", keyPath)
			}
			plugin := exec.Command(pluginBin, args...)
			plugin.Stdout = os.Stderr
			plugin.Stderr = os.Stderr
			if err := plugin.Start(); err != nil {
				t.Fatalf("failed to start v2ray-plugin server: %v", err)
			}
			t.Cleanup(func() {
				plugin.Process.Kill()
				plugin.Process.Wait()
			})
			if m.mode == "quic" {
				// quic listens on UDP; wait for the SS service port (TCP) to be ready,
				// then give the plugin a startup buffer.
				waitForTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ssPort)))
				time.Sleep(800 * time.Millisecond)
			} else {
				waitForTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(pubPort)))
			}

			// assemble the client ?plugin= parameter (matching the ss-android export format)
			opts := fmt.Sprintf("v2ray-plugin;mode=%s;host=%s", m.mode, host)
			if m.tls {
				opts += ";tls"
			}
			if m.tls || m.mode == "quic" {
				opts += ";certRaw=" + certRawB64
			}
			u := fmt.Sprintf("ss://%s@127.0.0.1:%d?plugin=%s", b64url(method+":"+password), pubPort, url.QueryEscape(opts))
			p, err := NewProxy(u)
			if err != nil {
				t.Fatalf("NewProxy: %v", err)
			}

			payload := []byte("hello over v2ray-plugin " + m.name + " + ss e2e")
			conn, err := p.Connect(ctx, "127.0.0.1", tcpPort)
			if err != nil {
				t.Fatalf("Connect via %s failed: %v", m.name, err)
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
			t.Logf("TCP round-trip OK (%d bytes) via real v2ray-plugin (%s)", len(payload), m.name)
		})
	}
}

// genE2ECert generates a self-signed ECDSA certificate for host, writes it to disk
// and returns the PEM content (for certRaw pinning). Same approach as the vcmux experiment.
func genE2ECert(certPath, keyPath, host string) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return certPEM, nil
}

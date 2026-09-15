package upstream

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestNewProxy_SingBoxSchemes(t *testing.T) {
	tests := []struct {
		name       string
		link       string
		wantScheme ProxyScheme
		wantHost   string
		wantPort   int
		wantTag    string
		wantName   string
		udpSupport bool
	}{
		{
			name:       "vless",
			link:       "vless://bf6dfd00-4b53-41bb-98f5-46f9e612803c@1.2.3.4:443?security=reality&sni=example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=6ba7b810#Node-VLESS",
			wantScheme: SchemeVLESS,
			wantHost:   "1.2.3.4",
			wantPort:   443,
			wantName:   "Node-VLESS",
			udpSupport: true,
		},
		{
			name:       "hysteria2",
			link:       "hysteria2://secret-pass@2.3.4.5:8443?sni=hy2.example.com#Hy2-Node",
			wantScheme: SchemeHysteria2,
			wantHost:   "2.3.4.5",
			wantPort:   8443,
			wantName:   "Hy2-Node",
			udpSupport: true,
		},
		{
			name:       "trojan",
			link:       "trojan://trojan-secret@3.4.5.6:443?sni=trojan.example.com#Trojan-Node",
			wantScheme: SchemeTrojan,
			wantHost:   "3.4.5.6",
			wantPort:   443,
			wantName:   "Trojan-Node",
			udpSupport: true,
		},
		{
			name:       "tuic",
			link:       "tuic://bf6dfd00-4b53-41bb-98f5-46f9e612803c:tuic-pass@4.5.6.7:9443?sni=tuic.example.com#TUIC-Node",
			wantScheme: SchemeTUIC,
			wantHost:   "4.5.6.7",
			wantPort:   9443,
			wantName:   "TUIC-Node",
			udpSupport: true,
		},
		{
			name:       "raw-json",
			link:       `{"type":"shadowsocks","tag":"lantern-hk-01","server":"5.6.7.8","server_port":8388,"method":"aes-128-gcm","password":"pass"}`,
			wantScheme: "shadowsocks",
			wantHost:   "5.6.7.8",
			wantPort:   8388,
			wantName:   "lantern-hk-01",
			udpSupport: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewProxy(tt.link)
			if err != nil {
				if strings.Contains(err.Error(), "not included in this build") || strings.Contains(err.Error(), "uTLS is required") {
					t.Skipf("skipping %s: build tag missing: %v", tt.name, err)
				}
				t.Fatalf("NewProxy failed: %v", err)
			}
			if p.Scheme != tt.wantScheme {
				t.Errorf("Scheme = %v, want %v", p.Scheme, tt.wantScheme)
			}
			if p.Host != tt.wantHost {
				t.Errorf("Host = %v, want %v", p.Host, tt.wantHost)
			}
			if p.Port != tt.wantPort {
				t.Errorf("Port = %v, want %v", p.Port, tt.wantPort)
			}
			if p.singboxTag == "" {
				t.Errorf("singboxTag should not be empty")
			}
			if p.SchemeSupportsUDP() != tt.udpSupport {
				t.Errorf("SchemeSupportsUDP = %v, want %v", p.SchemeSupportsUDP(), tt.udpSupport)
			}

			// Test MaskProxyURL does not leak sensitive information
			masked := MaskProxyURL(tt.link)
			if masked == tt.link && (tt.name != "raw-json") {
				t.Errorf("MaskProxyURL should mask credentials, got %s", masked)
			}
		})
	}
}

func TestSingBoxProxy_DirectConnectInProcess(t *testing.T) {
	// Start a local TCP echo server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(append([]byte("echo:"), buf[:n]...))
	}()

	// Register a direct sing-box outbound
	directJSON := fmt.Sprintf(`{"type":"direct","tag":"sb-test-direct"}`)
	p, err := NewProxy(directJSON)
	if err != nil {
		t.Fatalf("NewProxy(direct) failed: %v", err)
	}

	ctx := context.Background()
	conn, err := p.Connect(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	resp := make([]byte, 32)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(resp[:n]) != "echo:hello" {
		t.Errorf("got %q, want 'echo:hello'", string(resp[:n]))
	}
}

func TestManager_SetProviderProxies(t *testing.T) {
	mgr, err := NewManager(UpstreamConfig{
		Default: "round_robin",
		Proxies: []ProxyEntry{
			{
				Alias: "static-1",
				URL:   `{"type":"direct","tag":"static-direct"}`,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Stop()

	// Initial state: only static-1
	if len(mgr.defaultProxies) != 1 {
		t.Fatalf("expected 1 initial proxy, got %d", len(mgr.defaultProxies))
	}

	// Register 2 Lantern provider nodes
	lanternNodes := []ProxyEntry{
		{
			Alias: "[Lantern] JP-01",
			URL:   `{"type":"direct","tag":"lantern-jp"}`,
		},
		{
			Alias: "[Lantern] US-01",
			URL:   `{"type":"direct","tag":"lantern-us"}`,
		},
	}
	mgr.SetProviderProxies("lantern", lanternNodes)

	if len(mgr.defaultProxies) != 3 {
		t.Fatalf("expected 3 proxies after provider register, got %d", len(mgr.defaultProxies))
	}
	if _, ok := mgr.aliasMap["[Lantern] JP-01"]; !ok {
		t.Errorf("expected [Lantern] JP-01 in aliasMap")
	}
	if _, ok := mgr.aliasMap["[Lantern] US-01"]; !ok {
		t.Errorf("expected [Lantern] US-01 in aliasMap")
	}

	// Manually pin one provider circuit
	if err := mgr.SetCircuitHealth("[Lantern] JP-01", "tcp", "disable"); err != nil {
		t.Fatalf("SetCircuitHealth failed: %v", err)
	}
	if mgr.aliasMap["[Lantern] JP-01"].IsAvailable() {
		t.Errorf("expected [Lantern] JP-01 to be disabled")
	}

	// Update provider nodes (e.g. account rotated or new nodes)
	updatedNodes := []ProxyEntry{
		{
			Alias: "[Lantern] JP-01", // Should keep manual disabled pin!
			URL:   `{"type":"direct","tag":"lantern-jp-v2"}`,
		},
		{
			Alias: "[Lantern] SG-01",
			URL:   `{"type":"direct","tag":"lantern-sg"}`,
		},
	}
	mgr.SetProviderProxies("lantern", updatedNodes)

	if len(mgr.defaultProxies) != 3 {
		t.Fatalf("expected 3 proxies after provider update, got %d", len(mgr.defaultProxies))
	}
	if _, ok := mgr.aliasMap["[Lantern] US-01"]; ok {
		t.Errorf("[Lantern] US-01 should have been removed")
	}
	if _, ok := mgr.aliasMap["[Lantern] SG-01"]; !ok {
		t.Errorf("[Lantern] SG-01 should be present")
	}
	// Verify manual pin was preserved
	if mgr.aliasMap["[Lantern] JP-01"].IsAvailable() {
		t.Errorf("[Lantern] JP-01 manual pin should have been preserved across update")
	}

	// Remove provider nodes
	mgr.SetProviderProxies("lantern", nil)
	if len(mgr.defaultProxies) != 1 {
		t.Fatalf("expected 1 proxy after provider remove, got %d", len(mgr.defaultProxies))
	}
}


package lantern

import (
	"encoding/json"
	"testing"
	"time"

	"smartproxy/internal/upstream"
)

func TestProvider_LifecycleAndNodeInjection(t *testing.T) {
	mgr, err := upstream.NewManager(upstream.UpstreamConfig{
		Default: "round_robin",
		Proxies: []upstream.ProxyEntry{
			{
				Alias: "static-proxy",
				URL:   `{"type":"direct","tag":"static-direct"}`,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Stop()

	// Initial count
	if len(mgr.Proxies()) != 1 {
		t.Fatalf("expected 1 initial proxy, got %d", len(mgr.Proxies()))
	}

	tempDir := t.TempDir()
	p, err := NewProvider(Config{
		DataDir:         tempDir,
		MaxAccounts:     5,
		FilterDeadNodes: false,
	}, mgr)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	// Manually inject candidate nodes and mock account to verify SetProviderProxies mapping
	mockNode := json.RawMessage(`{"type":"direct","tag":"jp-tokyo-01"}`)
	p.client.mu.Lock()
	p.client.currentAccount = &Account{DeviceID: "mock-dev", QuotaOK: true}
	p.client.currentNodes = []json.RawMessage{mockNode}
	p.client.mu.Unlock()

	p.refreshNodes()

	proxies := mgr.Proxies()
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies after refresh, got %d", len(proxies))
	}

	foundLantern := false
	for _, px := range proxies {
		if px.Alias == "[Lantern] jp-tokyo-01" {
			foundLantern = true
			if px.Scheme != "direct" {
				t.Errorf("expected scheme direct, got %s", px.Scheme)
			}
		}
	}
	if !foundLantern {
		t.Errorf("expected [Lantern] jp-tokyo-01 in proxy list")
	}

	// Stop provider -> lantern nodes removed from manager
	p.Stop()
	time.Sleep(10 * time.Millisecond)

	proxies = mgr.Proxies()
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy after provider stop, got %d", len(proxies))
	}
}

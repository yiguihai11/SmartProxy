package subscription

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"smartproxy/internal/config"
	"smartproxy/internal/upstream"
)

func TestManager_LifecycleAndCache(t *testing.T) {
	tempDir := t.TempDir()

	// Mock subscription server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=1024; download=2048; total=1000000; expire=1800000000")
		w.Header().Set("Content-Type", "application/json")
		doc := sip008Doc{
			Version: 1,
			Servers: []sip008Server{
				{
					ID:         "node-1",
					Remarks:    "HK 01",
					Server:     "1.2.3.4",
					ServerPort: 8388,
					Method:     "chacha20-ietf-poly1305",
					Password:   "pwd1",
				},
				{
					ID:         "node-2",
					Remarks:    "JP 01",
					Server:     "5.6.7.8",
					ServerPort: 8388,
					Method:     "aes-128-gcm",
					Password:   "pwd2",
				},
			},
		}
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	mgrConfig := upstream.UpstreamConfig{
		Default: "failover",
	}
	upMgr, err := upstream.NewManager(mgrConfig)
	if err != nil {
		t.Fatalf("failed to create upstream manager: %v", err)
	}

	subsConf := []config.SubscriptionConf{
		{
			Name:           "TestSub",
			URL:            ts.URL,
			Type:           "auto",
			UpdateInterval: "1h",
			Enabled:        true,
		},
	}

	subMgr := NewManager(tempDir, subsConf, upMgr)
	defer subMgr.Stop()

	// 1. Refresh subscription
	count, err := subMgr.Refresh(context.Background(), "TestSub")
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 nodes, got %d", count)
	}

	// Verify status
	status := subMgr.Status()
	if len(status) != 1 {
		t.Fatalf("expected 1 status item, got %d", len(status))
	}
	if status[0].NodeCount != 2 {
		t.Errorf("expected node_count=2, got %d", status[0].NodeCount)
	}
	if status[0].Total != 1000000 {
		t.Errorf("expected total=1000000, got %d", status[0].Total)
	}

	// Verify cache file was written to disk
	cacheFile := filepath.Join(tempDir, cacheFileName)
	if _, err := os.Stat(cacheFile); err != nil {
		t.Errorf("cache file was not created: %v", err)
	}

	// 2. Simulate app restart with a new manager pointing at the same cache directory
	subMgr2 := NewManager(tempDir, subsConf, upMgr)
	defer subMgr2.Stop()

	// Immediately check status — should have restored 2 nodes from cache without network fetch!
	status2 := subMgr2.Status()
	if len(status2) != 1 || status2[0].NodeCount != 2 {
		t.Errorf("expected 2 nodes restored from cache, got %+v", status2)
	}

	// Test RemoveNodes
	removed := subMgr2.RemoveNodes([]string{"HK 01"})
	if removed != 1 {
		t.Errorf("expected 1 node removed, got %d", removed)
	}
	if st := subMgr2.Status(); len(st) != 1 || st[0].NodeCount != 1 {
		t.Errorf("expected 1 node remaining, got %+v", st)
	}

	// 3. Test Reload: disable subscription
	subsConf[0].Enabled = false
	subMgr2.Reload(subsConf)
	statusDisabled := subMgr2.Status()
	if statusDisabled[0].Enabled != false {
		t.Errorf("expected Enabled=false")
	}

	// 4. Test Reload: remove subscription
	subMgr2.Reload([]config.SubscriptionConf{})
	statusEmpty := subMgr2.Status()
	if len(statusEmpty) != 0 {
		t.Errorf("expected empty status after reload")
	}
}

func TestManager_ErrorHandling(t *testing.T) {
	tempDir := t.TempDir()

	mgrConfig := upstream.UpstreamConfig{Default: "failover"}
	upMgr, _ := upstream.NewManager(mgrConfig)

	// Sub pointing to invalid URL
	subsConf := []config.SubscriptionConf{
		{
			Name:    "BadSub",
			URL:     "http://127.0.0.1:59999/does-not-exist",
			Enabled: true,
		},
	}

	subMgr := NewManager(tempDir, subsConf, upMgr)
	defer subMgr.Stop()

	_, err := subMgr.Refresh(context.Background(), "BadSub")
	if err == nil {
		t.Fatalf("expected error on invalid URL")
	}

	status := subMgr.Status()
	if len(status) != 1 || status[0].LastError == "" {
		t.Errorf("expected LastError to be recorded, got %+v", status)
	}
}

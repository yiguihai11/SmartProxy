package adblock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestManagerRefreshAndCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "\"v1\"")
		_, _ = w.Write([]byte("||ads.example^\n"))
	}))
	defer server.Close()
	m := NewManager(t.TempDir(), []Subscription{{Name:"test", URL:server.URL, Enabled:true, UseProxy: boolPtr(false)}})
	if err := m.Refresh(context.Background(), "test"); err != nil { t.Fatal(err) }
	if !m.Blocked("x.ads.example") { t.Fatal("expected fetched rule active") }
	if _, err := filepath.Glob(filepath.Join(filepath.Dir(m.cachePath(m.subs[0])), "adblock-*.json")); err != nil { t.Fatal(err) }
}

func TestManagerKeepsLastGoodRulesOnBadRefresh(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 { _, _ = w.Write([]byte("||ads.example^\n")); return }
		_, _ = w.Write([]byte("unsupported-only"))
	}))
	defer server.Close()
	m := NewManager(t.TempDir(), []Subscription{{Name:"test", URL:server.URL, Enabled:true, UseProxy: boolPtr(false)}})
	if err := m.Refresh(context.Background(), "test"); err != nil { t.Fatal(err) }
	if err := m.Refresh(context.Background(), "test"); err == nil { t.Fatal("expected parse failure") }
	if !m.Blocked("ads.example") { t.Fatal("last good rules must remain active") }
}

func boolPtr(v bool) *bool { return &v }

func TestSubscriptionProxyDefaultsOn(t *testing.T) {
	if !(Subscription{URL: "https://example.com"}).UsesProxy() {
		t.Fatal("missing use_proxy should default to true")
	}
	if (Subscription{UseProxy: boolPtr(false)}).UsesProxy() {
		t.Fatal("explicit use_proxy=false should disable proxy")
	}
}

func TestProxyFetchRequiresUpstreamManager(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("||ads.example^\n"))
	}))
	defer server.Close()
	m := NewManager(t.TempDir(), []Subscription{{Name: "test", URL: server.URL, Enabled: true}})
	if err := m.Refresh(context.Background(), "test"); err == nil {
		t.Fatal("expected proxy-configured subscription to fail without upstream manager")
	}
	if m.Blocked("ads.example") {
		t.Fatal("failed proxy fetch must not activate rules")
	}
}

func TestManagerCountsBlockedQueriesBySubscription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("||ads.example^\n")) }))
	defer server.Close()
	m := NewManager(t.TempDir(), []Subscription{{Name:"test", URL:server.URL, Enabled:true, UseProxy:boolPtr(false)}})
	if err := m.Refresh(context.Background(), "test"); err != nil { t.Fatal(err) }
	for i:=0;i<3;i++ { if !m.Blocked("cdn.ads.example") { t.Fatal("expected blocked") } }
	status:=m.Status()
	if len(status)!=1 || status[0].Hits!=3 { t.Fatalf("expected 3 hits, got %+v",status) }
}

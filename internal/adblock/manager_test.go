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
	m := NewManager(t.TempDir(), []Subscription{{Name:"test", URL:server.URL, Enabled:true}})
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
	m := NewManager(t.TempDir(), []Subscription{{Name:"test", URL:server.URL, Enabled:true}})
	if err := m.Refresh(context.Background(), "test"); err != nil { t.Fatal(err) }
	if err := m.Refresh(context.Background(), "test"); err == nil { t.Fatal("expected parse failure") }
	if !m.Blocked("ads.example") { t.Fatal("last good rules must remain active") }
}

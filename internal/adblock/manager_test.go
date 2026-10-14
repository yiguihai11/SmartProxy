package adblock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"smartproxy/internal/config"
)

func TestManagerFetchAndPreserveGoodData(t *testing.T) {
	var body atomic.Pointer[string]
	initContent := "||ads.example.com^\n||tracker.net^\n"
	body.Store(&initContent)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"test-etag-1"`)
		b := body.Load()
		if b == nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(*b))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	conf := config.AdblockConf{
		Enabled:   true,
		CacheFile: "adblock_cache.txt",
		Lists: []config.AdblockListConf{
			{
				Name:    "test-list",
				URL:     server.URL,
				Enabled: true,
			},
		},
	}

	var currentSet atomic.Pointer[Set]
	sink := func(s *Set) {
		currentSet.Store(s)
	}

	mgr := NewManager(tmpDir, conf, nil, sink)
	defer mgr.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. 初始刷新: 正常加载 2 条规则
	kept, err := mgr.Refresh(ctx, "test-list")
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if kept < 2 {
		t.Fatalf("expected at least 2 kept rules, got %d", kept)
	}
	s := currentSet.Load()
	if s == nil || !s.Blocked("ads.example.com") {
		t.Fatal("expected ads.example.com to be blocked")
	}

	// 2. 模拟服务器故障 (HTTP 500): 必须保留上次好数据
	body.Store(nil)
	_, err = mgr.Refresh(ctx, "test-list")
	if err == nil {
		t.Fatal("expected refresh error on 500")
	}
	s = currentSet.Load()
	if s == nil || !s.Blocked("ads.example.com") {
		t.Fatal("expected previous good data to be preserved after 500 failure")
	}
	st := mgr.Status()
	if st.Items[0].LastError == "" {
		t.Fatal("expected LastError to be populated")
	}

	// 3. 模拟空清单返回: 同样必须保留上次好数据
	emptyContent := "# Just comments\n\n"
	body.Store(&emptyContent)
	_, err = mgr.Refresh(ctx, "test-list")
	if err == nil {
		t.Fatal("expected error on empty rules list")
	}
	s = currentSet.Load()
	if s == nil || !s.Blocked("ads.example.com") {
		t.Fatal("expected previous good data to be preserved after empty list")
	}
}

func TestManagerWhitelistImmediateRebuild(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("||ads.example.com^\n"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	conf := config.AdblockConf{
		Enabled:   true,
		CacheFile: "adblock_cache.txt",
		Lists: []config.AdblockListConf{
			{
				Name:    "list1",
				URL:     server.URL,
				Enabled: true,
			},
		},
	}

	var currentSet atomic.Pointer[Set]
	sink := func(s *Set) {
		currentSet.Store(s)
	}

	mgr := NewManager(tmpDir, conf, nil, sink)
	defer mgr.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := mgr.Refresh(ctx, "list1")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	s := currentSet.Load()
	if s == nil || !s.Blocked("ads.example.com") {
		t.Fatal("ads.example.com should be blocked initially")
	}

	// 添加白名单: 必须立即重建快照且放行该域名与子域名
	if err := mgr.AddWhitelist("ads.example.com"); err != nil {
		t.Fatalf("add whitelist: %v", err)
	}
	s = currentSet.Load()
	if s == nil || s.Blocked("ads.example.com") {
		t.Fatal("ads.example.com should be unblocked immediately after whitelist addition")
	}
	if s.Blocked("sub.ads.example.com") {
		t.Fatal("sub.ads.example.com should also be unblocked by parent whitelist")
	}

	// 移除白名单: 立即恢复拦截
	if err := mgr.RemoveWhitelist("ads.example.com"); err != nil {
		t.Fatalf("remove whitelist: %v", err)
	}
	s = currentSet.Load()
	if s == nil || !s.Blocked("ads.example.com") {
		t.Fatal("ads.example.com should be blocked again after whitelist removal")
	}
}

func TestManagerCompactCacheRestoration(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "test_cache.txt")

	// 手工写入紧凑缓存
	cacheData := "||cached-ad.com^\n@@||safe.cached-ad.com^\n"
	if err := os.WriteFile(cachePath, []byte(cacheData), 0o600); err != nil {
		t.Fatal(err)
	}

	conf := config.AdblockConf{
		Enabled:   true,
		CacheFile: cachePath,
	}

	var currentSet atomic.Pointer[Set]
	sink := func(s *Set) {
		currentSet.Store(s)
	}

	mgr := NewManager(tmpDir, conf, nil, sink)
	defer mgr.Stop()

	// 启动读取缓存
	mgr.Start()
	time.Sleep(100 * time.Millisecond)

	s := currentSet.Load()
	if s == nil {
		t.Fatal("expected snapshot to be restored from cache")
	}
	if !s.Blocked("cached-ad.com") {
		t.Fatal("cached-ad.com should be blocked from restored cache")
	}
	if s.Blocked("safe.cached-ad.com") {
		t.Fatal("safe.cached-ad.com should be exempt by restored cache allow rule")
	}
}

package route

import (
	"errors"
	"net"
	"testing"
	"time"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/upstream"
)

func TestBlacklist_AddAndCheck(t *testing.T) {
	b := NewBlacklist("test")
	if b.IsBlacklisted("example.com", 443) {
		t.Error("should not be blacklisted initially")
	}
	b.Add("example.com", 443, 10*time.Second, "connection refused")
	if !b.IsBlacklisted("example.com", 443) {
		t.Error("should be blacklisted after add")
	}
}

func TestBlacklist_Expired(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("example.com", 443, 1*time.Millisecond, "timeout")
	time.Sleep(10 * time.Millisecond)
	if b.IsBlacklisted("example.com", 443) {
		t.Error("should not be blacklisted after expiry")
	}
}

func TestBlacklist_DifferentPorts(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("example.com", 443, 10*time.Second, "reset")
	if b.IsBlacklisted("example.com", 80) {
		t.Error("different port should not match")
	}
	if !b.IsBlacklisted("example.com", 443) {
		t.Error("correct port should match")
	}
}

func TestBlacklist_DifferentHosts(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("example.com", 443, 10*time.Second, "dial failed")
	if b.IsBlacklisted("other.com", 443) {
		t.Error("different host should not match")
	}
}

func TestBlacklist_SnapshotCache(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("b.com", 443, time.Hour, "r1")
	b.Add("a.com", 443, time.Hour, "r2")
	// 结构性变更(Add)立即反映到快照,最近添加的 a.com 排前。
	e := b.Entries()
	if len(e) != 2 {
		t.Fatalf("want 2 entries, got %d", len(e))
	}
	if e[0].Host != "a.com" {
		t.Fatalf("want a.com (last added) first, got %s", e[0].Host)
	}
	// 无变更时快照稳定(两次 Entries 一致)。
	if e2 := b.Entries(); len(e2) != 2 {
		t.Fatalf("cached snapshot should stay consistent, got %d", len(e2))
	}
	// Remove 立即反映。
	b.Remove("b.com", 443)
	if e3 := b.Entries(); len(e3) != 1 || e3[0].Host != "a.com" {
		t.Fatalf("after remove want only a.com, got %d entries", len(e3))
	}
}

func TestBlacklist_SnapshotReorderAfterHit(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("a.com", 443, time.Hour, "r1")
	b.Add("b.com", 443, time.Hour, "r2")
	got := b.Entries()
	if got[0].Host != "b.com" {
		t.Fatalf("want b.com first initially, got %s", got[0].Host)
	}
	// 命中 a.com 刷新 lastHit;命中类变更经 hitRebuildInterval 节流后重建,a.com 置顶。
	if !b.IsBlacklisted("a.com", 443) {
		t.Fatal("a.com should be hit")
	}
	time.Sleep(hitRebuildInterval + 50*time.Millisecond)
	got = b.Entries()
	if got[0].Host != "a.com" {
		t.Fatalf("want a.com first after hit, got %s", got[0].Host)
	}
}

func TestBlacklist_CleanExpired(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("keep.com", 443, 10*time.Second, "timeout")
	b.Add("expire.com", 443, 1*time.Millisecond, "timeout")
	time.Sleep(10 * time.Millisecond)
	b.cleanExpired()
	if b.Len() != 1 {
		t.Errorf("expected 1 entry after cleanup, got %d", b.Len())
	}
	if b.IsBlacklisted("expire.com", 443) {
		t.Error("expired entry should be removed")
	}
	if !b.IsBlacklisted("keep.com", 443) {
		t.Error("non-expired entry should remain")
	}
}

func TestBlacklist_Len(t *testing.T) {
	b := NewBlacklist("test")
	if b.Len() != 0 {
		t.Error("new blacklist should be empty")
	}
	b.Add("a.com", 80, 10*time.Second, "test")
	b.Add("b.com", 80, 10*time.Second, "test")
	if b.Len() != 2 {
		t.Errorf("expected 2, got %d", b.Len())
	}
}

func TestBlacklist_Duplicate(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("example.com", 443, 5*time.Second, "first reason")
	b.Add("example.com", 443, 10*time.Second, "second reason")
	if b.Len() != 1 {
		t.Errorf("duplicate should update in place, got %d entries", b.Len())
	}
	if !b.IsBlacklisted("example.com", 443) {
		t.Error("should still be blacklisted")
	}
}

func TestBlacklist_EntriesIncludesReason(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("example.com", 443, 10*time.Second, "connection refused")
	entries := b.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].LastReason != "connection refused" {
		t.Errorf("expected 'connection refused', got %q", entries[0].LastReason)
	}
	if entries[0].Host != "example.com" {
		t.Errorf("expected 'example.com', got %q", entries[0].Host)
	}
	if entries[0].Port != 443 {
		t.Errorf("expected 443, got %d", entries[0].Port)
	}
}

func TestSimplifyError_Timeout(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: &testTimeoutError{}}
	got := simplifyError(err, "1.2.3.4", 80)
	if got != "i/o timeout" {
		t.Errorf("expected 'i/o timeout', got %q", got)
	}
}

type testTimeoutError struct{}

func (e *testTimeoutError) Error() string   { return "mock timeout" }
func (e *testTimeoutError) Timeout() bool   { return true }
func (e *testTimeoutError) Temporary() bool { return true }

func TestSimplifyError_ConnectionRefused(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	got := simplifyError(err, "host", 80)
	if got != "connection refused" {
		t.Errorf("expected 'connection refused', got %q", got)
	}
}

func newRouter() *Router {
	cn := chnroute.New()
	mgr, _ := upstream.NewManager(upstream.UpstreamConfig{Default: "failover"})
	return New(cn, mgr, false, 3*time.Second, nil, 300*time.Second)
}

func TestRouter_IsDomesticByIP(t *testing.T) {
	r := newRouter()
	if r.IsDomesticByIP("") {
		t.Error("empty string should not be domestic")
	}
}

func TestRouter_BlacklistSnapshot(t *testing.T) {
	r := newRouter()
	r.domainBlacklist.Add("test.com", 443, 10*time.Second, "connection refused")
	ipEntries, domainEntries := r.BlacklistSnapshot()
	if len(ipEntries) != 0 {
		t.Error("ip blacklist should be empty")
	}
	if len(domainEntries) != 1 {
		t.Fatalf("expected 1 domain entry, got %d", len(domainEntries))
	}
	if domainEntries[0].LastReason != "connection refused" {
		t.Errorf("expected 'connection refused', got %q", domainEntries[0].LastReason)
	}
}

func TestRouter_AddToBlacklists_Domain(t *testing.T) {
	r := newRouter()
	r.addToBlacklists("1.2.3.4", 443, "example.com", "timeout")
	if !r.ipBlacklist.IsBlacklisted("1.2.3.4", 443) {
		t.Error("ip should be blacklisted")
	}
	if !r.domainBlacklist.IsBlacklisted("example.com", 443) {
		t.Error("domain should be blacklisted")
	}
}

func TestRouter_AddToBlacklists_NoDomain(t *testing.T) {
	r := newRouter()
	r.addToBlacklists("1.2.3.4", 80, "", "dial failed")
	if !r.ipBlacklist.IsBlacklisted("1.2.3.4", 80) {
		t.Error("ip should be blacklisted")
	}
}

func TestRouter_UpdateConfig(t *testing.T) {
	cn := chnroute.New()
	mgr, _ := upstream.NewManager(upstream.UpstreamConfig{Default: "failover"})
	r := New(cn, mgr, true, 3*time.Second, nil, 300*time.Second)

	cfg := r.cfg.Load()
	if cfg.smartTimeout != 3*time.Second {
		t.Errorf("expected 3s timeout, got %v", cfg.smartTimeout)
	}
	r.UpdateConfig(5*time.Second, 600*time.Second)
	cfg = r.cfg.Load()
	if cfg.smartTimeout != 5*time.Second {
		t.Errorf("expected 5s timeout after update, got %v", cfg.smartTimeout)
	}
}

package upstream

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"smartproxy/internal/rules"
)

func TestNewManager_Empty(t *testing.T) {
	m, err := NewManager(UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.aliasMap) != 1 {
		t.Errorf("expected 1 alias (direct), got %d", len(m.aliasMap))
	}
	if _, ok := m.aliasMap["direct"]; !ok {
		t.Error("direct alias should exist")
	}
	if m.strategy != "" {
		t.Errorf("expected empty strategy, got %s", m.strategy)
	}
}

func TestNewManager_UDPInTCPEntryDefaultsTCPDown(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "hev", URL: "socks5://hev.proxy:1080", UDPInTCP: true},
			{Alias: "plain", URL: "socks5://plain.proxy:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hev := m.aliasMap["hev"]
	if hev == nil || !hev.UDPInTCP {
		t.Fatal("hev node should be UDPInTCP")
	}
	// The config-field udp_in_tcp switch (not the URL query) also pins TCP manually down:
	// plaintext framed carrier is GFW-fingerprintable, so TCP defaults off.
	if hev.EffectiveMode() != ModeUDPOnly {
		t.Errorf("hev EffectiveMode = %s, want udp_only (default)", hev.EffectiveMode())
	}
	if !hev.health.IsManuallyDisabled() {
		t.Error("hev TCP should be manually disabled (manual pin down), not auto-open")
	}
	if !hev.SupportsUDP() {
		t.Error("hev node should still support UDP routing (framed path)")
	}
	plain := m.aliasMap["plain"]
	if plain == nil {
		t.Fatal("plain node missing")
	}
	if plain.IsUDPOnly() {
		t.Error("plain socks5 node should not be udp_only")
	}

	// The user can re-enable TCP; the node returns to full tcp_and_udp.
	hev.health.SetManualState(true)
	if hev.EffectiveMode() != ModeTCPAndUDP {
		t.Errorf("after enable: EffectiveMode = %s, want tcp_and_udp", hev.EffectiveMode())
	}

	// A reload preserves the user's re-enable (restoreManualPins wins over the
	// construction default) instead of reverting to the manual TCP-down.
	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "hev", URL: "socks5://hev.proxy:1080", UDPInTCP: true},
			{Alias: "plain", URL: "socks5://plain.proxy:1080"},
		},
	})
	if got := m.aliasMap["hev"].EffectiveMode(); got != ModeTCPAndUDP {
		t.Errorf("after reload: EffectiveMode = %s, want tcp_and_udp (user re-enable preserved)", got)
	}
}

func TestNewManager_WithProxies(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Default: "failover",
		Proxies: []ProxyEntry{
			{Alias: "us", URL: "socks5://us.proxy:1080"},
			{Alias: "eu", URL: "http://eu.proxy:8080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.aliasMap) != 3 {
		t.Errorf("expected 3 aliases, got %d", len(m.aliasMap))
	}
	if m.aliasMap["us"] == nil || m.aliasMap["eu"] == nil {
		t.Error("aliases should be non-nil")
	}
	if m.strategy != "failover" {
		t.Errorf("expected strategy failover, got %s", m.strategy)
	}
	if len(m.defaultProxies) != 2 {
		t.Errorf("expected 2 default proxies, got %d", len(m.defaultProxies))
	}
}

func TestNewManager_AutoAlias(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{URL: "socks5://a:1080"},
			{URL: "socks5://b:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.aliasMap["proxy0"] == nil {
		t.Error("first unnamed proxy should be proxy0")
	}
	if m.aliasMap["proxy1"] == nil {
		t.Error("second unnamed proxy should be proxy1")
	}
}

func TestNewManager_DirectAliasIsNil(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "myproxy", URL: "socks5://127.0.0.1:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.aliasMap["direct"] != nil {
		t.Error("direct alias must remain nil")
	}
}

func TestNewManager_CannotOverrideDirect(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "direct", URL: "socks5://evil:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.aliasMap["direct"] != nil {
		t.Error("direct alias must not be overridden")
	}
}

func TestNewManager_ProxyWithoutURLSkipped(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "bad", URL: ""},
			{Alias: "good", URL: "socks5://127.0.0.1:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.aliasMap["bad"]; ok {
		t.Error("proxy without URL should not exist")
	}
	if m.aliasMap["good"] == nil {
		t.Error("good proxy should exist")
	}
}

func TestNewManager_InvalidURLSkipped(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "bad", URL: "://invalid"},
			{Alias: "good", URL: "socks5://127.0.0.1:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.aliasMap["bad"]; ok {
		t.Error("invalid URL proxy should not exist")
	}
	if m.aliasMap["good"] == nil {
		t.Error("good proxy should exist")
	}
}

func TestSelectProxy_FallbackWithoutEngine(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://127.0.0.1:1080"},
		},
	})
	result, proxy := m.SelectProxy("1.2.3.4", 443, "example.com", nil)
	if result != "fallback" {
		t.Errorf("expected fallback, got %s", result)
	}
	if proxy != nil {
		t.Error("proxy should be nil for fallback")
	}
}

func TestSelectProxy_DirectByRule(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://127.0.0.1:1080"},
		},
	})

	eng := newEngineWithRules("proxy ip 8.8.8.8 direct\n")
	result, proxy := m.SelectProxy("8.8.8.8", 0, "", eng)
	if result != "direct" {
		t.Errorf("expected direct, got %s", result)
	}
	if proxy != nil {
		t.Error("proxy should be nil for direct")
	}
}

func TestSelectProxy_AliasByRule(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "us", URL: "socks5://us.proxy:1080"},
		},
	})
	eng := newEngineWithRules("proxy domain google.com us\n")
	result, proxy := m.SelectProxy("", 0, "google.com", eng)
	if result != "" {
		t.Errorf("expected empty result, got %s", result)
	}
	if proxy == nil {
		t.Fatal("proxy should not be nil")
	}
	if proxy.Host != "us.proxy" {
		t.Errorf("expected us.proxy, got %s", proxy.Host)
	}
}

func TestSelectProxy_AliasNotFound(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://127.0.0.1:1080"},
		},
	})
	eng := newEngineWithRules("proxy domain example.com nonexistent\n")
	result, proxy := m.SelectProxy("", 0, "example.com", eng)
	if result != "fallback" {
		t.Errorf("expected fallback for unknown alias, got %s", result)
	}
	if proxy != nil {
		t.Error("proxy should be nil for unknown alias")
	}
}

func TestOrderedProxies_Failover(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Default: "failover",
		Proxies: []ProxyEntry{
			{Alias: "a", URL: "socks5://a:1080"},
			{Alias: "b", URL: "socks5://b:1080"},
			{Alias: "c", URL: "socks5://c:1080"},
		},
	})
	result := m.orderedProxies()
	if len(result) != 3 {
		t.Fatalf("expected 3 proxies, got %d", len(result))
	}
	if result[0].Host != "a" || result[1].Host != "b" || result[2].Host != "c" {
		t.Error("failover should preserve order")
	}
}

func TestOrderedProxies_RoundRobin(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Default: "round_robin",
		Proxies: []ProxyEntry{
			{Alias: "a", URL: "socks5://a:1080"},
			{Alias: "b", URL: "socks5://b:1080"},
		},
	})
	firsts := make(map[string]int)
	for range 10 {
		result := m.orderedProxies()
		t.Logf("order: %s, %s", result[0].Host, result[1].Host)
		firsts[result[0].Host]++
	}
	if firsts["a"] == 0 || firsts["b"] == 0 {
		t.Error("round_robin should rotate through all proxies")
	}
}

func TestOrderedProxies_Random(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Default: "random",
		Proxies: []ProxyEntry{
			{Alias: "a", URL: "socks5://a:1080"},
			{Alias: "b", URL: "socks5://b:1080"},
			{Alias: "c", URL: "socks5://c:1080"},
		},
	})
	firstCounts := make(map[string]int)
	for range 50 {
		result := m.orderedProxies()
		firstCounts[result[0].Host]++
	}
	for _, host := range []string{"a", "b", "c"} {
		if firstCounts[host] == 0 {
			t.Errorf("random should put %s first sometimes", host)
		}
	}
}

func TestOrderedProxies_SingleProxy(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Default: "round_robin",
		Proxies: []ProxyEntry{
			{Alias: "a", URL: "socks5://a:1080"},
		},
	})
	result := m.orderedProxies()
	if len(result) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(result))
	}
}

func TestOrderedProxies_Empty(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{})
	result := m.orderedProxies()
	if len(result) != 0 {
		t.Errorf("expected 0 proxies, got %d", len(result))
	}
}

func TestConnect_Direct(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{})
	eng := newEngineWithRules("proxy ip 10.0.0.1 direct\n")
	conn, mode := m.Connect(context.Background(), "10.0.0.1", 443, "", eng)
	if conn != nil {
		t.Error("conn should be nil for direct")
	}
	if mode != "direct" {
		t.Errorf("expected direct mode, got %s", mode)
	}
}

func TestConnect_FallbackAllFail(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "bad", URL: "socks5://127.0.0.1:19999"},
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, mode := m.Connect(ctx, "example.com", 443, "", nil)
	if conn != nil {
		t.Error("conn should be nil when all fail")
	}
	if mode != "failed" {
		t.Errorf("expected failed mode, got %s", mode)
	}
}

func TestUDPAssociate_DirectNotSupported(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{})
	eng := newEngineWithRules("proxy ip 10.0.0.1 direct\n")
	_, err := m.UDPAssociate(context.Background(), "10.0.0.1", 80, "", eng)
	if err == nil {
		t.Error("expected error for UDP direct")
	}
}

func TestUDPAssociate_NoSOCKS5Proxy(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "http", URL: "http://127.0.0.1:8080"},
		},
	})
	_, err := m.UDPAssociate(context.Background(), "example.com", 80, "", nil)
	if err == nil {
		t.Error("expected error when no SOCKS5 proxy available")
	}
}

// TestUDPAssociate_RawUpgradeByTraffic verifies the raw → standard recovery works through real
// traffic when the health checker is disabled (single-proxy auto-disable): a known-raw node
// whose ASSOCIATE recheck is due is classified from the successful standard relay it just made,
// upgrading the marker without any active probe.
func TestUDPAssociate_RawUpgradeByTraffic(t *testing.T) {
	fdns, dnsPort := startFrameDNSServer(t)
	defer fdns.Close()
	tcpPort, _ := startAssociateTCP(t, "standard", dnsPort)

	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: fmt.Sprintf("socks5://127.0.0.1:%d", tcpPort)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.dnsUDPPool.Close()
	// Health checking is effectively off: HealthCheck.Enabled defaults false and Start() returns
	// early, so no probe loop can detect the upgrade — only real traffic can.

	p := m.aliasMap["p1"]
	p.setUDPCapability(UDPCapRaw)
	p.rawRecheckAfter = time.Now().Add(-time.Minute) // recheck due

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := m.UDPAssociate(ctx, "1.1.1.1", 53, "", nil)
	if err != nil {
		t.Fatalf("UDPAssociate: %v", err)
	}
	conn.Close()

	if got := p.UDPCapability(); got != UDPCapStandard {
		t.Fatalf("real-traffic recheck must upgrade raw→standard, got %q", got)
	}
}

func TestReload_AddProxy(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://a:1080"},
		},
	})
	if len(m.aliasMap) != 2 {
		t.Fatalf("expected 2 aliases before reload, got %d", len(m.aliasMap))
	}

	m.Reload(UpstreamConfig{
		Default: "random",
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://a:1080"},
			{Alias: "p2", URL: "http://b:8080"},
		},
	})

	if len(m.aliasMap) != 3 {
		t.Errorf("expected 3 aliases after reload, got %d", len(m.aliasMap))
	}
	if m.aliasMap["p2"] == nil {
		t.Error("p2 should exist after reload")
	}
	if m.strategy != "random" {
		t.Errorf("expected strategy random, got %s", m.strategy)
	}
	if len(m.defaultProxies) != 2 {
		t.Errorf("expected 2 default proxies after reload, got %d", len(m.defaultProxies))
	}
}

func TestReload_RemoveProxy(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://a:1080"},
			{Alias: "p2", URL: "socks5://b:1080"},
		},
	})
	if len(m.aliasMap) != 3 {
		t.Fatalf("expected 3 aliases before reload, got %d", len(m.aliasMap))
	}

	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://a:1080"},
		},
	})

	if len(m.aliasMap) != 2 {
		t.Errorf("expected 2 aliases after reload, got %d", len(m.aliasMap))
	}
	if _, ok := m.aliasMap["p2"]; ok {
		t.Error("p2 should be removed after reload")
	}
	if len(m.defaultProxies) != 1 {
		t.Errorf("expected 1 default proxy after reload, got %d", len(m.defaultProxies))
	}
}

func TestReload_ReplaceProxy(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://old:1080"},
		},
	})
	oldHost := m.aliasMap["p1"].Host

	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://new:1080"},
		},
	})

	if m.aliasMap["p1"] == nil {
		t.Fatal("p1 should still exist after reload")
	}
	if m.aliasMap["p1"].Host != "new" {
		t.Errorf("expected host 'new', got %s", m.aliasMap["p1"].Host)
	}
	if m.aliasMap["p1"].Host == oldHost {
		t.Error("proxy should have been replaced")
	}
}

func TestReload_ConcurrentAccess(t *testing.T) {

	m, _ := NewManager(UpstreamConfig{
		Default: "round_robin",
		Proxies: []ProxyEntry{
			{Alias: "a", URL: "socks5://a:1080"},
		},
	})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				m.SelectProxy("1.2.3.4", 443, "", nil)
				m.orderedProxies()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 20 {
			select {
			case <-stop:
				return
			default:
			}
			m.Reload(UpstreamConfig{
				Default: "failover",
				Proxies: []ProxyEntry{
					{Alias: "a", URL: "socks5://a:1080"},
					{Alias: "b", URL: "socks5://b:1080"},
				},
			})
			_ = i
		}
	}()

	for range 200 {
		m.SelectProxy("1.2.3.4", 443, "", nil)
	}
	close(stop)
	wg.Wait()

}

func TestReload_DirectRemains(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://a:1080"},
		},
	})
	m.Reload(UpstreamConfig{})
	if m.aliasMap["direct"] != nil {
		t.Error("direct alias should be nil")
	}
	if _, ok := m.aliasMap["direct"]; !ok {
		t.Error("direct alias should exist")
	}
}

func TestReload_PreservesManualDisable(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://a:1080"},
			{Alias: "p2", URL: "socks5://b:1080"},
		},
	})
	if err := m.SetCircuitHealth("p1", "tcp", "disable"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetCircuitHealth("p2", "both", "disable"); err != nil {
		t.Fatal(err)
	}

	// Hot reload with the same two proxies — the manual disables must survive.
	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://a:1080"},
			{Alias: "p2", URL: "socks5://b:1080"},
		},
	})

	p1 := m.aliasMap["p1"]
	if p1 == nil {
		t.Fatal("p1 should exist after reload")
	}
	if !p1.health.IsManuallyDisabled() {
		t.Error("p1 TCP manual disable should survive reload")
	}
	if p1.udpHealth.IsManuallyDisabled() {
		t.Error("p1 UDP should NOT be manually disabled (only TCP was)")
	}
	p2 := m.aliasMap["p2"]
	if p2 == nil {
		t.Fatal("p2 should exist after reload")
	}
	if !p2.health.IsManuallyDisabled() || !p2.udpHealth.IsManuallyDisabled() {
		t.Error("p2 both-circuit manual disable should survive reload")
	}
}

func TestReload_ManualDisableSurvivesURLChange(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: "socks5://old:1080"}},
	})
	if err := m.SetCircuitHealth("p1", "tcp", "disable"); err != nil {
		t.Fatal(err)
	}

	// Same alias, different server: the user disabled the alias, not the server, so the
	// pin must stay put.
	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: "socks5://new:1080"}},
	})

	if !m.aliasMap["p1"].health.IsManuallyDisabled() {
		t.Error("manual disable should survive an alias's URL change")
	}
}

func TestReload_RemovedAliasDropsPin(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://a:1080"},
			{Alias: "p2", URL: "socks5://b:1080"},
		},
	})
	if err := m.SetCircuitHealth("p2", "both", "disable"); err != nil {
		t.Fatal(err)
	}

	// p2 removed from config: its pin must not be resurrected, and p1 keeps its state.
	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: "socks5://a:1080"}},
	})

	if _, ok := m.aliasMap["p2"]; ok {
		t.Fatal("p2 should be removed after reload")
	}
	if p1 := m.aliasMap["p1"]; p1.health.IsManuallyDisabled() {
		t.Error("p1 was never disabled, should not be disabled after reload")
	}
}

func TestReload_PreservesManualEnable(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: "socks5://a:1080"}},
	})
	if err := m.SetCircuitHealth("p1", "tcp", "enable"); err != nil {
		t.Fatal(err)
	}

	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: "socks5://a:1080"}},
	})

	pinned, up := m.aliasMap["p1"].health.ManualPin()
	if !pinned || !up {
		t.Errorf("manual enable should survive reload, got pinned=%v up=%v", pinned, up)
	}
}

// TestReload_ReleasedPluginNodeStaysReleased verifies a plugin node the user released to
// automatic (re-enabling UDP probing) does not revert to the default UDP-down on reload.
// Reload rebuilds the proxy, whose construction default is manual-down; the restore pass
// must re-apply the released state over that default.
func TestReload_ReleasedPluginNodeStaysReleased(t *testing.T) {
	pluginURL := "ss://none:pass@127.0.0.1:80?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dupay.10010.com"
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: pluginURL}},
	})
	if !m.aliasMap["p1"].udpHealth.IsManuallyDisabled() {
		t.Fatal("precondition: fresh plugin node should default to UDP-down")
	}
	// User opts into UDP probing by releasing the circuit to automatic.
	if err := m.SetCircuitHealth("p1", "udp", "auto"); err != nil {
		t.Fatal(err)
	}
	if m.aliasMap["p1"].udpHealth.IsManuallyDisabled() {
		t.Fatal("precondition: released circuit must not be manually disabled")
	}

	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: pluginURL}},
	})

	if m.aliasMap["p1"].udpHealth.IsManuallyDisabled() {
		t.Error("plugin node released to auto must stay released after reload, not revert to default UDP-down")
	}
}

func newEngineWithRules(content string) *rules.Engine {
	dir, _ := os.MkdirTemp("", "upstream-test")
	path := filepath.Join(dir, "rules.txt")
	os.WriteFile(path, []byte(content), 0644)
	eng, _ := rules.New(path)
	return eng
}

func TestSetCircuitHealth_DisableBoth(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Default: "failover",
		Proxies: []ProxyEntry{
			{Alias: "ss-local", URL: "socks5://127.0.0.1:1081"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.dnsUDPPool.Close()

	if err := m.SetCircuitHealth("ss-local", "both", "disable"); err != nil {
		t.Fatalf("disable failed: %v", err)
	}

	infos := m.Proxies()
	var found bool
	for _, info := range infos {
		if info.Alias != "ss-local" {
			continue
		}
		found = true
		if info.Health.Available {
			t.Error("expected tcp unavailable after disable")
		}
		if info.UDPHealth.Available {
			t.Error("expected udp unavailable after disable")
		}
		if !info.Health.Manual || !info.UDPHealth.Manual {
			t.Error("expected both circuits marked manual after disable")
		}
	}
	if !found {
		t.Fatal("ss-local not found")
	}
}

// TestSetCircuitHealth_DisableTCPOnly: disabling only the TCP circuit leaves UDP up, so
// the auto-derived effective mode becomes udp_only.
func TestSetCircuitHealth_DisableTCPOnly(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Default: "failover",
		Proxies: []ProxyEntry{
			{Alias: "ss-local", URL: "socks5://127.0.0.1:1081"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.dnsUDPPool.Close()

	if err := m.SetCircuitHealth("ss-local", "tcp", "disable"); err != nil {
		t.Fatalf("disable tcp failed: %v", err)
	}
	infos := m.Proxies()
	for _, info := range infos {
		if info.Alias != "ss-local" {
			continue
		}
		if info.Health.Available {
			t.Error("expected tcp unavailable")
		}
		if !info.UDPHealth.Available {
			t.Error("expected udp still available")
		}
		if info.Mode != ModeUDPOnly {
			t.Errorf("expected effective mode udp_only, got %s", info.Mode)
		}
	}
}

func TestSetCircuitHealth_ReleaseToAuto(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Default: "failover",
		Proxies: []ProxyEntry{
			{Alias: "ss-local", URL: "socks5://127.0.0.1:1081"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.dnsUDPPool.Close()

	_ = m.SetCircuitHealth("ss-local", "both", "disable")
	_ = m.SetCircuitHealth("ss-local", "both", "auto")

	infos := m.Proxies()
	for _, info := range infos {
		if info.Alias != "ss-local" {
			continue
		}
		if !info.Health.Available || !info.UDPHealth.Available {
			t.Error("expected circuits available after release to auto")
		}
		if info.Health.Manual || info.UDPHealth.Manual {
			t.Error("expected manual flag cleared after release to auto")
		}
	}
}

func TestSetCircuitHealth_UnknownAlias(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Default: "failover",
		Proxies: []ProxyEntry{
			{Alias: "ss-local", URL: "socks5://127.0.0.1:1081"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.dnsUDPPool.Close()

	if err := m.SetCircuitHealth("nonexistent", "both", "disable"); err == nil {
		t.Fatal("expected error for unknown alias")
	}
}

func TestSetCircuitHealth_DirectAlias(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Default: "failover",
		Proxies: []ProxyEntry{
			{Alias: "ss-local", URL: "socks5://127.0.0.1:1081"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.dnsUDPPool.Close()

	if err := m.SetCircuitHealth("direct", "both", "disable"); err == nil {
		t.Fatal("expected error for direct alias (nil proxy)")
	}
}

// TestNewManager_AutoMode verifies the effective mode is auto-derived from the circuits:
// TCP circuit down + UDP up → udp_only; UDP circuit down + TCP up → tcp_only; both up →
// tcp_and_udp. There is no configured mode anymore — the health probe drives it.
func TestNewManager_AutoMode(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "udp-only", URL: "socks5://127.0.0.1:1234"},
			{Alias: "tcp-only", URL: "socks5://127.0.0.1:1081"},
			{Alias: "normal", URL: "socks5://127.0.0.1:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.dnsUDPPool.Close()

	up := m.aliasMap["udp-only"]
	if up == nil {
		t.Fatal("udp-only proxy should exist")
	}
	// TCP circuit down → effective udp_only (the "no TCP listener" case).
	up.health.SetManualState(false)
	up.udpHealth.SetManualState(true)
	if !up.IsUDPOnly() {
		t.Error("proxy with TCP down should have effective mode=udp_only")
	}
	if !up.SupportsUDP() {
		t.Error("udp_only proxy should report SupportsUDP()=true")
	}

	only := m.aliasMap["tcp-only"]
	only.health.SetManualState(true)
	only.udpHealth.SetManualState(false) // UDP circuit down → effective tcp_only
	if !only.IsTCPOnly() {
		t.Error("proxy with UDP down should have effective mode=tcp_only")
	}
	if only.SupportsUDP() {
		t.Error("tcp_only proxy should report SupportsUDP()=false")
	}

	normal := m.aliasMap["normal"]
	if normal.IsUDPOnly() || normal.IsTCPOnly() {
		t.Error("fresh proxy with both circuits closed should be tcp_and_udp")
	}

	// Proxies() info must surface the mode for the dashboard badge, plus the capability
	// marker (unknown before any successful relay).
	var found bool
	for _, info := range m.Proxies() {
		if info.Alias == "udp-only" {
			found = true
			if info.Mode != ModeUDPOnly {
				t.Errorf("ProxyInfo should expose mode=%s for the TCP-down proxy, got %q", ModeUDPOnly, info.Mode)
			}
			if info.UDPCapability != string(UDPCapUnknown) {
				t.Errorf("ProxyInfo.udp_capability should be %q before any relay, got %q", UDPCapUnknown, info.UDPCapability)
			}
			if !info.UDPHealth.Available {
				t.Error("ProxyInfo should expose an available udp_health for a fresh proxy")
			}
		}
	}
	if !found {
		t.Error("udp-only should appear in Proxies()")
	}
}

// TestManager_UDPRoutingUsesUDPHealth verifies UDP routing is gated by the independent UDP
// circuit (IsUDPAvailable), while TCP routing keeps using IsAvailable — so opening only the
// UDP circuit changes UDP failover but never TCP.
func TestManager_ResetAutoOpenedCircuits(t *testing.T) {
	mockAddr, done := startSOCKS5Mock(t)
	defer done()

	m, err := NewManager(UpstreamConfig{
		Default: "failover",
		Proxies: []ProxyEntry{
			{Alias: "a", URL: "socks5://" + mockAddr},
			{Alias: "b", URL: "socks5://" + mockAddr},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	a, b := m.defaultProxies[0], m.defaultProxies[1]

	// a: TCP auto-opened by probe failures; UDP manually disabled (user pin).
	a.health.state = StateOpen
	a.health.consecutiveFailures = 2
	a.health.openSince = time.Now()
	a.udpHealth.SetManualState(false)

	// b: UDP auto-opened; TCP manually enabled (user pin).
	b.udpHealth.state = StateOpen
	b.udpHealth.openSince = time.Now()
	b.health.SetManualState(true)

	n := m.ResetAutoOpenedCircuits()
	if n != 2 {
		t.Errorf("expected 2 auto-opened circuits reset, got %d", n)
	}

	// Auto-opened circuits are back to available; the recovery is temporary (no manual pin).
	if !a.health.IsAvailable() {
		t.Error("a TCP should be available after reset")
	}
	if !b.udpHealth.IsAvailable() {
		t.Error("b UDP should be available after reset")
	}
	// Manual pins survive untouched.
	if !a.udpHealth.IsManuallyDisabled() {
		t.Error("a UDP manual-down pin must survive reset")
	}
	if _, pinned := b.health.ManualPin(); !pinned {
		t.Error("b TCP manual-up pin must survive reset")
	}
}

func TestManager_UDPRoutingUsesUDPHealth(t *testing.T) {
	mockAddr, done := startSOCKS5Mock(t)
	defer done()

	m, err := NewManager(UpstreamConfig{
		Default: "failover",
		Proxies: []ProxyEntry{{Alias: "p1", URL: "socks5://" + mockAddr}},
	})
	if err != nil {
		t.Fatal(err)
	}

	proxy := m.defaultProxies[0]
	// Break only the UDP circuit, the way a UDP health probe failure would.
	proxy.udpHealth.SetManualState(false)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := m.UDPAssociate(ctx, "example.com", 53, "", nil); err == nil {
		t.Error("UDPAssociate must skip a proxy whose UDP circuit is open")
	}

	if !proxy.IsAvailable() {
		t.Fatal("TCP health must be unaffected by the UDP manual disable")
	}
	conn, err := m.ConnectDefault(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("TCP routing must ignore UDP health, got: %v", err)
	}
	conn.Close()
}

// TestConnect_RuleRespectsManualDisable: rule routing must honor an explicit manual
// "Disable" — a rule-selected proxy whose TCP circuit is pinned down returns "failed"
// instead of being forced into service (the pre-fix contradiction with the Disable button).
func TestConnect_RuleRespectsManualDisable(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: "socks5://127.0.0.1:1080"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	eng := newEngineWithRules("proxy ip 1.2.3.4 p1\n")
	// Whole-node Disable (both circuits). With both down the effective mode is
	// tcp_and_udp (down), so IsUDPOnly() does not intercept — this must reach the
	// manual-disable check in Connect and fail, not be force-used by the rule.
	if err := m.SetCircuitHealth("p1", "both", "disable"); err != nil {
		t.Fatal(err)
	}

	conn, result := m.Connect(context.Background(), "1.2.3.4", 443, "", eng)
	if conn != nil {
		conn.Close()
	}
	if result != "failed" {
		t.Errorf("manually-disabled proxy under a rule must fail, got result=%q", result)
	}
}

// TestUDPAssociate_RuleRespectsManualDisable: the same honor applies to the UDP circuit
// on the rule-selected path of UDPAssociate.
func TestUDPAssociate_RuleRespectsManualDisable(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "p1", URL: "socks5://127.0.0.1:1080"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	eng := newEngineWithRules("proxy ip 1.2.3.4 p1\n")
	if err := m.SetCircuitHealth("p1", "udp", "disable"); err != nil {
		t.Fatal(err)
	}

	conn, err := m.UDPAssociate(context.Background(), "1.2.3.4", 53, "", eng)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Error("manually-disabled UDP under a rule must fail")
	}
}

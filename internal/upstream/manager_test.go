package upstream

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// TestReload_NewlyAddedUDPInTCPDefaultsTCPDown covers the add-node-at-runtime path (the
// panel writes config while the engine is running → Manager.Reload). A udp_in_tcp node
// that did NOT exist before the reload (so it is not in the captured manual pins) must
// still pick up the construction default TCP force-down. Previously Reload blanket-reset
// every new proxy's health: reset() cleared the default pin's forced StateOpen back to
// Closed while leaving manual=&false, so the snapshot reported Manual=true AND
// Available=true — the panel rendered "TCP up (manual)" instead of "TCP down", the first
// click did an `auto` release and read "unknown", and a second click was needed to
// actually disable it.
func TestReload_NewlyAddedUDPInTCPDefaultsTCPDown(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "plain", URL: "socks5://plain.proxy:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Hot-reload adds the hev node for the first time (no pre-existing pin to restore).
	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "plain", URL: "socks5://plain.proxy:1080"},
			{Alias: "hev", URL: "socks5://hev.proxy:1080", UDPInTCP: true},
		},
	})

	hev := m.aliasMap["hev"]
	if hev == nil || !hev.UDPInTCP {
		t.Fatal("hev node should be added as UDPInTCP after reload")
	}
	if !hev.health.IsManuallyDisabled() {
		t.Error("freshly-added hev node's TCP should be manually disabled (force-down pin)")
	}
	snap := hev.health.Snapshot()
	if !snap.Manual {
		t.Error("hev TCP snapshot should report manual=true (pinned at construction)")
	}
	if snap.Available {
		t.Errorf("hev TCP snapshot should report available=false for a force-down pin, got state=%s (manual and available must not disagree)", snap.State)
	}
	if hev.EffectiveMode() != ModeUDPOnly {
		t.Errorf("freshly-added hev EffectiveMode = %s, want udp_only (TCP default off)", hev.EffectiveMode())
	}
	if !hev.SupportsUDP() {
		t.Error("hev node should still support UDP routing (framed path) after reload")
	}
	// The pre-existing plain node is unaffected: automatic, not force-down.
	plain := m.aliasMap["plain"]
	if plain == nil || plain.health.IsManuallyDisabled() {
		t.Error("plain node's TCP should stay automatic after reload")
	}
}

// TestReload_FlipUDPInTCPOnExistingNodeAppliesTCPDefault covers the edit-existing-node
// path: a plain socks5 node (TCP automatic) is edited to enable udp_in_tcp. The reload must
// apply the construction TCP force-down default to that circuit instead of overlaying the
// stale pre-toggle auto pin — otherwise the freshly-enabled hev node silently skips its
// "TCP off by default" intent.
func TestReload_FlipUDPInTCPOnExistingNodeAppliesTCPDefault(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "srv", URL: "socks5://srv.proxy:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.aliasMap["srv"].EffectiveMode(); got != ModeTCPAndUDP {
		t.Fatalf("precondition: plain socks5 EffectiveMode = %s, want tcp_and_udp", got)
	}

	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "srv", URL: "socks5://srv.proxy:1080", UDPInTCP: true},
		},
	})

	srv := m.aliasMap["srv"]
	if !srv.health.IsManuallyDisabled() {
		t.Errorf("after enabling udp_in_tcp: TCP should be force-down (default), got EffectiveMode=%s", srv.EffectiveMode())
	}
	if srv.EffectiveMode() != ModeUDPOnly {
		t.Errorf("after enabling udp_in_tcp: EffectiveMode = %s, want udp_only", srv.EffectiveMode())
	}
}

// TestReload_FlipPluginOnExistingNodeAppliesUDPDefault is the SS-plugin analog: a plain ss
// node (UDP automatic) edited to carry a SIP003 plugin must get the construction UDP
// force-down default applied, since plugin deployments usually expose no UDP relay.
func TestReload_FlipPluginOnExistingNodeAppliesUDPDefault(t *testing.T) {
	const noPlugin = "ss://none:pass@srv.proxy:8388"
	const withPlugin = "ss://none:pass@srv.proxy:8388?plugin=obfs-local%3Bobfs%3Dhttp"
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "ss", URL: noPlugin}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.aliasMap["ss"].udpHealth.IsManuallyDisabled() {
		t.Fatal("precondition: plain ss node UDP should not be force-down")
	}

	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{{Alias: "ss", URL: withPlugin}},
	})

	ss := m.aliasMap["ss"]
	if !ss.udpHealth.IsManuallyDisabled() {
		t.Error("after enabling plugin: UDP should be force-down (default)")
	}
}

// TestReload_UserReEnableSurvivesUnchangedReload guards the other direction: a hev node
// whose TCP the user force-enabled must keep that pin across a reload that does NOT toggle
// the udp_in_tcp flag (e.g. a port edit), so the flag-on default logic never clobbers an
// explicit user choice when the flag was already on.
func TestReload_UserReEnableSurvivesUnchangedReload(t *testing.T) {
	mk := func() UpstreamConfig {
		return UpstreamConfig{
			Proxies: []ProxyEntry{
				{Alias: "hev", URL: "socks5://hev.proxy:1080", UDPInTCP: true},
			},
		}
	}
	m, err := NewManager(mk())
	if err != nil {
		t.Fatal(err)
	}
	hev := m.aliasMap["hev"]
	if !hev.health.IsManuallyDisabled() {
		t.Fatal("precondition: hev node TCP should default force-down")
	}
	// User explicitly turns TCP back on.
	hev.health.SetManualState(true)

	m.Reload(mk()) // flag unchanged (true → true)
	if got := m.aliasMap["hev"].EffectiveMode(); got != ModeTCPAndUDP {
		t.Errorf("user force-enable must survive an unchanged-flag reload, got EffectiveMode=%s", got)
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
	result, proxy := m.SelectProxy(context.Background(), "1.2.3.4", 443, "example.com", nil)
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
	result, proxy := m.SelectProxy(context.Background(), "8.8.8.8", 0, "", eng)
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
	result, proxy := m.SelectProxy(context.Background(), "", 0, "google.com", eng)
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
	result, proxy := m.SelectProxy(context.Background(), "", 0, "example.com", eng)
	if result != "proxy_default" {
		t.Errorf("expected proxy_default for unknown alias, got %s", result)
	}
	if proxy != nil {
		t.Error("proxy should be nil for unknown alias")
	}
}

func TestSelectProxy_DefaultAlias(t *testing.T) {
	m, _ := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://127.0.0.1:1080"},
		},
	})
	eng := newEngineWithRules("proxy domain github.com default\n")
	result, proxy := m.SelectProxy(context.Background(), "", 0, "github.com", eng)
	if result != "proxy_default" {
		t.Errorf("expected proxy_default for 'default' alias, got %s", result)
	}
	if proxy != nil {
		t.Error("proxy should be nil for 'default' alias")
	}
}


func TestReload_RefreshGeoOnURLEdit(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "node1", URL: "socks5://us-server.com:1080"},
			{Alias: "node2", URL: "socks5://hk-server.com:1080"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Manually inject geo info (as if trace probe completed)
	node1 := m.aliasMap["node1"]
	node1.SetGeoInfo("US", "198.51.100.1")

	node2 := m.aliasMap["node2"]
	node2.SetGeoInfo("HK", "203.0.113.1")

	// Reload with node1 URL changed to JP, and node2 unchanged
	m.Reload(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "node1", URL: "socks5://jp-server.com:1080"},
			{Alias: "node2", URL: "socks5://hk-server.com:1080"},
		},
	})

	reloadedNode1 := m.aliasMap["node1"]
	// node1 URL changed: stale exitIP must be cleared, countryCode updated from new URL (JP)
	if reloadedNode1.ExitIP() != "" {
		t.Errorf("expected exitIP to be cleared for edited URL, got %q", reloadedNode1.ExitIP())
	}
	if reloadedNode1.CountryCode() != "JP" {
		t.Errorf("expected CountryCode to be inferred as JP, got %q", reloadedNode1.CountryCode())
	}

	reloadedNode2 := m.aliasMap["node2"]
	// node2 URL unchanged: geo info preserved
	if reloadedNode2.ExitIP() != "203.0.113.1" || reloadedNode2.CountryCode() != "HK" {
		t.Errorf("expected node2 geo info preserved, got %s / %s", reloadedNode2.CountryCode(), reloadedNode2.ExitIP())
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

// TestOrderedProxies_RoundRobinCounterWrap 回归 rrCounter 回绕 panic:计数器加到 2^64
// 回绕、Add 返回到 0 时,Add(1)-1 在 uint64 里下溢成 MaxUint64;旧代码先转成 int 拿到
// -1,(start+i)%n 随即索引 [-1] 直接 panic。概率上要跑满 2^64 次才撞上,但崩点在那儿,
// 且一旦崩整个代理进程跟着死。
func TestOrderedProxies_RoundRobinCounterWrap(t *testing.T) {
	hosts := []string{"a", "b", "c"}
	entries := make([]ProxyEntry, len(hosts))
	for i, h := range hosts {
		entries[i] = ProxyEntry{Alias: h, URL: "socks5://" + h + ":1080"}
	}
	m, _ := NewManager(UpstreamConfig{Default: "round_robin", Proxies: entries})
	n := uint64(len(hosts))

	// 回绕前一拍、回绕那一拍(旧代码必 panic 的点)、回绕后一拍。
	// 断言:不 panic、是全集的排列、首元素等于调用序号 mod n(前 2^64 次选择的轮转律)。
	for _, c := range []uint64{math.MaxUint64 - 1, math.MaxUint64, 0} {
		m.order[transportTCP].rr.Store(c)
		got := m.orderedProxies()
		if uint64(len(got)) != n {
			t.Fatalf("counter=%d: expected %d proxies, got %d", c, n, len(got))
		}
		if want := hosts[c%n]; got[0].Host != want {
			t.Errorf("counter=%d: first proxy is %s, want %s", c, got[0].Host, want)
		}
		seen := make(map[string]bool, n)
		for _, p := range got {
			if seen[p.Host] {
				t.Errorf("counter=%d: %s appears twice in one rotation", c, p.Host)
			}
			seen[p.Host] = true
		}
		if uint64(len(seen)) != n {
			t.Errorf("counter=%d: rotation is not a permutation: %v", c, got)
		}
	}
}

// TestOrderedProxies_RoundRobinCountersIndependent 回归 TCP/UDP 共用轮转指针:两个协议
// 各自建连却推同一个计数器时会互相插队 —— 每条 UDP 关联都把 TCP 的轮转顶掉一格,反之
// 亦然。乱成什么样取决于当时两个协议的流量配比,既不可复现,也让 round_robin 承诺的
// "按序均摊"彻底落空。
func TestOrderedProxies_RoundRobinCountersIndependent(t *testing.T) {
	hosts := []string{"a", "b", "c"}
	entries := make([]ProxyEntry, len(hosts))
	for i, h := range hosts {
		entries[i] = ProxyEntry{Alias: h, URL: "socks5://" + h + ":1080"}
	}
	m, _ := NewManager(UpstreamConfig{Default: "round_robin", Proxies: entries})

	// UDP 侧先推两次(2 不是 n 的倍数,指针被顶偏),TCP 侧的轮转必须一点不受影响。
	m.orderedProxiesUDP()
	m.orderedProxiesUDP()
	for i, want := range []string{"a", "b", "c", "a"} {
		if got := m.orderedProxies()[0].Host; got != want {
			t.Errorf("TCP selection #%d = %s, want %s (UDP traffic must not advance the TCP rotation)",
				i, got, want)
		}
	}
	// 反向:TCP 推了 4 次之后,UDP 自己那条指针应停在它的第 3 次选择上,给出 c;
	// 若两者共用一个计数器,这里会按 (2+4)%3=0 拿到 a。
	if got := m.orderedProxiesUDP()[0].Host; got != "c" {
		t.Errorf("UDP selection #2 = %s, want c (TCP traffic must not advance the UDP rotation)", got)
	}
}

// newLatencyManager 建一个 latency 策略的管理器,hosts 即配置顺序。
func newLatencyManager(t *testing.T, hosts ...string) *Manager {
	t.Helper()
	entries := make([]ProxyEntry, len(hosts))
	for i, h := range hosts {
		entries[i] = ProxyEntry{Alias: h, URL: "socks5://" + h + ":1080"}
	}
	m, err := NewManager(UpstreamConfig{Default: "latency", Proxies: entries})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	// 填上 geo 信息让 probeInitialGeo 跳过这些节点:那条探测是异步的,成功时会把直连
	// RTT 写进 health.latency(manager.go 的 probeInitialGeo),和用例注入的样本打架,
	// 会让断言随机失败。
	for _, h := range hosts {
		m.aliasMap[h].SetGeoInfo("US", "203.0.113.1")
	}
	return m
}

// setCircuitLatency 给节点的 TCP 或 UDP 电路写入一个延迟样本,模拟健康探测的结果。
func setCircuitLatency(m *Manager, alias string, udp bool, d time.Duration) {
	if udp {
		m.aliasMap[alias].udpHealth.UpdateLatency(d)
		return
	}
	m.aliasMap[alias].health.UpdateLatency(d)
}

// proxyHosts 取出排序结果里的 host 序列,便于整条断言。
func proxyHosts(proxies []*Proxy) []string {
	out := make([]string, len(proxies))
	for i, p := range proxies {
		out[i] = p.Host
	}
	return out
}

// TestOrderedProxies_LatencyColdStart 回归冷启动:节点还没测出延迟时,旧实现一律按
// time.Hour 处理,于是**第一个**探到延迟的节点——哪怕它自己是 3s 这种烂数字——会压过所有
// 还没测的节点,把冷启动窗口里每条新流的流量全吸走,直到其余节点的探测落地。
// 未测量的节点必须用"已测量延迟的中位数"占位:没数据就不站队,既不插到已证实的快节点
// 前面,也不会被打到一个已知很慢的节点后面。
func TestOrderedProxies_LatencyColdStart(t *testing.T) {
	m := newLatencyManager(t, "a", "b", "c")
	// 只有 b 有实测延迟,而且是 3s 这种烂数字。
	setCircuitLatency(m, "b", false, 3*time.Second)

	// 中位数占位后三者同分(都是 3s),全部入带;首拍轮转起点为 0,稳定排序保持配置
	// 顺序 —— 而不是把一个已知很慢的 b 顶到最前面。
	want := []string{"a", "b", "c"}
	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, want) {
		t.Errorf("order = %v, want %v (a known-slow measured node must not jump ahead of unmeasured ones)", got, want)
	}

	// 已证实的快节点仍然要排在未测量的前面:中位数只会把"没数据"摆到中间,不会让它
	// 白捡第一。
	setCircuitLatency(m, "c", false, 30*time.Millisecond)
	if got := m.orderedProxies()[0].Host; got != "c" {
		t.Errorf("first = %s, want c (a proven-fast node still wins)", got)
	}
}

// TestOrderedProxies_LatencyBandRotation 延迟在最优 1.5 倍以内的节点组成候选带,每建一条
// 新连接在带内轮转起点,把流量摊给所有"差不多快"的节点;带外节点按延迟沉在带后当对冲
// 备胎,不带轮转。
func TestOrderedProxies_LatencyBandRotation(t *testing.T) {
	m := newLatencyManager(t, "a", "b", "c")
	// 进入线 = 95ms + max(95/2, 20ms) ≈ 142ms:b、a 在带内,c=300ms 在带外。
	setCircuitLatency(m, "a", false, 100*time.Millisecond)
	setCircuitLatency(m, "b", false, 95*time.Millisecond)
	setCircuitLatency(m, "c", false, 300*time.Millisecond)

	want := [][]string{
		{"b", "a", "c"},
		{"a", "b", "c"},
		{"b", "a", "c"},
	}
	for i := range want {
		if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, want[i]) {
			t.Errorf("rotation call %d = %v, want %v (rotate inside the band; the out-of-band node stays tail)", i, got, want[i])
		}
	}
}

// TestOrderedProxies_LatencyBandEdgeHysteresis 带缘滞回:带外节点够到"进入线"(最优 1.5
// 倍)才能入带;带内成员要烂过更宽的"退出线"(再让 best/4,地板 20ms)才被踢。不然 EWMA
// 在带线附近抖一下,成员每拍进出,轮转集合乱跳。判定技巧:单成员带不轮转,双成员带每拍
// 换首位——连续两拍的次序就能区分成员到底在不在带里。
func TestOrderedProxies_LatencyBandEdgeHysteresis(t *testing.T) {
	m := newLatencyManager(t, "a", "b", "c")
	setCircuitLatency(m, "a", false, 100*time.Millisecond)
	setCircuitLatency(m, "b", false, 155*time.Millisecond) // 进入线 150ms,b 带外
	setCircuitLatency(m, "c", false, 900*time.Millisecond)

	// b 在进入线外:候选带只有 a,连续两拍都是 a 领头。
	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("call 1 = %v, want [a b c]", got)
	}
	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("call 2 = %v, want [a b c] (an outsider past the 1.5x line must not enter)", got)
	}

	// b 进到 145ms <= 进入线:入带,下一拍轮转把它顶到首位。
	setCircuitLatency(m, "b", false, 145*time.Millisecond)
	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("call 3 = %v, want [a b c]", got)
	}
	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, []string{"b", "a", "c"}) {
		t.Fatalf("call 4 = %v, want [b a c] (b reached the enter line and joins the rotation)", got)
	}

	// b 又抖到 165ms:越过进入线但没烂过退出线(175ms),带籍保留,继续参与轮转。
	setCircuitLatency(m, "b", false, 165*time.Millisecond)
	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("call 5 = %v, want [a b c]", got)
	}
	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, []string{"b", "a", "c"}) {
		t.Fatalf("call 6 = %v, want [b a c] (a wobble back across the enter line must not kick a member)", got)
	}

	// b 烂到 200ms > 退出线:出带,候选带只剩 a,不再轮转。
	setCircuitLatency(m, "b", false, 200*time.Millisecond)
	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("call 7 = %v, want [a b c]", got)
	}
	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("call 8 = %v, want [a b c] (b past the leave line drops out of the band)", got)
	}
}

// TestOrderedProxies_LatencyBandLowLatencyFloor 低延迟区 1.5 倍的相对宽度比测量噪声还窄
// (最优 20ms 时只有 10ms),进入线压一条 20ms 加法地板:40ms 的节点仍在带内,45ms 的
// 出局。
func TestOrderedProxies_LatencyBandLowLatencyFloor(t *testing.T) {
	m := newLatencyManager(t, "a", "b", "c")
	setCircuitLatency(m, "a", false, 20*time.Millisecond)
	setCircuitLatency(m, "b", false, 40*time.Millisecond)
	setCircuitLatency(m, "c", false, 45*time.Millisecond)

	want := [][]string{
		{"a", "b", "c"},
		{"b", "a", "c"},
	}
	for i := range want {
		if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, want[i]) {
			t.Errorf("call %d = %v, want %v (enter line is best+20ms in the low-latency zone)", i, got, want[i])
		}
	}
}

// TestOrderedProxies_LatencyBandCounterWrap 带内轮转指针在 uint64 回绕处不许 panic、不许
// 出现负下标——和 round_robin 同一个坑,共用 rrStart 但两边都得验。
func TestOrderedProxies_LatencyBandCounterWrap(t *testing.T) {
	m := newLatencyManager(t, "a", "b")
	setCircuitLatency(m, "a", false, 100*time.Millisecond)
	setCircuitLatency(m, "b", false, 100*time.Millisecond)

	cases := []struct {
		c    uint64
		want string
	}{
		{math.MaxUint64 - 1, "a"},
		{math.MaxUint64, "b"},
		{0, "a"},
	}
	for _, tc := range cases {
		m.order[transportTCP].rr.Store(tc.c)
		got := proxyHosts(m.orderedProxies())
		if len(got) != 2 || (got[0] != "a" && got[0] != "b") || got[0] == got[1] {
			t.Errorf("counter %d: order = %v, want a full 2-node permutation", tc.c, got)
		}
		if got[0] != tc.want {
			t.Errorf("counter %d: first = %s, want %s", tc.c, got[0], tc.want)
		}
	}
}

// TestOrderedProxies_LatencyBandMemberUnavailable 带内成员掉线时必须立刻出带、沉底,不能
// 因为滞回快照还记着它就继续摆在前面——排在第一位的是个不可用节点,选路白撞一次。
func TestOrderedProxies_LatencyBandMemberUnavailable(t *testing.T) {
	m := newLatencyManager(t, "a", "b")
	setCircuitLatency(m, "a", false, 20*time.Millisecond)
	setCircuitLatency(m, "b", false, 300*time.Millisecond)

	if got := m.orderedProxies()[0].Host; got != "a" {
		t.Fatalf("cold pick = %s, want a", got)
	}

	m.aliasMap["a"].health.SetManualState(false) // a 掉线
	want := []string{"b", "a"}
	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, want) {
		t.Errorf("order = %v, want %v (an unavailable band member must be replaced and sunk to the end)", got, want)
	}
}

// TestOrderedProxies_LatencyBandPerTransport TCP 建连和 UDP 关联各按各的电路延迟组带,
// 轮转指针也各走各的。这里 TCP 候选带只有 a(a=20ms,b=100ms 在带外),UDP 候选带是
// [b,a](95ms/100ms 都在带内)。共用指针的话第一拍 UDP 就会被 TCP 推进一格、错拿 a 领头,
// 把 UDP 包发给一条更烂的 UDP 电路。
func TestOrderedProxies_LatencyBandPerTransport(t *testing.T) {
	m := newLatencyManager(t, "a", "b")
	// a:TCP 快 UDP 慢;b 反过来。
	setCircuitLatency(m, "a", false, 20*time.Millisecond)
	setCircuitLatency(m, "a", true, 100*time.Millisecond)
	setCircuitLatency(m, "b", false, 100*time.Millisecond)
	setCircuitLatency(m, "b", true, 95*time.Millisecond)

	wantUDP := []string{"b", "a", "b"}
	for i := range wantUDP {
		if got := m.orderedProxies()[0].Host; got != "a" {
			t.Fatalf("call %d: TCP pick = %s, want a (a is the only TCP band member)", i, got)
		}
		if got := m.orderedProxiesUDP()[0].Host; got != wantUDP[i] {
			t.Fatalf("call %d: UDP pick = %s, want %s (UDP band [b,a] rotates on its own counter)", i, got, wantUDP[i])
		}
	}
}

// TestOrderedProxies_LatencyBandUDPAvailability latency 排序的可用/不可用分区必须按路径走:
// b 的 TCP 电路被手工关掉(模拟 udp_only),TCP 路径上它沉底;但它的 UDP 电路健康且更快,
// UDP 路径上它必须是候选带领头,不能被 TCP 熔断器连坐。
func TestOrderedProxies_LatencyBandUDPAvailability(t *testing.T) {
	m := newLatencyManager(t, "a", "b")
	setCircuitLatency(m, "a", false, 100*time.Millisecond)
	setCircuitLatency(m, "a", true, 100*time.Millisecond)
	setCircuitLatency(m, "b", false, 200*time.Millisecond)
	setCircuitLatency(m, "b", true, 90*time.Millisecond)
	m.aliasMap["b"].health.SetManualState(false) // b 的 TCP 电路关断,UDP 电路照常

	if got := proxyHosts(m.orderedProxies()); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("TCP order = %v, want [a b] (a TCP-down node is tail on the TCP path)", got)
	}
	if got := proxyHosts(m.orderedProxiesUDP()); !slices.Equal(got, []string{"b", "a"}) {
		t.Fatalf("UDP order = %v, want [b a] (UDP path ranks on the UDP circuit, not TCP's breaker)", got)
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
				m.SelectProxy(context.Background(), "1.2.3.4", 443, "", nil)
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
		m.SelectProxy(context.Background(), "1.2.3.4", 443, "", nil)
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

func TestManager_TestProxy(t *testing.T) {
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := deadLn.Addr().String()
	deadLn.Close()

	m, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p-socks", URL: "socks5://" + deadAddr},
			{Alias: "p-http", URL: "http://" + deadAddr},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// 1. Bad alias
	if _, err := m.TestProxy(ctx, "nonexistent", "tcp"); err == nil {
		t.Error("expected error for non-existent alias")
	}

	// 2. Bad protocol
	if _, err := m.TestProxy(ctx, "p-socks", "invalid"); err == nil {
		t.Error("expected error for invalid protocol")
	}

	// 3. UDP on non-UDP scheme
	if _, err := m.TestProxy(ctx, "p-http", "udp"); err == nil {
		t.Error("expected error for UDP on http scheme")
	}

	// 4. Offline node returns error
	if _, err := m.TestProxy(ctx, "p-socks", "tcp"); err == nil {
		t.Error("expected error for offline proxy")
	}

	// 5. Ping/TCPing offline node returns error
	if _, err := m.TestProxy(ctx, "p-socks", "ping"); err == nil {
		t.Error("expected error for ping to offline proxy")
	}
	if _, err := m.TestProxy(ctx, "p-socks", "tcping"); err == nil {
		t.Error("expected error for tcping to offline proxy")
	}

	// 6. Ping online node succeeds and sets PingLatency
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()

	mLive, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "live-node", URL: "socks5://" + ln.Addr().String()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	liveCtx, liveCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer liveCancel()
	lat, err := mLive.TestProxy(liveCtx, "live-node", "tcping")
	if err != nil {
		t.Fatalf("expected tcping to succeed, got %v", err)
	}
	if lat <= 0 {
		t.Errorf("expected positive latency, got %v", lat)
	}
	proxies := mLive.Proxies()
	if len(proxies) != 1 || proxies[0].PingLatency <= 0 {
		t.Errorf("expected ProxyInfo to reflect positive PingLatency, got %+v", proxies)
	}
}

func TestManager_SetProviderProxies(t *testing.T) {
	mgr, err := NewManager(UpstreamConfig{
		Default: "round_robin",
		Proxies: []ProxyEntry{
			{
				Alias: "static-1",
				URL:   "socks5://127.0.0.1:1080",
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
			URL:   "socks5://127.0.0.1:1081",
		},
		{
			Alias: "[Lantern] US-01",
			URL:   "socks5://127.0.0.1:1082",
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
			URL:   "socks5://127.0.0.1:1083",
		},
		{
			Alias: "[Lantern] SG-01",
			URL:   "socks5://127.0.0.1:1084",
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

func TestManager_DuplicateAliases(t *testing.T) {
	cfg := UpstreamConfig{
		Default: "failover",
		Proxies: []ProxyEntry{
			{Alias: "Node-A", URL: "ss://YWVzLTEyOC1nY206cGFzczE@1.1.1.1:8388"},
			{Alias: "Node-A", URL: "ss://YWVzLTEyOC1nY206cGFzczI@2.2.2.2:8388"},
			{Alias: "Node-A", URL: "ss://YWVzLTEyOC1nY206cGFzczM@3.3.3.3:8388"},
		},
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	proxies := mgr.Proxies()
	if len(proxies) != 3 {
		t.Fatalf("expected 3 proxies, got %d", len(proxies))
	}

	expectedAliases := []string{"Node-A", "Node-A (2)", "Node-A (3)"}
	for i, exp := range expectedAliases {
		if proxies[i].Alias != exp {
			t.Errorf("expected proxy %d alias %q, got %q", i, exp, proxies[i].Alias)
		}
		if _, ok := mgr.aliasMap[exp]; !ok {
			t.Errorf("alias %q not found in aliasMap", exp)
		}
	}
}

func TestManager_FindProxyLocked_Fallback(t *testing.T) {
	mgr, err := NewManager(UpstreamConfig{})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Stop()

	lanternNodes := []ProxyEntry{
		{
			Alias: "[Lantern] vless-reality-node-01",
			URL:   "socks5://1.2.3.4:443#vless-reality-node-01",
		},
	}
	mgr.SetProviderProxies("lantern", lanternNodes)

	// 1. Exact alias match with [Lantern] prefix
	mgr.mu.RLock()
	p1, a1 := mgr.findProxyLocked("[Lantern] vless-reality-node-01")
	mgr.mu.RUnlock()
	if p1 == nil || a1 != "[Lantern] vless-reality-node-01" {
		t.Fatalf("expected exact alias match, got p=%v, a=%q", p1, a1)
	}

	// 2. Case-insensitive match
	mgr.mu.RLock()
	p2, a2 := mgr.findProxyLocked("[lantern] VLESS-REALITY-NODE-01")
	mgr.mu.RUnlock()
	if p2 == nil || a2 != "[Lantern] vless-reality-node-01" {
		t.Fatalf("expected case-insensitive match, got p=%v, a=%q", p2, a2)
	}

	// 3. Fallback match via proxy.Name (omitting the [Lantern] prefix)
	mgr.mu.RLock()
	p3, a3 := mgr.findProxyLocked("vless-reality-node-01")
	mgr.mu.RUnlock()
	if p3 == nil || a3 != "[Lantern] vless-reality-node-01" {
		t.Fatalf("expected fallback match via Name, got p=%v, a=%q", p3, a3)
	}

	// 4. Test via ProxyInfo
	info, ok := mgr.ProxyInfo("vless-reality-node-01")
	if !ok || info.Alias != "[Lantern] vless-reality-node-01" {
		t.Fatalf("ProxyInfo fallback failed: ok=%v, info.Alias=%q", ok, info.Alias)
	}
}

func TestManager_HandleNetworkChange(t *testing.T) {
	mgr, err := NewManager(UpstreamConfig{
		Proxies: []ProxyEntry{
			{Alias: "p1", URL: "socks5://1.2.3.4:1080"},
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Stop()

	p := mgr.aliasMap["p1"]
	if p == nil {
		t.Fatal("proxy p1 not found")
	}

	// Simulate failure on handover
	p.health.mu.Lock()
	p.health.state = StateOpen
	p.health.consecutiveFailures = 4
	p.health.mu.Unlock()

	p.udpHealth.mu.Lock()
	p.udpHealth.state = StateOpen
	p.udpHealth.consecutiveFailures = 4
	p.udpHealth.mu.Unlock()

	// Put dummy connection in UDP pool
	c1, c2 := net.Pipe()
	defer c2.Close()
	mgr.dnsUDPPool.Release(c1)
	if mgr.dnsUDPPool.Len() != 1 {
		t.Fatalf("expected pool len 1, got %d", mgr.dnsUDPPool.Len())
	}

	// Trigger network change
	mgr.HandleNetworkChange()

	// Check pool drained
	if mgr.dnsUDPPool.Len() != 0 {
		t.Fatalf("expected pool len 0, got %d", mgr.dnsUDPPool.Len())
	}

	// Check circuits reset
	p.health.mu.RLock()
	if p.health.state != StateClosed || p.health.consecutiveFailures != 0 {
		t.Errorf("expected health closed with 0 failures, got state=%v, failures=%d", p.health.state, p.health.consecutiveFailures)
	}
	p.health.mu.RUnlock()

	p.udpHealth.mu.RLock()
	if p.udpHealth.state != StateClosed || p.udpHealth.consecutiveFailures != 0 {
		t.Errorf("expected udpHealth closed with 0 failures, got state=%v, failures=%d", p.udpHealth.state, p.udpHealth.consecutiveFailures)
	}
	p.udpHealth.mu.RUnlock()
}

func TestManager_IPv6Selection(t *testing.T) {
	m, err := NewManager(UpstreamConfig{
		Default: "latency",
		Proxies: []ProxyEntry{
			{Alias: "ss-node", URL: "socks5://127.0.0.1:1080"},
			{Alias: "lantern-node", URL: "socks5://127.0.0.2:1080", Provider: "lantern"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	ssNode := m.aliasMap["ss-node"]
	lanternNode := m.aliasMap["lantern-node"]

	// Set ss-node to higher latency (100ms) and confirm IPv6 capability
	setCircuitLatency(m, "ss-node", false, 100*time.Millisecond)
	ssNode.SetIPv6Capability(IPv6CapSupported)

	// Set lantern-node to lower latency (10ms). Its provider is "lantern", so SupportsIPv6 is false.
	setCircuitLatency(m, "lantern-node", false, 10*time.Millisecond)

	if ssNode.SupportsIPv6() != true {
		t.Fatalf("expected ssNode.SupportsIPv6() == true")
	}
	if lanternNode.SupportsIPv6() != false {
		t.Fatalf("expected lanternNode.SupportsIPv6() == false")
	}

	// Verify orderedProxies puts lantern-node first due to lower latency (10ms vs 100ms)
	ordered := m.orderedProxies()
	if len(ordered) < 2 || ordered[0].Host != "127.0.0.2" {
		t.Fatalf("expected lantern-node (127.0.0.2) to be first for TCP latency, got %v", ordered[0].Host)
	}

	// 1. Dialing IPv6 destination when only lantern is available: must fail immediately
	mLanternOnly, err := NewManager(UpstreamConfig{
		Default: "latency",
		Proxies: []ProxyEntry{
			{Alias: "lantern-node", URL: "socks5://127.0.0.2:1080", Provider: "lantern"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mLanternOnly.Stop()

	_, err = mLanternOnly.ConnectDefault(context.Background(), "2400:8905::1", 80)
	if err == nil || !strings.Contains(err.Error(), "no IPv6 capable proxy available") {
		t.Fatalf("expected 'no IPv6 capable proxy available' error, got %v", err)
	}

	// 2. Dialing IPv6 UDP when only lantern is available: must fail immediately
	_, err = mLanternOnly.defaultUDPAssociate(context.Background(), slog.Default(), "2400:8905::1", 53)
	if err == nil || !strings.Contains(err.Error(), "no default UDP proxy available supporting IPv6") {
		t.Fatalf("expected 'no default UDP proxy available supporting IPv6' error, got %v", err)
	}

	// 3. Dialing IPv6 destination with pool [ss-node, lantern-node]:
	// Candidates filter skips lantern-node, selects ss-node.
	// When ss-node dial fails, it marks IPv6 unsupported but isolates TCP circuit breaker.
	_, _ = m.ConnectDefault(context.Background(), "2400:8905::1", 80)
	if ssNode.IPv6Capability() != IPv6CapUnsupported {
		t.Fatalf("expected ssNode to become IPv6CapUnsupported after IPv6 dial failure, got %v", ssNode.IPv6Capability())
	}
	if ssNode.health.consecutiveFailures != 0 {
		t.Fatalf("expected ssNode TCP health failures == 0, got %d", ssNode.health.consecutiveFailures)
	}
}





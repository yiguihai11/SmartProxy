package upstream

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"smartproxy/internal/config"
	"smartproxy/internal/rules"
	"smartproxy/internal/trace"
)

type Manager struct {
	mu             sync.RWMutex
	aliasMap       map[string]*Proxy
	defaultProxies []*Proxy
	strategy       string
	rrCounter      atomic.Uint64
	healthChecker  *HealthChecker
	dnsUDPPool     *UDPAssociatePool
}

func NewManager(cfg UpstreamConfig) (*Manager, error) {
	m := &Manager{
		dnsUDPPool: NewUDPAssociatePool(4),
	}
	m.rebuildFromConfig(cfg)
	m.healthChecker = NewHealthChecker(cfg.HealthCheck, m.defaultProxies)
	m.healthChecker.Start()
	slog.Info("upstream manager initialized", "aliases", len(m.aliasMap), "strategy", m.strategy)
	return m, nil
}

func (m *Manager) Reload(cfg UpstreamConfig) {
	m.mu.Lock()
	// Rebuild creates brand-new Proxy objects whose health is fully automatic, which would
	// silently revert any explicit user disable/enable. Preserve the manual pins (keyed by
	// alias) so a config hot-reload keeps the user's choice.
	pins := m.captureManualPins()
	m.rebuildFromConfig(cfg)
	newProxies := m.defaultProxies
	m.mu.Unlock()

	if m.dnsUDPPool != nil {
		m.dnsUDPPool.Close()
	}
	m.dnsUDPPool = NewUDPAssociatePool(4)

	// newProxies are freshly built by rebuildFromConfig: their health is zero-value
	// (StateClosed) apart from construction-time default pins, which set state and
	// manual consistently (hev udp_in_tcp TCP-down via applyUDPInTCPDefaults, SS-plugin
	// UDP-down via NewProxy). Do NOT blanket-reset them: reset() would clear a default
	// pin's forced StateOpen back to Closed while leaving manual=&false, reporting the
	// circuit as both "manual" and "available" (the add-node-shows-TCP-up bug).
	// restoreManualPins overlays the PRE-reload user pins for aliases that already existed
	// (Set/ClearManualState keep state and manual in sync); brand-new aliases keep their
	// construction defaults.
	m.restoreManualPins(pins)

	if m.healthChecker != nil {
		m.healthChecker.Reload(cfg.HealthCheck, newProxies)
	}
	slog.Info("upstream manager reloaded", "aliases", len(m.aliasMap), "strategy", m.strategy)
}

// Stop shuts down the manager's background work: the health checker's per-node check loops
// and the DNS UDP associate pool. It is called from Engine.Stop. Without it, every
// stop/restart (e.g. toggling the Android VPN) leaks one goroutine per proxy node (each
// checkLoop spins on stopCh forever) plus up to four pooled UDP ASSOCIATE connections.
func (m *Manager) Stop() {
	if m.healthChecker != nil {
		m.healthChecker.Stop()
	}
	if m.dnsUDPPool != nil {
		m.dnsUDPPool.Close()
	}
}

// circuitPin captures one health circuit's manual pin: whether it is pinned and, if so,
// the forced availability. Both index 0 (TCP) and index 1 (UDP) live in the same array.
// defaultDriven records whether the circuit's construction-time default force-down applied
// on the PRE-reload node (TCP: hev udp_in_tcp; UDP: ss + SIP003 plugin), so a reload that
// newly flips that flag on can let the fresh construction default win instead of overlaying
// a stale pin from when the node had no such default.
type circuitPin struct {
	pinned        bool
	up            bool
	defaultDriven bool
}

// captureManualPins records each proxy's manual circuit pins keyed by alias. Caller must
// hold m.mu (any level).
func (m *Manager) captureManualPins() map[string][2]circuitPin {
	pins := make(map[string][2]circuitPin, len(m.aliasMap))
	for alias, p := range m.aliasMap {
		if p == nil {
			continue // "direct" has no health circuit
		}
		tpinned, tup := p.health.ManualPin()
		upinned, uup := p.udpHealth.ManualPin()
		pins[alias] = [2]circuitPin{
			{pinned: tpinned, up: tup, defaultDriven: p.tcpDefaultDriven()},
			{pinned: upinned, up: uup, defaultDriven: p.udpDefaultDriven()},
		}
	}
	return pins
}

// restoreManualPins re-applies saved manual pins to proxies that still exist after a reload.
// An alias that disappeared from the config drops its pin (the node no longer exists); an
// alias that kept its name keeps its pin even if its URL changed, since the user disabled
// the alias, not the server. The saved state is applied in full — pinned circuits are
// re-pinned and released circuits are cleared — so the exact pre-reload manual state wins
// over any construction default (e.g. a plugin node released to automatic stays released,
// instead of reverting to its default UDP-down). The one exception: when a circuit's
// default force-down flag is flipped ON by the reload itself (a normal socks node edited to
// enable udp_in_tcp, or an ss node that gains a plugin), the pre-toggle pin is stale — the
// fresh construction default is left in place rather than re-applying the old auto/up pin,
// otherwise the newly-enabled hev/plugin node would silently skip its safety default.
// Caller must not hold m.mu.
func (m *Manager) restoreManualPins(pins map[string][2]circuitPin) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for alias, pin := range pins {
		p, ok := m.aliasMap[alias]
		if !ok || p == nil {
			continue
		}
		restore := func(ph *ProxyHealth, cp circuitPin, nowDefaultDriven bool) {
			// Flag just toggled on (was not default-driven, now is): keep the construction
			// default applied by rebuildFromConfig and drop the stale pre-toggle pin.
			if nowDefaultDriven && !cp.defaultDriven {
				return
			}
			if cp.pinned {
				ph.SetManualState(cp.up)
			} else {
				ph.ClearManualState()
			}
		}
		restore(&p.health, pin[0], p.tcpDefaultDriven())
		restore(&p.udpHealth, pin[1], p.udpDefaultDriven())
	}
}

func (m *Manager) rebuildFromConfig(cfg UpstreamConfig) {
	aliasMap := make(map[string]*Proxy)
	aliasMap["direct"] = nil
	reservedAliases := map[string]bool{"direct": true}
	var defaultProxies []*Proxy

	for i, entry := range cfg.Proxies {
		alias := entry.Alias
		if alias == "" {
			alias = fmt.Sprintf("proxy%d", i)
		}
		if entry.URL == "" {
			if !reservedAliases[alias] {
				slog.Warn("proxy without URL skipped", "alias", alias)
			}
			continue
		}
		if reservedAliases[alias] {
			slog.Warn("cannot override reserved alias, skipping", "alias", alias)
			continue
		}
		proxy, err := NewProxy(entry.URL)
		if err != nil {
			slog.Warn("failed to create proxy", "url", MaskProxyURL(entry.URL), "error", err)
			continue
		}
		// The config entry's udp_in_tcp field (the panel switch) is the primary source;
		// an imported link may also carry ?udp_in_tcp=1, which NewProxy already parsed.
		proxy.UDPInTCP = entry.UDPInTCP || proxy.UDPInTCP
		// A udp_in_tcp node defaults to TCP manually down (plaintext framed carrier, GFW-
		// fingerprintable); the user can re-enable it per circuit. restoreManualPins runs
		// after rebuild and re-applies any saved pin, so this default only sticks on
		// freshly-built nodes and never reverts a user's re-enable.
		proxy.applyUDPInTCPDefaults()
		aliasMap[alias] = proxy
		defaultProxies = append(defaultProxies, proxy)
	}
	m.aliasMap = aliasMap
	m.defaultProxies = defaultProxies
	m.strategy = cfg.Default
}

type UpstreamConfig struct {
	Default     string
	HealthCheck config.HealthCheckConf
	Proxies     []ProxyEntry
}

type ProxyEntry struct {
	Alias string
	URL   string
	// UDPInTCP carries the node's udp_in_tcp switch from the config entry (see
	// Proxy.UDPInTCP). It is OR-ed with whatever the URL's ?udp_in_tcp=1 query set.
	UDPInTCP bool
}

func (m *Manager) SelectProxy(ctx context.Context, targetIP string, targetPort int, domain string, engine *rules.Engine) (string, *Proxy) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// 选路发生在某条流的会话建立里:日志必须带 flow id(TUN/SOCKS5 入口注入的 ctx 一路
	// 传到这里),否则 "proxy rule matched" 这条最关键的选路日志会掉号,破坏 grep flow=N
	// 从入口追到转出的整条链。测试传 context.Background() 时 trace.Log 退回 slog.Default。
	ll := trace.Log(ctx)
	if engine != nil {
		alias, matched := engine.MatchProxyRule(targetIP, targetPort, domain)
		if matched {
			ll.Info("proxy rule matched", "alias", alias)
			if alias == "direct" {
				return "direct", nil
			}
			proxy, ok := m.aliasMap[alias]
			if ok && proxy != nil {
				return "", proxy
			}
			ll.Warn("alias not found, falling back to default", "alias", alias)
			return "fallback", nil
		}
	}
	return "fallback", nil
}

func (m *Manager) ConnectDefault(ctx context.Context, host string, port int) (net.Conn, error) {
	ll := trace.Log(ctx)
	for _, proxy := range m.orderedProxies() {
		if proxy.IsUDPOnly() {
			ll.Debug("skipping udp_only proxy for TCP", "url", MaskProxyURL(proxy.URL))
			continue
		}
		if !proxy.IsAvailable() {
			ll.Debug("skipping unhealthy proxy", "url", MaskProxyURL(proxy.URL))
			continue
		}
		ll.Info("trying default proxy", "url", MaskProxyURL(proxy.URL))
		conn, err := proxy.Connect(ctx, host, port)
		if err != nil {
			ll.Warn("default proxy failed", "url", MaskProxyURL(proxy.URL), "error", err)
			if m.healthChecker != nil {
				m.healthChecker.RecordFailure(proxy, err)
			}
			continue
		}
		ll.Info("connected via", "url", MaskProxyURL(proxy.URL))
		if m.healthChecker != nil {
			m.healthChecker.RecordSuccess(proxy, 0)
		}
		return conn, nil
	}
	return nil, fmt.Errorf("all default upstream proxies failed to connect to %s:%d", host, port)
}

func (m *Manager) orderedProxies() []*Proxy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.defaultProxies)
	if n <= 1 {
		return m.defaultProxies
	}
	switch m.strategy {
	case "round_robin":
		start := int(m.rrCounter.Add(1)-1) % n
		result := make([]*Proxy, n)
		for i := 0; i < n; i++ {
			result[i] = m.defaultProxies[(start+i)%n]
		}
		return result
	case "random":
		result := make([]*Proxy, n)
		copy(result, m.defaultProxies)
		rand.Shuffle(n, func(i, j int) { result[i], result[j] = result[j], result[i] })
		return result
	case "latency":
		result := make([]*Proxy, n)
		copy(result, m.defaultProxies)
		sort.SliceStable(result, func(i, j int) bool {
			li, lj := result[i].IsAvailable(), result[j].IsAvailable()
			if li && !lj {
				return true
			}
			if !li && lj {
				return false
			}
			latI := result[i].health.Latency()
			latJ := result[j].health.Latency()
			if latI == 0 {
				latI = time.Hour
			}
			if latJ == 0 {
				latJ = time.Hour
			}
			return latI < latJ
		})
		return result
	default:
		return m.defaultProxies
	}
}

func (m *Manager) Connect(ctx context.Context, host string, port int, domain string, engine *rules.Engine) (net.Conn, string) {
	ll := trace.Log(ctx)
	result, selected := m.SelectProxy(ctx, host, port, domain, engine)
	if result == "direct" {
		return nil, "direct"
	}
	if result == "fallback" {
		conn, err := m.ConnectDefault(ctx, host, port)
		if err != nil {
			return nil, "failed"
		}
		return conn, "proxy"
	}
	if selected == nil {
		return nil, "failed"
	}
	if selected.IsUDPOnly() {
		ll.Warn("rule selected a udp_only proxy for TCP, connection failed", "url", MaskProxyURL(selected.URL))
		return nil, "failed"
	}
	// An explicit manual "Disable" is honored even by rule routing: a disabled node must
	// never carry traffic, whatever the rule says. Auto-opened circuits (probe failures)
	// are still tried — rules are explicit intent and a live recovery may succeed.
	if selected.health.IsManuallyDisabled() {
		ll.Warn("rule selected a manually-disabled proxy for TCP, connection failed", "url", MaskProxyURL(selected.URL))
		return nil, "failed"
	}
	if !selected.IsAvailable() {
		ll.Warn("selected proxy is unhealthy but still using it due to rule", "alias", MaskProxyURL(selected.URL))
	}
	conn, err := selected.Connect(ctx, host, port)
	if err != nil {
		ll.Error("proxy connect failed", "url", MaskProxyURL(selected.URL), "error", err)
		if m.healthChecker != nil {
			m.healthChecker.RecordFailure(selected, err)
		}
		return nil, "failed"
	}
	if m.healthChecker != nil {
		m.healthChecker.RecordSuccess(selected, 0)
	}
	return conn, "proxy"
}

func (m *Manager) AcquireDNSUDP(ctx context.Context, dnsHost string, dnsPort int) (net.Conn, error) {
	return m.dnsUDPPool.Acquire(ctx, dnsHost, dnsPort, func(ctx context.Context, host string, port int) (net.Conn, error) {
		return m.UDPAssociate(ctx, host, port, "", nil)
	})
}

func (m *Manager) ReleaseDNSUDP(conn net.Conn) {
	m.dnsUDPPool.Release(conn)
}

func (m *Manager) DiscardDNSUDP(conn net.Conn) {
	m.dnsUDPPool.Discard(conn)
}

func (m *Manager) UDPAssociate(ctx context.Context, host string, port int, domain string, engine *rules.Engine) (net.Conn, error) {
	ll := trace.Log(ctx)
	result, selected := m.SelectProxy(ctx, host, port, domain, engine)
	if result == "direct" {
		return nil, fmt.Errorf("UDP direct is not supported")
	}
	if selected != nil {
		// Honor an explicit manual "Disable" even under rule routing, mirroring Connect.
		if selected.udpHealth.IsManuallyDisabled() {
			ll.Warn("rule selected a manually-disabled proxy for UDP, connection failed", "url", MaskProxyURL(selected.URL))
			return nil, fmt.Errorf("proxy %s is manually disabled for UDP", MaskProxyURL(selected.URL))
		}
		ll.Debug("UDPAssociate: using selected proxy by rule",
			"proxy", MaskProxyURL(selected.URL), "target", fmt.Sprintf("%s:%d", host, port))
		conn, err := selected.UDPAssociate(ctx, host, port)
		// First-detection capability record from real traffic: a raw-only node is learned
		// even before the health probe runs, enabling the raw routing fast path. Re-classifies
		// a raw node whose ASSOCIATE recheck just succeeded (raw → standard). A probe finding
		// (standard/raw/none) is never overridden.
		if err == nil && selected.needsCapabilityClassify() {
			selected.classifyUDPCapability(conn)
		}
		if m.healthChecker != nil {
			if err != nil {
				m.healthChecker.RecordUDPFailure(selected, err)
			} else {
				m.healthChecker.RecordUDPSuccess(selected, 0)
			}
		}
		return conn, err
	}
	for _, proxy := range m.orderedProxies() {
		if proxy.SupportsUDP() {
			if !proxy.IsUDPAvailable() {
				ll.Debug("UDPAssociate: skipping unhealthy proxy", "proxy", MaskProxyURL(proxy.URL))
				continue
			}
			ll.Debug("UDPAssociate: trying proxy", "proxy", MaskProxyURL(proxy.URL),
				"target", fmt.Sprintf("%s:%d", host, port))
			conn, err := proxy.UDPAssociate(ctx, host, port)
			if m.healthChecker != nil {
				if err != nil {
					m.healthChecker.RecordUDPFailure(proxy, err)
				} else {
					m.healthChecker.RecordUDPSuccess(proxy, 0)
				}
			}
			if err == nil {
				if proxy.needsCapabilityClassify() {
					proxy.classifyUDPCapability(conn)
				}
				ll.Debug("UDPAssociate: proxy succeeded", "proxy", MaskProxyURL(proxy.URL))
				return conn, nil
			}
			ll.Warn("UDPAssociate: proxy failed, trying next",
				"proxy", MaskProxyURL(proxy.URL), "error", err)
		}
	}
	return nil, fmt.Errorf("no default UDP proxy available")
}

// UDPAssociateSelected uses a pre-selected proxy for UDP ASSOCIATE
// (skipping the duplicate SelectProxy match)
func (m *Manager) UDPAssociateSelected(ctx context.Context, host string, port int, selected *Proxy) (net.Conn, error) {
	ll := trace.Log(ctx)
	if selected != nil {
		ll.Debug("UDPAssociateSelected: using pre-selected proxy",
			"proxy", MaskProxyURL(selected.URL), "target", fmt.Sprintf("%s:%d", host, port))
		conn, err := selected.UDPAssociate(ctx, host, port)
		if err == nil && selected.needsCapabilityClassify() {
			selected.classifyUDPCapability(conn)
		}
		if m.healthChecker != nil {
			if err != nil {
				m.healthChecker.RecordUDPFailure(selected, err)
			} else {
				m.healthChecker.RecordUDPSuccess(selected, 0)
			}
		}
		return conn, err
	}
	// selected == nil: fall back to orderedProxies
	for _, proxy := range m.orderedProxies() {
		if proxy.SupportsUDP() {
			if !proxy.IsUDPAvailable() {
				ll.Debug("UDPAssociateSelected: skipping unhealthy proxy", "proxy", MaskProxyURL(proxy.URL))
				continue
			}
			ll.Debug("UDPAssociateSelected: trying proxy", "proxy", MaskProxyURL(proxy.URL),
				"target", fmt.Sprintf("%s:%d", host, port))
			conn, err := proxy.UDPAssociate(ctx, host, port)
			if m.healthChecker != nil {
				if err != nil {
					m.healthChecker.RecordUDPFailure(proxy, err)
				} else {
					m.healthChecker.RecordUDPSuccess(proxy, 0)
				}
			}
			if err == nil {
				if proxy.needsCapabilityClassify() {
					proxy.classifyUDPCapability(conn)
				}
				ll.Debug("UDPAssociateSelected: proxy succeeded", "proxy", MaskProxyURL(proxy.URL))
				return conn, nil
			}
			ll.Warn("UDPAssociateSelected: proxy failed, trying next",
				"proxy", MaskProxyURL(proxy.URL), "error", err)
		}
	}
	return nil, fmt.Errorf("no default UDP proxy available")
}

type ProxyInfo struct {
	Alias string `json:"alias"`
	URL   string `json:"url"`
	// Name is the node's friendly name from the ss:// #fragment (see Proxy.Name);
	// empty for URLs without one.
	Name   string `json:"name"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
	// UDPInTCP reports whether the node is configured as a hev UDP-in-TCP relay
	// (see Proxy.UDPInTCP). The panel reads this to pre-check the switch when editing.
	UDPInTCP bool `json:"udp_in_tcp"`
	// Mode is the effective mode derived purely from scheme capability plus probe results
	// (see Proxy.EffectiveMode) — the value routing actually uses, so it moves over time.
	Mode string `json:"mode"`
	// UDPCapability is how this node's UDP relay works, auto-detected from probing and real
	// traffic (unknown/standard/raw/none, see Proxy.UDPCapability). unknown means not yet
	// detected — e.g. health check disabled or a non-UDP scheme that is never probed.
	UDPCapability string              `json:"udp_capability"`
	Health        ProxyHealthSnapshot `json:"health"`
	UDPHealth     ProxyHealthSnapshot `json:"udp_health"`
}

func (m *Manager) Proxies() []ProxyInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	reverseMap := make(map[*Proxy]string, len(m.aliasMap))
	for alias, proxy := range m.aliasMap {
		if proxy != nil {
			reverseMap[proxy] = alias
		}
	}

	infos := make([]ProxyInfo, 0, len(m.defaultProxies))
	for _, proxy := range m.defaultProxies {
		alias := reverseMap[proxy]
		infos = append(infos, ProxyInfo{
			Alias:         alias,
			URL:           proxy.URL,
			Name:          proxy.Name,
			Host:          proxy.Host,
			Port:          proxy.Port,
			Scheme:        string(proxy.Scheme),
			UDPInTCP:      proxy.UDPInTCP,
			Mode:          proxy.EffectiveMode(),
			UDPCapability: string(proxy.UDPCapability()),
			Health:        proxy.health.Snapshot(),
			UDPHealth:     proxy.udpHealth.Snapshot(),
		})
	}
	return infos
}

// SetCircuitHealth pins or releases one (or both) of a proxy's circuits. circuit is
// "tcp", "udp" or "both"; action is "enable" (force up), "disable" (force down) or
// "auto" (release back to automatic health-check control). Pinned circuits stay put
// across probe cycles until released.
func (m *Manager) SetCircuitHealth(alias, circuit, action string) error {
	m.mu.RLock()
	proxy, ok := m.aliasMap[alias]
	m.mu.RUnlock()
	if !ok || proxy == nil {
		return fmt.Errorf("proxy alias %q not found", alias)
	}
	apply := func(ph *ProxyHealth) {
		switch action {
		case "enable":
			ph.SetManualState(true)
		case "disable":
			ph.SetManualState(false)
		case "auto":
			ph.ClearManualState()
		}
	}
	switch circuit {
	case "tcp":
		apply(&proxy.health)
	case "udp":
		apply(&proxy.udpHealth)
	default: // "both"
		apply(&proxy.health)
		apply(&proxy.udpHealth)
	}
	slog.Info("manual proxy health set", "alias", alias, "circuit", circuit, "action", action)
	return nil
}

// ResetAutoOpenedCircuits is the "one-click recover nodes" action: every circuit the
// health checker auto-opened (probe-failure Open/HalfOpen with no manual pin) is returned
// to closed, so it is immediately usable again and re-validated by the next probe. Manual
// pins — force-up or force-down — are never touched, and recovery stays temporary: another
// probe/traffic failure re-opens the circuit through the normal flow. Returns how many
// circuits were reset.
func (m *Manager) ResetAutoOpenedCircuits() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var n int
	for _, proxy := range m.defaultProxies {
		if proxy.health.resetAutoOpened() {
			n++
		}
		if proxy.udpHealth.resetAutoOpened() {
			n++
		}
	}
	return n
}

func (m *Manager) Strategy() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.strategy
}

// TestProxy runs an on-demand, real network test for the given proxy alias and protocol ("tcp" or "udp").
// Returns the round-trip latency and any error encountered during the probe.
func (m *Manager) TestProxy(ctx context.Context, alias, protocol string) (time.Duration, error) {
	m.mu.RLock()
	proxy, ok := m.aliasMap[alias]
	m.mu.RUnlock()
	if !ok || proxy == nil {
		return 0, fmt.Errorf("proxy alias %q not found", alias)
	}

	protocol = strings.ToLower(protocol)
	var latency time.Duration
	var err error

	switch protocol {
	case "tcp":
		if m.healthChecker != nil {
			latency, err = m.healthChecker.ProbeTCP(ctx, proxy)
		} else {
			latency, err = probeTCP(ctx, proxy, "http://cp.cloudflare.com/generate_204")
		}
		if err == nil {
			proxy.health.UpdateLatency(latency)
			if m.healthChecker != nil {
				m.healthChecker.RecordSuccess(proxy, latency)
			}
		}
	case "udp":
		if !proxy.SchemeSupportsUDP() {
			return 0, fmt.Errorf("proxy scheme %s does not support UDP", proxy.Scheme)
		}
		if m.healthChecker != nil {
			latency, err = m.healthChecker.ProbeUDP(ctx, proxy)
		} else {
			dummyHC := NewHealthChecker(config.HealthCheckConf{}, nil)
			latency, err = dummyHC.ProbeUDP(ctx, proxy)
		}
		if err == nil {
			proxy.udpHealth.UpdateLatency(latency)
			if m.healthChecker != nil {
				m.healthChecker.RecordUDPSuccess(proxy, latency)
			}
		}
	default:
		return 0, fmt.Errorf("invalid protocol %q, must be tcp or udp", protocol)
	}

	return latency, err
}

package upstream

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"smartproxy/internal/config"
	"smartproxy/internal/rules"
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

	for _, p := range newProxies {
		p.health.reset()
	}
	// Restore after reset so a pin's forced state wins over the fresh automatic state.
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
type circuitPin struct {
	pinned bool
	up     bool
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
		pins[alias] = [2]circuitPin{{pinned: tpinned, up: tup}, {pinned: upinned, up: uup}}
	}
	return pins
}

// restoreManualPins re-applies saved manual pins to proxies that still exist after a reload.
// An alias that disappeared from the config drops its pin (the node no longer exists); an
// alias that kept its name keeps its pin even if its URL changed, since the user disabled
// the alias, not the server. The saved state is applied in full — pinned circuits are
// re-pinned and released circuits are cleared — so the exact pre-reload manual state wins
// over any construction default (e.g. a plugin node released to automatic stays released,
// instead of reverting to its default UDP-down). Caller must not hold m.mu.
func (m *Manager) restoreManualPins(pins map[string][2]circuitPin) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for alias, pin := range pins {
		p, ok := m.aliasMap[alias]
		if !ok || p == nil {
			continue
		}
		restore := func(ph *ProxyHealth, cp circuitPin) {
			if cp.pinned {
				ph.SetManualState(cp.up)
			} else {
				ph.ClearManualState()
			}
		}
		restore(&p.health, pin[0])
		restore(&p.udpHealth, pin[1])
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

func (m *Manager) SelectProxy(targetIP string, targetPort int, domain string, engine *rules.Engine) (string, *Proxy) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if engine != nil {
		alias, matched := engine.MatchProxyRule(targetIP, targetPort, domain)
		if matched {
			slog.Info("proxy rule matched", "alias", alias)
			if alias == "direct" {
				return "direct", nil
			}
			proxy, ok := m.aliasMap[alias]
			if ok && proxy != nil {
				return "", proxy
			}
			slog.Warn("alias not found, falling back to default", "alias", alias)
			return "fallback", nil
		}
	}
	return "fallback", nil
}

func (m *Manager) ConnectDefault(ctx context.Context, host string, port int) (net.Conn, error) {
	for _, proxy := range m.orderedProxies() {
		if proxy.IsUDPOnly() {
			slog.Debug("skipping udp_only proxy for TCP", "url", proxy.URL)
			continue
		}
		if !proxy.IsAvailable() {
			slog.Debug("skipping unhealthy proxy", "url", proxy.URL)
			continue
		}
		slog.Info("trying default proxy", "url", proxy.URL)
		conn, err := proxy.Connect(ctx, host, port)
		if err != nil {
			slog.Warn("default proxy failed", "url", proxy.URL, "error", err)
			if m.healthChecker != nil {
				m.healthChecker.RecordFailure(proxy, err)
			}
			continue
		}
		slog.Info("connected via", "url", proxy.URL)
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
	result, selected := m.SelectProxy(host, port, domain, engine)
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
		slog.Warn("rule selected a udp_only proxy for TCP, connection failed", "url", selected.URL)
		return nil, "failed"
	}
	// An explicit manual "Disable" is honored even by rule routing: a disabled node must
	// never carry traffic, whatever the rule says. Auto-opened circuits (probe failures)
	// are still tried — rules are explicit intent and a live recovery may succeed.
	if selected.health.IsManuallyDisabled() {
		slog.Warn("rule selected a manually-disabled proxy for TCP, connection failed", "url", selected.URL)
		return nil, "failed"
	}
	if !selected.IsAvailable() {
		slog.Warn("selected proxy is unhealthy but still using it due to rule", "alias", selected.URL)
	}
	conn, err := selected.Connect(ctx, host, port)
	if err != nil {
		slog.Error("proxy connect failed", "url", selected.URL, "error", err)
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
	result, selected := m.SelectProxy(host, port, domain, engine)
	if result == "direct" {
		return nil, fmt.Errorf("UDP direct is not supported")
	}
	if selected != nil {
		// Honor an explicit manual "Disable" even under rule routing, mirroring Connect.
		if selected.udpHealth.IsManuallyDisabled() {
			slog.Warn("rule selected a manually-disabled proxy for UDP, connection failed", "url", selected.URL)
			return nil, fmt.Errorf("proxy %s is manually disabled for UDP", selected.URL)
		}
		slog.Debug("UDPAssociate: using selected proxy by rule",
			"proxy", selected.URL, "target", fmt.Sprintf("%s:%d", host, port))
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
				slog.Debug("UDPAssociate: skipping unhealthy proxy", "proxy", proxy.URL)
				continue
			}
			slog.Debug("UDPAssociate: trying proxy", "proxy", proxy.URL,
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
				slog.Debug("UDPAssociate: proxy succeeded", "proxy", proxy.URL)
				return conn, nil
			}
			slog.Warn("UDPAssociate: proxy failed, trying next",
				"proxy", proxy.URL, "error", err)
		}
	}
	return nil, fmt.Errorf("no default UDP proxy available")
}

// UDPAssociateSelected uses a pre-selected proxy for UDP ASSOCIATE
// (skipping the duplicate SelectProxy match)
func (m *Manager) UDPAssociateSelected(ctx context.Context, host string, port int, selected *Proxy) (net.Conn, error) {
	if selected != nil {
		slog.Debug("UDPAssociateSelected: using pre-selected proxy",
			"proxy", selected.URL, "target", fmt.Sprintf("%s:%d", host, port))
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
				slog.Debug("UDPAssociateSelected: skipping unhealthy proxy", "proxy", proxy.URL)
				continue
			}
			slog.Debug("UDPAssociateSelected: trying proxy", "proxy", proxy.URL,
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
				slog.Debug("UDPAssociateSelected: proxy succeeded", "proxy", proxy.URL)
				return conn, nil
			}
			slog.Warn("UDPAssociateSelected: proxy failed, trying next",
				"proxy", proxy.URL, "error", err)
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

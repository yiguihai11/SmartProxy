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
	if m.healthChecker != nil {
		m.healthChecker.Reload(cfg.HealthCheck, newProxies)
	}
	slog.Info("upstream manager reloaded", "aliases", len(m.aliasMap), "strategy", m.strategy)
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
			slog.Warn("failed to create proxy", "url", entry.URL, "error", err)
			continue
		}
		proxy.Mode = entry.Mode
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
	// Mode is the upstream's status marker: "tcp_and_udp" (default), "tcp_only" or "udp_only".
	// tcp_only is skipped by UDP, udp_only is skipped by TCP routing and by the TCP health
	// probe, so TCP unavailability never disables a udp_only upstream's UDP.
	Mode string
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
		slog.Debug("UDPAssociate: using selected proxy by rule",
			"proxy", selected.URL, "target", fmt.Sprintf("%s:%d", host, port))
		conn, err := selected.UDPAssociate(ctx, host, port)
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
	Alias     string              `json:"alias"`
	URL       string              `json:"url"`
	Host      string              `json:"host"`
	Port      int                 `json:"port"`
	Scheme    string              `json:"scheme"`
	Mode      string              `json:"mode,omitempty"`
	Health    ProxyHealthSnapshot `json:"health"`
	UDPHealth ProxyHealthSnapshot `json:"udp_health"`
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
			Alias:     alias,
			URL:       proxy.URL,
			Host:      proxy.Host,
			Port:      proxy.Port,
			Scheme:    string(proxy.Scheme),
			Mode:      proxy.ModeName(),
			Health:    proxy.health.Snapshot(),
			UDPHealth: proxy.udpHealth.Snapshot(),
		})
	}
	return infos
}

func (m *Manager) SetProxyHealth(alias string, available bool) error {
	m.mu.RLock()
	proxy, ok := m.aliasMap[alias]
	m.mu.RUnlock()
	if !ok || proxy == nil {
		return fmt.Errorf("proxy alias %q not found", alias)
	}
	proxy.health.SetManualState(available)
	proxy.udpHealth.SetManualState(available)
	slog.Info("manual proxy health set", "alias", alias, "available", available)
	return nil
}

func (m *Manager) Strategy() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.strategy
}

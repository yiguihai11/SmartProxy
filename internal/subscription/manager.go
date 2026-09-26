package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"smartproxy/internal/config"
	"smartproxy/internal/safego"
	"smartproxy/internal/upstream"
)

const (
	defaultUpdateInterval = 12 * time.Hour
	minUpdateInterval     = 5 * time.Minute
	httpTimeout           = 30 * time.Second
	maxResponseBodySize   = 10 * 1024 * 1024 // 10MB
	cacheFileName         = "subscriptions_cache.json"
)

// ItemState holds the runtime status and metadata of a single subscription.
type ItemState struct {
	Name           string                `json:"name"`
	URL            string                `json:"url"`
	Type           string                `json:"type,omitempty"`
	UpdateInterval string                `json:"update_interval,omitempty"`
	Enabled        bool                  `json:"enabled"`
	UseProxy       bool                  `json:"use_proxy"`
	LastUpdate     time.Time             `json:"last_update,omitempty"`
	LastError      string                `json:"last_error,omitempty"`
	NodeCount      int                   `json:"node_count"`
	Upload         int64                 `json:"upload,omitempty"`
	Download       int64                 `json:"download,omitempty"`
	Total          int64                 `json:"total,omitempty"`
	Expire         int64                 `json:"expire,omitempty"` // Unix timestamp seconds
	Nodes          []upstream.ProxyEntry `json:"nodes,omitempty"`
}

// Manager coordinates fetching, caching, and auto-refresh of upstream subscriptions.
type Manager struct {
	mu            sync.RWMutex
	cfgDir        string
	upstreamMgr   *upstream.Manager
	subs          map[string]*ItemState
	subsOrder     []string
	httpClient    *http.Client
	proxiedClient *http.Client
	ctx           context.Context
	cancel        context.CancelFunc
	stopOnce      sync.Once
}

// NewManager creates a Subscription Manager.
func NewManager(cfgDir string, configs []config.SubscriptionConf, upstreamMgr *upstream.Manager) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		cfgDir:      cfgDir,
		upstreamMgr: upstreamMgr,
		subs:        make(map[string]*ItemState),
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		ctx:    ctx,
		cancel: cancel,
	}
	// 走节点代理的客户端:DialContext 经 ConnectDefault 选最快可用节点转发,
	// 主机名透传到远端解析(等价 curl --socks5h);TLS 在隧道连接外本地完成。
	proxiedTransport := http.DefaultTransport.(*http.Transport).Clone()
	proxiedTransport.Proxy = nil
	proxiedTransport.DialContext = func(dialCtx context.Context, _, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid subscription target address %q: %w", addr, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid subscription target port %q: %w", portStr, err)
		}
		if m.upstreamMgr == nil {
			return nil, errors.New("no upstream manager available")
		}
		return m.upstreamMgr.ConnectDefault(dialCtx, host, port)
	}
	m.proxiedClient = &http.Client{
		Transport: proxiedTransport,
		Timeout:   httpTimeout,
	}

	// 1. Initialize states from config
	for _, c := range configs {
		name := stringsTrim(c.Name)
		if name == "" {
			continue
		}
		interval := stringsTrim(c.UpdateInterval)
		if interval == "" {
			interval = "12h"
		}
		item := &ItemState{
			Name:           name,
			URL:            stringsTrim(c.URL),
			Type:           stringsTrim(c.Type),
			UpdateInterval: interval,
			Enabled:        c.Enabled,
			UseProxy:       c.UsesProxy(),
		}
		m.subs[name] = item
		m.subsOrder = append(m.subsOrder, name)
	}

	// 2. Load disk cache if available
	m.loadCache()

	// 3. Inject cached nodes for enabled subscriptions immediately
	for _, name := range m.subsOrder {
		item := m.subs[name]
		if item.Enabled && len(item.Nodes) > 0 && m.upstreamMgr != nil {
			m.upstreamMgr.SetProviderProxies("sub:"+item.Name, item.Nodes)
			slog.Info("restored cached subscription nodes", "subscription", item.Name, "count", len(item.Nodes))
		}
	}

	return m
}

// Start runs background auto-refresh tasks.
func (m *Manager) Start() {
	// Initial refresh for enabled subscriptions with no nodes
	safego.Go("subscription.initial_refresh", func() {
		for _, name := range m.orderedNames() {
			m.mu.RLock()
			item, exists := m.subs[name]
			if !exists || !item.Enabled {
				m.mu.RUnlock()
				continue
			}
			needsFetch := len(item.Nodes) == 0 || time.Since(item.LastUpdate) >= parseInterval(item.UpdateInterval)
			m.mu.RUnlock()

			if needsFetch {
				_, _ = m.Refresh(m.ctx, name)
			}
		}
	})

	// Background ticker loop
	safego.Go("subscription.ticker", func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				for _, name := range m.orderedNames() {
					m.mu.RLock()
					item, exists := m.subs[name]
					if !exists || !item.Enabled {
						m.mu.RUnlock()
						continue
					}
					interval := parseInterval(item.UpdateInterval)
					needsUpdate := time.Since(item.LastUpdate) >= interval
					m.mu.RUnlock()

					if needsUpdate {
						slog.Info("subscription update interval reached, refreshing", "name", name)
						_, _ = m.Refresh(m.ctx, name)
					}
				}
			}
		}
	})
}

// Stop shuts down the subscription background manager.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		m.cancel()
	})
}

// Refresh fetches and updates a single subscription by name.
func (m *Manager) Refresh(ctx context.Context, name string) (int, error) {
	m.mu.RLock()
	item, exists := m.subs[name]
	if !exists {
		m.mu.RUnlock()
		return 0, fmt.Errorf("subscription %q not found", name)
	}
	subURL := item.URL
	subType := item.Type
	useProxy := item.UseProxy
	m.mu.RUnlock()

	if subURL == "" {
		return 0, fmt.Errorf("subscription %q has empty URL", name)
	}

	if ctx == nil {
		ctx = m.ctx
	}
	reqCtx, reqCancel := context.WithTimeout(ctx, httpTimeout)
	defer reqCancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, subURL, nil)
	if err != nil {
		m.recordError(name, err.Error())
		return 0, err
	}
	// Common airport user agents so subscription services return correct node lists
	req.Header.Set("User-Agent", "SmartProxy/1.0 (clash.meta; sing-box)")
	req.Header.Set("Accept", "*/*")

	client := m.httpClient
	if useProxy {
		client = m.proxiedClient
	}
	resp, err := client.Do(req)
	if err != nil {
		m.recordError(name, err.Error())
		return 0, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, resp.Status)
		m.recordError(name, errMsg)
		return 0, errors.New(errMsg)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		m.recordError(name, err.Error())
		return 0, fmt.Errorf("failed to read response body: %w", err)
	}

	entries, uinfo, err := ParseContent(subType, resp.Header, body)
	if err != nil {
		m.recordError(name, err.Error())
		return 0, fmt.Errorf("failed to parse subscription content: %w", err)
	}

	// Tag nodes with provider and deduplicate aliases within the subscription
	seenAliases := make(map[string]int)
	for i := range entries {
		entries[i].Provider = "sub:" + name
		alias := strings.TrimSpace(entries[i].Alias)
		if alias == "" {
			alias = fmt.Sprintf("[%s] %d", name, i+1)
		}
		seenAliases[alias]++
		if seenAliases[alias] > 1 {
			alias = fmt.Sprintf("%s (%d)", alias, seenAliases[alias])
		}
		entries[i].Alias = alias
	}

	// Update in-memory state
	m.mu.Lock()
	if it, ok := m.subs[name]; ok {
		it.Nodes = entries
		it.NodeCount = len(entries)
		it.LastUpdate = time.Now()
		it.LastError = ""
		if uinfo != nil {
			it.Upload = uinfo.Upload
			it.Download = uinfo.Download
			it.Total = uinfo.Total
			it.Expire = uinfo.Expire
		}
	}
	m.saveCacheLocked()
	m.mu.Unlock()

	// Inject into upstream manager
	if m.upstreamMgr != nil {
		m.upstreamMgr.SetProviderProxies("sub:"+name, entries)
	}

	slog.Info("subscription refreshed successfully", "name", name, "nodes", len(entries))
	return len(entries), nil
}

// RefreshAll triggers refresh for all enabled subscriptions.
func (m *Manager) RefreshAll(ctx context.Context) map[string]error {
	names := m.orderedNames()
	results := make(map[string]error)

	for _, name := range names {
		m.mu.RLock()
		item, exists := m.subs[name]
		if !exists || !item.Enabled {
			m.mu.RUnlock()
			continue
		}
		m.mu.RUnlock()

		_, err := m.Refresh(ctx, name)
		results[name] = err
	}
	return results
}

// Reload applies updated subscription configs without restart.
func (m *Manager) Reload(configs []config.SubscriptionConf) {
	m.mu.Lock()
	newMap := make(map[string]config.SubscriptionConf)
	for _, c := range configs {
		name := stringsTrim(c.Name)
		if name != "" {
			newMap[name] = c
		}
	}

	// 1. Remove deleted subscriptions
	for name, item := range m.subs {
		if _, exists := newMap[name]; !exists {
			delete(m.subs, name)
			if m.upstreamMgr != nil {
				m.upstreamMgr.SetProviderProxies("sub:"+name, nil)
			}
			slog.Info("removed subscription", "name", name)
			_ = item
		}
	}

	// 2. Add or update
	var newOrder []string
	for _, c := range configs {
		name := stringsTrim(c.Name)
		if name == "" {
			continue
		}
		newOrder = append(newOrder, name)
		interval := stringsTrim(c.UpdateInterval)
		if interval == "" {
			interval = "12h"
		}

		item, exists := m.subs[name]
		if !exists {
			item = &ItemState{
				Name:           name,
				URL:            stringsTrim(c.URL),
				Type:           stringsTrim(c.Type),
				UpdateInterval: interval,
				Enabled:        c.Enabled,
				UseProxy:       c.UsesProxy(),
			}
			m.subs[name] = item
			slog.Info("added subscription", "name", name, "url", item.URL)
		} else {
			urlChanged := item.URL != stringsTrim(c.URL)
			typeChanged := item.Type != stringsTrim(c.Type)
			enabledChanged := item.Enabled != c.Enabled

			item.URL = stringsTrim(c.URL)
			item.Type = stringsTrim(c.Type)
			item.UpdateInterval = interval
			item.Enabled = c.Enabled
			item.UseProxy = c.UsesProxy()

			if enabledChanged && !item.Enabled {
				if m.upstreamMgr != nil {
					m.upstreamMgr.SetProviderProxies("sub:"+name, nil)
				}
			} else if enabledChanged && item.Enabled && len(item.Nodes) > 0 {
				if m.upstreamMgr != nil {
					m.upstreamMgr.SetProviderProxies("sub:"+name, item.Nodes)
				}
			}

			if urlChanged || typeChanged {
				// URL changed, clear nodes and force refresh
				item.Nodes = nil
				item.NodeCount = 0
				item.LastUpdate = time.Time{}
			}
		}
	}
	m.subsOrder = newOrder
	m.saveCacheLocked()
	m.mu.Unlock()

	// Trigger refresh for enabled subscriptions with no nodes
	for _, name := range newOrder {
		m.mu.RLock()
		item := m.subs[name]
		needsFetch := item != nil && item.Enabled && len(item.Nodes) == 0
		m.mu.RUnlock()

		if needsFetch {
			safego.Go("subscription.reload_refresh", func() {
				_, _ = m.Refresh(m.ctx, name)
			})
		}
	}
}

// Status returns a snapshot of all subscription states for reporting and API.
func (m *Manager) Status() []ItemState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]ItemState, 0, len(m.subsOrder))
	for _, name := range m.subsOrder {
		if item, ok := m.subs[name]; ok {
			cp := *item
			// Do not leak full node payload into status summary
			cp.Nodes = nil
			res = append(res, cp)
		}
	}
	return res
}

// SubscriptionsCount returns total count of active subscription nodes.
func (m *Manager) TotalNodeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, item := range m.subs {
		if item.Enabled {
			count += item.NodeCount
		}
	}
	return count
}

// RemoveNodes removes nodes matching the given aliases across all subscriptions,
// updates the upstream manager provider proxies, and persists the cache.
func (m *Manager) RemoveNodes(aliases []string) int {
	if len(aliases) == 0 {
		return 0
	}
	aliasSet := make(map[string]bool, len(aliases))
	for _, a := range aliases {
		if a != "" {
			aliasSet[a] = true
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	totalRemoved := 0
	for _, item := range m.subs {
		if len(item.Nodes) == 0 {
			continue
		}
		var kept []upstream.ProxyEntry
		removedHere := 0
		for _, node := range item.Nodes {
			if aliasSet[node.Alias] {
				removedHere++
			} else {
				kept = append(kept, node)
			}
		}
		if removedHere > 0 {
			item.Nodes = kept
			item.NodeCount = len(kept)
			totalRemoved += removedHere
			if item.Enabled && m.upstreamMgr != nil {
				m.upstreamMgr.SetProviderProxies("sub:"+item.Name, item.Nodes)
			}
		}
	}
	if totalRemoved > 0 {
		m.saveCacheLocked()
		slog.Info("subscription nodes cleaned up", "removed", totalRemoved)
	}
	return totalRemoved
}

func (m *Manager) recordError(name, errStr string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if item, ok := m.subs[name]; ok {
		item.LastError = errStr
	}
	m.saveCacheLocked()
}

func (m *Manager) orderedNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]string, len(m.subsOrder))
	copy(res, m.subsOrder)
	return res
}

// ---- Disk Cache ----

type diskCacheDoc struct {
	Subscriptions []*ItemState `json:"subscriptions"`
}

func (m *Manager) cacheFilePath() string {
	if m.cfgDir == "" {
		return ""
	}
	return filepath.Join(m.cfgDir, cacheFileName)
}

func (m *Manager) loadCache() {
	path := m.cacheFilePath()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var doc diskCacheDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, cached := range doc.Subscriptions {
		if cached == nil || cached.Name == "" {
			continue
		}
		if current, exists := m.subs[cached.Name]; exists {
			// If URL matches, restore cached nodes and metadata
			if current.URL == cached.URL {
				current.Nodes = cached.Nodes
				current.NodeCount = len(cached.Nodes)
				current.LastUpdate = cached.LastUpdate
				current.LastError = cached.LastError
				current.Upload = cached.Upload
				current.Download = cached.Download
				current.Total = cached.Total
				current.Expire = cached.Expire
			}
		}
	}
}

func (m *Manager) saveCacheLocked() {
	path := m.cacheFilePath()
	if path == "" {
		return
	}
	doc := diskCacheDoc{
		Subscriptions: make([]*ItemState, 0, len(m.subs)),
	}
	for _, name := range m.subsOrder {
		if item, ok := m.subs[name]; ok {
			doc.Subscriptions = append(doc.Subscriptions, item)
		}
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func parseInterval(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d < minUpdateInterval {
		return defaultUpdateInterval
	}
	return d
}

func stringsTrim(s string) string {
	return strings.TrimSpace(s)
}

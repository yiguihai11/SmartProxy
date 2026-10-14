package adblock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"smartproxy/internal/upstream"
)

type Subscription struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Enabled  bool   `json:"enabled"`
	// nil preserves compatibility with older configs and defaults to proxy fetch.
	UseProxy *bool `json:"use_proxy,omitempty"`
}

func (s Subscription) UsesProxy() bool { return s.UseProxy == nil || *s.UseProxy }

type SourceState struct {
	Name string `json:"name"`
	URL string `json:"url"`
	Enabled bool `json:"enabled"`
	UseProxy bool `json:"use_proxy"`
	ActiveRules int `json:"active_rules"`
	IgnoredRules int `json:"ignored_rules"`
	LastUpdated time.Time `json:"last_updated,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

type diskCache struct {
	ETag string `json:"etag,omitempty"`
	Body string `json:"body"`
	Updated time.Time `json:"updated"`
}

type Manager struct {
	mu sync.Mutex
	dir string
	subs []Subscription
	client        *http.Client
	proxiedClient *http.Client
	upstreamMgr   *upstream.Manager
	active        atomic.Pointer[Set]
	enabled atomic.Bool
	states []SourceState
	startOnce sync.Once
	stop chan struct{}
}

func NewManager(dir string, subs []Subscription, upstreamManagers ...*upstream.Manager) *Manager {
	cp := append([]Subscription(nil), subs...)
	m := &Manager{
		dir: dir, subs: cp,
		client: &http.Client{Timeout: 20 * time.Second},
		stop: make(chan struct{}),
	}
	if len(upstreamManagers) > 0 {
		m.upstreamMgr = upstreamManagers[0]
	}
	if m.upstreamMgr != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, portText, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid adblock target address %q: %w", addr, err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				return nil, fmt.Errorf("invalid adblock target port %q: %w", portText, err)
			}
			return m.upstreamMgr.ConnectDefault(ctx, host, port)
		}
		m.proxiedClient = &http.Client{Transport: transport, Timeout: 20 * time.Second}
	}
	m.active.Store(NewSet(nil))
	m.enabled.Store(true)
	return m
}

// Configure replaces the configured source list and atomically rebuilds from any
// valid cached snapshots before fetching the new configuration.
func (m *Manager) Configure(subs []Subscription) {
	m.mu.Lock()
	m.subs = append([]Subscription(nil), subs...)
	m.mu.Unlock()
	m.rebuild()
	go m.refreshAll()
}

func (m *Manager) RefreshAll() { go m.refreshAll() }

func (m *Manager) Start() {
	m.startOnce.Do(func() {
		go m.refreshAll()
		go func() {
			t := time.NewTicker(12*time.Hour)
			defer t.Stop()
			for { select { case <-t.C: m.refreshAll(); case <-m.stop: return } }
		}()
	})
}

func (m *Manager) Stop() { select { case <-m.stop: default: close(m.stop) } }

func (m *Manager) SetEnabled(enabled bool) { m.enabled.Store(enabled) }

func (m *Manager) Blocked(domain string) bool {
	if !m.enabled.Load() { return false }
	s := m.active.Load()
	return s != nil && s.Blocked(domain)
}

func (m *Manager) Status() []SourceState {
	m.mu.Lock(); defer m.mu.Unlock()
	out := make([]SourceState, len(m.states)); copy(out, m.states)
	return out
}

func (m *Manager) Refresh(ctx context.Context, name string) error {
	m.mu.Lock()
	subs := append([]Subscription(nil), m.subs...)
	m.mu.Unlock()
	for _, sub := range subs {
		if sub.Name == name || sub.URL == name {
			if !sub.Enabled { return fmt.Errorf("subscription %q is disabled", name) }
			return m.refreshOne(ctx, sub)
		}
	}
	return fmt.Errorf("subscription %q not found", name)
}

func (m *Manager) refreshAll() {
	m.mu.Lock()
	subs := append([]Subscription(nil), m.subs...)
	m.mu.Unlock()
	for _, sub := range subs {
		if !sub.Enabled { continue }
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		if err := m.refreshOne(ctx, sub); err != nil { slog.Warn("adblock subscription refresh failed", "name", sub.Name, "error", err) }
		cancel()
	}
	m.rebuild()
}

func (m *Manager) cachePath(sub Subscription) string {
	// URL-derived names survive subscription reorder/removal and do not expose names
	// as filesystem path components.
	sum := sha256.Sum256([]byte(sub.URL))
	return filepath.Join(m.dir, "adblock-"+hex.EncodeToString(sum[:8])+".json")
}

func (m *Manager) refreshOne(ctx context.Context, sub Subscription) error {
	path := m.cachePath(sub)
	var cached diskCache
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &cached)
	}
	if cached.Body != "" {
		if _, stats, err := Parse(cached.Body); err == nil {
			m.setState(SourceState{Name: sub.Name, URL: sub.URL, Enabled: sub.Enabled, UseProxy: sub.UsesProxy(), ActiveRules: stats.Accepted, IgnoredRules: stats.Ignored, LastUpdated: cached.Updated})
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil { return m.setError(sub, err) }
	req.Header.Set("User-Agent", "SmartProxy-DNS-AdBlock/1.0")
	if cached.ETag != "" { req.Header.Set("If-None-Match", cached.ETag) }
	client := m.client
	if sub.UsesProxy() {
		if m.proxiedClient == nil {
			return m.setError(sub, fmt.Errorf("subscription is configured to use proxy, but no upstream manager is available"))
		}
		client = m.proxiedClient
	}
	resp, err := client.Do(req)
	if err != nil { return m.setError(sub, err) }
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && cached.Body != "" {
		return m.activateCached(sub, cached, path)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { return m.setError(sub, fmt.Errorf("HTTP %d", resp.StatusCode)) }
	const maxSubscriptionBytes = 32 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBytes+1))
	if err != nil { return m.setError(sub, err) }
	if len(body) > maxSubscriptionBytes { return m.setError(sub, fmt.Errorf("subscription exceeds 32 MiB limit")) }
	rules, stats, err := Parse(string(body))
	if err != nil { return m.setError(sub, err) }
	cached = diskCache{ETag: resp.Header.Get("ETag"), Body: string(body), Updated: time.Now()}
	if path != "" {
		if err := os.MkdirAll(m.dir, 0755); err != nil { return m.setError(sub, fmt.Errorf("create cache directory: %w", err)) }
		data, err := json.Marshal(cached)
		if err != nil { return m.setError(sub, fmt.Errorf("encode cache: %w", err)) }
		if err := atomicWrite(path, data); err != nil { return m.setError(sub, fmt.Errorf("write cache: %w", err)) }
	}
	m.setState(SourceState{Name: sub.Name, URL: sub.URL, Enabled: true, UseProxy: sub.UsesProxy(), ActiveRules: stats.Accepted, IgnoredRules: stats.Ignored, LastUpdated: cached.Updated})
	_ = rules
	m.rebuild()
	return nil
}

func (m *Manager) activateCached(sub Subscription, cached diskCache, path string) error {
	rules, stats, err := Parse(cached.Body)
	if err != nil { return m.setError(sub, err) }
	m.setState(SourceState{Name: sub.Name, URL: sub.URL, Enabled: true, ActiveRules: stats.Accepted, IgnoredRules: stats.Ignored, LastUpdated: cached.Updated})
	_ = rules
	m.rebuild()
	return nil
}

func (m *Manager) setError(sub Subscription, err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.states { if m.states[i].Name == sub.Name { m.states[i].LastError = err.Error(); return err } }
	m.states = append(m.states, SourceState{Name: sub.Name, URL: sub.URL, Enabled: sub.Enabled, UseProxy: sub.UsesProxy(), LastError: err.Error()})
	return err
}

func (m *Manager) setState(state SourceState) {
	m.mu.Lock(); defer m.mu.Unlock()
	for i := range m.states { if m.states[i].Name == state.Name { m.states[i] = state; return } }
	m.states = append(m.states, state)
}

func (m *Manager) rebuild() {
	all := make([]Rule, 0)
	m.mu.Lock()
	subs := append([]Subscription(nil), m.subs...)
	m.mu.Unlock()
	for _, sub := range subs {
		if !sub.Enabled { continue }
		path := m.cachePath(sub)
		if path == "" { continue }
		b, err := os.ReadFile(path); if err != nil { continue }
		var c diskCache; if json.Unmarshal(b, &c) != nil { continue }
		rules, _, err := Parse(c.Body); if err == nil { all = append(all, rules...) }
	}
	m.active.Store(NewSet(all))
}

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".adblock-*")
	if err != nil { return err }
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil { f.Close(); return err }
	if err = f.Sync(); err != nil { f.Close(); return err }
	if err = f.Close(); err != nil { return err }
	return os.Rename(name, path)
}

// RemoveSubscription drops a source from this manager and rebuilds the snapshot.
func (m *Manager) RemoveSubscription(name string) bool {
	m.mu.Lock()
	idx := -1
	for i, s := range m.subs { if s.Name == name || s.URL == name { idx = i; break } }
	if idx < 0 { m.mu.Unlock(); return false }
	path := m.cachePath(m.subs[idx])
	m.subs = append(m.subs[:idx], m.subs[idx+1:]...)
	m.states = append(m.states[:0], m.states...)
	m.mu.Unlock()
	if path != "" { _ = os.Remove(path) }
	m.rebuild()
	return true
}

func (m *Manager) AddSubscription(sub Subscription) error {
	sub.Name = strings.TrimSpace(sub.Name); sub.URL = strings.TrimSpace(sub.URL)
	if sub.Name == "" || !(strings.HasPrefix(sub.URL, "https://") || strings.HasPrefix(sub.URL, "http://")) { return fmt.Errorf("name and http(s) URL are required") }
	m.mu.Lock()
	for _, s := range m.subs { if s.Name == sub.Name || s.URL == sub.URL { m.mu.Unlock(); return fmt.Errorf("subscription already exists") } }
	m.subs = append(m.subs, sub); m.mu.Unlock()
	return nil
}

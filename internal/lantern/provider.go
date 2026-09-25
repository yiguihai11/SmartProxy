package lantern

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"smartproxy/internal/safego"
	"smartproxy/internal/upstream"
)

// Provider manages the background lifecycle of Lantern free nodes:
// 1. Account registration and rotation (up to 5 accounts max).
// 2. Node fetching, in-memory connectivity testing, and dead node filtering.
// 3. Injecting verified nodes directly into upstream.Manager as equal first-class proxies.
type Provider struct {
	client      *Client
	mgr         *upstream.Manager
	ctx         context.Context
	cancel      context.CancelFunc
	stopOnce    sync.Once
	refreshMu   sync.Mutex
	stateMu     sync.RWMutex
	refreshing  bool
	lastRefresh time.Time
	lastError   string
	nodeCount   int
}

// NewProvider creates a new Lantern Node Provider.
func NewProvider(cfg Config, mgr *upstream.Manager) (*Provider, error) {
	client, err := New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize lantern client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Provider{
		client: client,
		mgr:    mgr,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start launches the background worker to fetch, verify, and maintain Lantern nodes.
func (p *Provider) Start() {
	safego.Go("lantern.provider", func() {
		slog.Info("lantern provider started")
		_, _ = p.Refresh(nil)

		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-p.ctx.Done():
				slog.Info("lantern provider stopped by context")
				return
			case <-ticker.C:
				_, _ = p.Refresh(nil)
			}
		}
	})
}

// Refresh triggers node fetching, connectivity testing, and updates the upstream Manager.
func (p *Provider) Refresh(ctx context.Context) (int, error) {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	select {
	case <-p.ctx.Done():
		return 0, fmt.Errorf("lantern provider is stopped")
	default:
	}

	p.stateMu.Lock()
	p.refreshing = true
	p.stateMu.Unlock()
	defer func() {
		p.stateMu.Lock()
		p.refreshing = false
		p.stateMu.Unlock()
	}()

	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(p.ctx, 60*time.Second)
		defer cancel()
	}

	slog.Info("lantern provider fetching and testing nodes...")
	nodes, err := p.client.EnsureNodes(ctx)
	if err != nil {
		p.stateMu.Lock()
		p.lastError = err.Error()
		p.stateMu.Unlock()
		slog.Warn("lantern provider failed to ensure nodes", "error", err)
		return 0, err
	}

	if len(nodes) == 0 {
		p.stateMu.Lock()
		p.lastError = "no active nodes found"
		p.stateMu.Unlock()
		slog.Warn("lantern provider returned 0 active nodes")
		return 0, fmt.Errorf("no active nodes found")
	}

	var entries []upstream.ProxyEntry
	for i, raw := range nodes {
		var meta struct {
			Tag  string `json:"tag"`
			Type string `json:"type"`
		}
		_ = json.Unmarshal(raw, &meta)

		tag := meta.Tag
		if tag == "" {
			tag = fmt.Sprintf("node-%d", i)
		}

		alias := fmt.Sprintf("[Lantern] %s", tag)
		entries = append(entries, upstream.ProxyEntry{
			Alias:    alias,
			URL:      string(raw),
			Provider: "lantern",
		})
	}

	select {
	case <-p.ctx.Done():
		return 0, fmt.Errorf("lantern provider is stopped")
	default:
	}

	if p.mgr != nil {
		p.mgr.SetProviderProxies("lantern", entries)
	}
	p.stateMu.Lock()
	p.lastRefresh = time.Now()
	p.lastError = ""
	p.nodeCount = len(entries)
	p.stateMu.Unlock()
	slog.Info("lantern provider successfully injected nodes", "count", len(entries))
	return len(entries), nil
}

func (p *Provider) refreshNodes() {
	_, _ = p.Refresh(nil)
}

// Status returns provider health and statistics without blocking on Refresh.
func (p *Provider) Status() map[string]interface{} {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()

	res := map[string]interface{}{
		"enabled":    true,
		"running":    p.ctx.Err() == nil,
		"refreshing": p.refreshing,
		"node_count": p.nodeCount,
	}
	if !p.lastRefresh.IsZero() {
		res["last_refresh"] = p.lastRefresh.Format(time.RFC3339)
	}
	if p.lastError != "" {
		res["last_error"] = p.lastError
	}
	return res
}

// Stop terminates the provider and removes its proxies from the upstream Manager.
func (p *Provider) Stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		if p.mgr != nil {
			p.mgr.SetProviderProxies("lantern", nil)
		}
		slog.Info("lantern provider stopped and nodes removed from pool")
	})
}

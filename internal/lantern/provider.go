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
	client   *Client
	mgr      *upstream.Manager
	ctx      context.Context
	cancel   context.CancelFunc
	stopOnce sync.Once
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
		p.refreshNodes()

		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-p.ctx.Done():
				slog.Info("lantern provider stopped by context")
				return
			case <-ticker.C:
				p.refreshNodes()
			}
		}
	})
}

// refreshNodes fetches nodes, tests connectivity, and updates the upstream Manager.
func (p *Provider) refreshNodes() {
	ctx, cancel := context.WithTimeout(p.ctx, 45*time.Second)
	defer cancel()

	slog.Info("lantern provider fetching and testing nodes...")
	nodes, err := p.client.EnsureNodes(ctx)
	if err != nil {
		slog.Warn("lantern provider failed to ensure nodes", "error", err)
		return
	}

	if len(nodes) == 0 {
		slog.Warn("lantern provider returned 0 active nodes")
		return
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
			Alias: alias,
			URL:   string(raw),
		})
	}

	p.mgr.SetProviderProxies("lantern", entries)
	slog.Info("lantern provider successfully injected nodes", "count", len(entries))
}

// Stop terminates the provider and removes its proxies from the upstream Manager.
func (p *Provider) Stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		p.mgr.SetProviderProxies("lantern", nil)
		slog.Info("lantern provider stopped and nodes removed from pool")
	})
}

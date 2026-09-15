package lantern

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Client is the primary interface for managing Lantern accounts, fetching nodes, and rotating accounts.
type Client struct {
	cfg        Config
	httpClient *http.Client
	accMgr     *AccountManager
	nodesPath  string

	mu             sync.RWMutex
	currentAccount *Account
	currentNodes   []json.RawMessage
	lastEtag       string

	sseCancel context.CancelFunc
}

// New creates a new Lantern client.
func New(cfg Config) (*Client, error) {
	if cfg.MaxAccounts <= 0 {
		cfg.MaxAccounts = 5
	}
	if cfg.MinRemainBytes <= 0 {
		cfg.MinRemainBytes = 1024 * 1024 // 1MB
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}
	if cfg.TestTimeout <= 0 {
		cfg.TestTimeout = 5 * time.Second
	}
	if cfg.TestURL == "" {
		cfg.TestURL = "http://cp.cloudflare.com/generate_204"
	}
	if cfg.AccountsFile == "" {
		cfg.AccountsFile = "accounts.json"
	}
	if cfg.NodesFile == "" {
		cfg.NodesFile = "lantern_nodes.json"
	}
	if cfg.DataDir == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			cfg.DataDir = home
		} else {
			cfg.DataDir = "."
		}
	}

	accMgr, err := NewAccountManager(cfg.DataDir, cfg.AccountsFile, cfg.MaxAccounts, cfg.MinRemainBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to init account manager: %w", err)
	}

	client := &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: cfg.HTTPTimeout},
		accMgr:     accMgr,
		nodesPath:  filepath.Join(cfg.DataDir, cfg.NodesFile),
	}

	// Try loading cached nodes from disk
	_ = client.loadNodesFromCache()

	return client, nil
}

func (c *Client) loadNodesFromCache() error {
	data, err := os.ReadFile(c.nodesPath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}

	var nodes []json.RawMessage
	if err := json.Unmarshal(data, &nodes); err != nil {
		return err
	}

	c.mu.Lock()
	c.currentNodes = nodes
	c.mu.Unlock()
	return nil
}

func (c *Client) saveNodesToCache(nodes []json.RawMessage) error {
	dir := filepath.Dir(c.nodesPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := c.nodesPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpFile, c.nodesPath)
}

// GetAccountManager returns the underlying AccountManager.
func (c *Client) GetAccountManager() *AccountManager {
	return c.accMgr
}

// GetCurrentAccount returns a copy of the current active account.
func (c *Client) GetCurrentAccount() (Account, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.currentAccount == nil {
		return Account{}, false
	}
	return *c.currentAccount, true
}

// PickOrCreateAccount selects an available account or registers a new one if limit (<5) allows.
func (c *Client) PickOrCreateAccount(ctx context.Context) (*Account, error) {
	// 1. Pick from local accounts
	if acc, ok := c.accMgr.PickAvailable(); ok {
		// Verify quota if never checked
		if acc.LastCheck == 0 {
			res, err := CheckAccountQuota(ctx, c.httpClient, acc, c.cfg.MinRemainBytes)
			if err == nil {
				_ = c.accMgr.UpdateAccount(*acc)
				if res.QuotaOK {
					return acc, nil
				}
			}
		} else {
			return acc, nil
		}
	}

	// 2. Check if we can register a new account (max 5)
	if c.accMgr.CanRegister() {
		newAcc, err := AnonymousRegister(ctx, c.httpClient)
		if err != nil {
			return nil, fmt.Errorf("failed to register new account: %w", err)
		}
		if err := c.accMgr.AddAccount(newAcc); err != nil {
			return nil, err
		}
		return &newAcc, nil
	}

	// 3. Max accounts reached (5 accounts): check the earliest resetting account
	earliest := c.accMgr.EarliestResetAccount()
	if earliest != nil {
		// Probe quota to see if it reset already
		res, err := CheckAccountQuota(ctx, c.httpClient, earliest, c.cfg.MinRemainBytes)
		if err == nil && res.QuotaOK {
			_ = c.accMgr.UpdateAccount(*earliest)
			return earliest, nil
		}
		return nil, fmt.Errorf("%w: earliest reset at %s", ErrMaxAccountsReached, time.Unix(earliest.ExhaustedUntil, 0).Format(time.RFC3339))
	}

	return nil, ErrMaxAccountsReached
}

// EnsureNodes ensures there is an active account and valid working nodes.
func (c *Client) EnsureNodes(ctx context.Context) ([]json.RawMessage, error) {
	c.mu.Lock()
	if len(c.currentNodes) > 0 && c.currentAccount != nil {
		nodesCopy := make([]json.RawMessage, len(c.currentNodes))
		copy(nodesCopy, c.currentNodes)
		c.mu.Unlock()
		return nodesCopy, nil
	}
	c.mu.Unlock()

	// Select or register account
	acc, err := c.PickOrCreateAccount(ctx)
	if err != nil {
		// Fallback: if we already have cached nodes, return them
		c.mu.RLock()
		cached := c.currentNodes
		c.mu.RUnlock()
		if len(cached) > 0 {
			return cached, nil
		}
		return nil, err
	}

	c.mu.Lock()
	c.currentAccount = acc
	c.mu.Unlock()

	// Optionally start SSE if enabled
	if c.cfg.EnableSSE {
		c.startSSE(*acc)
	}

	// Fetch fresh nodes
	rawNodes, etag, err := FetchStandardOutbounds(ctx, c.httpClient, acc, "")
	if err != nil {
		// Fallback to cache if available
		c.mu.RLock()
		cached := c.currentNodes
		c.mu.RUnlock()
		if len(cached) > 0 {
			return cached, nil
		}
		return nil, fmt.Errorf("failed to fetch nodes and no local cache: %w", err)
	}

	nodes := rawNodes
	// Test connectivity and filter out dead nodes if requested
	if c.cfg.FilterDeadNodes && len(nodes) > 0 {
		tested, tErr := TestAndFilterNodes(ctx, nodes, c.cfg.SingBoxPath, c.cfg.TestURL, c.cfg.TestTimeout)
		if tErr == nil && len(tested) > 0 {
			nodes = tested
		}
	}

	c.mu.Lock()
	c.currentNodes = nodes
	c.lastEtag = etag
	c.mu.Unlock()

	_ = c.saveNodesToCache(nodes)
	return nodes, nil
}

// GetNodes returns the current working nodes.
func (c *Client) GetNodes(ctx context.Context) ([]json.RawMessage, error) {
	c.mu.RLock()
	if len(c.currentNodes) > 0 {
		res := make([]json.RawMessage, len(c.currentNodes))
		copy(res, c.currentNodes)
		c.mu.RUnlock()
		return res, nil
	}
	c.mu.RUnlock()

	return c.EnsureNodes(ctx)
}

// ReportFailure is called by the consumer when outbound connections fail.
// It checks the current account's quota. If exhausted, it rotates to another account,
// pulls new nodes, filters them, updates cache, and returns the new nodes with rotated = true.
func (c *Client) ReportFailure(ctx context.Context) (newNodes []json.RawMessage, rotated bool, err error) {
	c.mu.RLock()
	acc := c.currentAccount
	c.mu.RUnlock()

	if acc == nil {
		nodes, err := c.EnsureNodes(ctx)
		return nodes, true, err
	}

	// Probe current account quota
	res, qErr := CheckAccountQuota(ctx, c.httpClient, acc, c.cfg.MinRemainBytes)
	if qErr != nil || !res.QuotaOK {
		// Account is indeed exhausted or invalid
		_ = c.accMgr.MarkExhausted(acc.DeviceID, res.ResetUnix)

		c.stopSSE()

		// Pick next available account or create new one
		nextAcc, pErr := c.PickOrCreateAccount(ctx)
		if pErr != nil {
			return nil, false, fmt.Errorf("failed to rotate account: %w", pErr)
		}

		c.mu.Lock()
		c.currentAccount = nextAcc
		c.mu.Unlock()

		if c.cfg.EnableSSE {
			c.startSSE(*nextAcc)
		}

		// Fetch new nodes
		rawNodes, etag, fErr := FetchStandardOutbounds(ctx, c.httpClient, nextAcc, "")
		if fErr != nil {
			return nil, false, fmt.Errorf("failed to fetch nodes for rotated account: %w", fErr)
		}

		nodes := rawNodes
		if c.cfg.FilterDeadNodes && len(nodes) > 0 {
			tested, tErr := TestAndFilterNodes(ctx, nodes, c.cfg.SingBoxPath, c.cfg.TestURL, c.cfg.TestTimeout)
			if tErr == nil && len(tested) > 0 {
				nodes = tested
			}
		}

		c.mu.Lock()
		c.currentNodes = nodes
		c.lastEtag = etag
		c.mu.Unlock()

		_ = c.saveNodesToCache(nodes)
		return nodes, true, nil
	}

	// Account still has quota; failure might be transient network issue or specific dead nodes
	if c.cfg.FilterDeadNodes {
		c.mu.RLock()
		existing := c.currentNodes
		c.mu.RUnlock()

		if len(existing) > 0 {
			tested, tErr := TestAndFilterNodes(ctx, existing, c.cfg.SingBoxPath, c.cfg.TestURL, c.cfg.TestTimeout)
			if tErr == nil && len(tested) > 0 {
				c.mu.Lock()
				c.currentNodes = tested
				c.mu.Unlock()
				_ = c.saveNodesToCache(tested)
				return tested, false, nil
			}
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentNodes, false, nil
}

func (c *Client) startSSE(acc Account) {
	c.stopSSE()
	sseCtx, cancel := context.WithCancel(context.Background())
	c.sseCancel = cancel

	go StartSSEListener(sseCtx, c.httpClient, acc, func() {
		// Quota exhausted notification from SSE
		_, _, _ = c.ReportFailure(context.Background())
	})
}

func (c *Client) stopSSE() {
	if c.sseCancel != nil {
		c.sseCancel()
		c.sseCancel = nil
	}
}

// Close releases any background resources.
func (c *Client) Close() error {
	c.stopSSE()
	return nil
}

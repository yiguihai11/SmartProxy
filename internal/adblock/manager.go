package adblock

import (
	"bufio"
	"context"
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
	defaultUpdateInterval = 24 * time.Hour
	minUpdateInterval     = 10 * time.Minute
	httpTimeout           = 30 * time.Second
	maxSubscriptionBytes  = 32 << 20 // 32 MB
)

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ItemState 代表单条订阅清单的运行时状态。
type ItemState struct {
	Name       string         `json:"name"`
	URL        string         `json:"url"`
	Enabled    bool           `json:"enabled"`
	Interval   string         `json:"update_interval"`
	UseProxy   bool           `json:"use_proxy"`
	Kept       int            `json:"kept"`        // 生效条数 (该清单贡献)
	Lines      int            `json:"lines"`
	Skipped    int            `json:"skipped"`     // 被忽略条数
	SkipDetail map[string]int `json:"skip_detail,omitempty"`
	LastUpdate int64          `json:"last_update"` // unix 秒
	LastError  string         `json:"last_error,omitempty"`
	etag       string
	suffixes   []string
	allow      []string
	badfilters []string
}

// Status 描述整体广告过滤模块的状态, 供控制面板呈现。
type Status struct {
	Enabled    bool        `json:"enabled"`
	Items      []ItemState `json:"items"`
	TotalHits  int64       `json:"total_hits"`
	Since      int64       `json:"since"`
	TopDomains []DomainHit `json:"top_domains"`
	CacheCount int         `json:"cache_count"`
	CacheMtime int64       `json:"cache_mtime"`
}

// Manager 管理 DNS 广告过滤订阅、抓取、白名单与快照发布。
type Manager struct {
	mu          sync.RWMutex
	cfgDir      string
	conf        config.AdblockConf
	cachePath   string
	upstreamMgr *upstream.Manager
	sink        func(*Set)
	stats       *Stats

	items      map[string]*ItemState
	itemsOrder []string
	whitelist  []string

	httpClient    *http.Client
	proxiedClient *http.Client

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	refreshMu sync.Mutex
	stopped   bool
}

// NewManager 构造 Manager 实例。
func NewManager(cfgDir string, conf config.AdblockConf, upstreamMgr *upstream.Manager, sink func(*Set)) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	cacheFile := conf.CacheFile
	if cacheFile == "" {
		cacheFile = "adblock_cache.txt"
	}
	resolvedCache := cacheFile
	if !filepath.IsAbs(resolvedCache) {
		resolvedCache = filepath.Join(cfgDir, resolvedCache)
	}

	m := &Manager{
		cfgDir:      cfgDir,
		conf:        conf,
		cachePath:   resolvedCache,
		upstreamMgr: upstreamMgr,
		sink:        sink,
		stats:       NewStats(),
		items:       make(map[string]*ItemState),
		whitelist:   append([]string(nil), conf.Whitelist...),
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	if upstreamMgr != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = func(dialCtx context.Context, _, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid adblock target address %q: %w", addr, err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid adblock target port %q: %w", portStr, err)
			}
			return m.upstreamMgr.ConnectDefault(dialCtx, host, port)
		}
		m.proxiedClient = &http.Client{
			Transport: transport,
			Timeout:   httpTimeout,
		}
	}

	for _, l := range conf.Lists {
		name := strings.TrimSpace(l.Name)
		if name == "" {
			continue
		}
		interval := strings.TrimSpace(l.UpdateInterval)
		if interval == "" {
			interval = "24h"
		}
		item := &ItemState{
			Name:     name,
			URL:      strings.TrimSpace(l.URL),
			Enabled:  l.Enabled,
			Interval: interval,
			UseProxy: l.UsesProxy(),
		}
		m.items[name] = item
		m.itemsOrder = append(m.itemsOrder, name)
	}

	return m
}

// Start 启动后台任务: 读缓存建表 + 起定时刷新。不阻塞引擎构造。
func (m *Manager) Start() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.wg.Add(1)
	m.mu.Unlock()

	safego.Go("adblock.startup", func() {
		defer m.wg.Done()

		// 确保缓存目录存在
		if dir := filepath.Dir(m.cachePath); dir != "" {
			_ = os.MkdirAll(dir, 0o755)
		}

		// 1. 尝试从本地紧凑缓存加载并发布快照
		loaded := m.loadFromDiskCache()

		m.mu.RLock()
		enabled := m.conf.Enabled
		hasEnabledLists := false
		for _, it := range m.items {
			if it.Enabled {
				hasEnabledLists = true
				break
			}
		}
		m.mu.RUnlock()

		if !enabled {
			if m.sink != nil {
				m.sink(nil)
			}
		}

		// 2. 缓存缺失且启用了清单: 立即触发一次全量刷新
		if enabled && hasEnabledLists && (!loaded || m.needInitialRefresh()) {
			ctx, cancel := context.WithTimeout(m.ctx, 60*time.Second)
			_ = m.RefreshAll(ctx)
			cancel()
		}

		// 3. 定时刷新 ticker
		m.runTicker()
	})
}

// Stop 停止 Manager 并发布 nil 快照全放行。
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.stopped = true
	m.mu.Unlock()

	m.cancel()
	if m.sink != nil {
		m.sink(nil)
	}
	m.wg.Wait()
}

func (m *Manager) needInitialRefresh() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, it := range m.items {
		if it.Enabled && it.Kept == 0 && it.LastError == "" {
			return true
		}
	}
	return false
}

func (m *Manager) runTicker() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case now := <-ticker.C:
			m.checkAutoRefresh(now)
		}
	}
}

func (m *Manager) checkAutoRefresh(now time.Time) {
	m.mu.RLock()
	if !m.conf.Enabled || !m.conf.AutoUpdateEnabled() {
		m.mu.RUnlock()
		return
	}
	var toRefresh []string
	for _, name := range m.itemsOrder {
		it := m.items[name]
		if !it.Enabled {
			continue
		}
		interval := parseInterval(it.Interval)
		last := time.Unix(it.LastUpdate, 0)
		if now.Sub(last) >= interval {
			toRefresh = append(toRefresh, name)
		}
	}
	m.mu.RUnlock()

	for _, name := range toRefresh {
		if m.ctx.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(m.ctx, 45*time.Second)
		_, _ = m.Refresh(ctx, name)
		cancel()
	}
}

// Refresh 刷新指定清单 (空 name 表示全部)。返回本次生效总条数与可能发生的错误。
func (m *Manager) Refresh(ctx context.Context, name string) (int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		errMap := m.RefreshAll(ctx)
		var errs []string
		for n, err := range errMap {
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", n, err))
			}
		}
		m.mu.RLock()
		total := m.countActiveRulesLocked()
		m.mu.RUnlock()
		if len(errs) > 0 {
			return total, errors.New(strings.Join(errs, "; "))
		}
		return total, nil
	}

	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	m.mu.RLock()
	it, ok := m.items[name]
	if !ok {
		m.mu.RUnlock()
		return 0, fmt.Errorf("subscription %q not found", name)
	}
	url := it.URL
	useProxy := it.UseProxy
	etag := it.etag
	m.mu.RUnlock()

	suffixes, allow, badfilters, stats, newEtag, notModified, err := m.fetchAndParse(ctx, url, useProxy, etag)

	m.mu.Lock()
	it = m.items[name]
	if it == nil {
		m.mu.Unlock()
		return 0, fmt.Errorf("subscription %q deleted during refresh", name)
	}

	if notModified {
		it.LastError = ""
		it.LastUpdate = time.Now().Unix()
		if newEtag != "" {
			it.etag = newEtag
		}
		total := m.countActiveRulesLocked()
		m.mu.Unlock()
		return total, nil
	}

	if err != nil {
		it.LastError = err.Error()
		slog.Warn("adblock subscription refresh failed", "name", name, "error", err)
		m.mu.Unlock()
		return m.countActiveRulesLocked(), err
	}

	if len(suffixes) == 0 && len(allow) == 0 && stats.Lines > 0 {
		it.LastError = "no valid rules parsed; preserved last good data"
		m.mu.Unlock()
		return m.countActiveRulesLocked(), errors.New(it.LastError)
	}

	it.LastError = ""
	it.LastUpdate = time.Now().Unix()
	if newEtag != "" {
		it.etag = newEtag
	}
	it.Kept = len(suffixes) + len(allow)
	it.Lines = stats.Lines
	it.Skipped = stats.Skipped
	it.SkipDetail = stats.Reasons
	it.suffixes = suffixes
	it.allow = allow
	it.badfilters = badfilters

	m.rebuildAndPublishLocked()
	m.saveDiskCacheLocked()
	total := m.countActiveRulesLocked()
	m.mu.Unlock()

	return total, nil
}

// RefreshAll 并发刷新所有启用的清单。
func (m *Manager) RefreshAll(ctx context.Context) map[string]error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	m.mu.RLock()
	type target struct {
		name     string
		url      string
		useProxy bool
		etag     string
	}
	var targets []target
	for _, name := range m.itemsOrder {
		it := m.items[name]
		if it.Enabled {
			targets = append(targets, target{
				name:     name,
				url:      it.URL,
				useProxy: it.UseProxy,
				etag:     it.etag,
			})
		}
	}
	m.mu.RUnlock()

	type fetchResult struct {
		name        string
		suffixes    []string
		allow       []string
		badfilters  []string
		stats       ParseStats
		etag        string
		notModified bool
		err         error
	}

	ch := make(chan fetchResult, len(targets))
	for _, tg := range targets {
		go func(t target) {
			sList, aList, bfs, st, etag, notMod, err := m.fetchAndParse(ctx, t.url, t.useProxy, t.etag)
			ch <- fetchResult{
				name:        t.name,
				suffixes:    sList,
				allow:       aList,
				badfilters:  bfs,
				stats:       st,
				etag:        etag,
				notModified: notMod,
				err:         err,
			}
		}(tg)
	}

	errMap := make(map[string]error)
	anySuccess := false

	m.mu.Lock()
	for i := 0; i < len(targets); i++ {
		res := <-ch
		it := m.items[res.name]
		if it == nil {
			continue
		}
		if res.notModified {
			it.LastError = ""
			it.LastUpdate = time.Now().Unix()
			if res.etag != "" {
				it.etag = res.etag
			}
			anySuccess = true
			continue
		}
		if res.err != nil {
			it.LastError = res.err.Error()
			errMap[res.name] = res.err
			slog.Warn("adblock list refresh failed", "name", res.name, "error", res.err)
			continue
		}
		if len(res.suffixes) == 0 && len(res.allow) == 0 && res.stats.Lines > 0 {
			it.LastError = "no valid rules found; preserved last good data"
			errMap[res.name] = errors.New(it.LastError)
			continue
		}

		it.LastError = ""
		it.LastUpdate = time.Now().Unix()
		if res.etag != "" {
			it.etag = res.etag
		}
		it.Kept = len(res.suffixes) + len(res.allow)
		it.Lines = res.stats.Lines
		it.Skipped = res.stats.Skipped
		it.SkipDetail = res.stats.Reasons
		it.suffixes = res.suffixes
		it.allow = res.allow
		it.badfilters = res.badfilters
		anySuccess = true
	}

	if anySuccess || len(targets) == 0 {
		m.rebuildAndPublishLocked()
		m.saveDiskCacheLocked()
	}
	m.mu.Unlock()

	return errMap
}

func (m *Manager) fetchAndParse(ctx context.Context, url string, useProxy bool, etag string) (suffixes, allow, badfilters []string, stats ParseStats, newEtag string, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, nil, ParseStats{}, "", false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "SmartProxy-DNS-AdBlock/1.0")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	client := m.httpClient
	if useProxy && m.proxiedClient != nil {
		client = m.proxiedClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, ParseStats{}, "", false, fmt.Errorf("http fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		// 未修改, 保留既有数据
		return nil, nil, nil, ParseStats{}, etag, true, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, nil, ParseStats{}, "", false, fmt.Errorf("http status %d", resp.StatusCode)
	}

	if resp.ContentLength > maxSubscriptionBytes {
		return nil, nil, nil, ParseStats{}, "", false, fmt.Errorf("subscription exceeds maximum size limit of %d MB", maxSubscriptionBytes>>20)
	}

	cr := &countReader{r: resp.Body}
	limitReader := io.LimitReader(cr, maxSubscriptionBytes+1)
	sList, aList, bfs, st, parseErr := ParseList(limitReader)
	if parseErr != nil {
		return nil, nil, nil, st, "", false, fmt.Errorf("parse: %w", parseErr)
	}
	if cr.n > maxSubscriptionBytes {
		return nil, nil, nil, st, "", false, fmt.Errorf("subscription exceeds maximum size limit of %d MB", maxSubscriptionBytes>>20)
	}

	return sList, aList, bfs, st, resp.Header.Get("ETag"), false, nil
}

// Reload 处理配置变更。
func (m *Manager) Reload(conf config.AdblockConf) {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldEnabled := m.conf.Enabled
	m.conf = conf
	m.whitelist = append([]string(nil), conf.Whitelist...)

	// 更新或增加清单配置
	newOrder := make([]string, 0, len(conf.Lists))
	for _, l := range conf.Lists {
		name := strings.TrimSpace(l.Name)
		if name == "" {
			continue
		}
		newOrder = append(newOrder, name)
		interval := strings.TrimSpace(l.UpdateInterval)
		if interval == "" {
			interval = "24h"
		}

		if existing, ok := m.items[name]; ok {
			existing.URL = strings.TrimSpace(l.URL)
			existing.Enabled = l.Enabled
			existing.Interval = interval
			existing.UseProxy = l.UsesProxy()
		} else {
			m.items[name] = &ItemState{
				Name:     name,
				URL:      strings.TrimSpace(l.URL),
				Enabled:  l.Enabled,
				Interval: interval,
				UseProxy: l.UsesProxy(),
			}
		}
	}
	m.itemsOrder = newOrder

	if !conf.Enabled {
		if m.sink != nil {
			m.sink(nil)
		}
		return
	}

	// 白名单或清单配置变更: 立即根据现有好数据重建快照
	m.rebuildAndPublishLocked()

	// 若从停用变为启用, 且没有数据, 异步触发一次刷新
	if !oldEnabled && conf.Enabled {
		safego.Go("adblock.reload_refresh", func() {
			ctx, cancel := context.WithTimeout(m.ctx, 60*time.Second)
			_ = m.RefreshAll(ctx)
			cancel()
		})
	}
}

// Status 返回整体状态快照。
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := make([]ItemState, 0, len(m.itemsOrder))
	for _, name := range m.itemsOrder {
		if it, ok := m.items[name]; ok {
			cp := *it
			// 深拷贝避免外部修改
			if it.SkipDetail != nil {
				cp.SkipDetail = make(map[string]int, len(it.SkipDetail))
				for k, v := range it.SkipDetail {
					cp.SkipDetail[k] = v
				}
			}
			items = append(items, cp)
		}
	}

	snap := m.stats.Snapshot(50)

	var cacheCount int
	var cacheMtime int64
	if fi, err := os.Stat(m.cachePath); err == nil {
		cacheMtime = fi.ModTime().Unix()
	}
	cacheCount = m.countActiveRulesLocked()

	return Status{
		Enabled:    m.conf.Enabled,
		Items:      items,
		TotalHits:  snap.Total,
		Since:      snap.Since,
		TopDomains: snap.Top,
		CacheCount: cacheCount,
		CacheMtime: cacheMtime,
	}
}

// Whitelist 返回当前白名单列表。
func (m *Manager) Whitelist() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.whitelist...)
}

// AddWhitelist 添加一条白名单域名, 立即重建快照。
func (m *Manager) AddWhitelist(domain string) error {
	norm, _, ok := normalizeRuleDomain(domain)
	if !ok {
		return fmt.Errorf("invalid domain %q for whitelist", domain)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, d := range m.whitelist {
		if d == norm {
			return nil // 已存在
		}
	}
	if len(m.whitelist) >= 5000 {
		return errors.New("whitelist limit of 5000 entries exceeded")
	}

	m.whitelist = append(m.whitelist, norm)
	m.rebuildAndPublishLocked()
	return nil
}

// RemoveWhitelist 移除一条白名单域名, 立即重建快照。
func (m *Manager) RemoveWhitelist(domain string) error {
	norm, _, ok := normalizeRuleDomain(domain)
	if !ok {
		return fmt.Errorf("invalid domain %q for whitelist", domain)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	idx := -1
	for i, d := range m.whitelist {
		if d == norm {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("domain %q not in whitelist", domain)
	}

	m.whitelist = append(m.whitelist[:idx], m.whitelist[idx+1:]...)
	m.rebuildAndPublishLocked()
	return nil
}

func (m *Manager) countActiveRulesLocked() int {
	seen := make(map[string]struct{})
	for _, it := range m.items {
		if it.Enabled {
			for _, s := range it.suffixes {
				seen[s] = struct{}{}
			}
		}
	}
	return len(seen)
}

func (m *Manager) rebuildAndPublishLocked() {
	if !m.conf.Enabled {
		if m.sink != nil {
			m.sink(nil)
		}
		return
	}

	disabledBadfilters := make(map[string]struct{})
	for _, it := range m.items {
		if it.Enabled {
			for _, bf := range it.badfilters {
				disabledBadfilters[bf] = struct{}{}
			}
		}
	}

	allSuffixes := make([]string, 0)
	allAllow := append([]string(nil), m.whitelist...)

	seenSuffix := make(map[string]struct{})
	seenAllow := make(map[string]struct{})
	for _, d := range allAllow {
		seenAllow[d] = struct{}{}
	}

	for _, name := range m.itemsOrder {
		it := m.items[name]
		if !it.Enabled {
			continue
		}
		for _, s := range it.suffixes {
			if _, off := disabledBadfilters[s]; off {
				continue
			}
			if _, exists := seenSuffix[s]; !exists {
				if len(seenSuffix) >= maxTotalRules {
					break
				}
				seenSuffix[s] = struct{}{}
				allSuffixes = append(allSuffixes, s)
			}
		}
		for _, a := range it.allow {
			key := "@@" + a
			if _, off := disabledBadfilters[key]; off {
				continue
			}
			if _, exists := seenAllow[a]; !exists {
				seenAllow[a] = struct{}{}
				allAllow = append(allAllow, a)
			}
		}
	}

	set := NewSet(allSuffixes, allAllow, m.stats)
	if m.sink != nil {
		m.sink(set)
	}
}

// saveDiskCacheLocked 将当前生效的 suffixes 与 allow 紧凑落盘。
func (m *Manager) saveDiskCacheLocked() {
	if m.cachePath == "" {
		return
	}

	if dir := filepath.Dir(m.cachePath); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}

	var sb strings.Builder
	sb.WriteString("# SmartProxy adblock compact cache\n")
	for _, name := range m.itemsOrder {
		it := m.items[name]
		if it == nil || !it.Enabled {
			continue
		}
		sb.WriteString("# [item: ")
		sb.WriteString(it.Name)
		sb.WriteString("]\n")
		if it.LastUpdate > 0 {
			sb.WriteString(fmt.Sprintf("# last_update: %d\n", it.LastUpdate))
		}
		if it.etag != "" {
			sb.WriteString("# etag: ")
			sb.WriteString(it.etag)
			sb.WriteString("\n")
		}
		if it.Lines > 0 {
			sb.WriteString(fmt.Sprintf("# lines: %d\n", it.Lines))
		}
		if it.Skipped > 0 {
			sb.WriteString(fmt.Sprintf("# skipped: %d\n", it.Skipped))
		}
		for _, a := range it.allow {
			sb.WriteString("@@||")
			sb.WriteString(a)
			sb.WriteString("^\n")
		}
		for _, s := range it.suffixes {
			sb.WriteString("||")
			sb.WriteString(s)
			sb.WriteString("^\n")
		}
	}

	tmp := m.cachePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		slog.Warn("write adblock disk cache failed", "path", tmp, "error", err)
		return
	}
	if err := os.Rename(tmp, m.cachePath); err != nil {
		_ = os.Remove(tmp)
		slog.Warn("rename adblock disk cache failed", "error", err)
	}
}

// loadFromDiskCache 启动时从紧凑缓存文件恢复快照。
func (m *Manager) loadFromDiskCache() bool {
	f, err := os.Open(m.cachePath)
	if err != nil {
		return false
	}
	defer f.Close()

	type cachedItem struct {
		lastUpdate int64
		etag       string
		lines      int
		skipped    int
		suffixes   []string
		allow      []string
	}

	itemMap := make(map[string]*cachedItem)
	var curItem *cachedItem
	var allSuffixes []string
	var allAllow []string

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# [item: ") && strings.HasSuffix(line, "]") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "# [item: "), "]")
			curItem = &cachedItem{}
			itemMap[name] = curItem
			continue
		}
		if curItem != nil && strings.HasPrefix(line, "# ") {
			rest := strings.TrimPrefix(line, "# ")
			if strings.HasPrefix(rest, "last_update: ") {
				val, _ := strconv.ParseInt(strings.TrimPrefix(rest, "last_update: "), 10, 64)
				curItem.lastUpdate = val
			} else if strings.HasPrefix(rest, "etag: ") {
				curItem.etag = strings.TrimPrefix(rest, "etag: ")
			} else if strings.HasPrefix(rest, "lines: ") {
				val, _ := strconv.Atoi(strings.TrimPrefix(rest, "lines: "))
				curItem.lines = val
			} else if strings.HasPrefix(rest, "skipped: ") {
				val, _ := strconv.Atoi(strings.TrimPrefix(rest, "skipped: "))
				curItem.skipped = val
			}
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if strings.HasPrefix(line, "@@||") {
			domainPart := strings.TrimSuffix(strings.TrimPrefix(line, "@@||"), "^")
			if norm, _, ok := normalizeRuleDomain(domainPart); ok {
				allAllow = append(allAllow, norm)
				if curItem != nil {
					curItem.allow = append(curItem.allow, norm)
				}
			}
		} else if strings.HasPrefix(line, "||") {
			domainPart := strings.TrimSuffix(strings.TrimPrefix(line, "||"), "^")
			if norm, _, ok := normalizeRuleDomain(domainPart); ok {
				allSuffixes = append(allSuffixes, norm)
				if curItem != nil {
					curItem.suffixes = append(curItem.suffixes, norm)
				}
			}
		}
	}

	if len(allSuffixes) == 0 && len(allAllow) == 0 {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var fileMtime int64
	if fi, err := f.Stat(); err == nil {
		fileMtime = fi.ModTime().Unix()
	}

	if len(itemMap) > 0 {
		for name, ci := range itemMap {
			if it, ok := m.items[name]; ok {
				it.suffixes = ci.suffixes
				it.allow = ci.allow
				it.Kept = len(ci.suffixes) + len(ci.allow)
				it.Lines = ci.lines
				it.Skipped = ci.skipped
				it.LastUpdate = ci.lastUpdate
				if it.LastUpdate == 0 {
					it.LastUpdate = fileMtime
				}
				it.etag = ci.etag
			}
		}
	} else if len(m.itemsOrder) == 1 {
		// 兼容旧格式无 item 头的单订阅缓存
		if it, ok := m.items[m.itemsOrder[0]]; ok {
			it.suffixes = allSuffixes
			it.allow = allAllow
			it.Kept = len(allSuffixes) + len(allAllow)
			it.LastUpdate = fileMtime
		}
	}

	// 整合白名单
	allAllow = append(allAllow, m.whitelist...)
	set := NewSet(allSuffixes, allAllow, m.stats)
	if m.conf.Enabled && m.sink != nil {
		m.sink(set)
	}

	return true
}

func parseInterval(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d < minUpdateInterval {
		return defaultUpdateInterval
	}
	return d
}

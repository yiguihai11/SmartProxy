package route

import (
	"log/slog"
	"sort"
	"sync"
	"time"
)

const (
	blacklistMaxSize = 10000
	// hitRebuildInterval 是"命中刷新 lastHit"这类仅影响排序的变更允许的最小重建
	// 间隔。命中很频繁(每次代理检查都会 hit),但面板 SSE 3s 才看一次,排序滞后
	// 不到 1 秒用户感知不到;结构性变更(Add/Remove/过期删除)不节流,立即重建。
	hitRebuildInterval = time.Second
)

type BlacklistEntry struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	LastReason string `json:"last_reason"`
	ExpiresAt  int64  `json:"expires_at"`
	LastHit    int64  `json:"last_hit"` // 最近命中/添加时间,面板按它排序(最近在前)
}

type blacklistRecord struct {
	expiry     time.Time
	lastReason string
	lastHit    time.Time
}

type Blacklist struct {
	mu      sync.Mutex
	entries map[blacklistKey]blacklistRecord
	maxSize int
	name    string

	// 增量快照缓存:SSE 每 3s 调 Entries(),黑名单最多 1 万条时全量遍历+排序浪费
	// CPU。cacheDirty:1=结构性变更(立即重建),2=仅命中排序变更(节流重建)。
	// cached 是只读快照,调用方不得修改。
	cacheDirty  int
	cached      []BlacklistEntry
	lastCacheAt time.Time
}

type blacklistKey struct {
	host string
	port int
}

func NewBlacklist(name string) *Blacklist {
	return &Blacklist{
		entries: make(map[blacklistKey]blacklistRecord),
		maxSize: blacklistMaxSize,
		name:    name,
	}
}

func (b *Blacklist) IsBlacklisted(host string, port int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := blacklistKey{host: host, port: port}
	rec, exists := b.entries[key]
	if !exists {
		return false
	}
	now := time.Now()
	if now.After(rec.expiry) {
		delete(b.entries, key)
		b.cacheDirty = 1 // 过期删除是结构性变更
		return false
	}
	// 命中即刷新"最近使用",面板黑名单表按它排(最近命中的置顶)。
	// 只影响排序 → cacheDirty=2,Entries 节流重建。
	rec.lastHit = now
	b.entries[key] = rec
	b.cacheDirty = 2
	slog.Debug("dynamic blacklist hit", "type", b.name, "host", host, "port", port)
	return true
}

func (b *Blacklist) Add(host string, port int, ttl time.Duration, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := blacklistKey{host: host, port: port}
	now := time.Now()
	b.cacheDirty = 1 // 新增/更新都会改变快照内容

	if _, exists := b.entries[key]; !exists {
		if len(b.entries) >= b.maxSize {
			b.evictOldestLocked()
		}
	} else {

		b.entries[key] = blacklistRecord{
			expiry:     now.Add(ttl),
			lastReason: reason,
			lastHit:    now,
		}
		slog.Info("updated dynamic blacklist", "type", b.name, "host", host, "port", port, "reason", reason)
		return
	}

	b.entries[key] = blacklistRecord{
		expiry:     now.Add(ttl),
		lastReason: reason,
		lastHit:    now,
	}
	slog.Info("added to dynamic blacklist", "type", b.name, "host", host, "port", port, "ttl", ttl, "reason", reason)
}

func (b *Blacklist) evictOldestLocked() {
	var oldestKey blacklistKey
	var oldestExp time.Time
	first := true
	for k, rec := range b.entries {
		if first || rec.expiry.Before(oldestExp) {
			oldestKey = k
			oldestExp = rec.expiry
			first = false
		}
	}
	if !first {
		delete(b.entries, oldestKey)
	}
}

func (b *Blacklist) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}

// Entries returns a read-only snapshot of live (unexpired) entries, newest-last-hit
// first. The snapshot is cached: rebuilds only on structural change or, for hit-only
// reordering, at most once per hitRebuildInterval. Callers must not modify the slice.
func (b *Blacklist) Entries() []BlacklistEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	switch {
	case b.cached == nil:
		b.rebuildLocked(now)
	case b.cacheDirty == 1:
		b.rebuildLocked(now)
	case b.cacheDirty == 2 && now.Sub(b.lastCacheAt) >= hitRebuildInterval:
		b.rebuildLocked(now)
	}
	return b.cached
}

func (b *Blacklist) rebuildLocked(now time.Time) {
	result := make([]BlacklistEntry, 0, len(b.entries))
	for k, rec := range b.entries {
		if rec.expiry.After(now) {
			result = append(result, BlacklistEntry{
				Host:       k.host,
				Port:       k.port,
				LastReason: rec.lastReason,
				ExpiresAt:  rec.expiry.Unix(),
				// 纳秒精度:秒精度会让同一秒内多条记录排序退化(面板只用它排序,不显示)
				LastHit: rec.lastHit.UnixNano(),
			})
		}
	}
	// 面板按"最近访问使用"排序:最近命中/添加的排最前;同级按 host 稳定排。
	sort.Slice(result, func(i, j int) bool {
		if result[i].LastHit != result[j].LastHit {
			return result[i].LastHit > result[j].LastHit
		}
		if result[i].Host != result[j].Host {
			return result[i].Host < result[j].Host
		}
		return result[i].Port < result[j].Port
	})
	b.cached = result
	b.lastCacheAt = now
	b.cacheDirty = 0
}

func (b *Blacklist) cleanExpired() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	removed := false
	for k, rec := range b.entries {
		if rec.expiry.Before(now) {
			delete(b.entries, k)
			removed = true
		}
	}
	if removed {
		b.cacheDirty = 1
	}
}

func (b *Blacklist) Remove(host string, port int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	removed := false
	if port > 0 {
		if _, ok := b.entries[blacklistKey{host: host, port: port}]; ok {
			delete(b.entries, blacklistKey{host: host, port: port})
			removed = true
		}
	} else {
		for k := range b.entries {
			if k.host == host {
				delete(b.entries, k)
				removed = true
			}
		}
	}
	if removed {
		b.cacheDirty = 1
	}
}

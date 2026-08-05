package route

import (
	"log/slog"
	"sort"
	"sync"
	"time"
)

const (
	blacklistMaxSize = 10000
)

type BlacklistEntry struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	LastReason string `json:"last_reason"`
	ExpiresAt  int64  `json:"expires_at"`
}

type blacklistRecord struct {
	expiry     time.Time
	lastReason string
}

type Blacklist struct {
	mu      sync.Mutex
	entries map[blacklistKey]blacklistRecord
	maxSize int
	name    string
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
	if time.Now().After(rec.expiry) {
		delete(b.entries, key)
		return false
	}
	slog.Debug("dynamic blacklist hit", "type", b.name, "host", host, "port", port)
	return true
}

func (b *Blacklist) Add(host string, port int, ttl time.Duration, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := blacklistKey{host: host, port: port}

	if _, exists := b.entries[key]; !exists {
		if len(b.entries) >= b.maxSize {
			b.evictOldestLocked()
		}
	} else {

		b.entries[key] = blacklistRecord{
			expiry:     time.Now().Add(ttl),
			lastReason: reason,
		}
		slog.Info("updated dynamic blacklist", "type", b.name, "host", host, "port", port, "reason", reason)
		return
	}

	b.entries[key] = blacklistRecord{
		expiry:     time.Now().Add(ttl),
		lastReason: reason,
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

func (b *Blacklist) Entries() []BlacklistEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	var result []BlacklistEntry
	for k, rec := range b.entries {
		if rec.expiry.After(now) {
			result = append(result, BlacklistEntry{
				Host:       k.host,
				Port:       k.port,
				LastReason: rec.lastReason,
				ExpiresAt:  rec.expiry.Unix(),
			})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Host != result[j].Host {
			return result[i].Host < result[j].Host
		}
		return result[i].Port < result[j].Port
	})
	return result
}

func (b *Blacklist) cleanExpired() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for k, rec := range b.entries {
		if rec.expiry.Before(now) {
			delete(b.entries, k)
		}
	}
}

func (b *Blacklist) Remove(host string, port int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if port > 0 {
		delete(b.entries, blacklistKey{host: host, port: port})
		return
	}
	for k := range b.entries {
		if k.host == host {
			delete(b.entries, k)
		}
	}
}

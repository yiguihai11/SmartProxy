package dns

import (
	"container/list"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
	"smartproxy/internal/safego"
)

type cacheKey struct {
	qname string
	qtype uint16
}

type cacheEntry struct {
	wire   []byte
	expire time.Time
	key    cacheKey
	link   *list.Element
}

type Cache struct {
	mu         sync.RWMutex
	entries    map[cacheKey]*cacheEntry
	lru        list.List
	maxSize    int
	defaultTTL time.Duration

	stopClean chan struct{}
	cleanWg   sync.WaitGroup
}

func NewCache(maxSize int, defaultTTL time.Duration) *Cache {
	c := &Cache{
		entries:    make(map[cacheKey]*cacheEntry),
		maxSize:    maxSize,
		defaultTTL: defaultTTL,
		stopClean:  make(chan struct{}),
	}
	c.cleanWg.Add(1)
	safego.Go("dns.cache.cleanLoop", c.cleanLoop)
	return c
}

func (c *Cache) cleanLoop() {
	defer c.cleanWg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for k, v := range c.entries {
				if now.After(v.expire) {
					c.deleteEntry(k, v)
				}
			}
			c.mu.Unlock()
		case <-c.stopClean:
			return
		}
	}
}

func (c *Cache) deleteEntry(key cacheKey, entry *cacheEntry) {
	if entry.link != nil {
		c.lru.Remove(entry.link)
	}
	delete(c.entries, key)
}

func (c *Cache) Close() {
	close(c.stopClean)
	c.cleanWg.Wait()
}

func (c *Cache) Get(qname string, qtype uint16) []byte {
	key := cacheKey{qname: qname, qtype: qtype}

	c.mu.RLock()
	entry, ok := c.entries[key]
	if ok && !time.Now().After(entry.expire) {
		c.mu.RUnlock()

		c.mu.Lock()
		if entry.link != nil {
			c.lru.MoveToFront(entry.link)
		}
		c.mu.Unlock()
		return entry.wire
	}
	c.mu.RUnlock()

	if ok {

		c.mu.Lock()
		if entry, ok := c.entries[key]; ok && time.Now().After(entry.expire) {
			c.deleteEntry(key, entry)
		}
		c.mu.Unlock()
	}
	return nil
}

func (c *Cache) Set(qname string, qtype uint16, wire []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey{qname: qname, qtype: qtype}

	if existing, ok := c.entries[key]; ok {
		existing.wire = wire
		existing.expire = time.Now().Add(c.ttl(ttl))
		c.lru.MoveToFront(existing.link)
		return
	}

	if len(c.entries) >= c.maxSize {
		if back := c.lru.Back(); back != nil {
			evict := back.Value.(*cacheEntry)
			c.deleteEntry(evict.key, evict)
		}
	}

	entry := &cacheEntry{
		wire:   wire,
		expire: time.Now().Add(c.ttl(ttl)),
		key:    key,
	}
	entry.link = c.lru.PushFront(entry)
	c.entries[key] = entry
}

func (c *Cache) ttl(ttl time.Duration) time.Duration {
	if c.defaultTTL > 0 {
		return c.defaultTTL
	}
	if ttl <= 0 {
		return 0
	}
	return ttl
}

func (c *Cache) Remove(qname string, qtype uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey{qname: qname, qtype: qtype}
	if entry, ok := c.entries[key]; ok {
		c.deleteEntry(key, entry)
	}
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[cacheKey]*cacheEntry)
	c.lru.Init()
}

func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

type CacheEntryInfo struct {
	Qname   string   `json:"qname"`
	Qtype   uint16   `json:"qtype"`
	Expires int64    `json:"expires"`
	Answers []string `json:"answers,omitempty"`
}

func (c *Cache) Entries() []CacheEntryInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	result := make([]CacheEntryInfo, 0)
	for k, v := range c.entries {
		if v.expire.After(now) {
			info := CacheEntryInfo{
				Qname: k.qname, Qtype: k.qtype, Expires: v.expire.Unix(),
			}
			if k.qtype == dns.TypeA || k.qtype == dns.TypeAAAA {
				msg := new(dns.Msg)
				if err := msg.Unpack(v.wire); err == nil {
					for _, a := range msg.Answer {
						switch rr := a.(type) {
						case *dns.A:
							info.Answers = append(info.Answers, rr.A.String())
						case *dns.AAAA:
							info.Answers = append(info.Answers, rr.AAAA.String())
						}
					}
				}
			}
			result = append(result, info)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Qname != result[j].Qname {
			return result[i].Qname < result[j].Qname
		}
		return result[i].Qtype < result[j].Qtype
	})
	return result
}

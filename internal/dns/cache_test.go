package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// UpdateConfig 缩容时必须按 LRU 从最久未用淘汰到新容量,保留最近使用的条目。
func TestCacheUpdateConfigShrink(t *testing.T) {
	c := NewCache(5, time.Minute)
	defer c.Close()
	for i := 0; i < 5; i++ {
		k := string(rune('a' + i))
		c.Set(k, dns.TypeA, []byte(k), time.Minute)
	}
	if c.Len() != 5 {
		t.Fatalf("setup len = %d, want 5", c.Len())
	}

	// maxSize=2、defaultTTL=0(0 表示不改 TTL):应从最老的 a/b/c 淘汰到剩 2。
	c.UpdateConfig(2, 0)
	if got := c.Len(); got != 2 {
		t.Fatalf("after shrink len = %d, want 2", got)
	}
	if c.Get("e", dns.TypeA) == nil || c.Get("d", dns.TypeA) == nil {
		t.Fatal("LRU shrink evicted recent entries d/e")
	}
	if c.Get("a", dns.TypeA) != nil {
		t.Fatal("LRU shrink should have evicted oldest entry a")
	}
}

// 扩容不应淘汰任何条目;defaultTTL 更新后新写入按新 TTL 过期(不 panic、不缩容)。
func TestCacheUpdateConfigGrow(t *testing.T) {
	c := NewCache(2, time.Minute)
	defer c.Close()
	c.Set("a", dns.TypeA, []byte("a"), time.Minute)
	c.Set("b", dns.TypeA, []byte("b"), time.Minute)
	c.UpdateConfig(10, time.Hour)
	if c.Len() != 2 {
		t.Fatalf("after grow len = %d, want 2 (no eviction)", c.Len())
	}
	c.Set("c", dns.TypeA, []byte("c"), time.Hour)
	if c.Len() != 3 {
		t.Fatalf("after Set within new cap len = %d, want 3", c.Len())
	}
}

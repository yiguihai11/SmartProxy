package adblock

import (
	"fmt"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestSetApexAndSubdomains(t *testing.T) {
	suffixes := []string{"example.com", "adservice.net"}
	allow := []string{"safe.example.com"}
	stats := NewStats()
	set := NewSet(suffixes, allow, stats)

	tests := []struct {
		q       string
		blocked bool
	}{
		{"example.com", true},         // 含自身 (apex)
		{"ads.example.com", true},     // 子域名
		{"sub.ads.example.com", true}, // 多级子域名
		{"safe.example.com", false},   // 白名单例外
		{"sub.safe.example.com", false},// 白名单子域同样豁免
		{"notexample.com", false},     // 非子域
		{"adservice.net", true},       // 另一条规则自身
		{"sub.adservice.net", true},   // 另一条规则子域
		{"google.com", false},         // 未包含
	}

	for _, tt := range tests {
		got := set.Blocked(tt.q)
		if got != tt.blocked {
			t.Errorf("Blocked(%q) = %v, want %v", tt.q, got, tt.blocked)
		}
	}
	if stats.Total() == 0 {
		t.Fatal("expected non-zero block hits in stats")
	}
}

func TestSetSuffixCompression(t *testing.T) {
	// sub.a.com, a.com -> 应压缩为仅保留 a.com
	suffixes := []string{
		"a.com",
		"sub.a.com",
		"deep.sub.a.com",
		"b.com",
		"sub.b.com",
	}
	set := NewSet(suffixes, nil, nil)
	if set.Len() != 2 {
		t.Fatalf("expected compressed len=2, got %d", set.Len())
	}
	if !set.Blocked("deep.sub.a.com") || !set.Blocked("a.com") {
		t.Fatal("compressed set should still match all subdomains and apex")
	}
}

func TestSetNoAllocOnHit(t *testing.T) {
	set := NewSet([]string{"ad.example.com", "tracker.org"}, nil, NewStats())
	allocs := testing.AllocsPerRun(1000, func() {
		_ = set.Blocked("ad.example.com")
		_ = set.Blocked("sub.tracker.org")
		_ = set.Blocked("clean.site.com")
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs on query path, got %f", allocs)
	}
}

func TestSetBuild100k(t *testing.T) {
	const n = 100000
	suffixes := make([]string, n)
	for i := 0; i < n; i++ {
		// 生成具有父子关系的域名以测试压缩
		if i%4 == 0 {
			suffixes[i] = fmt.Sprintf("sub.domain%d.com", i/4)
		} else {
			suffixes[i] = fmt.Sprintf("domain%d.com", i)
		}
	}

	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	start := time.Now()
	set := NewSet(suffixes, nil, nil)
	elapsed := time.Since(start)

	runtime.ReadMemStats(&m2)
	allocMB := float64(m2.Alloc-m1.Alloc) / (1024 * 1024)

	t.Logf("100k build time: %v, mem: %.2f MB, kept rules: %d", elapsed, allocMB, set.Len())

	if elapsed > 200*time.Millisecond {
		t.Errorf("build time %v exceeded 200ms limit", elapsed)
	}
	// 堆内存增长通常在 6~10MB 之间
	if allocMB > 15.0 {
		t.Errorf("memory %.2f MB exceeded 15MB limit", allocMB)
	}
}

func BenchmarkSet_Blocked_100k(b *testing.B) {
	const count = 100000
	suffixes := make([]string, count)
	for i := 0; i < count; i++ {
		suffixes[i] = "ad" + strconv.Itoa(i) + ".example.com"
	}
	set := NewSet(suffixes, []string{"safe.ad0.example.com"}, nil)

	// 混合测试集: 40% 全名命中、40% 子域命中、20% 未命中
	queries := []string{
		"ad12345.example.com",        // 全名命中
		"ad67890.example.com",        // 全名命中
		"sub.ad12345.example.com",    // 子域命中
		"deep.sub.ad67890.example.com", // 子域命中
		"clean.domain.org",           // 未命中
	}
	numQ := len(queries)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Blocked(queries[i%numQ])
	}
}

func BenchmarkSet_BlockedWorst(b *testing.B) {
	const count = 100000
	suffixes := make([]string, count)
	for i := 0; i < count; i++ {
		suffixes[i] = "ad" + strconv.Itoa(i) + ".example.com"
	}
	set := NewSet(suffixes, nil, nil)

	// 8 级标签最坏情况未命中: 逐后缀 walk 走满 8 次
	worstQuery := "a.b.c.d.e.f.g.unmatched.org"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Blocked(worstQuery)
	}
}

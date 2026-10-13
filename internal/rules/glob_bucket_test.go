package rules

import (
	"path"
	"strings"
	"testing"
)

// glob 分桶(§6.2)是唯一一处会改变匹配路径的改动:如果桶键取错,某些本该命中的
// 域名会被跳过,表现是「广告突然不拦了」这种静默失效。所以这里的验证不是抽样,
// 而是对每个模式派生出会命中/接近命中的域名,再用改造前的暴力扫描做逐条比对。
//
// 参照实现就是改造前的逻辑:遍历全部模式跑 path.Match。

func bruteForceMatchAny(patterns []string, domain string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, domain); ok {
			return true
		}
	}
	return false
}

func bruteForceBestGlob(globs []proxyGlobRule, domain string) (proxyGlobRule, bool) {
	var best proxyGlobRule
	found := false
	for _, pg := range globs {
		if ok, _ := path.Match(pg.pattern, domain); ok && (!found || pg.target.index < best.target.index) {
			best, found = pg, true
		}
	}
	return best, found
}

// bucketTestPatterns 覆盖真实 ACL 里出现的模式形状,外加所有「不能分桶」的形状:
// 没有 '*' 的 ?/[ glob、最后一个 '*' 之后没有字面后缀、字面后缀不以 '.' 开头、
// 含转义反斜杠、纯 '*'。任何一类被错误地分进桶里都会漏命中。
var bucketTestPatterns = []string{
	// 真实 ACL 的 14 条中缀 glob
	"*ads*-*.zijieapi.com",
	"*ad*-*.zijieapi.com",
	"*polaris*.zijieapi.com",
	"*apm*.zijieapi.com",
	"*log*.zijieapi.com",
	"*mon*.zijieapi.com",
	"*security*.zijieapi.com",
	"*frontier*.zijieapi.com",
	"*tracker*.zijieapi.com",
	"*ugc*.zijieapi.com",
	"*minigame*-*.zijieapi.com",
	"*webcast*-*.zijieapi.com",
	"*reading-ad*.qznovelvod.com",
	"*-ad-*.byteimg.com",
	// *.X 形状(实际走后缀 trie,这里验证万一它落进 glob 也不会被分错)
	"*.oceanengine.com",
	"*.e.kuaishou.com",
	// 不能分桶的形状
	"*ad*",                  // 最后一个 '*' 之后没有字面后缀
	"ads*",                  // 同上,且尾部为空
	"*?ads.com",             // 后缀含 ?
	"*[0-9]ads.com",         // 后缀含 [
	"*ads*.com\\",           // 后缀含转义反斜杠(尾部有 '\' 时不能当字面量)
	"*ads\\*.com",           // 转义在最后一个 '*' 之前:尾部 ".com" 仍是可靠的必要条件,可以分桶
	"ads*.com",              // 字面后缀 ".com" 可以分桶
	"*a.b.c.example.org",    // 尾部不以 '.' 开头 → 兜底
	"*ads*.a.b.example.org", // 多段尾部且以 '.' 开头 → 可以分桶
	"x*z.com",
}

// bucketTestDomains 由模式派生 + 一批真实域名(命中的、接近命中的、完全无关的)。
func bucketTestDomains() []string {
	var domains []string
	add := func(d string) {
		if d != "" {
			domains = append(domains, d)
		}
	}

	for _, p := range bucketTestPatterns {
		// 把每个 '*' 替换成几种填充:空、单标签、多标签(跨 '.' —— path.Match 的
		// '*' 会匹配 '.'),以及含模式关键字的样子。派生出来的域名无论是否命中,
		// 两种实现都必须给出一致的答案。
		for _, fill := range []string{"", "x", "ads", "a.b", "minigame-1", "reading-ad"} {
			add(strings.ReplaceAll(p, "*", fill))
		}
		// 去掉最后一个 '*' 之后的字面后缀,造出「后缀相同但不该命中」的近似样本。
		if idx := strings.LastIndexByte(p, '*'); idx >= 0 {
			tail := p[idx+1:]
			add(strings.ReplaceAll(p[:idx], "*", "x") + tail)
			add("zzz" + tail)
			if strings.HasPrefix(tail, ".") {
				add("noise" + tail[1:])
			}
		}
	}

	add("www.google.com")
	add("www.qq.com")
	add("scc.bytedance.com")
	add("cdn.wwads.cn")
	add("example.com")
	add("a.b.c.d.e.f.foreign-cdn.net")
	add("ads.zijieapi.net")
	add("notads.zijieapi.com")
	add("x.ads.y.zijieapi.com")
	add("ads")
	add("")
	add(".")
	add("..")
	add(".com")
	add("com")

	return domains
}

// TestGlobBucket_EquivalentToLinearScan 是 §6.2 的正确性证明:对新旧两种实现,
// matchAny(拦截/放行)与 bestMatchingGlob(选路,按 index 优先)都必须逐条一致。
func TestGlobBucket_EquivalentToLinearScan(t *testing.T) {
	gb := newGlobBucket(bucketTestPatterns)
	domains := bucketTestDomains()

	if len(domains) < 100 {
		t.Fatalf("probe corpus too small: %d", len(domains))
	}

	hits, misses := 0, 0
	for _, d := range domains {
		want := bruteForceMatchAny(bucketTestPatterns, d)
		if got := gb.matchAny(bucketTestPatterns, d); got != want {
			t.Errorf("matchAny(%q) = %v, 暴力扫描 = %v", d, got, want)
		}
		if want {
			hits++
		} else {
			misses++
		}
	}
	// 语料必须同时含命中和未命中:只要有一边为空,「全 true」或「全 false」的退化
	// 实现也能让上面的逐条比对通过,测试就什么都没证明。
	// (纯 '*' 这种能匹配一切的极端模式被刻意排除在语料之外 —— 它会吃掉全部未命中样本,
	//  它的行为由 TestGlobBucket_MatchAllPattern 单独钉。)
	if hits == 0 || misses == 0 {
		t.Fatalf("probe corpus is degenerate: hits=%d misses=%d", hits, misses)
	}
	t.Logf("探针域名 %d 个(命中 %d / 未命中 %d),分桶与线性扫描完全一致", len(domains), hits, misses)
}

// TestGlobBucket_MatchAllPattern 钉住纯 '*' 这类「能匹配一切」的模式:它分不了桶,
// 只能留在 always 里逐条扫描,但正因为如此它必须对任何域名都命中 —— 一旦哪天它被
// 误分进某个桶(只有该后缀的域名才会被检查),拦截就会漏掉绝大部分域名。
func TestGlobBucket_MatchAllPattern(t *testing.T) {
	// 三条都分不了桶:纯 '*';'*ad*' 与 '*ads*' 最后一个 '*' 之后没有字面后缀。
	// (注意 '*.example.com' 属于可分桶形状,不在这里 —— 它由 TestBucketSuffix 钉。)
	patterns := []string{"*", "*ad*", "*ads*"}
	gb := newGlobBucket(patterns)
	if len(gb.always) != 3 || len(gb.bySuffix) != 0 {
		t.Fatalf("expected 3 always-scanned patterns, got always=%d bucketKeys=%d", len(gb.always), len(gb.bySuffix))
	}
	for _, d := range bucketTestDomains() {
		if !gb.matchAny(patterns, d) {
			t.Errorf("matchAny(%q) = false, 纯 '*' 模式必须命中一切", d)
		}
	}
}

// TestGlobBucket_BestMatchPicksEarliestRule 单独验证选路的「ACL 靠前优先」:
// 两条规则命中同一域名时,必须选中 index 小的那条 —— 即使其中一条在桶里、
// 另一条在 always 兜底里(遍历顺序不同,只能靠 index 比较保证语义)。
func TestGlobBucket_BestMatchPicksEarliestRule(t *testing.T) {
	globs := []proxyGlobRule{
		{pattern: "*tracker*.zijieapi.com", target: proxyTarget{index: 7, alias: "late-bucketed"}},
		{pattern: "*ad*", target: proxyTarget{index: 3, alias: "early-always"}},
		{pattern: "*ads*-*.zijieapi.com", target: proxyTarget{index: 5, alias: "mid-bucketed"}},
	}
	patterns := make([]string, len(globs))
	for i, pg := range globs {
		patterns[i] = pg.pattern
	}
	gb := newGlobBucket(patterns)

	for _, d := range bucketTestDomains() {
		want, wantOK := bruteForceBestGlob(globs, d)
		got, gotOK := gb.bestMatchingGlob(globs, d)
		if gotOK != wantOK {
			t.Errorf("bestMatchingGlob(%q) ok = %v, 暴力扫描 = %v", d, gotOK, wantOK)
			continue
		}
		if gotOK && got.target.index != want.target.index {
			t.Errorf("bestMatchingGlob(%q) 选中 index %d (%s), 暴力扫描选中 %d (%s)",
				d, got.target.index, got.target.alias, want.target.index, want.target.alias)
		}
	}

	// 钉住这个用例本身:域名同时命中 index 3 / 5 / 7 三条时,必须选 3。
	d := "x.ads.y.zijieapi.com"
	if got, ok := gb.bestMatchingGlob(globs, d); !ok || got.target.index != 3 {
		t.Errorf("bestMatchingGlob(%q) = (index %d, %v), want index 3", d, got.target.index, ok)
	}
}

// TestBucketSuffix 直接钉住桶键的判定规则:哪些模式允许分桶、键取什么。
// 取错任何一个都会让对应模式的命中率变成 0(漏拦截)。
func TestBucketSuffix(t *testing.T) {
	allow := map[string]string{
		"*ads*-*.zijieapi.com":        ".zijieapi.com",
		"*tracker*.zijieapi.com":      ".zijieapi.com",
		"*reading-ad*.qznovelvod.com": ".qznovelvod.com",
		"*-ad-*.byteimg.com":          ".byteimg.com",
		"*.oceanengine.com":           ".oceanengine.com",
		"ads*.com":                    ".com",
		"*ads*.a.b.example.org":       ".a.b.example.org",
		// 转义在最后一个 '*' 之前:尾部 ".com" 仍然是「任何命中者都必须以此结尾」的
		// 可靠必要条件(转义的那颗星由 path.Match 在候选上照常匹配)。
		"*ads\\*.com": ".com",
	}
	deny := []string{
		"*ad*", "ads*", "*", "no-star.com", "a?b.com", "a[0-9].com",
		"*ads*.com\\", "*ads*foo.com", "*ads*[x].com", "*a.b.c.example.org",
		"*foo.com", "*ads*.foo.com\\",
	}
	for p, want := range allow {
		got, ok := bucketSuffix(p)
		if !ok || got != want {
			t.Errorf("bucketSuffix(%q) = (%q, %v), want (%q, true)", p, got, ok, want)
		}
	}
	for _, p := range deny {
		if got, ok := bucketSuffix(p); ok {
			t.Errorf("bucketSuffix(%q) = (%q, true), 该模式不能分桶", p, got)
		}
	}
}

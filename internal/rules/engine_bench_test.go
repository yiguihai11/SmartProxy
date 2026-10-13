package rules

import (
	"strings"
	"testing"
)

// sink 接住被测函数的返回值,防止编译器把「结果没人用」的调用整个优化掉 ——
// 那样 AllocsPerRun 量到的是空循环,门禁会假绿。
var (
	sinkAlias   string
	sinkMatched bool
	sinkBlocked bool
)

// benchACL 与设备上真实 acl.txt 同形状:精确域名 + *.X 后缀 + 中缀 glob(番茄小说/
// 红果那 14 条)+ CIDR + 端口,直连/默认/指定出口三种别名都有。
//
// 基准必须跑这个形状而不是人造的几十条 glob:glob 分桶(§6.2)的收益完全取决于
// 真实规则条数与模式形状,用假数据量出来的数字没有参考价值。
const benchACL = `
allow port 22
block port 135
block port 445

block domain scc.bytedance.com
block domain cdn.wwads.cn
block domain ads.mozilla.org

block domain *ads*-*.zijieapi.com
block domain *ad*-*.zijieapi.com
block domain *polaris*.zijieapi.com
block domain *apm*.zijieapi.com
block domain *log*.zijieapi.com
block domain *mon*.zijieapi.com
block domain *security*.zijieapi.com
block domain *frontier*.zijieapi.com
block domain *tracker*.zijieapi.com
block domain *ugc*.zijieapi.com
block domain *minigame*-*.zijieapi.com
block domain *webcast*-*.zijieapi.com
block domain *reading-ad*.qznovelvod.com
block domain *-ad-*.byteimg.com

block domain *.oceanengine.com
block domain *.pangolin-sdk-toutiao.com
block domain *.zijieapi.net
block domain *.pstatp.com
block domain *.kuaishou.com
block domain *.ad.toutiao.com
block domain *.stsdk.vivo.com.cn

proxy domain *.google.com "[TW] 台湾中转1"
proxy domain *.googleapis.com "[TW] 台湾中转1"
proxy domain *.github.com default
proxy domain *.anthropic.com default
proxy domain api.deps.dev default
proxy domain *.blob.core.windows.net default
proxy domain *ads*.example-cdn.com direct
proxy domain *.qq.com direct
proxy cidr 10.0.0.0/8 direct
proxy ip 1.2.3.4 default
`

// benchDomains 覆盖四种走向:命中精确域名、命中 *.X 后缀、命中中缀 glob、完全不命中。
// 只测命中或只测不命中都量不到真实成本(不命中要扫完全部候选)。
var benchDomains = []string{
	"scc.bytedance.com",
	"cdn.wwads.cn",
	"ads.mozilla.org",
	"x.ads.y.zijieapi.com",
	"log.snssdk.zijieapi.com",
	"a.minigame-b.zijieapi.com",
	"x.reading-ad.qznovelvod.com",
	"p-ads-q.byteimg.com",
	"www.oceanengine.com",
	"e.kuaishou.com",
	"moni-onrt-stsdk.vivo.com.cn",
	"www.google.com",
	"oauth2.googleapis.com",
	"github.com",
	"api.deps.dev",
	"foo.blob.core.windows.net",
	"www.qq.com",
	"www.baidu.com",
	"example.com",
	"a.b.c.d.e.f.foreign-cdn.net",
	"ads.zijieapi.net",
	"notads.zijieapi.com",
}

func benchEngine(b *testing.B) *Engine {
	b.Helper()
	e, err := New(writeTempRuleFile(b, benchACL))
	if err != nil {
		b.Fatalf("load bench ACL: %v", err)
	}
	return e
}

// BenchmarkMatchProxyRule 量的是每条流建立时的选路判定:目标 IP/端口/域名 → 别名。
// 它跑在 upstream.Manager.SelectProxy 的最前面,是 TUN/SOCKS5/UDP 三条入口共用的热点。
func BenchmarkMatchProxyRule(b *testing.B) {
	e := benchEngine(b)
	b.ReportAllocs()
	b.ResetTimer()
	i := 0
	for b.Loop() {
		sinkAlias, sinkMatched = e.MatchProxyRule("1.2.3.4", 443, benchDomains[i])
		i++
		if i == len(benchDomains) {
			i = 0
		}
	}
}

// BenchmarkIsDomainBlocked 量的是域名拦截判定。DNS 管线对每个查询、SOCKS5/TUN 对每条
// 连接都要问一次,广告拦截的实际收益就落在这里。
func BenchmarkIsDomainBlocked(b *testing.B) {
	e := benchEngine(b)
	b.ReportAllocs()
	b.ResetTimer()
	i := 0
	for b.Loop() {
		sinkBlocked = e.IsDomainBlocked(benchDomains[i])
		i++
		if i == len(benchDomains) {
			i = 0
		}
	}
}

// TestRulesHotPathNoAlloc 是分配门禁:选路与拦截判定在每个流建立/每次 DNS 响应上都会
// 走一遍,任何一次多出来的堆分配都会变成 GC 压力。它同时钉住两件事:
//   - glob 分桶(§6.2)不能引入回调闭包这类每次调用的分配;
//   - normalizeDomain 在「域名本来就是小写」这个绝大多数情况下不再分配。
func TestRulesHotPathNoAlloc(t *testing.T) {
	e, err := New(writeTempRuleFile(t, benchACL))
	if err != nil {
		t.Fatalf("load bench ACL: %v", err)
	}

	for _, d := range benchDomains {
		domain := d
		t.Run(domain, func(t *testing.T) {
			if avg := testing.AllocsPerRun(200, func() {
				sinkAlias, sinkMatched = e.MatchProxyRule("1.2.3.4", 443, domain)
			}); avg != 0 {
				t.Errorf("MatchProxyRule allocates %v objects per call, want 0", avg)
			}
			if avg := testing.AllocsPerRun(200, func() {
				sinkBlocked = e.IsDomainBlocked(domain)
			}); avg != 0 {
				t.Errorf("IsDomainBlocked allocates %v objects per call, want 0", avg)
			}
		})
	}
}

// TestNormalizeDomainKeepsSemantics 钉住 normalizeDomain 的语义:它必须等价于
// TrimSuffix(ToLower(x), ".")。这条测试的用处不是验证当前实现,而是拦住「以后
// 有人为了省分配自己写 ASCII 快路径,却漏掉某类会被 ToLower 改写的输入」——
// 那样域名规则会静默失配(注意 Go 的 ToLower 自己已有 ASCII 快路径,本来就零分配)。
func TestNormalizeDomainKeepsSemantics(t *testing.T) {
	cases := []string{
		"", ".", "..", "www.google.com", "WWW.Google.COM", "www.google.com.",
		"ÄÖÜ.example.com", "İstanbul.example.com", "ß.example.com",
		"例子.中国", "xn--fsqu00a.xn--fiqs8s",
		"aKb.example.com", // Kelvin sign:ToLower 会改写
		"*ADS*-*.ZiJieApi.com", "MiXeD.CaSe.Example.COM.",
	}
	for _, in := range cases {
		want := strings.TrimSuffix(strings.ToLower(in), ".")
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

package adblock

import (
	"io"
	"strings"
	"testing"
)

func TestParseHostsAllCases(t *testing.T) {
	input := `
# System hosts file with adblock lines
127.0.0.1 localhost
0.0.0.0 broadcasthost
::1 ip6-localhost
0.0.0.0 first.ad.com second.ad.com # inline comment
127.0.0.1 third.ad.com
1.2.3.4 legitimate-override.com
`
	suffixes, allow, _, stats, err := ParseList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(allow) != 0 {
		t.Fatalf("expected 0 allow rules, got %d", len(allow))
	}

	// 应该包含 first.ad.com, second.ad.com, third.ad.com
	expected := map[string]bool{
		"first.ad.com":  true,
		"second.ad.com": true,
		"third.ad.com":  true,
	}
	for _, s := range suffixes {
		if !expected[s] {
			t.Errorf("unexpected suffix %q", s)
		}
		delete(expected, s)
	}
	if len(expected) != 0 {
		t.Errorf("missing expected suffixes: %v", expected)
	}

	// 真实 IP 应该被跳过
	if stats.Reasons["real_ip_host"] != 1 {
		t.Errorf("expected 1 real_ip_host skip, got %d", stats.Reasons["real_ip_host"])
	}
	// localhost 等噪音应该被跳过
	if stats.Reasons["noise_hosts"] < 3 {
		t.Errorf("expected at least 3 noise_hosts skips, got %d", stats.Reasons["noise_hosts"])
	}
}

func TestParseABPAndPlainDomains(t *testing.T) {
	input := `
! Comment line
[Adblock Plus 2.0]
||adservice.com^
||analytics.com^$important
@@||safe.analytics.com^
plain-tracker.net
`
	suffixes, allow, _, stats, err := ParseList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stats.Kept != 4 {
		t.Fatalf("expected 4 kept rules, got %d", stats.Kept)
	}

	set := NewSet(suffixes, allow, nil)
	if !set.Blocked("adservice.com") {
		t.Error("adservice.com should be blocked")
	}
	if !set.Blocked("analytics.com") {
		t.Error("analytics.com should be blocked ($important preserved)")
	}
	if set.Blocked("safe.analytics.com") {
		t.Error("safe.analytics.com should be exempt by allow rule")
	}
	if !set.Blocked("plain-tracker.net") {
		t.Error("plain-tracker.net from bare-domain list should be blocked")
	}
}

func TestParseOrderTrapCosmeticVsComment(t *testing.T) {
	// 顺序陷阱: ## 开头的元素隐藏规则绝不能被当成 # 注释跳过
	input := `
##.ad-banner
#?#div.sponsored
# Real comment
`
	_, _, _, stats, err := ParseList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Reasons["cosmetic"] != 2 {
		t.Fatalf("expected 2 cosmetic skips, got %d", stats.Reasons["cosmetic"])
	}
}

func TestParseUnsupportedABPFeatures(t *testing.T) {
	input := `
||ads.com^$third-party
||ads.com^$dnsrewrite=NOERROR
/ads[0-9]+\.com/
https://example.com/ad/banner.js
*.wildcard.org
`
	_, _, _, stats, err := ParseList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Reasons["option"] < 2 {
		t.Errorf("expected >=2 option skips, got %d", stats.Reasons["option"])
	}
	if stats.Reasons["regex"] != 1 {
		t.Errorf("expected 1 regex skip, got %d", stats.Reasons["regex"])
	}
	if stats.Reasons["url_path"] != 1 {
		t.Errorf("expected 1 url_path skip, got %d", stats.Reasons["url_path"])
	}
	if stats.Reasons["wildcard"] != 1 {
		t.Errorf("expected 1 wildcard skip, got %d", stats.Reasons["wildcard"])
	}
}

func TestParseBadfilterOrderIndependent(t *testing.T) {
	// 两个清单, 分别测试 badfilter 在前和在后的情况
	inputs := []struct {
		desc string
		list string
	}{
		{
			desc: "badfilter after rule",
			list: "||bad.com^\n||bad.com^$badfilter\n||keep.com^\n",
		},
		{
			desc: "badfilter before rule",
			list: "||bad.com^$badfilter\n||bad.com^\n||keep.com^\n",
		},
	}

	for _, tc := range inputs {
		readers := map[string]io.Reader{
			tc.desc: strings.NewReader(tc.list),
		}
		suffixes, _, _, err := ParseLists(readers)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.desc, err)
		}
		set := NewSet(suffixes, nil, nil)
		if set.Blocked("bad.com") {
			t.Errorf("%s: bad.com should have been canceled by $badfilter", tc.desc)
		}
		if !set.Blocked("keep.com") {
			t.Errorf("%s: keep.com should remain blocked", tc.desc)
		}
	}
}

func TestParseMaxLinesLimit(t *testing.T) {
	// 构建超过 50 万行的清单
	input := strings.Repeat("! comment\n", maxLinesPerList+5)
	_, _, _, stats, err := ParseList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Reasons["line_limit_exceeded"] != 1 {
		t.Fatal("expected line_limit_exceeded flag in stats")
	}
}

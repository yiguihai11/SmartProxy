package rules

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSuffixTrie_InsertAndMatch(t *testing.T) {
	st := newSuffixTrie()
	st.insert(".example.com")
	if !st.match("www.example.com") {
		t.Error("www.example.com should match .example.com")
	}
	if !st.match("test.example.com") {
		t.Error("test.example.com should match .example.com")
	}
}

func TestSuffixTrie_NoMatchExactDomain(t *testing.T) {
	st := newSuffixTrie()
	st.insert(".example.com")
	if st.match("example.com") {
		t.Error("example.com should NOT match .example.com")
	}
}

func TestSuffixTrie_NoMatchDifferentDomain(t *testing.T) {
	st := newSuffixTrie()
	st.insert(".example.com")
	if st.match("www.other.com") {
		t.Error("www.other.com should NOT match .example.com")
	}
}

func TestSuffixTrie_MultipleSuffixes(t *testing.T) {
	st := newSuffixTrie()
	st.insert(".adnetwork.com")
	st.insert(".tracker.com")
	if !st.match("ads.adnetwork.com") {
		t.Error("ads.adnetwork.com should match .adnetwork.com")
	}
	if !st.match("api.tracker.com") {
		t.Error("api.tracker.com should match .tracker.com")
	}
	if st.match("example.com") {
		t.Error("example.com should not match anything")
	}
}

func TestSuffixTrie_SubdomainChain(t *testing.T) {
	st := newSuffixTrie()
	st.insert(".google.com")
	if !st.match("www.google.com") {
		t.Error("www.google.com should match")
	}
	if !st.match("mail.google.com") {
		t.Error("mail.google.com should match")
	}
	if !st.match("a.b.c.google.com") {
		t.Error("a.b.c.google.com should match")
	}
	if st.match("google.com") {
		t.Error("google.com should not match")
	}
}

func TestSuffixTrie_Empty(t *testing.T) {
	st := newSuffixTrie()
	if st.match("example.com") {
		t.Error("empty trie should not match")
	}
	if !st.isEmpty() {
		t.Error("new trie should be empty")
	}
}

func TestSuffixTrie_IsEmpty(t *testing.T) {
	st := newSuffixTrie()
	if !st.isEmpty() {
		t.Error("new trie should be empty")
	}
	st.insert(".example.com")
	if st.isEmpty() {
		t.Error("trie with entries should not be empty")
	}
}

func TestSuffixTrie_CaseSensitivity(t *testing.T) {
	st := newSuffixTrie()
	st.insert(".example.com")

	if !st.match("www.example.com") {
		t.Error("lowercase domain should match")
	}
}

func writeTempRuleFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEngine_LoadEmpty(t *testing.T) {
	path := writeTempRuleFile(t, "")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsIPBlocked("1.2.3.4") {
		t.Error("empty rules should not block")
	}
}

func TestEngine_CommentsAndBlankLines(t *testing.T) {
	path := writeTempRuleFile(t, "# comment\n\nallow port 80\n# another comment\n\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsPortBlocked(80) {
		t.Error("port 80 should be allowed")
	}
}

func TestEngine_AllowPort(t *testing.T) {
	path := writeTempRuleFile(t, "block port 53\nallow port 53\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsPortBlocked(53) {
		t.Error("allow should override block")
	}
}

func TestEngine_BlockPort(t *testing.T) {
	path := writeTempRuleFile(t, "block port 25\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsPortBlocked(25) {
		t.Error("port 25 should be blocked")
	}
	if e.IsPortBlocked(80) {
		t.Error("port 80 should not be blocked")
	}
}

func TestEngine_AllowIP(t *testing.T) {
	path := writeTempRuleFile(t, "block ip 10.0.0.1\nallow ip 10.0.0.1\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsIPBlocked("10.0.0.1") {
		t.Error("allow should override block")
	}
}

func TestEngine_BlockIP(t *testing.T) {
	path := writeTempRuleFile(t, "block ip 192.168.1.100\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsIPBlocked("192.168.1.100") {
		t.Error("IP should be blocked")
	}
	if e.IsIPBlocked("192.168.1.101") {
		t.Error("different IP should not be blocked")
	}
}

func TestEngine_AllowCIDR(t *testing.T) {
	path := writeTempRuleFile(t, "block cidr 10.0.0.0/8\nallow cidr 10.0.0.0/16\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsIPBlocked("10.0.0.1") {
		t.Error("10.0.0.1 should be allowed by /16")
	}
	if !e.IsIPBlocked("10.255.0.1") {
		t.Error("10.255.0.1 should be blocked (not in /16)")
	}
}

func TestEngine_BlockCIDR(t *testing.T) {
	path := writeTempRuleFile(t, "block cidr 10.0.0.0/8\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsIPBlocked("10.1.2.3") {
		t.Error("10.1.2.3 should be blocked by /8")
	}
	if e.IsIPBlocked("192.168.1.1") {
		t.Error("192.168.1.1 should not be blocked")
	}
}

func TestEngine_AllowDomain(t *testing.T) {
	path := writeTempRuleFile(t, "block domain example.com\nallow domain example.com\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsDomainBlocked("example.com") {
		t.Error("allow should override block")
	}
}

func TestEngine_BlockDomain(t *testing.T) {
	path := writeTempRuleFile(t, "block domain evil.com\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsDomainBlocked("evil.com") {
		t.Error("domain should be blocked")
	}
	if e.IsDomainBlocked("good.com") {
		t.Error("different domain should not be blocked")
	}
}

func TestEngine_DomainCaseInsensitive(t *testing.T) {
	path := writeTempRuleFile(t, "block domain Evil.COM\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsDomainBlocked("evil.com") {
		t.Error("case-insensitive block should work")
	}
	if !e.IsDomainBlocked("EVIL.COM") {
		t.Error("uppercase domain should also be blocked")
	}
}

func TestEngine_AllowDomainSuffix(t *testing.T) {
	path := writeTempRuleFile(t, "block domain *.adnetwork.com\nallow domain *.good-adnetwork.com\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	if !e.IsDomainBlocked("ads.adnetwork.com") {
		t.Error("ads.adnetwork.com should be blocked by *.adnetwork.com")
	}

	if e.IsDomainBlocked("tracker.good-adnetwork.com") {
		t.Error("tracker.good-adnetwork.com should be allowed by *.good-adnetwork.com")
	}
}

func TestEngine_BlockDomainSuffix(t *testing.T) {
	path := writeTempRuleFile(t, "block domain *.tracker.com\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsDomainBlocked("analytics.tracker.com") {
		t.Error("analytics.tracker.com should be blocked by suffix")
	}
	if e.IsDomainBlocked("tracker.com") {
		t.Error("tracker.com itself should NOT be blocked by *.tracker.com")
	}
}

func TestEngine_ProxyRulePort(t *testing.T) {
	path := writeTempRuleFile(t, "proxy port 22 proxy1\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, matched := e.MatchProxyRule("", 22, "")
	if !matched || alias != "proxy1" {
		t.Errorf("expected proxy1, got %q (matched=%v)", alias, matched)
	}
	_, matched = e.MatchProxyRule("", 80, "")
	if matched {
		t.Error("port 80 should not match")
	}
}

func TestEngine_ProxyRuleIP(t *testing.T) {
	path := writeTempRuleFile(t, "proxy ip 8.8.8.8 direct\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, matched := e.MatchProxyRule("8.8.8.8", 0, "")
	if !matched || alias != "direct" {
		t.Errorf("expected direct, got %q (matched=%v)", alias, matched)
	}
}

func TestEngine_ProxyRuleCIDR(t *testing.T) {
	path := writeTempRuleFile(t, "proxy cidr 10.0.0.0/8 internal\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, matched := e.MatchProxyRule("10.1.2.3", 0, "")
	if !matched || alias != "internal" {
		t.Errorf("expected internal, got %q (matched=%v)", alias, matched)
	}
	_, matched = e.MatchProxyRule("192.168.1.1", 0, "")
	if matched {
		t.Error("192.168.1.1 should not match 10.0.0.0/8")
	}
}

func TestEngine_ProxyRuleDomain(t *testing.T) {
	path := writeTempRuleFile(t, "proxy domain google.com direct\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, matched := e.MatchProxyRule("", 0, "google.com")
	if !matched || alias != "direct" {
		t.Errorf("expected direct, got %q (matched=%v)", alias, matched)
	}
	_, matched = e.MatchProxyRule("", 0, "")
	if matched {
		t.Error("empty domain should not match")
	}
}

func TestEngine_ProxyRuleWildcardDomain(t *testing.T) {
	path := writeTempRuleFile(t, "proxy domain *.google.com proxy1\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, matched := e.MatchProxyRule("", 0, "www.google.com")
	if !matched || alias != "proxy1" {
		t.Errorf("expected proxy1, got %q (matched=%v)", alias, matched)
	}
	_, matched = e.MatchProxyRule("", 0, "google.com")
	if matched {
		t.Error("google.com should not match *.google.com")
	}
}

func TestEngine_ProxyRules(t *testing.T) {
	path := writeTempRuleFile(t, "proxy port 80 http_proxy\nproxy domain example.com direct\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	rules := e.ProxyRules()
	if len(rules) != 2 {
		t.Errorf("expected 2 proxy rules, got %d", len(rules))
	}
}

func TestEngine_ProxyRulePriority(t *testing.T) {

	path := writeTempRuleFile(t, "proxy domain example.com proxy1\nproxy domain example.com proxy2\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, _ := e.MatchProxyRule("", 0, "example.com")
	if alias != "proxy1" {
		t.Errorf("first rule should win, got %q", alias)
	}
}

func TestEngine_InvalidRulesIgnored(t *testing.T) {
	path := writeTempRuleFile(t, "invalid line here\nallow port abc\nblock\n\nallow port 80\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsPortBlocked(80) {
		t.Error("port 80 should be allowed despite invalid lines")
	}
}

func TestEngine_Reload(t *testing.T) {
	path1 := writeTempRuleFile(t, "block port 25\n")
	e, err := New(path1)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsPortBlocked(25) {
		t.Error("port 25 should be blocked")
	}

	path2 := writeTempRuleFile(t, "allow port 25\n")
	if err := e.Reload(path2); err != nil {
		t.Fatal(err)
	}
	if e.IsPortBlocked(25) {
		t.Error("port 25 should be allowed after reload")
	}
}

func TestEngine_MissingFile(t *testing.T) {
	_, err := New("/nonexistent/file")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// TestEngine_ConcurrentReadDuringReload exercises the copy-on-write snapshot:
// readers must observe a consistent rule set while Load swaps in fresh snapshots.
func TestEngine_ConcurrentReadDuringReload(t *testing.T) {
	paths := []string{
		writeTempRuleFile(t, "block port 25\nblock ip 10.0.0.1\nblock domain evil.com\nproxy port 22 ssh_proxy\n"),
		writeTempRuleFile(t, "block port 443\nproxy domain google.com g_proxy\n"),
		writeTempRuleFile(t, "block cidr 10.0.0.0/8\nproxy cidr 192.168.0.0/16 lan_proxy\n"),
	}
	e, err := New(paths[0])
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	// concurrent readers
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					e.IsPortBlocked(22)
					e.IsPortBlocked(443)
					e.IsIPBlocked("10.0.0.1")
					e.IsDomainBlocked("evil.com")
					e.MatchProxyRule("8.8.8.8", 443, "google.com")
				}
			}
		}()
	}

	// concurrent writers
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if err := e.Reload(paths[(i+j)%len(paths)]); err != nil {
					t.Error("reload failed:", err)
					return
				}
			}
		}()
	}

	close(done) // signal readers to stop once writers finish
	wg.Wait()
}

func TestEngine_ConcurrentMatchProxy(t *testing.T) {
	path := writeTempRuleFile(t, strings.TrimSpace(`
proxy port 22 ssh_proxy
proxy cidr 10.0.0.0/8 internal
proxy domain google.com google_proxy
proxy domain *.github.com gh_proxy
`))
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		ip    string
		port  int
		dom   string
		alias string
	}{
		{"", 22, "", "ssh_proxy"},
		{"10.1.2.3", 0, "", "internal"},
		{"", 0, "google.com", "google_proxy"},
		{"", 0, "api.github.com", "gh_proxy"},
		{"8.8.8.8", 443, "example.com", ""},
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				for _, c := range cases {
					alias, matched := e.MatchProxyRule(c.ip, c.port, c.dom)
					if matched != (c.alias != "") || (matched && alias != c.alias) {
						t.Errorf("MatchProxyRule(%q,%d,%q) = (%q,%v), want alias %q",
							c.ip, c.port, c.dom, alias, matched, c.alias)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}

func TestEngine_InvalidIP(t *testing.T) {
	path := writeTempRuleFile(t, "block port 80\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsIPBlocked("not.an.ip") {
		t.Error("invalid IP should not be blocked")
	}
	if e.IsIPBlocked("") {
		t.Error("empty IP should not be blocked")
	}
}

func TestEngine_PortRange(t *testing.T) {
	path := writeTempRuleFile(t, "block port 22\nblock port 80\nblock port 443\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []int{22, 80, 443} {
		if !e.IsPortBlocked(p) {
			t.Errorf("port %d should be blocked", p)
		}
	}
	if e.IsPortBlocked(8080) {
		t.Error("port 8080 should not be blocked")
	}
}

func TestEngine_BlocklistMatchCaseInsensitive(t *testing.T) {
	path := writeTempRuleFile(t, "block domain tracker.EXAMPLE.com\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsDomainBlocked("TRACKER.example.COM") {
		t.Error("domain block should be case-insensitive")
	}
}

func TestEngine_InvalidPortFiltered(t *testing.T) {
	path := writeTempRuleFile(t, "block port abc\nblock port 88\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsPortBlocked(88) {
		t.Error("port 88 should be blocked (invalid 'abc' line should be skipped)")
	}
}

func TestEngine_DomainBlockSuffix(t *testing.T) {
	path := writeTempRuleFile(t, strings.TrimSpace(`
block domain *.adnetwork.com
block domain *.tracker.net
allow domain *.google.com
	`))
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	if !e.IsDomainBlocked("ads.adnetwork.com") {
		t.Error("ads.adnetwork.com should be blocked")
	}
	if !e.IsDomainBlocked("analytics.tracker.net") {
		t.Error("analytics.tracker.net should be blocked")
	}

	if e.IsDomainBlocked("adnetwork.com") {
		t.Error("adnetwork.com should NOT be blocked (exact domain)")
	}
	if e.IsDomainBlocked("google.com") {
		t.Error("google.com should NOT be blocked")
	}
}

func TestEngine_ProxyRuleMultiCIDR(t *testing.T) {

	path := writeTempRuleFile(t, "proxy cidr 10.0.0.0/8 internal\nproxy cidr 192.168.0.0/16 direct\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	alias, matched := e.MatchProxyRule("10.1.2.3", 0, "")
	if !matched || alias != "internal" {
		t.Errorf("10.1.2.3: expected internal, got %q (matched=%v)", alias, matched)
	}

	alias, matched = e.MatchProxyRule("192.168.1.1", 0, "")
	if !matched || alias != "direct" {
		t.Errorf("192.168.1.1: expected direct, got %q (matched=%v)", alias, matched)
	}

	_, matched = e.MatchProxyRule("8.8.8.8", 0, "")
	if matched {
		t.Error("8.8.8.8 should not match any CIDR rule")
	}
}

func TestEngine_AllowBlocksProxyRule(t *testing.T) {

	path := writeTempRuleFile(t, "allow port 80\nproxy port 80 myproxy\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	_, matched := e.MatchProxyRule("", 80, "")
	if matched {
		t.Error("allow port should prevent proxy rule from matching the same port")
	}

	_, matched = e.MatchProxyRule("", 443, "")
	if matched {
		t.Error("no proxy rule for port 443 should match")
	}
}

func TestEngine_AllowIPBlocksProxyRule(t *testing.T) {
	path := writeTempRuleFile(t, "allow ip 1.2.3.4\nproxy ip 1.2.3.4 direct\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	_, matched := e.MatchProxyRule("1.2.3.4", 0, "")
	if matched {
		t.Error("allow ip should prevent proxy rule from matching the same IP")
	}
}

func TestEngine_AllowDomainBlocksProxyRule(t *testing.T) {
	path := writeTempRuleFile(t, "allow domain google.com\nproxy domain google.com proxy1\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	_, matched := e.MatchProxyRule("", 0, "google.com")
	if matched {
		t.Error("allow domain should prevent proxy rule from matching the same domain")
	}
}

func TestEngine_AllowCIDRBlocksProxyRule(t *testing.T) {
	path := writeTempRuleFile(t, "allow cidr 10.0.0.0/8\nproxy cidr 10.0.0.0/8 internal\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	_, matched := e.MatchProxyRule("10.1.2.3", 0, "")
	if matched {
		t.Error("allow cidr should prevent proxy rule from matching the same CIDR")
	}
}

func TestEngine_ProxyRuleCIDR_IPv6(t *testing.T) {
	path := writeTempRuleFile(t, "proxy cidr 2001:db8::/32 ipv6proxy\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, matched := e.MatchProxyRule("2001:db8:1234::1", 0, "")
	if !matched || alias != "ipv6proxy" {
		t.Errorf("expected ipv6proxy, got %q (matched=%v)", alias, matched)
	}
	_, matched = e.MatchProxyRule("2002::1", 0, "")
	if matched {
		t.Error("2002::1 should not match 2001:db8::/32")
	}
}

func TestEngine_ProxyRuleCIDR_IPv6_SingleHost(t *testing.T) {
	path := writeTempRuleFile(t, "proxy cidr 2001:db8::1 ipv6single\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, matched := e.MatchProxyRule("2001:db8::1", 0, "")
	if !matched || alias != "ipv6single" {
		t.Errorf("expected ipv6single, got %q (matched=%v)", alias, matched)
	}
	_, matched = e.MatchProxyRule("2001:db8::2", 0, "")
	if matched {
		t.Error("2001:db8::2 should not match 2001:db8::1/128")
	}
}

func TestEngine_ProxyRuleCIDR_MixedV4V6(t *testing.T) {
	path := writeTempRuleFile(t, "proxy cidr 10.0.0.0/8 internal_v4\nproxy cidr 2001:db8::/32 internal_v6\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, _ := e.MatchProxyRule("10.1.2.3", 0, "")
	if alias != "internal_v4" {
		t.Errorf("expected internal_v4, got %q", alias)
	}
	alias, _ = e.MatchProxyRule("2001:db8::1", 0, "")
	if alias != "internal_v6" {
		t.Errorf("expected internal_v6, got %q", alias)
	}
}

func TestEngine_ProxyRulePort_Duplicate(t *testing.T) {
	path := writeTempRuleFile(t, "proxy port 80 first_proxy\nproxy port 80 second_proxy\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, matched := e.MatchProxyRule("", 80, "")
	if !matched || alias != "first_proxy" {
		t.Errorf("first rule should win, got %q (matched=%v)", alias, matched)
	}
}

func TestEngine_ProxyRuleIP_Duplicate(t *testing.T) {
	path := writeTempRuleFile(t, "proxy ip 8.8.8.8 first_proxy\nproxy ip 8.8.8.8 second_proxy\n")
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	alias, matched := e.MatchProxyRule("8.8.8.8", 0, "")
	if !matched || alias != "first_proxy" {
		t.Errorf("first rule should win, got %q (matched=%v)", alias, matched)
	}
}

func TestEngine_ProxyRule_MixedTypes(t *testing.T) {
	path := writeTempRuleFile(t, strings.TrimSpace(`
proxy port 22 ssh_proxy
proxy ip 172.16.0.1 internal_ip
proxy cidr 10.0.0.0/8 internal_cidr
proxy domain google.com google_proxy
proxy domain *.github.com gh_proxy
	`))
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	a, m := e.MatchProxyRule("", 22, "")
	if !m || a != "ssh_proxy" {
		t.Errorf("port 22: expected ssh_proxy, got %q (%v)", a, m)
	}

	a, m = e.MatchProxyRule("172.16.0.1", 0, "")
	if !m || a != "internal_ip" {
		t.Errorf("ip 172.16.0.1: expected internal_ip, got %q (%v)", a, m)
	}

	a, m = e.MatchProxyRule("10.255.255.255", 0, "")
	if !m || a != "internal_cidr" {
		t.Errorf("cidr 10/8: expected internal_cidr, got %q (%v)", a, m)
	}

	a, m = e.MatchProxyRule("", 0, "google.com")
	if !m || a != "google_proxy" {
		t.Errorf("domain google.com: expected google_proxy, got %q (%v)", a, m)
	}

	a, m = e.MatchProxyRule("", 0, "api.github.com")
	if !m || a != "gh_proxy" {
		t.Errorf("domain *.github.com: expected gh_proxy, got %q (%v)", a, m)
	}

	_, m = e.MatchProxyRule("8.8.8.8", 443, "example.com")
	if m {
		t.Error("unmatched target should not trigger proxy")
	}
}

func TestEngine_ProxyRules_Complete(t *testing.T) {
	path := writeTempRuleFile(t, strings.TrimSpace(`
proxy port 22 ssh_proxy
proxy ip 8.8.8.8 direct
proxy cidr 10.0.0.0/8 internal
proxy domain google.com google_proxy
proxy domain *.github.com gh_proxy
	`))
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	rules := e.ProxyRules()
	if len(rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rules))
	}

	expected := []struct{ typ, alias string }{
		{"port", "ssh_proxy"},
		{"ip", "direct"},
		{"cidr", "internal"},
		{"domain", "google_proxy"},
		{"domain", "gh_proxy"},
	}
	for i, exp := range expected {
		if rules[i].Type != exp.typ || rules[i].Alias != exp.alias {
			t.Errorf("rule[%d]: expected %s→%s, got %s→%s",
				i, exp.typ, exp.alias, rules[i].Type, rules[i].Alias)
		}
	}
}

func TestEngine_ProxyRuleWildcardDomain_Priority(t *testing.T) {

	path := writeTempRuleFile(t, strings.TrimSpace(`
proxy domain *.com general
proxy domain *.example.com specific
	`))
	e, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	alias, matched := e.MatchProxyRule("", 0, "api.example.com")
	if !matched || alias != "specific" {
		t.Errorf("expected specific, got %q (matched=%v)", alias, matched)
	}

	alias, matched = e.MatchProxyRule("", 0, "other.com")
	if !matched || alias != "general" {
		t.Errorf("expected general for non-example.com, got %q (matched=%v)", alias, matched)
	}
}

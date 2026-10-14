package adblock

import "testing"

func TestParseDomainAndExceptions(t *testing.T) {
	rules, stats, err := Parse("||ads.example^\n@@||safe.ads.example^\n127.0.0.1 tracker.test\n")
	if err != nil { t.Fatal(err) }
	if stats.Accepted != 3 || stats.Exceptions != 1 { t.Fatalf("unexpected stats: %+v", stats) }
	set := NewSet(rules)
	for _, d := range []string{"ads.example", "x.ads.example"} {
		if !set.Blocked(d) { t.Errorf("%s should be blocked", d) }
	}
	if set.Blocked("safe.ads.example") || set.Blocked("x.safe.ads.example") { t.Fatal("exception should override parent block") }
	if set.Blocked("example") { t.Fatal("parent domain should not be blocked") }
}

func TestParseSkipsUnsupportedAndLocal(t *testing.T) {
	_, stats, err := Parse("||ads.example^\n||ads.example^$third-party\n127.0.0.1 localhost\n")
	if err != nil { t.Fatal(err) }
	if stats.Ignored != 2 { t.Fatalf("ignored=%d", stats.Ignored) }
}

func TestParseRejectsEmptyOrUnsupported(t *testing.T) {
	if _, _, err := Parse("! comment only"); err == nil { t.Fatal("expected empty list error") }
	if _, _, err := Parse("||example.com^$dnsrewrite=NOERROR"); err == nil { t.Fatal("expected unsupported-only list error") }
}

func BenchmarkSet_Blocked_100k(b *testing.B) {
	rules := make([]Rule, 100000)
	for i := range rules { rules[i] = Rule{Domain: "ads" + itoa(i) + ".example"} }
	set := NewSet(rules)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ { set.Blocked("x.ads99999.example") }
}

func itoa(n int) string {
	if n == 0 { return "0" }
	var b [20]byte
	i := len(b)
	for n > 0 { i--; b[i] = byte('0' + n%10); n /= 10 }
	return string(b[i:])
}

package chnroute

import (
	"math/rand"
	"net"
	"net/netip"
	"testing"
)

func TestTrieBasic(t *testing.T) {
	tr := New()
	if !tr.IsEmpty() {
		t.Fatal("expected empty trie")
	}

	prefix := netip.MustParsePrefix("192.168.1.0/24")
	tr.Insert(prefix)
	if tr.IsEmpty() {
		t.Fatal("expected non-empty trie after insert")
	}
	if tr.Count() != 1 {
		t.Fatalf("expected 1, got %d", tr.Count())
	}

	if !tr.Contains(net.ParseIP("192.168.1.1")) {
		t.Fatal("expected 192.168.1.1 to match 192.168.1.0/24")
	}
	if tr.Contains(net.ParseIP("192.168.2.1")) {
		t.Fatal("expected 192.168.2.1 NOT to match 192.168.1.0/24")
	}
}

func TestTrieMultiplePrefixes(t *testing.T) {
	prefixes := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"192.168.1.0/24",
		"8.8.8.0/24",
	}

	tr := New()
	for _, p := range prefixes {
		tr.Insert(netip.MustParsePrefix(p))
	}
	if tr.Count() != len(prefixes) {
		t.Fatalf("expected %d, got %d", len(prefixes), tr.Count())
	}

	tests := []struct {
		ip    string
		match bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.15.0.1", false},
		{"192.168.0.1", true},
		{"192.168.1.1", true},
		{"192.168.2.1", true},
		{"192.169.0.1", false},
		{"8.8.8.8", true},
		{"8.8.9.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := tr.Contains(ip); got != tt.match {
			t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.match)
		}
	}
}

func TestTrieOverlappingPrefixes(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("10.0.0.0/8"))
	tr.Insert(netip.MustParsePrefix("10.1.0.0/16"))
	tr.Insert(netip.MustParsePrefix("10.1.1.0/24"))

	if !tr.Contains(net.ParseIP("10.0.0.1")) {
		t.Fatal("10.0.0.1 should match 10.0.0.0/8")
	}
	if !tr.Contains(net.ParseIP("10.1.0.1")) {
		t.Fatal("10.1.0.1 should match")
	}
	if !tr.Contains(net.ParseIP("10.1.1.1")) {
		t.Fatal("10.1.1.1 should match")
	}
	if tr.Contains(net.ParseIP("11.0.0.1")) {
		t.Fatal("11.0.0.1 should NOT match")
	}
}

func TestTrieIPv6(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("2001:db8::/32"))
	tr.Insert(netip.MustParsePrefix("2001:db8:1::/48"))
	tr.Insert(netip.MustParsePrefix("fe80::/10"))

	if tr.Count() != 3 {
		t.Fatalf("expected 3, got %d", tr.Count())
	}

	if !tr.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("2001:db8::1 should match 2001:db8::/32")
	}
	if !tr.Contains(net.ParseIP("2001:db8:1::1")) {
		t.Fatal("2001:db8:1::1 should match")
	}
	if tr.Contains(net.ParseIP("2001:db9::1")) {
		t.Fatal("2001:db9::1 should NOT match")
	}
	if !tr.Contains(net.ParseIP("fe80::1")) {
		t.Fatal("fe80::1 should match fe80::/10")
	}
}

func TestTrieHostPrefix(t *testing.T) {
	tr := New()

	tr.Insert(netip.MustParsePrefix("1.2.3.4/32"))
	if tr.Count() != 1 {
		t.Fatalf("expected 1, got %d", tr.Count())
	}

	if !tr.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("1.2.3.4 should match /32")
	}
	if tr.Contains(net.ParseIP("1.2.3.5")) {
		t.Fatal("1.2.3.5 should NOT match /32")
	}
}

func TestTrieDefault(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("0.0.0.0/0"))
	if tr.Count() != 1 {
		t.Fatalf("expected 1, got %d", tr.Count())
	}

	if !tr.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("1.2.3.4 should match 0/0")
	}
	if !tr.Contains(net.ParseIP("255.255.255.255")) {
		t.Fatal("255.255.255.255 should match 0/0")
	}
}

func TestTrieNonZeroBitSplits(t *testing.T) {

	prefixes := []string{
		"1.0.1.0/24",
		"2.0.0.0/8",
		"3.0.0.0/8",
		"4.0.0.0/8",
	}
	tr := New()
	for _, p := range prefixes {
		tr.Insert(netip.MustParsePrefix(p))
	}

	tests := []struct {
		ip    string
		match bool
	}{
		{"1.0.1.0", true},
		{"1.0.1.55", true},
		{"1.0.2.0", false},
		{"2.0.0.5", true},
		{"3.3.3.3", true},
		{"4.0.0.1", true},
		{"5.5.5.5", false},
		{"8.8.8.8", false},
	}
	for _, tt := range tests {
		got := tr.Contains(net.ParseIP(tt.ip))
		if got != tt.match {
			t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.match)
		}
	}
}

func TestTrieNonZeroBitSplitsExtended(t *testing.T) {

	prefixes := []string{
		"1.0.1.0/24",
		"2.0.0.0/8",
		"3.0.0.0/8",
		"4.0.0.0/8",
		"5.0.0.0/8",
		"10.0.0.0/8",
		"11.0.0.0/8",
		"100.0.0.0/8",
		"114.0.0.0/8",
		"223.0.0.0/8",
	}
	tr := New()
	for _, p := range prefixes {
		tr.Insert(netip.MustParsePrefix(p))
	}

	if tr.Count() != len(prefixes) {
		t.Errorf("Count() = %d, want %d", tr.Count(), len(prefixes))
	}

	for _, p := range prefixes {
		prefix := netip.MustParsePrefix(p)
		ip := net.ParseIP(prefix.Addr().String())
		if !tr.Contains(ip) {
			t.Errorf("Contains(%s) = false, prefix %s should match itself", ip, p)
		}
	}
}

func TestTrieInsertBatchEquivalence(t *testing.T) {
	prefixes := []string{
		"1.0.1.0/24", "2.0.0.0/8", "3.0.0.0/8", "4.0.0.0/8",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"192.168.1.0/24", "8.8.8.0/24", "223.0.0.0/8",
		"2001:db8::/32", "2001:db8:1::/48", "fe80::/10",
	}

	var pfxList []netip.Prefix
	for _, s := range prefixes {
		pfxList = append(pfxList, netip.MustParsePrefix(s))
	}

	t1 := New()
	t1.InsertBatch(pfxList)

	t2 := New()
	for _, p := range pfxList {
		t2.Insert(p)
	}

	if t1.Count() != t2.Count() {
		t.Errorf("Count mismatch: InsertBatch=%d Insert=%d", t1.Count(), t2.Count())
	}

	for _, p := range pfxList {
		ip := net.ParseIP(p.Addr().String())
		r1 := t1.Contains(ip)
		r2 := t2.Contains(ip)
		if r1 != r2 {
			t.Errorf("Contains(%s): InsertBatch=%v Insert=%v", ip, r1, r2)
		}
	}

	randomIPs := []string{
		"1.0.1.55", "2.3.4.5", "8.8.8.8", "10.255.255.255",
		"172.31.0.1", "192.168.100.1", "223.255.255.1",
		"2001:db8::1", "2001:db9::1", "fe80::1",
		"1.1.1.1", "114.114.114.114",
	}
	for _, ip := range randomIPs {
		r1 := t1.Contains(net.ParseIP(ip))
		r2 := t2.Contains(net.ParseIP(ip))
		if r1 != r2 {
			t.Errorf("Random IP %s: InsertBatch=%v Insert=%v", ip, r1, r2)
		}
	}
}

func TestTrieMixedAddressFamily(t *testing.T) {
	prefixes := []string{
		"10.0.0.0/8",
		"192.168.0.0/16",
		"2001:db8::/32",
		"8.8.8.0/24",
		"fe80::/10",
		"172.16.0.0/12",
		"::1/128",
	}
	tr := New()
	for _, p := range prefixes {
		tr.Insert(netip.MustParsePrefix(p))
	}

	tests := []struct {
		ip    string
		match bool
	}{

		{"10.0.0.1", true},
		{"192.168.0.1", true},
		{"172.16.0.1", true},
		{"8.8.8.8", true},

		{"2001:db8::1", true},
		{"fe80::1", true},
		{"::1", true},

		{"11.0.0.1", false},
		{"2001:db9::1", false},
		{"8.8.9.1", false},
	}
	for _, tt := range tests {
		got := tr.Contains(net.ParseIP(tt.ip))
		if got != tt.match {
			t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.match)
		}
	}
}

func TestTrieDuplicateInsert(t *testing.T) {
	tr := New()
	p := netip.MustParsePrefix("10.0.0.0/8")
	tr.Insert(p)
	tr.Insert(p)

	if tr.Count() != 1 {
		t.Errorf("Count after duplicate = %d, want 1", tr.Count())
	}
	if !tr.Contains(net.ParseIP("10.0.0.1")) {
		t.Error("10.0.0.1 should still match after duplicate insert")
	}
}

func TestTrieReverseOrderInsert(t *testing.T) {
	prefixes := []string{
		"1.0.1.0/24", "2.0.0.0/8", "3.0.0.0/8", "4.0.0.0/8",
		"10.0.0.0/8", "100.0.0.0/8", "200.0.0.0/8",
	}

	t1 := New()
	for _, s := range prefixes {
		t1.Insert(netip.MustParsePrefix(s))
	}

	t2 := New()
	for i := len(prefixes) - 1; i >= 0; i-- {
		t2.Insert(netip.MustParsePrefix(prefixes[i]))
	}

	if t1.Count() != t2.Count() {
		t.Errorf("Count: forward=%d reverse=%d", t1.Count(), t2.Count())
	}

	testIPs := []string{
		"1.0.1.0", "1.0.1.55", "1.0.2.0",
		"2.0.0.5", "3.3.3.3", "4.4.4.4",
		"10.0.0.1", "100.100.100.100", "200.200.200.200",
		"5.5.5.5", "8.8.8.8",
	}
	for _, ip := range testIPs {
		r1 := t1.Contains(net.ParseIP(ip))
		r2 := t2.Contains(net.ParseIP(ip))
		if r1 != r2 {
			t.Errorf("Reverse order mismatch for %s: forward=%v reverse=%v", ip, r1, r2)
		}
	}
}

func TestTrieLargeInsertBatch(t *testing.T) {
	var pfxList []netip.Prefix

	bases := []string{
		"1.0.0.0/8", "2.0.0.0/8", "4.0.0.0/8", "8.0.0.0/8",
		"10.0.0.0/8", "14.0.0.0/8", "27.0.0.0/8", "36.0.0.0/8",
		"42.0.0.0/8", "49.0.0.0/8", "58.0.0.0/8", "60.0.0.0/8",
		"101.0.0.0/8", "110.0.0.0/8", "112.0.0.0/8", "113.0.0.0/8",
		"114.0.0.0/8", "115.0.0.0/8", "116.0.0.0/8", "118.0.0.0/8",
		"120.0.0.0/8", "122.0.0.0/8", "123.0.0.0/8", "124.0.0.0/8",
		"202.0.0.0/8", "210.0.0.0/8", "218.0.0.0/8", "220.0.0.0/8",
		"222.0.0.0/8", "223.0.0.0/8",
	}
	for _, b := range bases {
		pfxList = append(pfxList, netip.MustParsePrefix(b))
	}

	subPrefixes := []string{
		"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16",
		"114.114.0.0/16", "114.114.114.0/24",
		"192.168.0.0/16", "192.168.1.0/24", "192.168.2.0/24",
		"172.16.0.0/12", "172.16.0.0/16",
	}
	for _, s := range subPrefixes {
		pfxList = append(pfxList, netip.MustParsePrefix(s))
	}

	ipv6Prefixes := []string{
		"2001:250::/35", "2001:250:2000::/35", "2001:251::/32",
		"2001:db8::/32", "2001:db8:1::/48",
		"fe80::/10", "2400::/12", "240e::/16",
	}
	for _, s := range ipv6Prefixes {
		pfxList = append(pfxList, netip.MustParsePrefix(s))
	}

	tr := New()
	tr.InsertBatch(pfxList)

	if tr.IsEmpty() {
		t.Fatal("trie should not be empty")
	}

	for _, p := range pfxList {
		ip := net.ParseIP(p.Addr().String())
		if !tr.Contains(ip) {
			t.Errorf("Contains(%s) = false, prefix %s should match itself", ip, p)
		}
	}

	foreign := []string{
		"128.0.0.1", "129.0.0.1", "208.67.222.222",
		"2001:4860::1", "2606:4700::1",
	}
	for _, ip := range foreign {
		if tr.Contains(net.ParseIP(ip)) {
			t.Errorf("Contains(%s) = true, should not match (foreign IP)", ip)
		}
	}
}

func TestTriePull(t *testing.T) {
	tr1 := New()
	tr1.Insert(netip.MustParsePrefix("10.0.0.0/8"))

	tr2 := New()
	tr2.Insert(netip.MustParsePrefix("192.168.0.0/16"))

	tr1.Pull(tr2)
	if tr1.Contains(net.ParseIP("10.0.0.1")) {
		t.Error("after Pull, tr1 should NOT contain 10.0.0.0/8")
	}
	if !tr1.Contains(net.ParseIP("192.168.0.1")) {
		t.Error("after Pull, tr1 should contain 192.168.0.0/16")
	}

	if !tr2.Contains(net.ParseIP("192.168.0.1")) {
		t.Error("after Pull, tr2 should still contain 192.168.0.0/16")
	}

}

func TestTrieEmptyEdge(t *testing.T) {
	tr := New()

	if !tr.IsEmpty() {
		t.Error("new trie should be empty")
	}
	if tr.Count() != 0 {
		t.Errorf("empty trie Count = %d, want 0", tr.Count())
	}

	if tr.Contains(net.ParseIP("1.2.3.4")) {
		t.Error("empty trie should not contain any IP")
	}
	if tr.Contains(nil) {
		t.Error("empty trie should not contain nil IP")
	}

	tr.InsertBatch(nil)
	if !tr.IsEmpty() {
		t.Error("InsertBatch(nil) should leave trie empty")
	}

	tr.InsertBatch([]netip.Prefix{})
	if !tr.IsEmpty() {
		t.Error("InsertBatch([]) should leave trie empty")
	}

	tr.Insert(netip.MustParsePrefix("0.0.0.0/0"))
	if tr.Contains(net.ParseIP("1.2.3.4")) {

	}
	if !tr.Contains(net.ParseIP("255.255.255.255")) {
		t.Error("0/0 should match everything")
	}
}

func TestTrieUnsortedInsertion(t *testing.T) {

	prefixes := []string{
		"1.0.1.0/24",
		"2001:250::/35",
		"1.0.2.0/23",
		"10.0.0.0/8",
		"2001:251::/32",
		"1.0.8.0/21",
		"192.168.0.0/16",
		"2001:250:2000::/35",
		"114.114.114.0/24",
		"172.16.0.0/12",
		"223.5.5.0/24",
		"fe80::/10",
	}

	tr := New()
	for _, p := range prefixes {
		tr.Insert(netip.MustParsePrefix(p))
	}

	tests := []struct {
		ip    string
		match bool
	}{
		{"1.0.1.0", true},
		{"1.0.2.0", true},
		{"1.0.8.0", true},
		{"1.0.16.0", false},
		{"10.0.0.1", true},
		{"114.114.114.114", true},
		{"223.5.5.5", true},
		{"192.168.0.1", true},
		{"172.16.0.1", true},
		{"2001:250::1", true},
		{"2001:251::1", true},
		{"2001:250:2000::1", true},
		{"fe80::1", true},

		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:db8::1", false},
	}
	for _, tt := range tests {
		got := tr.Contains(net.ParseIP(tt.ip))
		if got != tt.match {
			t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.match)
		}
	}
}

func TestTrieContainsRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	rawPrefixes := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"1.0.1.0/24", "1.0.2.0/23", "4.0.0.0/8", "5.0.0.0/8",
		"100.0.0.0/8", "114.0.0.0/8", "223.0.0.0/8",
		"2001:db8::/32", "fe80::/10",
	}

	var prefixes []netip.Prefix
	for _, s := range rawPrefixes {
		prefixes = append(prefixes, netip.MustParsePrefix(s))
	}

	tr := New()
	tr.InsertBatch(prefixes)

	linearMatch := func(ip net.IP) bool {
		for _, p := range prefixes {
			if p.Contains(mustNetIPToAddr(ip)) {
				return true
			}
		}
		return false
	}

	for i := 0; i < 100; i++ {
		ip := make(net.IP, 4)
		ip[0] = byte(rng.Intn(256))
		ip[1] = byte(rng.Intn(256))
		ip[2] = byte(rng.Intn(256))
		ip[3] = byte(rng.Intn(256))

		trieResult := tr.Contains(ip)
		linearResult := linearMatch(ip)

		if trieResult != linearResult {
			t.Errorf("Random IP %s: trie=%v linear=%v", ip, trieResult, linearResult)
		}
	}
}

func mustNetIPToAddr(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		addr, _ = netip.AddrFromSlice(ip.To4())
	}
	return addr
}

func TestTrieLongestPrefixMatch(t *testing.T) {

	tr := New()
	tr.Insert(netip.MustParsePrefix("10.0.0.0/8"))
	tr.Insert(netip.MustParsePrefix("10.1.0.0/16"))
	tr.Insert(netip.MustParsePrefix("10.1.1.0/24"))

	if !tr.Contains(net.ParseIP("10.1.1.1")) {
		t.Error("10.1.1.1 should match (longest prefix)")
	}

	if !tr.Contains(net.ParseIP("10.1.2.1")) {
		t.Error("10.1.2.1 should match 10.1.0.0/16")
	}

	if !tr.Contains(net.ParseIP("10.2.0.1")) {
		t.Error("10.2.0.1 should match 10.0.0.0/8")
	}

	tr2 := New()
	tr2.Insert(netip.MustParsePrefix("192.168.1.0/24"))
	tr2.Insert(netip.MustParsePrefix("192.168.0.0/16"))

	if !tr2.Contains(net.ParseIP("192.168.1.1")) {
		t.Error("192.168.1.1 should match")
	}
	if !tr2.Contains(net.ParseIP("192.168.2.1")) {
		t.Error("192.168.2.1 should match 192.168.0.0/16")
	}
}

func BenchmarkTrieContains(b *testing.B) {
	tr := New()

	prefixes := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21",
		"14.0.0.0/8", "27.0.0.0/8", "36.0.0.0/8",
		"42.0.0.0/8", "49.0.0.0/8", "58.0.0.0/8",
		"60.0.0.0/8", "101.0.0.0/8", "110.0.0.0/8",
		"111.0.0.0/8", "112.0.0.0/8", "113.0.0.0/8",
		"114.0.0.0/8", "115.0.0.0/8", "116.0.0.0/8",
		"117.0.0.0/8", "118.0.0.0/8", "119.0.0.0/8",
		"120.0.0.0/8", "121.0.0.0/8", "122.0.0.0/8",
		"123.0.0.0/8", "124.0.0.0/8", "125.0.0.0/8",
		"202.0.0.0/8", "210.0.0.0/8", "218.0.0.0/8",
		"220.0.0.0/8", "222.0.0.0/8", "223.0.0.0/8",
	}
	for _, p := range prefixes {
		tr.Insert(netip.MustParsePrefix(p))
	}

	ips := []net.IP{
		net.ParseIP("10.0.0.1"),
		net.ParseIP("8.8.8.8"),
		net.ParseIP("192.168.1.1"),
		net.ParseIP("1.2.3.4"),
		net.ParseIP("202.96.0.1"),
		net.ParseIP("35.1.0.1"),
		net.ParseIP("223.255.255.1"),
		net.ParseIP("123.123.123.123"),
	}

	b.ResetTimer()
	for b.Loop() {
		for _, ip := range ips {
			tr.Contains(ip)
		}
	}
}

func BenchmarkTrieInsert(b *testing.B) {
	prefixes := make([]netip.Prefix, b.N)
	for i := range prefixes {
		prefixes[i] = netip.MustParsePrefix("10.0.0.0/8")
	}

	b.ResetTimer()
	for b.Loop() {
		tr := New()
		tr.Insert(prefixes[0])
	}
}

func BenchmarkTrieInsertBatch(b *testing.B) {

	raw := []string{
		"1.0.1.0/24", "2.0.0.0/8", "3.0.0.0/8", "4.0.0.0/8",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"8.8.8.0/24", "114.0.0.0/8", "223.0.0.0/8",
		"2001:db8::/32", "fe80::/10",
	}
	var pfx []netip.Prefix
	for _, s := range raw {
		pfx = append(pfx, netip.MustParsePrefix(s))
	}

	b.ResetTimer()
	for b.Loop() {
		tr := New()
		tr.InsertBatch(pfx)
	}
}

func TestTrieCountV4V6(t *testing.T) {
	tr := New()
	prefixes := []string{
		"10.0.0.0/8",
		"192.168.0.0/16",
		"8.8.8.0/24",
		"2001:db8::/32",
		"fe80::/10",
		"::1/128",
	}
	for _, p := range prefixes {
		tr.Insert(netip.MustParsePrefix(p))
	}

	if v4 := tr.CountV4(); v4 != 3 {
		t.Errorf("expected 3 v4 prefixes, got %d", v4)
	}
	if v6 := tr.CountV6(); v6 != 3 {
		t.Errorf("expected 3 v6 prefixes, got %d", v6)
	}
	if total := tr.Count(); total < 6 {
		t.Errorf("expected at least 6 nodes, got %d", total)
	}
}

func TestTrieCountV4V6_Empty(t *testing.T) {
	tr := New()
	if v4 := tr.CountV4(); v4 != 0 {
		t.Errorf("expected 0 v4, got %d", v4)
	}
	if v6 := tr.CountV6(); v6 != 0 {
		t.Errorf("expected 0 v6, got %d", v6)
	}
}

func TestTrieCountV4V6_OnlyV4(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("10.0.0.0/8"))
	tr.Insert(netip.MustParsePrefix("192.168.0.0/16"))
	if v4 := tr.CountV4(); v4 != 2 {
		t.Errorf("expected 2 v4, got %d", v4)
	}
	if v6 := tr.CountV6(); v6 != 0 {
		t.Errorf("expected 0 v6, got %d", v6)
	}
}

// A v4 aggregate sitting above a more-specific v4 prefix is still a loaded v4
// prefix and must be counted (leaf-only counting dropped it, so CountV4()+CountV6()
// no longer equalled Count()).
func TestTrieCountV4V6_NestedSameFamily(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("10.0.0.0/8"))    // aggregate ancestor
	tr.Insert(netip.MustParsePrefix("10.1.0.0/16"))   // leaf below it
	tr.Insert(netip.MustParsePrefix("2001:db8::/32")) // leaf
	if v4 := tr.CountV4(); v4 != 2 {
		t.Errorf("expected 2 v4 (incl. aggregate 10.0.0.0/8), got %d", v4)
	}
	if v6 := tr.CountV6(); v6 != 1 {
		t.Errorf("expected 1 v6, got %d", v6)
	}
	if total := tr.Count(); total != 3 {
		t.Errorf("expected Count()=3, got %d", total)
	}
}

// Cross-family nesting in the shared bit trie: a v4 prefix whose bit path a longer
// IPv6 prefix shares must still count as a v4 prefix (seen in real chnroute data:
// v4 36.x aggregates sit above 2400:: v6 entries). Ensures CountV4()+CountV6()==Count().
func TestTrieCountV4V6_NestedCrossFamily(t *testing.T) {
	tr := New()
	tr.Insert(netip.MustParsePrefix("36.0.16.0/20")) // shares bit path with the v6 below
	tr.Insert(netip.MustParsePrefix("2400:1000::/32"))
	if v4 := tr.CountV4(); v4 != 1 {
		t.Errorf("expected 1 v4 (36.0.16.0/20), got %d", v4)
	}
	if v6 := tr.CountV6(); v6 != 1 {
		t.Errorf("expected 1 v6, got %d", v6)
	}
	if total := tr.Count(); total != 2 {
		t.Errorf("expected Count()=2, got %d", total)
	}
}

func TestTrieCountV4V6_SumEqualsCount(t *testing.T) {
	tr := New()
	for _, p := range []string{
		"10.0.0.0/8", "10.1.0.0/16", "36.0.16.0/20", "2400:1000::/32",
		"192.168.0.0/16", "2001:db8::/32", "fe80::/10", "::1/128",
	} {
		tr.Insert(netip.MustParsePrefix(p))
	}
	if v4, v6, total := tr.CountV4(), tr.CountV6(), tr.Count(); v4+v6 != total {
		t.Errorf("CountV4()+CountV6()=%d+%d != Count()=%d", v4, v6, total)
	}
}

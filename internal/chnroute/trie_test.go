package chnroute

import (
	"math/rand"
	"net"
	"net/netip"
	"os"
	"testing"
)

// sink 接住被测函数的返回值。没有它,编译器可以把「结果没人用」的调用整个优化掉,
// 于是 AllocsPerRun 量到的是空循环的 0 分配 —— 门禁会假绿。
var sink bool

// testdataChnroute 是仓库里真实下发的那份 chnroute(android assets,10k+ 前缀,
// 由 CI 每月更新)。基准与分配门禁都跑它,不跑手写的小表:前缀条数决定树的深度、
// 分支和缓存局部性,在 36 条前缀上量出来的 ns/op 比真实值低一个数量级,拿它做
// 回归对比没有意义。
const testdataChnroute = "../../android/app/src/main/assets/chnroute.txt"

func loadTestdataTrie(tb testing.TB) *Trie {
	tb.Helper()
	tr, err := Load(testdataChnroute)
	if err != nil {
		tb.Fatalf("load %s: %v", testdataChnroute, err)
	}
	// 空树会让基准和门禁静默通过(恒 false、零分配),必须显式失败。
	if tr.IsEmpty() {
		tb.Fatalf("%s contains no prefixes", testdataChnroute)
	}
	return tr
}

// benchProbes 从真实 chnroute 里派生命中地址(前半段取 v4、后半段取 v6),再混入
// 一组境外地址作为未命中样本。命中/未命中各占一半:全部命中会只测到树的一侧,
// 而真实流量里境外目标(未命中)同样常见。
func benchProbes(tb testing.TB) []net.IP {
	tb.Helper()
	data, err := os.ReadFile(testdataChnroute)
	if err != nil {
		tb.Fatalf("read %s: %v", testdataChnroute, err)
	}
	prefixes, err := parsePrefixes(data)
	if err != nil {
		tb.Fatalf("parse %s: %v", testdataChnroute, err)
	}

	var probes []net.IP
	// 按跨度取样而不是取前 N 条:表里前段集中在小网段,只取开头会让探针全落在树的
	// 一侧,量不到真实分布。
	const wantPerFamily = 4
	for _, v4 := range []bool{true, false} {
		stride := len(prefixes) / (wantPerFamily * 2)
		if stride < 1 {
			stride = 1
		}
		taken := 0
		for i := 0; i < len(prefixes) && taken < wantPerFamily; i += stride {
			p := prefixes[i]
			if p.Addr().Is4() != v4 {
				continue
			}
			probes = append(probes, net.IP(p.Masked().Addr().AsSlice()))
			taken++
		}
	}
	// 境外未命中样本:公共 DNS / CDN / 大门户,都是真实流量里会出现的目标。
	for _, s := range []string{
		"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",
		"151.101.1.69", "91.198.174.192", "23.1.36.10", "104.16.132.229",
		"2606:4700:4700::1111", "2001:4860:4860::8888",
	} {
		if ip := net.ParseIP(s); ip != nil {
			probes = append(probes, ip)
		}
	}
	if len(probes) == 0 {
		tb.Fatal("no probes derived from chnroute testdata")
	}
	return probes
}

// BenchmarkTrieContains 量的是「一次域名/IP 分流判定」的成本 —— 它在每个 TUN/SOCKS5
// 包、每次 DNS 应答记录上都会走,是这条流水线上最热的纯计算函数。
func BenchmarkTrieContains(b *testing.B) {
	tr := loadTestdataTrie(b)
	probes := benchProbes(b)
	b.ReportAllocs()
	b.ResetTimer()
	// 一轮一次查找:b.Loop() 把总耗时除以 b.N,旧版一轮做 8 次查找,等于把 ns/op
	// 报大 8 倍,跟任何单次查找的基线都没法比。
	i := 0
	for b.Loop() {
		sink = tr.Contains(probes[i])
		i++
		if i == len(probes) {
			i = 0
		}
	}
}

// BenchmarkTrieContainsParallel 走并发路径:快照是 atomic.Pointer 读的,真实运行
// 时有多个入口(TUN / SOCKS5 / UDP / DNS)同时查表,单线程基准测不到这条。
func BenchmarkTrieContainsParallel(b *testing.B) {
	tr := loadTestdataTrie(b)
	probes := benchProbes(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			sink = tr.Contains(probes[i])
			i++
			if i == len(probes) {
				i = 0
			}
		}
	})
}

// TestContainsNoAlloc 是分配门禁:Contains 在热路径上,每次多一次堆分配就是每包
// 一次 GC 压力。§6.4 修掉的正是 addrBytes 把 As4/As16 的数组切片返回导致数组逃逸
// (1 alloc/op),这条测试把「不许再退化」钉在 CI 上。
func TestContainsNoAlloc(t *testing.T) {
	tr := loadTestdataTrie(t)
	probes := benchProbes(t)

	cases := []struct {
		name string
		ip   net.IP
	}{
		{"domestic hit", probes[0]},
		{"foreign miss", net.ParseIP("8.8.8.8")},
		{"ipv6 miss", net.ParseIP("2606:4700:4700::1111")},
	}
	for _, tc := range cases {
		ip := tc.ip
		if ip == nil {
			t.Fatalf("%s: nil probe", tc.name)
		}
		if avg := testing.AllocsPerRun(200, func() { sink = tr.Contains(ip) }); avg != 0 {
			t.Errorf("Contains(%s) allocates %v objects per call, want 0", tc.name, avg)
		}
	}
}

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

func TestTrie_CrossFamilyPrefixCollision(t *testing.T) {
	// Regression test: IPv4 36.0.0.0/8 (0x24) must never match IPv6 2404:6800:: (0x24) or 2400::/8.
	tr := New()
	tr.Insert(netip.MustParsePrefix("36.0.0.0/8"))
	tr.Insert(netip.MustParsePrefix("2408:8000::/20")) // China Unicom IPv6

	if !tr.Contains(net.ParseIP("36.1.2.3")) {
		t.Error("IPv4 36.1.2.3 should match 36.0.0.0/8")
	}
	if !tr.Contains(net.ParseIP("2408:8459:3c20::1")) {
		t.Error("IPv6 2408:8459:3c20::1 should match 2408:8000::/20")
	}
	if tr.Contains(net.ParseIP("2404:6800:4012:2::200e")) {
		t.Error("Foreign Google IPv6 2404:6800:... must NOT match IPv4 36.0.0.0/8")
	}
	if tr.Contains(net.ParseIP("2400:8905::2000:6bff:fe22:d426")) {
		t.Error("Foreign Linode IPv6 2400:8905:... must NOT match IPv4 36.0.0.0/8")
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

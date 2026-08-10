package dns

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/netutil"
	"smartproxy/internal/rules"
	"smartproxy/internal/upstream"
)

func TestCache_GetMiss(t *testing.T) {
	c := NewCache(100, 60*time.Second)
	if got := c.Get("example.com", dns.TypeA); got != nil {
		t.Error("expected nil for cache miss")
	}
}

func TestCache_GetHit(t *testing.T) {
	c := NewCache(100, 60*time.Second)
	c.Set("example.com", dns.TypeA, []byte{1, 2, 3}, 10*time.Second)

	got := c.Get("example.com", dns.TypeA)
	if string(got) != "\x01\x02\x03" {
		t.Errorf("expected [1,2,3], got %v", got)
	}
}

func TestCache_DifferentQtype(t *testing.T) {
	c := NewCache(100, 60*time.Second)
	c.Set("example.com", dns.TypeA, []byte{1}, 10*time.Second)

	if got := c.Get("example.com", dns.TypeAAAA); got != nil {
		t.Error("AAAA should miss when only A is cached")
	}
	if got := c.Get("example.com", dns.TypeA); got == nil {
		t.Error("A should hit")
	}
}

func TestCache_DifferentQname(t *testing.T) {
	c := NewCache(100, 60*time.Second)
	c.Set("example.com", dns.TypeA, []byte{1}, 10*time.Second)

	if got := c.Get("other.com", dns.TypeA); got != nil {
		t.Error("different qname should miss")
	}
}

func TestCache_Expired(t *testing.T) {
	c := NewCache(100, 1*time.Millisecond)
	c.Set("example.com", dns.TypeA, []byte{1, 2, 3}, 1*time.Millisecond)

	time.Sleep(5 * time.Millisecond)

	if got := c.Get("example.com", dns.TypeA); got != nil {
		t.Error("expected nil for expired cache entry")
	}
	if c.Len() != 0 {
		t.Error("expired entry should be removed")
	}
}

func TestCache_DefaultTTL(t *testing.T) {
	c := NewCache(100, 60*time.Second)
	c.Set("example.com", dns.TypeA, []byte{1}, 0)

	if got := c.Get("example.com", dns.TypeA); got == nil {
		t.Error("expected hit with default TTL")
	}
}

func TestCache_Eviction(t *testing.T) {
	c := NewCache(2, 60*time.Second)
	c.Set("a.com", dns.TypeA, []byte{1}, 60*time.Second)
	c.Set("b.com", dns.TypeA, []byte{2}, 60*time.Second)
	c.Set("c.com", dns.TypeA, []byte{3}, 60*time.Second)

	if c.Len() != 2 {
		t.Errorf("expected 2 entries after eviction, got %d", c.Len())
	}

	if got := c.Get("c.com", dns.TypeA); got == nil {
		t.Error("newest entry should survive eviction")
	}
}

func TestCache_Len(t *testing.T) {
	c := NewCache(100, 60*time.Second)
	if c.Len() != 0 {
		t.Error("new cache should be empty")
	}
	c.Set("a.com", dns.TypeA, []byte{1}, 10*time.Second)
	c.Set("b.com", dns.TypeA, []byte{2}, 10*time.Second)
	if c.Len() != 2 {
		t.Errorf("expected 2, got %d", c.Len())
	}
}

func TestCache_SetUpdate(t *testing.T) {
	c := NewCache(100, 60*time.Second)
	c.Set("example.com", dns.TypeA, []byte{1}, 10*time.Second)
	c.Set("example.com", dns.TypeA, []byte{9, 9, 9}, 10*time.Second)

	got := c.Get("example.com", dns.TypeA)
	if string(got) != "\x09\x09\x09" {
		t.Error("update should overwrite previous value")
	}
	if c.Len() != 1 {
		t.Error("same key should not increase count")
	}
}

func TestParseHostPort_Empty(t *testing.T) {
	host, port := netutil.ParseHostPort("", 53)
	if host != "" || port != 53 {
		t.Errorf("empty: expected ('', 53), got (%q, %d)", host, port)
	}
}

func TestParseHostPort_PlainHost(t *testing.T) {
	host, port := netutil.ParseHostPort("8.8.8.8", 53)
	if host != "8.8.8.8" || port != 53 {
		t.Errorf("plain: expected ('8.8.8.8', 53), got (%q, %d)", host, port)
	}
}

func TestParseHostPort_IPv4WithPort(t *testing.T) {
	host, port := netutil.ParseHostPort("8.8.8.8:5353", 53)
	if host != "8.8.8.8" || port != 5353 {
		t.Errorf("expected ('8.8.8.8', 5353), got (%q, %d)", host, port)
	}
}

func TestParseHostPort_IPv6WithBrackets(t *testing.T) {
	host, port := netutil.ParseHostPort("[2001:db8::1]:5353", 53)
	if host != "2001:db8::1" || port != 5353 {
		t.Errorf("expected ('2001:db8::1', 5353), got (%q, %d)", host, port)
	}
}

func TestParseHostPort_IPv6WithBracketsNoPort(t *testing.T) {
	host, port := netutil.ParseHostPort("[2001:db8::1]", 53)
	if host != "2001:db8::1" || port != 53 {
		t.Errorf("expected ('2001:db8::1', 53), got (%q, %d)", host, port)
	}
}

func TestParseHostPort_IPv6NoBrackets(t *testing.T) {

	host, port := netutil.ParseHostPort("2001:db8::1", 53)

	if port != 1 {
		t.Errorf("expected port 1 (final segment parsed as port), got %d", port)
	}
	if host != "2001:db8:" {
		t.Errorf("expected host '2001:db8:', got %q", host)
	}
}

func TestParseHostPort_DomainWithPort(t *testing.T) {
	host, port := netutil.ParseHostPort("dns.example.com:5353", 53)
	if host != "dns.example.com" || port != 5353 {
		t.Errorf("expected ('dns.example.com', 5353), got (%q, %d)", host, port)
	}
}

func TestParseHostPort_OpenBracketOnly(t *testing.T) {
	host, port := netutil.ParseHostPort("[2001:db8::1", 53)

	if host != "[2001:db8::1" || port != 53 {
		t.Errorf("expected ('[2001:db8::1', 53), got (%q, %d)", host, port)
	}
}

func TestExtractIP_A(t *testing.T) {
	rr := &dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.ParseIP("1.2.3.4")}
	if got := extractIP(rr); got != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %q", got)
	}
}

func TestExtractIP_AAAA(t *testing.T) {
	rr := &dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}, AAAA: net.ParseIP("2001:db8::1")}
	if got := extractIP(rr); got != "2001:db8::1" {
		t.Errorf("expected '2001:db8::1', got %q", got)
	}
}

func TestExtractIP_OtherType(t *testing.T) {
	rr := &dns.CNAME{Hdr: dns.RR_Header{Rrtype: dns.TypeCNAME}}
	if got := extractIP(rr); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestEncodeSOCKS5Addr_IPv4(t *testing.T) {
	atyp, addr := encodeSOCKS5Addr("1.2.3.4")
	if atyp != 0x01 {
		t.Errorf("expected atyp 0x01, got 0x%02x", atyp)
	}
	if len(addr) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(addr))
	}
}

func TestEncodeSOCKS5Addr_IPv6(t *testing.T) {
	atyp, addr := encodeSOCKS5Addr("2001:db8::1")
	if atyp != 0x04 {
		t.Errorf("expected atyp 0x04, got 0x%02x", atyp)
	}
	if len(addr) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(addr))
	}
}

func TestEncodeSOCKS5Addr_Domain(t *testing.T) {
	atyp, addr := encodeSOCKS5Addr("example.com")
	if atyp != 0x03 {
		t.Errorf("expected atyp 0x03, got 0x%02x", atyp)
	}
	if addr[0] != 11 {
		t.Errorf("expected length byte 11, got %d", addr[0])
	}
	if string(addr[1:]) != "example.com" {
		t.Errorf("expected 'example.com', got %q", string(addr[1:]))
	}
}

func buildTestDNSQuery(domain string, qtype uint16) []byte {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true
	wire, _ := msg.Pack()
	return wire
}

func TestBuildFakeResponse(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	query := buildTestDNSQuery("blocked.com", dns.TypeA)
	resp := h.buildFakeResponse(query)

	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}

	if !msg.Response {
		t.Error("expected response flag set")
	}
	if len(msg.Answer) == 0 {
		t.Fatal("expected at least one answer")
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected A record")
	}
	if a.A.String() != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0, got %s", a.A.String())
	}
}

func TestBuildFakeResponse_BadWire(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	resp := h.buildFakeResponse([]byte{0x00, 0x01})
	if string(resp) != "\x00\x01" {
		t.Error("expected original wire for invalid input")
	}
}

func makeDNSResponseWithA(domain string, ip string, ttl uint32) []byte {
	msg := new(dns.Msg)
	msg.SetReply(new(dns.Msg))
	msg.Question = []dns.Question{{Name: dns.Fqdn(domain), Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	}
	msg.Answer = append(msg.Answer, rr)
	wire, _ := msg.Pack()
	return wire
}

func makeDNSResponseWithAAAA(domain string, ip string, ttl uint32) []byte {
	msg := new(dns.Msg)
	msg.SetReply(new(dns.Msg))
	msg.Question = []dns.Question{{Name: dns.Fqdn(domain), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}
	rr := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: net.ParseIP(ip),
	}
	msg.Answer = append(msg.Answer, rr)
	wire, _ := msg.Pack()
	return wire
}

func TestIsDNSClean_EmptyChnroute(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	resp := makeDNSResponseWithA("example.com", "8.8.8.8", 60)
	if !h.isDNSClean(resp) {
		t.Error("empty chnroute should always return clean")
	}
}

func TestIsDNSClean_DomesticIP(t *testing.T) {
	cn := chnroute.New()

	cn.Insert(netip.MustParsePrefix("1.1.1.0/24"))

	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	resp := makeDNSResponseWithA("example.com", "1.1.1.1", 60)
	if !h.isDNSClean(resp) {
		t.Error("domestic IP should be clean")
	}
}

func TestIsDNSClean_ForeignIP(t *testing.T) {
	cn := chnroute.New()
	cn.Insert(netip.MustParsePrefix("1.1.1.0/24"))

	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	resp := makeDNSResponseWithA("example.com", "8.8.8.8", 60)
	if h.isDNSClean(resp) {
		t.Error("foreign IP should be polluted")
	}
}

func TestIsDNSClean_ForeignIPv6(t *testing.T) {
	cn := chnroute.New()
	cn.Insert(netip.MustParsePrefix("2400:3200::/32"))

	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	resp := makeDNSResponseWithAAAA("example.com", "2001:4860:4860::8888", 60)
	if h.isDNSClean(resp) {
		t.Error("foreign IPv6 should be polluted")
	}
}

func TestIsDNSClean_BadWire(t *testing.T) {
	cn := chnroute.New()
	cn.Insert(netip.MustParsePrefix("1.1.1.0/24"))

	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	if h.isDNSClean([]byte{0x00}) {
		t.Error("bad wire should return false")
	}
}

func TestApplyIPPreference_Disabled(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	resp := makeDNSResponseWithA("example.com", "10.0.0.1", 60)
	result, cached := h.applyIPPreference(context.Background(), resp, "example.com")

	if string(resp) != string(result) {
		t.Error("disabled preference should return original response unchanged")
	}
	if cached {
		t.Error("disabled preference should not return cacheable result")
	}
}

func TestIsDNSCleanAndPrefer(t *testing.T) {
	cn := chnroute.New()
	cn.Insert(netip.MustParsePrefix("10.0.0.0/8"))

	// IP preference disabled: domestic response → clean, returned as-is, not cached
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)
	resp := makeDNSResponseWithA("example.com", "10.0.0.1", 60)
	out, cached, clean := h.isDNSCleanAndPrefer(context.Background(), resp, "example.com")
	if !clean {
		t.Error("domestic response should be clean")
	}
	if cached {
		t.Error("preference disabled should not be cacheable")
	}
	if string(out) != string(resp) {
		t.Error("should return original response when preference disabled")
	}

	// Polluted response (foreign IP, not in chnroute 10/8) → not clean
	respForeign := makeDNSResponseWithA("evil.com", "8.8.8.8", 60)
	_, _, clean = h.isDNSCleanAndPrefer(context.Background(), respForeign, "evil.com")
	if clean {
		t.Error("foreign IP response should be flagged polluted")
	}
}

func TestHandler_Enabled(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)
	if !h.Enabled() {
		t.Error("expected enabled")
	}

	h2 := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, false)
	if h2.Enabled() {
		t.Error("expected disabled")
	}
}

func TestNewHandler(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(200, 120, "8.8.8.8:53", "[2001:4860:4860::8888]:53", cn, nil, 5, "0.0.0.0", "::", false, PreferNone, nil, true)

	cfg := h.cfg.Load()
	if cfg.foreignIPv4 != "8.8.8.8" || cfg.foreignIPv4Port != 53 {
		t.Errorf("wrong foreign IPv4: %s:%d", cfg.foreignIPv4, cfg.foreignIPv4Port)
	}
	if cfg.foreignIPv6 != "2001:4860:4860::8888" || cfg.foreignIPv6Port != 53 {
		t.Errorf("wrong foreign IPv6: %s:%d", cfg.foreignIPv6, cfg.foreignIPv6Port)
	}
	if cfg.queryTimeout != 5*time.Second {
		t.Errorf("wrong timeout: %v", cfg.queryTimeout)
	}
	if cfg.blockedIP != "0.0.0.0" {
		t.Errorf("wrong blocked IP: %s", cfg.blockedIP)
	}
	if h.cache == nil {
		t.Error("cache is nil")
	}
	if h.cache.Len() != 0 {
		t.Error("cache should be empty")
	}
}

func TestParseSpeedCheckMode_Empty(t *testing.T) {
	mode, ports := ParseSpeedCheckMode("")
	if mode != PreferNone || ports != nil {
		t.Errorf("empty: expected (PreferNone, nil), got (%q, %v)", mode, ports)
	}
}

func TestParseSpeedCheckMode_Ping(t *testing.T) {
	mode, ports := ParseSpeedCheckMode("ping")
	if mode != PreferPing || ports != nil {
		t.Errorf("expected (PreferPing, nil), got (%q, %v)", mode, ports)
	}
}

func TestParseSpeedCheckMode_PingCaseInsensitive(t *testing.T) {
	tests := []string{"PING", "Ping", " Ping "}
	for _, s := range tests {
		mode, _ := ParseSpeedCheckMode(s)
		if mode != PreferPing {
			t.Errorf("%q: expected PreferPing, got %q", s, mode)
		}
	}
}

func TestParseSpeedCheckMode_TCP(t *testing.T) {
	mode, ports := ParseSpeedCheckMode("tcp:80")
	if mode != PreferTCP || len(ports) != 1 || ports[0] != 80 {
		t.Errorf("expected (PreferTCP, [80]), got (%q, %v)", mode, ports)
	}
}

func TestParseSpeedCheckMode_TCPMultiple(t *testing.T) {
	_, ports := ParseSpeedCheckMode("tcp:80,443,8080")
	if len(ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(ports))
	}
}

func TestParseSpeedCheckMode_TCPInvalidSkipped(t *testing.T) {
	_, ports := ParseSpeedCheckMode("tcp:80,invalid,443")
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Errorf("expected [80, 443], got %v", ports)
	}
}

func TestParseSpeedCheckMode_TCPInvalidPorts(t *testing.T) {
	tests := []string{"tcp:0", "tcp:99999", "tcp:", "tcp:invalid"}
	for _, s := range tests {
		mode, ports := ParseSpeedCheckMode(s)
		if mode != PreferNone || ports != nil {
			t.Errorf("%q: expected (PreferNone, nil), got (%q, %v)", s, mode, ports)
		}
	}
}

func TestParseSpeedCheckMode_Invalid(t *testing.T) {
	mode, ports := ParseSpeedCheckMode("invalid")
	if mode != PreferNone || ports != nil {
		t.Errorf("expected (PreferNone, nil), got (%q, %v)", mode, ports)
	}
}

func TestFmtSscanf(t *testing.T) {
	var p int
	n := fmtSscanf("80", &p)
	if n != 1 || p != 80 {
		t.Errorf("expected (1, 80), got (%d, %d)", n, p)
	}
	n = fmtSscanf(" 443 ", &p)
	if n != 1 || p != 443 {
		t.Errorf("expected (1, 443), got (%d, %d)", n, p)
	}
	n = fmtSscanf("invalid", &p)
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
	n = fmtSscanf("", &p)
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestPreferIPs_Disabled(t *testing.T) {
	p := &Preference{enabled: false}
	got := p.PreferIPs(context.Background(), []string{"10.0.0.1", "10.0.0.2"})
	if got != "" {
		t.Errorf("disabled should return empty, got %q", got)
	}
}

func TestPreferIPs_SingleIP(t *testing.T) {
	p := &Preference{enabled: true}
	got := p.PreferIPs(context.Background(), []string{"10.0.0.1"})
	if got != "10.0.0.1" {
		t.Errorf("single IP should be returned, got %q", got)
	}
}

func TestPreferIPs_Empty(t *testing.T) {
	p := &Preference{enabled: true}
	got := p.PreferIPs(context.Background(), []string{})
	if got != "" {
		t.Errorf("empty list should return empty, got %q", got)
	}
}

func TestPreferIPs_UnknownMode(t *testing.T) {

	p := &Preference{enabled: true, mode: "unknown"}
	got := p.PreferIPs(context.Background(), []string{"10.0.0.1", "10.0.0.2"})
	if got != "" {
		t.Errorf("unknown mode with no probes should return empty, got %q", got)
	}
}

func TestPreferModeConstants(t *testing.T) {
	if PreferNone != "" {
		t.Error("PreferNone should be empty string")
	}
	if PreferPing != "ping" {
		t.Error("PreferPing should be 'ping'")
	}
	if PreferTCP != "tcp" {
		t.Error("PreferTCP should be 'tcp'")
	}
}

func TestHandler_IsDomestic(t *testing.T) {
	cn := chnroute.New()
	cn.Insert(netip.MustParsePrefix("10.0.0.0/8"))

	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	tests := []struct {
		ip     string
		expect bool
	}{
		{"10.1.2.3", true},
		{"8.8.8.8", false},
		{"192.168.1.1", false},
		{"invalid", false},
		{"", false},
	}
	for _, tt := range tests {
		got := h.IsDomestic(tt.ip)
		if got != tt.expect {
			t.Errorf("IsDomestic(%q) = %v, want %v", tt.ip, got, tt.expect)
		}
	}
}

func TestBuildSERVFAIL(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	query := buildTestDNSQuery("example.com", dns.TypeA)
	resp := h.buildSERVFAIL(query)

	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatalf("failed to unpack SERVFAIL response: %v", err)
	}
	if !msg.Response {
		t.Error("expected response flag set")
	}
	if msg.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL (%d), got %d", dns.RcodeServerFailure, msg.Rcode)
	}
	if len(msg.Answer) != 0 {
		t.Errorf("expected no answers in SERVFAIL, got %d", len(msg.Answer))
	}
}

func TestBuildSERVFAIL_BadWire(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	resp := h.buildSERVFAIL([]byte{0x00, 0x01})
	if string(resp) != "\x00\x01" {
		t.Error("expected original wire for invalid input")
	}
}

// TestHandleDNS_ForeignFailureAnswersSERVFAIL drives the direct-foreign path (an
// empty chnroute makes every target non-domestic) through a dead proxy, asserting
// the handler answers SERVFAIL — bounded by the configured queryTimeout — instead
// of returning nil and letting the client hang.
func TestHandleDNS_ForeignFailureAnswersSERVFAIL(t *testing.T) {
	mgr, err := upstream.NewManager(upstream.UpstreamConfig{
		Default: "failover",
		Proxies: []upstream.ProxyEntry{
			{Alias: "dead", URL: "socks5://127.0.0.1:1081"},
		},
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, mgr, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	query := buildTestDNSQuery("example.com", dns.TypeA)
	start := time.Now()
	resp := h.HandleDNS(context.Background(), query, "8.8.8.8", 53, nil)
	elapsed := time.Since(start)
	if elapsed > 4*time.Second {
		t.Errorf("foreign fallback exceeded queryTimeout budget: %v", elapsed)
	}
	if resp == nil {
		t.Fatal("expected SERVFAIL response, got nil")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if msg.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL (%d), got %d", dns.RcodeServerFailure, msg.Rcode)
	}
}

func TestHandleDNS_Disabled(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, false)

	query := buildTestDNSQuery("example.com", dns.TypeA)
	resp := h.HandleDNS(context.Background(), query, "8.8.8.8", 53, nil)
	if resp != nil {
		t.Error("disabled handler should return nil")
	}
}

func TestHandleDNS_InvalidWire(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	resp := h.HandleDNS(context.Background(), []byte{0x00}, "8.8.8.8", 53, nil)
	if resp != nil {
		t.Error("invalid wire should return nil")
	}
}

func makeEngine(t *testing.T, aclContent string) *rules.Engine {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "acl-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(aclContent); err != nil {
		tmpFile.Close()
		t.Fatalf("write temp file: %v", err)
	}
	tmpFile.Close()

	engine, err := rules.New(tmpFile.Name())
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	return engine
}

func TestHandleDNS_DomainBlocked(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "127.0.0.1", "::", false, PreferNone, nil, true)

	engine := makeEngine(t, "block domain blocked.com\n")
	query := buildTestDNSQuery("blocked.com", dns.TypeA)
	resp := h.HandleDNS(context.Background(), query, "8.8.8.8", 53, engine)

	if resp == nil {
		t.Fatal("expected fake response for blocked domain")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if len(msg.Answer) == 0 {
		t.Fatal("expected answer in blocked response")
	}
	a := msg.Answer[0].(*dns.A)
	if a.A.String() != "127.0.0.1" {
		t.Errorf("expected blocked IP 127.0.0.1, got %s", a.A.String())
	}
}

func TestHandleDNS_QnameNormalization(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "127.0.0.1", "::", false, PreferNone, nil, true)

	engine := makeEngine(t, "block domain mixedcase.com\n")
	query := buildTestDNSQuery("MixedCase.com", dns.TypeA)

	resp := h.HandleDNS(context.Background(), query, "8.8.8.8", 53, engine)
	if resp == nil {
		t.Error("block should match case-insensitively")
	}
}

func TestHandleDNS_BlockBeforeCache(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "10.0.0.1", "::", false, PreferNone, nil, true)

	engine := makeEngine(t, "block domain cached.com\n")

	h.CacheSet("cached.com", dns.TypeA, []byte{1, 2, 3}, 60*time.Second)

	query := buildTestDNSQuery("cached.com", dns.TypeA)
	resp := h.HandleDNS(context.Background(), query, "8.8.8.8", 53, engine)

	if resp == nil {
		t.Fatal("expected response")
	}
	msg := new(dns.Msg)
	msg.Unpack(resp)
	a := msg.Answer[0].(*dns.A)
	if a.A.String() != "10.0.0.1" {
		t.Errorf("domain block should override cache, got %s", a.A.String())
	}
}

func TestHandler_CacheGetSet(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	if h.CacheGet("test.com", dns.TypeA) != nil {
		t.Error("cache should be empty")
	}
	h.CacheSet("test.com", dns.TypeA, []byte{5, 6, 7}, 10*time.Second)
	if h.CacheGet("test.com", dns.TypeA) == nil {
		t.Error("cache should have entry after set")
	}
}

func TestHandler_BuildFakeResponse(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	query := buildTestDNSQuery("test.com", dns.TypeA)
	resp := h.BuildFakeResponse(query)

	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if !msg.Response {
		t.Error("expected response")
	}
}

func TestHandler_IsDNSClean(t *testing.T) {
	cn := chnroute.New()
	cn.Insert(netip.MustParsePrefix("1.1.1.0/24"))

	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	clean := makeDNSResponseWithA("test.com", "1.1.1.1", 60)
	if !h.IsDNSClean(clean) {
		t.Error("should be clean")
	}
	polluted := makeDNSResponseWithA("test.com", "8.8.8.8", 60)
	if h.IsDNSClean(polluted) {
		t.Error("should be polluted")
	}
}

func TestHandler_QueryUDP_InvalidHost(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 1, "0.0.0.0", "::", false, PreferNone, nil, true)

	query := buildTestDNSQuery("example.com", dns.TypeA)

	_, err := h.QueryUDP(context.Background(), query, "255.255.255.255", 5353)
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

func TestBuildTestDNSQuery(t *testing.T) {
	query := buildTestDNSQuery("example.com", dns.TypeA)
	msg := new(dns.Msg)
	if err := msg.Unpack(query); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	qname := strings.TrimSuffix(msg.Question[0].Name, ".")
	qname = strings.ToLower(qname)
	if qname != "example.com" {
		t.Errorf("expected 'example.com', got %q", qname)
	}
	if msg.Question[0].Qtype != dns.TypeA {
		t.Errorf("expected TypeA, got %d", msg.Question[0].Qtype)
	}
}

func TestMakeDNSResponse(t *testing.T) {
	resp := makeDNSResponseWithA("example.com", "1.2.3.4", 300)
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
	a := msg.Answer[0].(*dns.A)
	if a.A.String() != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", a.A.String())
	}
	if a.Hdr.Ttl != 300 {
		t.Errorf("expected TTL 300, got %d", a.Hdr.Ttl)
	}
}

func TestCache_Clear(t *testing.T) {
	c := NewCache(100, 60*time.Second)
	c.Set("a.com", dns.TypeA, []byte{1}, 10*time.Second)
	c.Set("b.com", dns.TypeAAAA, []byte{2}, 10*time.Second)
	if c.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", c.Len())
	}

	c.Clear()
	if c.Len() != 0 {
		t.Errorf("expected 0 after Clear, got %d", c.Len())
	}
	if got := c.Get("a.com", dns.TypeA); got != nil {
		t.Error("expected nil after Clear")
	}
}

func TestCache_ClearEmpty(t *testing.T) {
	c := NewCache(100, 60*time.Second)
	c.Clear() // should not panic
	if c.Len() != 0 {
		t.Errorf("expected 0, got %d", c.Len())
	}
}

func TestCache_ClearThenReuse(t *testing.T) {
	c := NewCache(100, 60*time.Second)
	c.Set("a.com", dns.TypeA, []byte{1}, 10*time.Second)
	c.Clear()
	c.Set("b.com", dns.TypeA, []byte{2}, 10*time.Second)
	if c.Len() != 1 {
		t.Errorf("expected 1 after clear+set, got %d", c.Len())
	}
	if got := c.Get("b.com", dns.TypeA); string(got) != "\x02" {
		t.Error("cache should work after Clear+Set")
	}
}

func TestStaticRecords_HandleDNS(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)
	h.SetStaticRecords(map[string][]net.IP{
		"smartproxy.lan": {net.ParseIP("192.168.1.1"), net.ParseIP("fc00::1")},
	})

	t.Run("A query returns IPv4 record", func(t *testing.T) {
		resp := h.HandleDNS(context.Background(), buildTestDNSQuery("smartproxy.lan", dns.TypeA), "8.8.8.8", 53, nil)
		msg := new(dns.Msg)
		if err := msg.Unpack(resp); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if !msg.Response || !msg.Authoritative {
			t.Errorf("expected authoritative response, resp=%v auth=%v", msg.Response, msg.Authoritative)
		}
		if len(msg.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
		}
		a, ok := msg.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("expected A record, got %T", msg.Answer[0])
		}
		if a.A.String() != "192.168.1.1" {
			t.Errorf("expected 192.168.1.1, got %s", a.A.String())
		}
		if a.Hdr.Ttl != staticRecordTTL {
			t.Errorf("expected TTL %d, got %d", staticRecordTTL, a.Hdr.Ttl)
		}
	})

	t.Run("AAAA query returns IPv6 record", func(t *testing.T) {
		resp := h.HandleDNS(context.Background(), buildTestDNSQuery("smartproxy.lan", dns.TypeAAAA), "8.8.8.8", 53, nil)
		msg := new(dns.Msg)
		if err := msg.Unpack(resp); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if len(msg.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
		}
		aaaa, ok := msg.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("expected AAAA record, got %T", msg.Answer[0])
		}
		if aaaa.AAAA.String() != "fc00::1" {
			t.Errorf("expected fc00::1, got %s", aaaa.AAAA.String())
		}
	})

	t.Run("ANY query returns both families", func(t *testing.T) {
		resp := h.HandleDNS(context.Background(), buildTestDNSQuery("smartproxy.lan", dns.TypeANY), "8.8.8.8", 53, nil)
		msg := new(dns.Msg)
		if err := msg.Unpack(resp); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		var v4, v6 int
		for _, rr := range msg.Answer {
			switch rr.(type) {
			case *dns.A:
				v4++
			case *dns.AAAA:
				v6++
			}
		}
		if v4 != 1 || v6 != 1 {
			t.Errorf("expected 1 A and 1 AAAA, got A=%d AAAA=%d", v4, v6)
		}
	})

	t.Run("other qtype returns NODATA", func(t *testing.T) {
		resp := h.HandleDNS(context.Background(), buildTestDNSQuery("smartproxy.lan", dns.TypeTXT), "8.8.8.8", 53, nil)
		msg := new(dns.Msg)
		if err := msg.Unpack(resp); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if !msg.Response {
			t.Error("expected response flag")
		}
		if len(msg.Answer) != 0 {
			t.Errorf("expected empty answer (NODATA), got %d", len(msg.Answer))
		}
	})
}

func TestStaticRecordAnswer(t *testing.T) {
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)

	if _, ok := h.StaticRecordAnswer(buildTestDNSQuery("smartproxy.lan", dns.TypeA)); ok {
		t.Error("expected miss when no static records are set")
	}

	h.SetStaticRecords(map[string][]net.IP{
		"smartproxy.lan": {net.ParseIP("192.168.1.1")},
	})

	wire, ok := h.StaticRecordAnswer(buildTestDNSQuery("smartproxy.lan", dns.TypeA))
	if !ok {
		t.Fatal("expected hit for smartproxy.lan")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(msg.Answer) != 1 || msg.Answer[0].Header().Rrtype != dns.TypeA {
		t.Errorf("expected 1 A answer, got %d", len(msg.Answer))
	}

	if _, ok := h.StaticRecordAnswer(buildTestDNSQuery("other.com", dns.TypeA)); ok {
		t.Error("expected miss for unknown domain")
	}
}

func TestStaticRecords_BeforeBlock(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "acl.txt")
	if err := os.WriteFile(rulePath, []byte("block domain evil.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := rules.New(rulePath)
	if err != nil {
		t.Fatal(err)
	}
	cn := chnroute.New()
	h := NewHandler(100, 60, "", "", cn, nil, 3, "0.0.0.0", "::", false, PreferNone, nil, true)
	h.SetStaticRecords(map[string][]net.IP{
		"evil.com": {net.ParseIP("192.168.1.1")},
	})

	resp := h.HandleDNS(context.Background(), buildTestDNSQuery("evil.com", dns.TypeA), "8.8.8.8", 53, engine)
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", msg.Answer[0])
	}
	if a.A.String() != "192.168.1.1" {
		t.Errorf("static record should win over block rule, got %s", a.A.String())
	}
}

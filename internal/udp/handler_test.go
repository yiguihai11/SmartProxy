package udp

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/config"
	"smartproxy/internal/dns"
	"smartproxy/internal/netutil"
	"smartproxy/internal/rules"
)

func TestParseTarget_IPv4(t *testing.T) {
	host, port := netutil.ParseHostPort("8.8.8.8", 53)
	if host != "8.8.8.8" {
		t.Errorf("host: got %q, want 8.8.8.8", host)
	}
	if port != 53 {
		t.Errorf("port: got %d, want 53", port)
	}
}

func TestParseTarget_IPv4WithPort(t *testing.T) {
	host, port := netutil.ParseHostPort("8.8.8.8:5353", 53)
	if host != "8.8.8.8" {
		t.Errorf("host: got %q", host)
	}
	if port != 5353 {
		t.Errorf("port: got %d", port)
	}
}

func TestParseTarget_IPv6(t *testing.T) {
	host, port := netutil.ParseHostPort("[::1]", 53)
	if host != "::1" {
		t.Errorf("host: got %q", host)
	}
	if port != 53 {
		t.Errorf("port: got %d", port)
	}
}

func TestParseTarget_IPv6WithPort(t *testing.T) {
	host, port := netutil.ParseHostPort("[2001:4860:4860::8888]:853", 53)
	if host != "2001:4860:4860::8888" {
		t.Errorf("host: got %q", host)
	}
	if port != 853 {
		t.Errorf("port: got %d", port)
	}
}

func TestParseTarget_Empty(t *testing.T) {
	host, port := netutil.ParseHostPort("", 53)
	if host != "" {
		t.Errorf("host: got %q, want empty", host)
	}
	if port != 53 {
		t.Errorf("port: got %d", port)
	}
}

func TestParseTarget_UnclosedBracket(t *testing.T) {
	host, port := netutil.ParseHostPort("[2001:db8::1", 53)
	if host != "[2001:db8::1" {
		t.Errorf("host should be returned as-is, got %q", host)
	}
	if port != 53 {
		t.Errorf("port should default to 53, got %d", port)
	}
}

func TestParseTarget_Domain(t *testing.T) {
	host, port := netutil.ParseHostPort("dns.google.com", 53)
	if host != "dns.google.com" {
		t.Errorf("host: got %q", host)
	}
	if port != 53 {
		t.Errorf("port: got %d", port)
	}
}

func TestBuildResponseHeader_IPv4(t *testing.T) {
	ip := "1.2.3.4"
	hdr := buildResponseHeader(ip, 443, net.ParseIP(ip))
	if len(hdr) != 10 {
		t.Errorf("expected 10 bytes for IPv4, got %d", len(hdr))
	}
	if hdr[0] != 0 || hdr[1] != 0 {
		t.Error("reserved bytes should be 0")
	}
	if hdr[2] != 0 {
		t.Error("frag should be 0")
	}
	if hdr[3] != 0x01 {
		t.Error("ATYP should be 0x01 (IPv4)")
	}

	port := int(hdr[8])<<8 | int(hdr[9])
	if port != 443 {
		t.Errorf("port: got %d, want 443", port)
	}
}

func TestBuildResponseHeader_IPv6(t *testing.T) {
	ip := "2001:db8::1"
	hdr := buildResponseHeader(ip, 53, net.ParseIP(ip))
	if len(hdr) != 22 {
		t.Errorf("expected 22 bytes for IPv6, got %d", len(hdr))
	}
	if hdr[3] != 0x04 {
		t.Error("ATYP should be 0x04 (IPv6)")
	}
}

func TestBuildResponseHeader_NilParsed(t *testing.T) {
	hdr := buildResponseHeader("8.8.8.8", 53, nil)
	if len(hdr) != 22 {
		t.Errorf("nil parsed should fallback to IPv6, got %d bytes", len(hdr))
	}
}

func TestIsPrivateIP_Private(t *testing.T) {
	tests := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"127.0.0.1",
		"::1",
		"fd00::1",
		"169.254.0.1",
	}
	for _, ip := range tests {
		if !isPrivateIP(ip) {
			t.Errorf("%s should be private", ip)
		}
	}
}

func TestIsPrivateIP_Public(t *testing.T) {
	tests := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
		"2001:4860:4860::8888",
	}
	for _, ip := range tests {
		if isPrivateIP(ip) {
			t.Errorf("%s should NOT be private", ip)
		}
	}
}

func TestIsPrivateIP_Invalid(t *testing.T) {
	if isPrivateIP("not.an.ip") {
		t.Error("invalid IP should not be private")
	}
	if isPrivateIP("") {
		t.Error("empty string should not be private")
	}
}

func TestExtractDNSQname_Valid(t *testing.T) {

	query := buildDNSQuery("example.com")
	qname := extractDNSQname(query)
	if qname != "example.com" {
		t.Errorf("got %q, want example.com", qname)
	}
}

func TestExtractDNSQname_MultiLabel(t *testing.T) {
	query := buildDNSQuery("www.google.com")
	qname := extractDNSQname(query)
	if qname != "www.google.com" {
		t.Errorf("got %q, want www.google.com", qname)
	}
}

func TestExtractDNSQname_Invalid(t *testing.T) {
	if got := extractDNSQname([]byte{0x00}); got != "" {
		t.Errorf("expected empty for invalid DNS data, got %q", got)
	}
	if got := extractDNSQname(nil); got != "" {
		t.Errorf("expected empty for nil, got %q", got)
	}
}

func buildDNSQuery(domain string) []byte {

	var b []byte

	b = append(b, 0x12, 0x34)
	b = append(b, 0x01, 0x00)
	b = append(b, 0x00, 0x01)
	b = append(b, 0x00, 0x00)
	b = append(b, 0x00, 0x00)
	b = append(b, 0x00, 0x00)

	parts := strings.Split(domain, ".")
	for _, part := range parts {
		b = append(b, byte(len(part)))
		b = append(b, []byte(part)...)
	}
	b = append(b, 0x00)
	b = append(b, 0x00, 0x01)
	b = append(b, 0x00, 0x01)

	return b
}

func TestNewHandler(t *testing.T) {

	h := NewHandler(nil, nil, nil, nil, nil, "127.0.0.1", nil, false, 0, config.SmartProxyQuicConf{})

	if h.chnroute != nil {
		t.Error("chnroute should be nil if passed nil")
	}
	if h.ruleEngine != nil {
		t.Error("ruleEngine should be nil if passed nil")
	}
	if h.upstreamMgr != nil {
		t.Error("upstreamMgr should be nil if passed nil")
	}
	if h.dnsHandler != nil {
		t.Error("dnsHandler should be nil if passed nil")
	}
	if h.clientIP != "127.0.0.1" {
		t.Errorf("clientIP: got %q, want 127.0.0.1", h.clientIP)
	}
	if h.conn != nil {
		t.Error("conn should be nil if passed nil")
	}
}

// TestHandleDNS_CacheHitRewritesTransactionID regression test:
// on a DNS cache hit, the returned response must rewrite the transaction ID to the current query's ID,
// otherwise strict DNS clients drop the response due to the ID mismatch, causing the lookup to time out.
func TestHandleDNS_CacheHitRewritesTransactionID(t *testing.T) {
	// Use a real DNS handler + cache, pre-seeded with an A response for v2ex.com with ID=0x1234
	dh := dns.NewHandler(100, 60, "", "", nil, nil, 3, "0.0.0.0", "::",
		false, dns.PreferNone, nil, true)

	cachedResp := new(mdns.Msg)
	cachedResp.SetQuestion("v2ex.com.", mdns.TypeA)
	cachedResp.Id = 0x1234 // the transaction ID in the cached response, different from the later query
	cachedResp.Answer = append(cachedResp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "v2ex.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
		A:   net.ParseIP("172.66.137.6"),
	})
	cachedWire, err := cachedResp.Pack()
	if err != nil {
		t.Fatalf("pack cached response: %v", err)
	}
	dh.CacheSet("v2ex.com", mdns.TypeA, cachedWire, 0)

	// The current query uses a different random ID
	query := new(mdns.Msg)
	query.SetQuestion("v2ex.com.", mdns.TypeA)
	query.Id = 0xABCD
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer client.Close()
	hConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen handler conn: %v", err)
	}
	defer hConn.Close()

	h := NewHandler(nil, nil, &rules.Engine{}, nil, dh, "127.0.0.1", hConn, true, 60*time.Second, config.SmartProxyQuicConf{})

	h.handleDNS(context.Background(), queryWire, client.LocalAddr(), "8.8.8.8", 53, "8.8.8.8", 53)

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	data := buf[:n]

	// Strip the SOCKS5 UDP header and take the DNS response payload
	if len(data) < 4 {
		t.Fatalf("response too short: %d bytes", len(data))
	}
	var payloadOffset int
	switch atyp := data[3]; atyp {
	case 0x01:
		payloadOffset = 4 + 4 + 2
	case 0x04:
		payloadOffset = 4 + 16 + 2
	case 0x03:
		if len(data) < 5 {
			t.Fatalf("domain response too short")
		}
		payloadOffset = 4 + 1 + int(data[4]) + 2
	default:
		t.Fatalf("unexpected address type %d", atyp)
	}
	if payloadOffset >= len(data) {
		t.Fatalf("payload offset %d out of range, len=%d", payloadOffset, len(data))
	}
	dnsResp := data[payloadOffset:]

	gotID := binary.BigEndian.Uint16(dnsResp[:2])
	if gotID != query.Id {
		t.Fatalf("response transaction ID = %#04x, want %#04x (current query ID); cached wire had %#04x",
			gotID, query.Id, cachedResp.Id)
	}

	// Confirm the answer is still the A record from the cache
	msg := new(mdns.Msg)
	if err := msg.Unpack(dnsResp); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if len(msg.Answer) == 0 {
		t.Fatalf("response has no answer")
	}
	a, ok := msg.Answer[0].(*mdns.A)
	if !ok || a.A.String() != "172.66.137.6" {
		t.Fatalf("unexpected answer: %v", msg.Answer)
	}
}

// startFakeDNSServer starts a local UDP DNS server: the response transaction ID is determined by idFn
// (pass identity for the correct ID, or id+1 for a mismatched ID), optionally including an A record.
func startFakeDNSServer(t *testing.T, idFn func(uint16) uint16, answer string) (*net.UDPAddr, func()) {
	t.Helper()
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen fake DNS server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, addr, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := new(mdns.Msg)
			if err := req.Unpack(buf[:n]); err != nil || len(req.Question) == 0 {
				continue
			}
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Id = idFn(req.Id)
			if answer != "" {
				resp.Answer = append(resp.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
					A:   net.ParseIP(answer),
				})
			}
			wire, err := resp.Pack()
			if err != nil {
				continue
			}
			srv.WriteToUDP(wire, addr)
		}
	}()
	stop := func() {
		srv.Close()
		<-done
	}
	return srv.LocalAddr().(*net.UDPAddr), stop
}

// TestHandleDNS_PrivatePathRejectsMismatchedID regression test:
// the private/LAN DNS direct-connect path must validate the response's transaction ID:
// when the server returns a response with a mismatched ID, the response must be dropped,
// and the client receives nothing (no forwarding, no caching).
func TestHandleDNS_PrivatePathRejectsMismatchedID(t *testing.T) {
	srvAddr, stop := startFakeDNSServer(t, func(id uint16) uint16 { return id + 1 }, "")
	defer stop()

	dh := dns.NewHandler(100, 60, "", "", chnroute.New(), nil, 3, "0.0.0.0", "::",
		false, dns.PreferNone, nil, true)

	query := new(mdns.Msg)
	query.SetQuestion("idtest.example.com.", mdns.TypeA)
	query.Id = 0xABCD
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer client.Close()
	hConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen handler conn: %v", err)
	}
	defer hConn.Close()

	h := NewHandler(chnroute.New(), nil, &rules.Engine{}, nil, dh, "127.0.0.1", hConn, true, 60*time.Second, config.SmartProxyQuicConf{})
	ip := srvAddr.IP.String()
	h.handleDNS(context.Background(), queryWire, client.LocalAddr(), ip, srvAddr.Port, ip, srvAddr.Port)

	client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 512)
	if _, _, err := client.ReadFrom(buf); err == nil {
		t.Fatalf("expected no response when DNS server returns mismatched transaction ID")
	}
}

// TestHandleDNS_PrivatePathAcceptsMatchingID positive case:
// when the private DNS returns a response with the correct ID, it should be forwarded to the client as normal,
// with the ID matching the query and the content being the answer record.
func TestHandleDNS_PrivatePathAcceptsMatchingID(t *testing.T) {
	srvAddr, stop := startFakeDNSServer(t, func(id uint16) uint16 { return id }, "1.2.3.4")
	defer stop()

	dh := dns.NewHandler(100, 60, "", "", chnroute.New(), nil, 3, "0.0.0.0", "::",
		false, dns.PreferNone, nil, true)

	query := new(mdns.Msg)
	query.SetQuestion("idtest.example.com.", mdns.TypeA)
	query.Id = 0xABCD
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer client.Close()
	hConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen handler conn: %v", err)
	}
	defer hConn.Close()

	h := NewHandler(chnroute.New(), nil, &rules.Engine{}, nil, dh, "127.0.0.1", hConn, true, 60*time.Second, config.SmartProxyQuicConf{})
	ip := srvAddr.IP.String()
	h.handleDNS(context.Background(), queryWire, client.LocalAddr(), ip, srvAddr.Port, ip, srvAddr.Port)

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	data := buf[:n]
	if len(data) < 10 {
		t.Fatalf("response too short: %d bytes", len(data))
	}
	if data[3] != 0x01 {
		t.Fatalf("unexpected address type %d", data[3])
	}
	dnsResp := data[10:]

	gotID := binary.BigEndian.Uint16(dnsResp[:2])
	if gotID != query.Id {
		t.Fatalf("response transaction ID = %#04x, want %#04x", gotID, query.Id)
	}
	msg := new(mdns.Msg)
	if err := msg.Unpack(dnsResp); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if len(msg.Answer) == 0 {
		t.Fatalf("response has no answer")
	}
	a, ok := msg.Answer[0].(*mdns.A)
	if !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("unexpected answer: %v", msg.Answer)
	}
}

// TestSetSocketBuffers smoke test: enlarging the UDP socket send/receive buffers should not error
// (sets SO_RCVBUF/SO_SNDBUF for real on Linux; no-op implementation on non-Linux).
func TestSetSocketBuffers(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := SetSocketBuffers(conn); err != nil {
		t.Fatalf("SetSocketBuffers: %v", err)
	}
}

// TestSessionKeyFor_Identity regression test: the session key must keep the same identity semantics as the old string key:
// the same (clientAddr, targetIP, targetPort) yields the same key; any differing component yields a different key.
func TestSessionKeyFor_Identity(t *testing.T) {
	base := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	const target = "8.8.8.8"
	const port = 53

	k1 := sessionKeyFor(base, target, port)
	if k2 := sessionKeyFor(base, target, port); k2 != k1 {
		t.Fatalf("same client+target should yield equal keys: %v vs %v", k1, k2)
	}
	if k := sessionKeyFor(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}, target, port); k == k1 {
		t.Fatalf("different client port should yield different key")
	}
	if k := sessionKeyFor(base, "9.9.9.9", port); k == k1 {
		t.Fatalf("different target should yield different key")
	}
	if k := sessionKeyFor(base, target, 443); k == k1 {
		t.Fatalf("different target port should yield different key")
	}
}

// TestSessionKeyFor_IPv6Zone regression test: the IPv6 zone must also participate in session identity,
// otherwise the same link-local address on different interfaces would be incorrectly merged into one session.
func TestSessionKeyFor_IPv6Zone(t *testing.T) {
	withZone := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 1234, Zone: "wlan0"}
	noZone := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 1234}
	if sessionKeyFor(withZone, "x", 1) == sessionKeyFor(noZone, "x", 1) {
		t.Fatalf("IPv6 zone must distinguish session keys")
	}
	sameZone := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 1234, Zone: "wlan0"}
	if sessionKeyFor(withZone, "x", 1) != sessionKeyFor(sameZone, "x", 1) {
		t.Fatalf("same zone+ip should yield equal keys")
	}
}

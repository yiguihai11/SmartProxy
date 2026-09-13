package route

import (
	"errors"
	"net"
	"testing"
	"time"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/upstream"
)

func TestBlacklist_AddAndCheck(t *testing.T) {
	b := NewBlacklist("test")
	if b.IsBlacklisted("example.com", 443) {
		t.Error("should not be blacklisted initially")
	}
	b.Add("example.com", 443, 10*time.Second, "connection refused")
	if !b.IsBlacklisted("example.com", 443) {
		t.Error("should be blacklisted after add")
	}
}

func TestBlacklist_Expired(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("example.com", 443, 1*time.Millisecond, "timeout")
	time.Sleep(10 * time.Millisecond)
	if b.IsBlacklisted("example.com", 443) {
		t.Error("should not be blacklisted after expiry")
	}
}

func TestBlacklist_DifferentPorts(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("example.com", 443, 10*time.Second, "reset")
	if b.IsBlacklisted("example.com", 80) {
		t.Error("different port should not match")
	}
	if !b.IsBlacklisted("example.com", 443) {
		t.Error("correct port should match")
	}
}

func TestBlacklist_DifferentHosts(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("example.com", 443, 10*time.Second, "dial failed")
	if b.IsBlacklisted("other.com", 443) {
		t.Error("different host should not match")
	}
}

func TestBlacklist_SnapshotCache(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("b.com", 443, time.Hour, "r1")
	b.Add("a.com", 443, time.Hour, "r2")
	// 结构性变更(Add)立即反映到快照,最近添加的 a.com 排前。
	e := b.Entries()
	if len(e) != 2 {
		t.Fatalf("want 2 entries, got %d", len(e))
	}
	if e[0].Host != "a.com" {
		t.Fatalf("want a.com (last added) first, got %s", e[0].Host)
	}
	// 无变更时快照稳定(两次 Entries 一致)。
	if e2 := b.Entries(); len(e2) != 2 {
		t.Fatalf("cached snapshot should stay consistent, got %d", len(e2))
	}
	// Remove 立即反映。
	b.Remove("b.com", 443)
	if e3 := b.Entries(); len(e3) != 1 || e3[0].Host != "a.com" {
		t.Fatalf("after remove want only a.com, got %d entries", len(e3))
	}
}

func TestBlacklist_SnapshotReorderAfterHit(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("a.com", 443, time.Hour, "r1")
	b.Add("b.com", 443, time.Hour, "r2")
	got := b.Entries()
	if got[0].Host != "b.com" {
		t.Fatalf("want b.com first initially, got %s", got[0].Host)
	}
	// 命中 a.com 刷新 lastHit;命中类变更经 hitRebuildInterval 节流后重建,a.com 置顶。
	if !b.IsBlacklisted("a.com", 443) {
		t.Fatal("a.com should be hit")
	}
	time.Sleep(hitRebuildInterval + 50*time.Millisecond)
	got = b.Entries()
	if got[0].Host != "a.com" {
		t.Fatalf("want a.com first after hit, got %s", got[0].Host)
	}
}

func TestBlacklist_CleanExpired(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("keep.com", 443, 10*time.Second, "timeout")
	b.Add("expire.com", 443, 1*time.Millisecond, "timeout")
	time.Sleep(10 * time.Millisecond)
	b.cleanExpired()
	if b.Len() != 1 {
		t.Errorf("expected 1 entry after cleanup, got %d", b.Len())
	}
	if b.IsBlacklisted("expire.com", 443) {
		t.Error("expired entry should be removed")
	}
	if !b.IsBlacklisted("keep.com", 443) {
		t.Error("non-expired entry should remain")
	}
}

func TestBlacklist_Len(t *testing.T) {
	b := NewBlacklist("test")
	if b.Len() != 0 {
		t.Error("new blacklist should be empty")
	}
	b.Add("a.com", 80, 10*time.Second, "test")
	b.Add("b.com", 80, 10*time.Second, "test")
	if b.Len() != 2 {
		t.Errorf("expected 2, got %d", b.Len())
	}
}

func TestBlacklist_Duplicate(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("example.com", 443, 5*time.Second, "first reason")
	b.Add("example.com", 443, 10*time.Second, "second reason")
	if b.Len() != 1 {
		t.Errorf("duplicate should update in place, got %d entries", b.Len())
	}
	if !b.IsBlacklisted("example.com", 443) {
		t.Error("should still be blacklisted")
	}
}

func TestBlacklist_EntriesIncludesReason(t *testing.T) {
	b := NewBlacklist("test")
	b.Add("example.com", 443, 10*time.Second, "connection refused")
	entries := b.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].LastReason != "connection refused" {
		t.Errorf("expected 'connection refused', got %q", entries[0].LastReason)
	}
	if entries[0].Host != "example.com" {
		t.Errorf("expected 'example.com', got %q", entries[0].Host)
	}
	if entries[0].Port != 443 {
		t.Errorf("expected 443, got %d", entries[0].Port)
	}
}

func TestSimplifyError_Timeout(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: &testTimeoutError{}}
	got := simplifyError(err, "1.2.3.4", 80)
	if got != "i/o timeout" {
		t.Errorf("expected 'i/o timeout', got %q", got)
	}
}

type testTimeoutError struct{}

func (e *testTimeoutError) Error() string   { return "mock timeout" }
func (e *testTimeoutError) Timeout() bool   { return true }
func (e *testTimeoutError) Temporary() bool { return true }

func TestSimplifyError_ConnectionRefused(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	got := simplifyError(err, "host", 80)
	if got != "connection refused" {
		t.Errorf("expected 'connection refused', got %q", got)
	}
}

func newRouter() *Router {
	cn := chnroute.New()
	mgr, _ := upstream.NewManager(upstream.UpstreamConfig{Default: "failover"})
	return New(cn, mgr, false, 3*time.Second, nil, 300*time.Second)
}

func TestRouter_IsDomesticByIP(t *testing.T) {
	r := newRouter()
	if r.IsDomesticByIP("") {
		t.Error("empty string should not be domestic")
	}
}

func TestRouter_BlacklistSnapshot(t *testing.T) {
	r := newRouter()
	r.domainBlacklist.Add("test.com", 443, 10*time.Second, "connection refused")
	ipEntries, domainEntries := r.BlacklistSnapshot()
	if len(ipEntries) != 0 {
		t.Error("ip blacklist should be empty")
	}
	if len(domainEntries) != 1 {
		t.Fatalf("expected 1 domain entry, got %d", len(domainEntries))
	}
	if domainEntries[0].LastReason != "connection refused" {
		t.Errorf("expected 'connection refused', got %q", domainEntries[0].LastReason)
	}
}

func TestRouter_AddToBlacklists_Domain(t *testing.T) {
	r := newRouter()
	r.addToBlacklists("1.2.3.4", 443, "example.com", "timeout")
	if !r.ipBlacklist.IsBlacklisted("1.2.3.4", 443) {
		t.Error("ip should be blacklisted")
	}
	if !r.domainBlacklist.IsBlacklisted("example.com", 443) {
		t.Error("domain should be blacklisted")
	}
}

func TestRouter_AddToBlacklists_NoDomain(t *testing.T) {
	r := newRouter()
	r.addToBlacklists("1.2.3.4", 80, "", "dial failed")
	if !r.ipBlacklist.IsBlacklisted("1.2.3.4", 80) {
		t.Error("ip should be blacklisted")
	}
}

func TestRouter_UpdateConfig(t *testing.T) {
	cn := chnroute.New()
	mgr, _ := upstream.NewManager(upstream.UpstreamConfig{Default: "failover"})
	r := New(cn, mgr, true, 3*time.Second, nil, 300*time.Second)

	cfg := r.cfg.Load()
	if cfg.smartTimeout != 3*time.Second {
		t.Errorf("expected 3s timeout, got %v", cfg.smartTimeout)
	}
	r.UpdateConfig(5*time.Second, 600*time.Second)
	cfg = r.cfg.Load()
	if cfg.smartTimeout != 5*time.Second {
		t.Errorf("expected 5s timeout after update, got %v", cfg.smartTimeout)
	}
}

// --- QUIC 黑洞自愈导出入口：判死回调写黑名单，路由侧再查（TUN/SOCKS5-UDP seam 共用） ---

func TestRouter_QuicBlacklistIP(t *testing.T) {
	r := newRouter()
	r.BlacklistIP("203.0.113.9", 443, "quic:no server reply within timeout")
	if !r.IsIPBlacklisted("203.0.113.9", 443) {
		t.Error("ip:443 should be blacklisted after QUIC death")
	}
	if r.IsIPBlacklisted("203.0.113.9", 80) {
		t.Error("different port must not match")
	}
	if r.IsIPBlacklisted("198.51.100.7", 443) {
		t.Error("different ip must not match")
	}
}

func TestRouter_QuicBlacklistDomain(t *testing.T) {
	r := newRouter()
	r.BlacklistDomain("video.example.com", 443, "quic:initial retransmission with no server reply")
	if !r.IsDomainBlacklisted("video.example.com", 443) {
		t.Error("domain:443 should be blacklisted after QUIC death")
	}
	if r.IsDomainBlacklisted("video.example.com", 80) {
		t.Error("different port must not match")
	}
	if r.IsDomainBlacklisted("other.example.com", 443) {
		t.Error("different domain must not match")
	}
}

func TestIsTLSClientHello(t *testing.T) {
	// 1. Valid TLS 1.2 ClientHello (50 bytes)
	validClientHello := []byte{
		0x16,       // ContentType: Handshake (22)
		0x03, 0x01, // Version: TLS 1.0 (Record layer outer version)
		0x00, 0x2d, // Record Length: 45 bytes payload
		0x01,             // HandshakeType: ClientHello (1)
		0x00, 0x00, 0x29, // HandshakeLength: 41 bytes
		0x03, 0x03, // ClientVersion: TLS 1.2
		// 32 bytes Random
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		0x00,                   // SessionID length: 0
		0x00, 0x02, 0x13, 0x01, // Cipher suites (len 2 + 1 suite)
		0x01, 0x00, // Compression methods (len 1 + null)
	}
	if !isTLSClientHello(validClientHello) {
		t.Error("validClientHello should be recognized as TLS ClientHello")
	}

	// 2. Truncated packet (< 44 bytes)
	if isTLSClientHello(validClientHello[:43]) {
		t.Error("truncated packet (< 44 bytes) must be rejected")
	}

	// 3. Malformed length attack (user review case: recordLen and hsLen exceed buffer)
	malformed := []byte{0x16, 0x03, 0x03, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff}
	if isTLSClientHello(malformed) {
		t.Error("malformed overflow record must be rejected")
	}

	// 4. recordLen claiming more bytes than packet carries
	exceedRecord := make([]byte, len(validClientHello))
	copy(exceedRecord, validClientHello)
	exceedRecord[3] = 0x01 // recordLen = 256 > 45
	if isTLSClientHello(exceedRecord) {
		t.Error("recordLen exceeding buffer length must be rejected")
	}

	// 5. hsLen claiming more bytes than record payload
	exceedHS := make([]byte, len(validClientHello))
	copy(exceedHS, validClientHello)
	exceedHS[8] = 0x30 // hsLen = 48 > recordLen-4 (41)
	if isTLSClientHello(exceedHS) {
		t.Error("hsLen exceeding record payload must be rejected")
	}

	// 6. Invalid SessionID length (> 32 bytes)
	badSessID := make([]byte, len(validClientHello))
	copy(badSessID, validClientHello)
	badSessID[43] = 33 // SessionID len 33 (RFC max is 32)
	if isTLSClientHello(badSessID) {
		t.Error("SessionID len > 32 must be rejected")
	}

	// 7. HTTP GET request
	httpGet := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if isTLSClientHello(httpGet) {
		t.Error("HTTP GET must not be recognized as TLS ClientHello")
	}

	// 8. HTTP POST request
	httpPost := []byte("POST /api/pay HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\n{\"amt\":100}")
	if isTLSClientHello(httpPost) {
		t.Error("HTTP POST must not be recognized as TLS ClientHello")
	}

	// 9. TLS Application Data (0x17) instead of Handshake (0x16)
	tlsAppData := make([]byte, len(validClientHello))
	copy(tlsAppData, validClientHello)
	tlsAppData[0] = 0x17 // Application Data
	if isTLSClientHello(tlsAppData) {
		t.Error("TLS Application Data must not be recognized as ClientHello")
	}

	// 10. TLS Handshake but ServerHello (0x02) instead of ClientHello (0x01)
	tlsServerHello := make([]byte, len(validClientHello))
	copy(tlsServerHello, validClientHello)
	tlsServerHello[5] = 0x02 // ServerHello
	if isTLSClientHello(tlsServerHello) {
		t.Error("TLS ServerHello must not be recognized as ClientHello")
	}

	// 11. Case A: Pipelined TLS Application Data following ClientHello (e.g. [ClientHello][AppData])
	pipelinedAppData := append(append([]byte(nil), validClientHello...), 0x17, 0x03, 0x03, 0x00, 0x05, 'H', 'E', 'L', 'L', 'O')
	if isTLSClientHello(pipelinedAppData) {
		t.Error("pipelined TLS Application Data must be rejected to prevent replay attacks")
	}

	// 12. Case B: Two pipelined ClientHello records ([ClientHello][ClientHello])
	pipelinedTwoRecords := append(append([]byte(nil), validClientHello...), validClientHello...)
	if isTLSClientHello(pipelinedTwoRecords) {
		t.Error("multiple pipelined TLS records must be rejected")
	}

	// 13. Case C: Single trailing junk byte after complete ClientHello record
	trailingByte := append(append([]byte(nil), validClientHello...), 0x00)
	if isTLSClientHello(trailingByte) {
		t.Error("packet with trailing byte after complete TLS record must be rejected")
	}

	// 14. Case D: Structurally valid TLS Extension framing (opaque experimental extension type 0xff00)
	// The extension payload itself is intentionally opaque because isTLSClientHello only validates record/handshake framing.
	// Extension framing: type=0xff00, len=0x0002, data=[0xaa, 0xbb]
	withExt := append([]byte(nil), validClientHello...)
	// Append 2-byte extensions vector length (6) + 2-byte type (0xff, 0x00) + 2-byte len (2) + 2-byte data
	withExt = append(withExt, 0x00, 0x06, 0xff, 0x00, 0x00, 0x02, 0xaa, 0xbb)
	// Update recordLen (was 45 -> 53 = 0x35)
	withExt[3] = 0x00
	withExt[4] = 0x35
	// Update hsLen (was 41 -> 49 = 0x31)
	withExt[6] = 0x00
	withExt[7] = 0x00
	withExt[8] = 0x31
	if !isTLSClientHello(withExt) {
		t.Error("valid ClientHello with structurally valid TLS extension framing should be accepted")
	}

	// 15. Case E: Extensions vector length claims more bytes than packet carries
	badVectorOverflow := append([]byte(nil), withExt...)
	badVectorOverflow[51] = 0x07 // extLen = 7 > 6 bytes remaining
	if isTLSClientHello(badVectorOverflow) {
		t.Error("extensions vector length overflow must be rejected")
	}

	// 16. Case F: Extensions vector length claims fewer bytes than packet carries (trailing bytes in record)
	badVectorUnderflow := append([]byte(nil), withExt...)
	badVectorUnderflow[51] = 0x05 // extLen = 5 < 6 bytes remaining
	if isTLSClientHello(badVectorUnderflow) {
		t.Error("extensions vector length underflow with trailing bytes must be rejected")
	}

	// 17. Case G: Individual extension data length claims more bytes than extension vector carries
	badExtDataLen := append([]byte(nil), withExt...)
	badExtDataLen[55] = 0x03 // extDataLen = 3 > 2 bytes remaining in vector
	if isTLSClientHello(badExtDataLen) {
		t.Error("individual extension data length overflow must be rejected")
	}

	// 18. Case H: Arbitrary opaque payload without valid extension structure (e.g. 0xaabbccdd)
	pseudoExt := append([]byte(nil), validClientHello...)
	pseudoExt = append(pseudoExt, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd)
	pseudoExt[3] = 0x00
	pseudoExt[4] = 0x33 // 51 bytes payload
	pseudoExt[6] = 0x00
	pseudoExt[7] = 0x00
	pseudoExt[8] = 0x2f // 47 bytes handshake
	if isTLSClientHello(pseudoExt) {
		t.Error("arbitrary payload without structurally valid extension headers must be rejected")
	}
}



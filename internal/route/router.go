package route

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"smartproxy/internal/safego"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/fwmark"
	"smartproxy/internal/netutil"
	"smartproxy/internal/rules"
	"smartproxy/internal/trace"
	"smartproxy/internal/upstream"
)

type routerConfig struct {
	smartTimeout time.Duration
	blacklistTTL time.Duration
}

type Router struct {
	cfg         atomic.Pointer[routerConfig]
	chnroute    *chnroute.Trie
	upstreamMgr *upstream.Manager

	domainBlacklist *Blacklist
	ipBlacklist     *Blacklist

	cleanupStopCh chan struct{}
	cleanupWg     sync.WaitGroup
}

func New(cn *chnroute.Trie, mgr *upstream.Manager,
	_ bool, smartTimeout time.Duration,
	_ []int, blacklistTTL time.Duration) *Router {

	r := &Router{
		chnroute:        cn,
		upstreamMgr:     mgr,
		domainBlacklist: NewBlacklist("domain"),
		ipBlacklist:     NewBlacklist("ip"),
	}
	r.cfg.Store(&routerConfig{
		smartTimeout: smartTimeout,
		blacklistTTL: blacklistTTL,
	})
	return r
}

func (r *Router) UpdateConfig(smartTimeout, blacklistTTL time.Duration) {
	r.cfg.Store(&routerConfig{
		smartTimeout: smartTimeout,
		blacklistTTL: blacklistTTL,
	})
	slog.Info("router config updated", "smartTimeout", smartTimeout, "blacklistTTL", blacklistTTL)
}

func (r *Router) IsDomestic(ip string) bool {
	addr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return false
	}
	return r.chnroute.Contains(addr.IP)
}

func (r *Router) IsDomesticByIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip != nil {
		return r.chnroute.Contains(ip)
	}
	return false
}

func (r *Router) isDomesticHost(host string) bool {
	ip := net.ParseIP(host)
	if ip != nil {
		return r.chnroute.Contains(ip)
	}
	return false
}

func (r *Router) EstablishConnection(ctx context.Context, host string, port int,
	domain string, engine *rules.Engine) (net.Conn, bool, error) {

	ll := trace.Log(ctx)
	result, selected := r.upstreamMgr.SelectProxy(ctx, host, port, domain, engine)
	switch {
	case result == "direct":
		ll.Info("proxy rule forces direct connection", "host", host, "port", port, "domain", domain)
		conn, err := dialTCP(ctx, host, port, 10*time.Second)
		return conn, false, err
	case result != "fallback":
		if selected.IsUDPOnly() {
			ll.Warn("rule selected a udp_only proxy for TCP", "url", upstream.MaskProxyURL(selected.URL), "host", host, "port", port)
			return nil, false, errors.New("proxy is udp_only, cannot serve TCP")
		}
		ll.Info("using proxy alias from rule", "url", upstream.MaskProxyURL(selected.URL), "host", host, "port", port, "domain", domain)
		conn, err := selected.Connect(ctx, host, port)
		return conn, true, err
	}

	if r.isDomesticHost(host) {
		ll.Info("using direct connection (domestic)", "host", host, "port", port, "domain", domain)
		conn, err := dialTCP(ctx, host, port, 10*time.Second)
		return conn, false, err
	}

	ll.Info("using upstream proxy (non-smart)", "host", host, "port", port, "domain", domain)
	conn, status := r.upstreamMgr.Connect(ctx, host, port, domain, engine)
	if status != "proxy" {
		return nil, false, errors.New("failed to connect via upstream")
	}
	return conn, true, nil
}

func simplifyError(err error, host string, port int) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "i/o timeout"
	}
	errStr := err.Error()
	if strings.Contains(errStr, "connection reset by peer") {
		return "connection reset by peer"
	}
	if strings.Contains(errStr, "connection refused") {
		return "connection refused"
	}
	if strings.Contains(errStr, "no route to host") {
		return "no route to host"
	}
	if strings.Contains(errStr, "network is unreachable") {
		return "network unreachable"
	}
	if strings.Contains(errStr, "host is down") {
		return "host is down"
	}
	prefix := fmt.Sprintf("dial tcp %s:%d: ", host, port)
	if strings.HasPrefix(errStr, prefix) {
		return strings.TrimPrefix(errStr, prefix)
	}
	readPrefix := fmt.Sprintf("read tcp %s:%d->%s:%d: ", host, port, host, port)
	if strings.HasPrefix(errStr, readPrefix) {
		return strings.TrimPrefix(errStr, readPrefix)
	}
	if idx := strings.Index(errStr, ": "); idx != -1 {
		return errStr[idx+2:]
	}
	return errStr
}

// SmartConnectWithFallback returns (connection, r2c prefix, isProxy, error). The prefix only
// carries the first response byte already read when the smart-direct connection verification
// succeeds: relay replays it before continuing to splice, avoiding a wrapping connection that
// would break zero-copy.
func (r *Router) SmartConnectWithFallback(ctx context.Context, host string, port int,
	domain string, firstPkt []byte, engine *rules.Engine) (net.Conn, []byte, bool, error) {

	cfg := r.cfg.Load()
	ll := trace.Log(ctx)

	result, selected := r.upstreamMgr.SelectProxy(ctx, host, port, domain, engine)
	switch {
	case result == "direct":
		ll.Info("proxy rule forces direct connection", "host", host, "port", port, "domain", domain)
		conn, err := dialTCP(ctx, host, port, cfg.smartTimeout)
		if err != nil {
			return nil, nil, false, err
		}
		if _, err := conn.Write(firstPkt); err != nil {
			conn.Close()
			return nil, nil, false, err
		}
		return conn, nil, false, nil
	case result != "fallback":
		if selected.IsUDPOnly() {
			ll.Warn("rule selected a udp_only proxy for TCP", "url", upstream.MaskProxyURL(selected.URL), "host", host, "port", port)
			return nil, nil, false, errors.New("proxy is udp_only, cannot serve TCP")
		}
		ll.Info("using proxy alias from rule", "url", upstream.MaskProxyURL(selected.URL), "host", host, "port", port, "domain", domain)
		conn, err := selected.Connect(ctx, host, port)
		if err != nil {
			return nil, nil, false, err
		}
		if _, err := conn.Write(firstPkt); err != nil {
			conn.Close()
			return nil, nil, false, err
		}
		return conn, nil, true, nil
	}

	if (domain != "" && r.domainBlacklist.IsBlacklisted(domain, port)) || r.ipBlacklist.IsBlacklisted(host, port) {
		ll.Info("dynamic blacklist matched, using proxy directly", "host", host, "port", port, "domain", domain)
		conn, err := r.upstreamMgr.ConnectDefault(ctx, host, port)
		if err != nil {
			return nil, nil, false, err
		}
		if _, err := conn.Write(firstPkt); err != nil {
			conn.Close()
			return nil, nil, false, err
		}
		return conn, nil, true, nil
	}

	ll.Info("attempting smart proxy direct connection", "host", host, "port", port, "domain", domain, "timeout", cfg.smartTimeout)
	conn, err := dialTCP(ctx, host, port, cfg.smartTimeout)
	if err != nil {
		shortReason := simplifyError(err, host, port)
		ll.Warn("direct connection failed, falling back to proxy", "host", host, "port", port, "domain", domain, "reason", shortReason)
		r.addToBlacklists(host, port, domain, shortReason)

		proxyConn, pErr := r.upstreamMgr.ConnectDefault(ctx, host, port)
		if pErr != nil {
			return nil, nil, false, fmt.Errorf("direct failed (%v) and proxy fallback failed (%v)", err, pErr)
		}
		if _, err := proxyConn.Write(firstPkt); err != nil {
			proxyConn.Close()
			return nil, nil, false, err
		}
		return proxyConn, nil, true, nil
	}

	wn, writeErr := conn.Write(firstPkt)
	if writeErr != nil {
		conn.Close()
		shortReason := simplifyError(writeErr, host, port)
		r.addToBlacklists(host, port, domain, shortReason)
		if wn == 0 {
			// 0 bytes sent to direct remote: safe to fallback to proxy
			ll.Warn("direct write failed with 0 bytes, falling back to proxy", "host", host, "port", port, "domain", domain, "reason", shortReason)
			proxyConn, pErr := r.upstreamMgr.ConnectDefault(ctx, host, port)
			if pErr != nil {
				return nil, nil, false, fmt.Errorf("direct write failed (%v) and proxy fallback failed (%v)", writeErr, pErr)
			}
			if _, err := proxyConn.Write(firstPkt); err != nil {
				proxyConn.Close()
				return nil, nil, false, err
			}
			return proxyConn, nil, true, nil
		}
		// Partial write (wn > 0): data has entered the wire!
		// Replay is STRICTLY FORBIDDEN to prevent duplicate processing.
		ll.Error("direct write failed partially, replay forbidden", "written", wn, "total", len(firstPkt), "host", host, "port", port, "domain", domain, "reason", shortReason)
		return nil, nil, false, fmt.Errorf("direct partial write failed (%d/%d bytes sent): %w", wn, len(firstPkt), writeErr)
	}

	conn.SetReadDeadline(time.Now().Add(cfg.smartTimeout))
	oneByte := make([]byte, 1)
	_, readErr := io.ReadFull(conn, oneByte)
	conn.SetReadDeadline(time.Time{})

	if readErr != nil {
		conn.Close()
		shortReason := simplifyError(readErr, host, port)
		ll.Warn("direct connection failed on read verify, falling back to proxy", "host", host, "port", port, "domain", domain, "reason", shortReason)
		r.addToBlacklists(host, port, domain, shortReason)

		// All bytes of firstPkt were written to direct server, but no response was received within timeout.
		// Only allow replay if the payload is proven to be a side-effect-free protocol handshake (TLS ClientHello).
		if isTLSClientHello(firstPkt) {
			ll.Info("replaying TLS ClientHello over proxy after direct read timeout", "host", host, "port", port, "domain", domain)
			proxyConn, pErr := r.upstreamMgr.ConnectDefault(ctx, host, port)
			if pErr != nil {
				return nil, nil, false, fmt.Errorf("direct read timeout (%v) and proxy fallback failed (%v)", readErr, pErr)
			}
			if _, err := proxyConn.Write(firstPkt); err != nil {
				proxyConn.Close()
				return nil, nil, false, err
			}
			return proxyConn, nil, true, nil
		}

		// Non-handshake or unknown application data (e.g. HTTP POST, non-idempotent TCP payload):
		// Server may have already received and started processing the request.
		// Fail safe: return read error to caller, do NOT replay.
		ll.Error("direct read timeout for non-handshake payload, replay forbidden", "host", host, "port", port, "domain", domain, "reason", shortReason)
		return nil, nil, false, fmt.Errorf("direct connection read verify timeout (payload not replay-safe): %w", readErr)
	}

	ll.Info("direct connection successfully verified, keeping direct", "host", host, "port", port, "domain", domain)
	// Return the raw connection plus the first byte already read, which relay replays before
	// splicing, avoiding a prefixedConn that would break zero-copy.
	return conn, oneByte, false, nil
}

// isTLSClientHello reports whether pkt contains exactly and exclusively a single,
// well-formed TLS ClientHello handshake record with no trailing or pipelined data.
//
// In SmartConnect's connection establishment model, a validated ClientHello is handshake-level
// data that has not committed any application transaction; replaying it over proxy upon direct
// read timeout is permitted. Application data (HTTP requests, custom TCP) or pipelined
// payloads are strictly rejected and never replayed.
func isTLSClientHello(pkt []byte) bool {
	// A valid TLS ClientHello record requires at least:
	// 5 bytes TLS record header
	// 4 bytes Handshake header (type + 3-byte length)
	// 2 bytes ClientVersion
	// 32 bytes ClientRandom
	// 1 byte SessionID length
	// Total minimum = 44 bytes
	if len(pkt) < 44 {
		return false
	}
	// Byte 0: ContentType 0x16 (Handshake)
	if pkt[0] != 0x16 {
		return false
	}
	// Bytes 1..2: ProtocolVersion (Major 3, Minor 0..4: SSL 3.0 to TLS 1.3)
	if pkt[1] != 0x03 || pkt[2] > 0x04 {
		return false
	}
	recordLen := int(binary.BigEndian.Uint16(pkt[3:5]))
	// The packet must consist exclusively of this single record. Any trailing bytes
	// (such as pipelined TLS Application Data or a second record) invalidate replay safety.
	if recordLen != len(pkt)-5 {
		return false
	}
	// Byte 5: HandshakeType 0x01 (ClientHello)
	if pkt[5] != 0x01 {
		return false
	}
	hsLen := int(pkt[6])<<16 | int(pkt[7])<<8 | int(pkt[8])
	// The handshake message must occupy the entire record payload (no trailing fragments).
	if hsLen != recordLen-4 {
		return false
	}

	offset := 9 // 5 (record header) + 4 (handshake header)

	// client_version (2 bytes) + random (32 bytes) + session_id_len (1 byte)
	if offset+35 > len(pkt) {
		return false
	}
	if pkt[offset] != 0x03 || pkt[offset+1] > 0x04 {
		return false
	}
	offset += 2  // client_version
	offset += 32 // random

	sessIDLen := int(pkt[offset])
	offset++
	if sessIDLen > 32 || offset+sessIDLen > len(pkt) {
		return false
	}
	offset += sessIDLen

	// cipher_suites: 2-byte length prefix
	if offset+2 > len(pkt) {
		return false
	}
	csLen := int(binary.BigEndian.Uint16(pkt[offset : offset+2]))
	offset += 2
	if csLen < 2 || (csLen%2) != 0 || offset+csLen > len(pkt) {
		return false
	}
	offset += csLen

	// compression_methods: 1-byte length prefix
	if offset+1 > len(pkt) {
		return false
	}
	compLen := int(pkt[offset])
	offset++
	if compLen < 1 || offset+compLen > len(pkt) {
		return false
	}
	offset += compLen

	// End of mandatory ClientHello fields.
	// If no extensions follow, the offset must exactly match packet length.
	if offset == len(pkt) {
		return true
	}

	// If bytes remain, they must parse as the 2-byte extensions vector length.
	if offset+2 > len(pkt) {
		return false
	}
	extLen := int(binary.BigEndian.Uint16(pkt[offset : offset+2]))
	offset += 2
	if offset+extLen != len(pkt) {
		return false
	}

	// Iteratively validate each TLS Extension structure (RFC 5246 section 7.4.1.4 / RFC 8446 section 4.2):
	// Extension:
	//   extension_type     uint16 (2 bytes)
	//   extension_data_len uint16 (2 bytes)
	//   extension_data     opaque (extension_data_len bytes)
	extEnd := offset + extLen
	for offset < extEnd {
		if extEnd-offset < 4 {
			return false // Incomplete extension header
		}
		// Skip 2-byte extension_type
		extDataLen := int(binary.BigEndian.Uint16(pkt[offset+2 : offset+4]))
		offset += 4
		if extDataLen > extEnd-offset {
			return false // Extension data overflows the extensions vector
		}
		offset += extDataLen
	}

	return offset == extEnd
}

func (r *Router) addToBlacklists(host string, port int, domain, reason string) {
	cfg := r.cfg.Load()

	r.ipBlacklist.Add(host, port, cfg.blacklistTTL, reason)

	if domain != "" {
		r.domainBlacklist.Add(domain, port, cfg.blacklistTTL, reason)
	}
}

func (r *Router) BlacklistSnapshot() (ipEntries, domainEntries []BlacklistEntry) {
	return r.ipBlacklist.Entries(), r.domainBlacklist.Entries()
}

// --- UDP smart 决策入口(QUIC 黑洞自愈用,供 TUN / SOCKS5-UDP 两条 seam 共用) ---

// IsIPBlacklisted 报告目标 IP:port 是否命中动态黑名单。命中表示此前该目标直连被证
// 死(TCP smart 或 QUIC 黑洞判死),TCP 与 UDP 一律直接走代理,不再尝试直连。
func (r *Router) IsIPBlacklisted(ip string, port int) bool {
	return r.ipBlacklist.IsBlacklisted(ip, port)
}

// IsDomainBlacklisted 报告域名:port 是否命中动态黑名单(UDP 域名型目标用)。
func (r *Router) IsDomainBlacklisted(domain string, port int) bool {
	return r.domainBlacklist.IsBlacklisted(domain, port)
}

// BlacklistIP 把目标 IP 加入动态黑名单(QUIC 判死回调 / 其它"直连判死"后调用),
// 生存期取 blacklist_ttl。之后该 IP 的 TCP smart 直连与 UDP 路由都会改走代理。
func (r *Router) BlacklistIP(ip string, port int, reason string) {
	cfg := r.cfg.Load()
	r.ipBlacklist.Add(ip, port, cfg.blacklistTTL, reason)
	slog.Info("blacklisted ip (UDP smart)", "ip", ip, "port", port, "reason", reason)
}

// BlacklistDomain 把目标域名加入动态黑名单(UDP 域名型目标判死时按 SNI/ATYP 域名写)。
func (r *Router) BlacklistDomain(domain string, port int, reason string) {
	cfg := r.cfg.Load()
	r.domainBlacklist.Add(domain, port, cfg.blacklistTTL, reason)
	slog.Info("blacklisted domain (UDP smart)", "domain", domain, "port", port, "reason", reason)
}

func (r *Router) RemoveFromBlacklist(host string, port int, typ string) {
	switch typ {
	case "ip":
		r.ipBlacklist.Remove(host, port)
	case "domain":
		r.domainBlacklist.Remove(host, port)
	default:
		r.ipBlacklist.Remove(host, port)
		r.domainBlacklist.Remove(host, port)
	}
}

func (r *Router) StartCleanup(interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	r.cleanupStopCh = make(chan struct{})
	r.cleanupWg.Add(1)
	safego.Go("route.router.cleanup", func() {
		defer r.cleanupWg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.domainBlacklist.cleanExpired()
				r.ipBlacklist.cleanExpired()
			case <-r.cleanupStopCh:
				slog.Debug("cleanup goroutine stopped")
				return
			}
		}
	})
}

func (r *Router) StopCleanup() {
	if r.cleanupStopCh != nil {
		close(r.cleanupStopCh)
	}
	r.cleanupWg.Wait()
}

func dialTCP(ctx context.Context, host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, Control: fwmark.Control}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	// Align with proxy connections (upstream/proxy.go dial): direct connections also disable
	// Nagle and enable KeepAlive to reduce small-packet latency.
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(15 * time.Second)
		netutil.SetKeepAliveInterval(tcp, 15*time.Second)
	}
	return conn, nil
}

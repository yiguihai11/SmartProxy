package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"golang.org/x/sync/singleflight"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/fwmark"
	"smartproxy/internal/netutil"
	"smartproxy/internal/relay"
	"smartproxy/internal/rules"
	"smartproxy/internal/upstream"
)

// BlockedIP is the response IP backfilled when a domain is blocked; hardcoded and not configurable.
const (
	BlockedIPv4 = "0.0.0.0"
	BlockedIPv6 = "::"
)

type dnsConfig struct {
	foreignIPv4     string
	foreignIPv4Port int
	foreignIPv6     string
	foreignIPv6Port int
	queryTimeout    time.Duration
	blockedIP       string
	blockedIP6      string
	enabled         bool
	preference      *Preference
}

type Handler struct {
	cfg         atomic.Pointer[dnsConfig]
	cache       *Cache
	chnroute    *chnroute.Trie
	upstreamMgr *upstream.Manager
	group       singleflight.Group
	// staticRecords is the host→IPs override table (hosts-override semantics,
	// checked before block rules and cache). The whole map is swapped atomically on
	// config reload so readers always see a consistent snapshot.
	staticRecords atomic.Pointer[map[string][]net.IP]
}

func NewHandler(cacheSize, cacheTTL int,
	foreignIPv4, foreignIPv6 string,
	cn *chnroute.Trie, mgr *upstream.Manager,
	queryTimeout int, blockedIP, blockedIP6 string,
	preferEnabled bool, preferMode PreferMode, preferPorts []int,
	enabled bool) *Handler {

	h := &Handler{
		cache:       NewCache(cacheSize, time.Duration(cacheTTL)*time.Second),
		chnroute:    cn,
		upstreamMgr: mgr,
	}
	h.storeConfig(foreignIPv4, foreignIPv6, queryTimeout, blockedIP, blockedIP6,
		enabled, preferEnabled, preferMode, preferPorts)
	return h
}

func (h *Handler) storeConfig(
	foreignIPv4, foreignIPv6 string,
	queryTimeout int, blockedIP, blockedIP6 string,
	enabled bool, preferEnabled bool, preferMode PreferMode, preferPorts []int,
) {
	v4Host, v4Port := netutil.ParseHostPort(foreignIPv4, 53)
	v6Host, v6Port := netutil.ParseHostPort(foreignIPv6, 53)
	h.cfg.Store(&dnsConfig{
		foreignIPv4:     v4Host,
		foreignIPv4Port: v4Port,
		foreignIPv6:     v6Host,
		foreignIPv6Port: v6Port,
		queryTimeout:    time.Duration(queryTimeout) * time.Second,
		blockedIP:       blockedIP,
		blockedIP6:      blockedIP6,
		enabled:         enabled,
		preference:      NewPreference(preferEnabled, preferMode, preferPorts),
	})
}

func (h *Handler) UpdateConfig(
	foreignIPv4, foreignIPv6 string,
	queryTimeout int, blockedIP, blockedIP6 string,
	enabled bool, preferEnabled bool, preferMode PreferMode, preferPorts []int,
) {
	h.storeConfig(foreignIPv4, foreignIPv6, queryTimeout, blockedIP, blockedIP6,
		enabled, preferEnabled, preferMode, preferPorts)
	slog.Info("DNS handler config updated",
		"foreignIPv4", foreignIPv4, "foreignIPv6", foreignIPv6,
		"queryTimeout", queryTimeout, "enabled", enabled)
}

func (h *Handler) Enabled() bool {
	return h.cfg.Load().enabled
}

func (h *Handler) IsDomestic(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return h.chnroute.Contains(parsed)
}

func (h *Handler) HandleDNS(ctx context.Context, queryWire []byte, targetIP string, targetPort int, engine *rules.Engine) []byte {
	cfg := h.cfg.Load()
	if !cfg.enabled {
		return nil
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(queryWire); err != nil {
		slog.Error("invalid DNS query", "error", err)
		return nil
	}
	if len(msg.Question) == 0 {
		return nil
	}

	qname := strings.TrimSuffix(msg.Question[0].Name, ".")
	qname = strings.ToLower(qname)
	qtype := msg.Question[0].Qtype
	// Logging INFO for every query is pure overhead under high query rates; the hot path is downgraded to Debug
	slog.Debug("handling DNS query", "qname", qname, "qtype", qtype)

	// Static records are authoritative overrides: answer before block rules so an
	// explicit hosts-style entry always wins over a blocklist or stale cache.
	if m := h.staticRecords.Load(); m != nil && len(*m) > 0 {
		if ips, ok := (*m)[qname]; ok {
			slog.Debug("static record hit", "qname", qname)
			if resp, ok := buildStaticResponse(msg, ips); ok {
				return resp
			}
		}
	}

	if engine != nil && engine.IsDomainBlocked(qname) {
		slog.Info("blocked DNS query", "domain", qname)
		return h.buildFakeResponse(queryWire)
	}

	if cached := h.cache.Get(qname, qtype); cached != nil {
		slog.Debug("DNS cache hit", "qname", qname, "qtype", qtype, "responseLen", len(cached))
		if len(cached) >= 2 && (cached[0] != queryWire[0] || cached[1] != queryWire[1]) {
			cachedCp := make([]byte, len(cached))
			copy(cachedCp, cached)
			cachedCp[0], cachedCp[1] = queryWire[0], queryWire[1]
			return cachedCp
		}
		return cached
	}

	// Coalesce concurrent queries: when the same domain and type are requested simultaneously, query only once
	key := qname + "|" + strconv.Itoa(int(qtype))
	result, err, _ := h.group.Do(key, func() (interface{}, error) {
		isDomestic := h.IsDomestic(targetIP)

		var resp []byte
		var rerr error

		if isDomestic {
			slog.Debug("querying domestic DNS", "target", fmt.Sprintf("%s:%d", targetIP, targetPort))
			resp, rerr = h.QueryUDPVerifyID(ctx, queryWire, targetIP, targetPort)
			if rerr != nil {
				slog.Warn("domestic DNS query failed, falling back to foreign DNS",
					"qname", qname, "error", rerr)
				foreignHost := cfg.foreignIPv4
				foreignPort := cfg.foreignIPv4Port
				if strings.Contains(targetIP, ":") {
					foreignHost = cfg.foreignIPv6
					foreignPort = cfg.foreignIPv6Port
				}
				resp, rerr = h.queryForeignDNSWithRetry(ctx, queryWire, foreignHost, foreignPort)
				if rerr != nil {
					slog.Error("foreign DNS fallback also failed, answering SERVFAIL", "qname", qname, "error", rerr)
					return h.buildSERVFAIL(queryWire), nil
				}
				h.cache.Set(qname, qtype, resp, 0)
				return resp, nil
			}
		} else {
			slog.Debug("querying foreign DNS via proxy", "target", fmt.Sprintf("%s:%d", targetIP, targetPort))
			resp, rerr = h.queryForeignDNSWithRetry(ctx, queryWire, targetIP, targetPort)
			if rerr != nil {
				slog.Error("foreign DNS query failed, answering SERVFAIL", "error", rerr)
				return h.buildSERVFAIL(queryWire), nil
			}
		}

		if isDomestic {
			// A single parse performs both the pollution check and IP preference selection (avoiding unpacking the response twice)
			if preferred, cached, clean := h.isDNSCleanAndPrefer(ctx, resp, qname); clean {
				resp = preferred
				if cached {
					h.cache.Set(qname, qtype, resp, 0)
				}
				return resp, nil
			} else {
				slog.Warn("domestic DNS response polluted, falling back to foreign DNS", "qname", qname)
				foreignHost := cfg.foreignIPv4
				foreignPort := cfg.foreignIPv4Port
				if strings.Contains(targetIP, ":") {
					foreignHost = cfg.foreignIPv6
					foreignPort = cfg.foreignIPv6Port
				}
				fallback, ferr := h.queryForeignDNSWithRetry(ctx, queryWire, foreignHost, foreignPort)
				if ferr != nil || fallback == nil {
					slog.Warn("foreign DNS fallback failed, answering SERVFAIL",
						"qname", qname, "foreignTarget", fmt.Sprintf("%s:%d", foreignHost, foreignPort),
						"error", ferr, "queryLen", len(queryWire))
					return h.buildSERVFAIL(queryWire), nil
				}
				resp = fallback
				h.cache.Set(qname, qtype, resp, 0)
				return resp, nil
			}
		} else {
			h.cache.Set(qname, qtype, resp, 0)
			return resp, nil
		}
	})
	if err != nil || result == nil {
		return nil
	}

	// Share the result and fix the DNS transaction ID for the current caller
	resp := result.([]byte)
	if len(resp) >= 2 && (resp[0] != queryWire[0] || resp[1] != queryWire[1]) {
		respCopy := make([]byte, len(resp))
		copy(respCopy, resp)
		respCopy[0], respCopy[1] = queryWire[0], queryWire[1]
		return respCopy
	}
	return resp
}

// QueryUDPVerifyID sends a UDP query directly to the DNS server and only returns when the
// response's transaction ID matches the query, preventing forged or mismatched-ID responses
// from being taken as the result of this query.
func (h *Handler) QueryUDPVerifyID(ctx context.Context, queryWire []byte, host string, port int) ([]byte, error) {
	resp, err := h.queryUDP(ctx, queryWire, host, port)
	if err != nil {
		return nil, err
	}
	if len(resp) < 2 || resp[0] != queryWire[0] || resp[1] != queryWire[1] {
		return nil, fmt.Errorf("DNS transaction ID mismatch")
	}
	return resp, nil
}

func (h *Handler) queryViaProxyVerifyID(ctx context.Context, queryWire []byte, dnsHost string, dnsPort int, timeout time.Duration) ([]byte, error) {
	resp, err := h.queryViaProxy(ctx, queryWire, dnsHost, dnsPort, timeout)
	if err != nil {
		return nil, err
	}
	if len(resp) < 2 || resp[0] != queryWire[0] || resp[1] != queryWire[1] {
		return nil, fmt.Errorf("DNS transaction ID mismatch")
	}
	return resp, nil
}

// queryForeignDNSWithRetry queries a foreign DNS server through the proxy,
// retrying once when the first attempt fails. The total time across attempts is
// bounded by cfg.queryTimeout (split evenly between them), so the retry never
// pushes the whole foreign lookup past the configured DNS timeout. On persistent
// failure it returns the last error so the caller can answer SERVFAIL instead of
// silently dropping the query.
func (h *Handler) queryForeignDNSWithRetry(ctx context.Context, queryWire []byte, host string, port int) ([]byte, error) {
	cfg := h.cfg.Load()
	const attempts = 2
	perAttempt := cfg.queryTimeout / attempts
	if perAttempt < time.Millisecond {
		perAttempt = cfg.queryTimeout
	}
	budgetCtx, cancel := context.WithTimeout(ctx, cfg.queryTimeout)
	defer cancel()
	var lastErr error
	for i := 0; i < attempts; i++ {
		resp, err := h.queryViaProxyVerifyID(budgetCtx, queryWire, host, port, perAttempt)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("DNS query failed")
	}
	return nil, lastErr
}

func (h *Handler) queryUDP(ctx context.Context, queryWire []byte, host string, port int) ([]byte, error) {
	cfg := h.cfg.Load()
	d := net.Dialer{Timeout: cfg.queryTimeout, Control: fwmark.Control}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(cfg.queryTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(queryWire); err != nil {
		return nil, err
	}

	pktPtr := relay.PacketPool.Get().(*[]byte)
	buf := *pktPtr
	n, err := conn.Read(buf)
	if err != nil {
		relay.PacketPool.Put(pktPtr)
		return nil, err
	}
	resp := make([]byte, n)
	copy(resp, buf[:n])
	relay.PacketPool.Put(pktPtr)
	return resp, nil
}

func (h *Handler) queryViaProxy(ctx context.Context, queryWire []byte, dnsHost string, dnsPort int, timeout time.Duration) ([]byte, error) {
	slog.Debug("querying DNS via proxy", "dns", fmt.Sprintf("%s:%d", dnsHost, dnsPort),
		"queryLen", len(queryWire))

	udpConn, err := h.upstreamMgr.AcquireDNSUDP(ctx, dnsHost, dnsPort)
	if err != nil {
		slog.Error("UDP ASSOCIATE failed for DNS", "dns", fmt.Sprintf("%s:%d", dnsHost, dnsPort), "error", err)
		return nil, fmt.Errorf("UDP ASSOCIATE failed: %w", err)
	}

	success := false
	defer func() {
		if success {
			h.upstreamMgr.ReleaseDNSUDP(udpConn)
		} else {
			h.upstreamMgr.DiscardDNSUDP(udpConn)
		}
	}()

	slog.Debug("UDP ASSOCIATE established for DNS",
		"dns", fmt.Sprintf("%s:%d", dnsHost, dnsPort),
		"localAddr", udpConn.LocalAddr())

	atyp, addr := encodeSOCKS5Addr(dnsHost)
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[0:2], 0)
	header[2] = 0
	header[3] = atyp
	header = append(header, addr...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(dnsPort))
	header = append(header, portBuf...)

	packet := append(header, queryWire...)
	slog.Debug("sending DNS query through proxy UDP",
		"dns", fmt.Sprintf("%s:%d", dnsHost, dnsPort),
		"totalPacketLen", len(packet), "headerLen", len(header), "payloadLen", len(queryWire))

	deadline := time.Now().Add(timeout)
	udpConn.SetDeadline(deadline)
	writeStart := time.Now()
	if _, err := udpConn.Write(packet); err != nil {
		slog.Error("failed to write DNS query to proxy UDP", "error", err)
		return nil, err
	}
	slog.Debug("DNS query written to proxy UDP", "writeLatency", time.Since(writeStart))

	pktPtr := relay.PacketPool.Get().(*[]byte)
	buf := *pktPtr
	readStart := time.Now()
	n, err := udpConn.Read(buf)
	readLatency := time.Since(readStart)
	relay.PacketPool.Put(pktPtr)
	if err != nil {
		slog.Error("DNS proxy read error",
			"dns", fmt.Sprintf("%s:%d", dnsHost, dnsPort),
			"error", err,
			"timeout", timeout,
			"readWait", readLatency)
		return nil, fmt.Errorf("DNS proxy read error: %w", err)
	}
	slog.Debug("DNS response received from proxy",
		"responseLen", n, "readLatency", readLatency)

	data := make([]byte, n)
	copy(data, buf[:n])
	if len(data) < 4 {
		slog.Error("UDP response too short from proxy", "len", len(data))
		return nil, fmt.Errorf("UDP response too short")
	}
	respAtyp := data[3]
	slog.Debug("proxy UDP response header",
		"atyp", respAtyp, "totalLen", len(data))
	var payloadOffset int
	switch respAtyp {
	case 0x01:
		payloadOffset = 4 + 4 + 2
		slog.Debug("proxy response IPv4", "ip", net.IP(data[4:8]).String(),
			"port", binary.BigEndian.Uint16(data[8:10]))
	case 0x03:
		if len(data) < 5 {
			return nil, fmt.Errorf("UDP response too short for domain")
		}
		domainLen := int(data[4])
		payloadOffset = 4 + 1 + domainLen + 2
		domain := string(data[5 : 5+domainLen])
		slog.Debug("proxy response domain", "domain", domain,
			"port", binary.BigEndian.Uint16(data[5+domainLen:5+domainLen+2]))
	case 0x04:
		payloadOffset = 4 + 16 + 2
		slog.Debug("proxy response IPv6", "ip", net.IP(data[4:20]).String(),
			"port", binary.BigEndian.Uint16(data[20:22]))
	default:
		slog.Warn("unknown response address type", "atyp", respAtyp)
		payloadOffset = 4
	}
	if payloadOffset >= len(data) {
		return nil, fmt.Errorf("UDP response payload offset out of range: offset=%d len=%d", payloadOffset, len(data))
	}
	dnsPayload := data[payloadOffset:]
	slog.Debug("DNS payload extracted from proxy response", "payloadLen", len(dnsPayload))

	success = true
	return dnsPayload, nil
}

func (h *Handler) isDNSClean(wire []byte) bool {
	if h.chnroute.IsEmpty() {
		slog.Debug("ChnRoute not loaded, skipping DNS pollution check")
		return true
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		return false
	}
	for _, rr := range msg.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeA, dns.TypeAAAA:
			ip := extractIP(rr)
			if ip != "" && !h.chnroute.Contains(net.ParseIP(ip)) {
				slog.Debug("polluted DNS response found foreign IP", "ip", ip)
				return false
			}
		}
	}
	return true
}

func extractIP(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String()
	case *dns.AAAA:
		return r.AAAA.String()
	}
	return ""
}

// staticRecordTTL is the TTL for answers synthesized from static records.
const staticRecordTTL = 60

// buildStaticResponse builds an authoritative answer for a static-record hit. The
// record type follows the query type: TypeA → A records (IPv4 entries), TypeAAAA →
// AAAA records (IPv6 entries), TypeANY → both families, and any other type yields
// an empty NOERROR answer (NODATA) so the client can fall back to another query.
func buildStaticResponse(msg *dns.Msg, ips []net.IP) ([]byte, bool) {
	qtype := msg.Question[0].Qtype
	resp := msg.SetReply(msg)
	resp.Authoritative = true
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && (qtype == dns.TypeA || qtype == dns.TypeANY) {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: staticRecordTTL},
				A:   v4,
			})
		} else if v4 == nil && (qtype == dns.TypeAAAA || qtype == dns.TypeANY) {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: staticRecordTTL},
				AAAA: ip,
			})
		}
	}
	wire, err := resp.Pack()
	if err != nil {
		return nil, false
	}
	return wire, true
}

// SetStaticRecords replaces the static-record lookup table atomically. The caller
// must build a fresh map per update (never mutate one in place) so concurrent
// readers always see a complete snapshot.
func (h *Handler) SetStaticRecords(m map[string][]net.IP) {
	h.staticRecords.Store(&m)
}

// StaticRecordAnswer serves a static-record answer for the given raw DNS query,
// returning (wire, true) on a hit. The UDP relay path calls this first so static
// records are honored ahead of its own blocked-domain/cache shortcut.
func (h *Handler) StaticRecordAnswer(queryWire []byte) ([]byte, bool) {
	m := h.staticRecords.Load()
	if m == nil || len(*m) == 0 {
		return nil, false
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(queryWire); err != nil {
		return nil, false
	}
	if len(msg.Question) == 0 {
		return nil, false
	}
	qname := strings.ToLower(strings.TrimSuffix(msg.Question[0].Name, "."))
	ips, ok := (*m)[qname]
	if !ok || len(ips) == 0 {
		return nil, false
	}
	return buildStaticResponse(msg, ips)
}

// buildSERVFAIL packs a ServerFailure response for the given query, so a failed
// foreign-DNS lookup surfaces as a real DNS error the client can act on (e.g.
// fall back to its own secondary resolver) instead of a silent timeout. On an
// unpack/pack failure it returns the original wire unchanged.
func (h *Handler) buildSERVFAIL(queryWire []byte) []byte {
	msg := new(dns.Msg)
	if err := msg.Unpack(queryWire); err != nil {
		return queryWire
	}
	resp := msg.SetReply(msg)
	resp.Rcode = dns.RcodeServerFailure
	wire, err := resp.Pack()
	if err != nil {
		return queryWire
	}
	return wire
}

func (h *Handler) buildFakeResponse(queryWire []byte) []byte {
	cfg := h.cfg.Load()
	msg := new(dns.Msg)
	if err := msg.Unpack(queryWire); err != nil {
		return queryWire
	}
	resp := msg.SetReply(msg)
	for _, q := range msg.Question {
		switch q.Qtype {
		case dns.TypeAAAA:
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				AAAA: net.ParseIP(cfg.blockedIP6),
			}
			resp.Answer = append(resp.Answer, rr)
		default:
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP(cfg.blockedIP),
			}
			resp.Answer = append(resp.Answer, rr)
		}
	}
	wire, err := resp.Pack()
	if err != nil {
		return queryWire
	}
	return wire
}

// isDNSCleanAndPrefer parses the domestic DNS response only once: it first performs the
// pollution check, and if not polluted and IP preference is enabled, filters further.
// Returns (output wire, whether the preference cache was hit, whether it is clean).
func (h *Handler) isDNSCleanAndPrefer(ctx context.Context, wire []byte, qname string) (out []byte, preferCached, clean bool) {
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		return wire, false, false
	}

	if h.chnroute.IsEmpty() {
		slog.Debug("ChnRoute not loaded, skipping DNS pollution check")
	} else {
		for _, rr := range msg.Answer {
			switch rr.Header().Rrtype {
			case dns.TypeA, dns.TypeAAAA:
				ip := extractIP(rr)
				if ip != "" && !h.chnroute.Contains(net.ParseIP(ip)) {
					slog.Debug("polluted DNS response found foreign IP", "ip", ip)
					return wire, false, false
				}
			}
		}
	}

	cfg := h.cfg.Load()
	if cfg.preference == nil || !cfg.preference.enabled {
		return wire, false, true
	}

	preferred, cached := h.filterIPPreference(ctx, cfg.preference, msg, wire, qname)
	return preferred, cached, true
}

// filterIPPreference selects the fastest IP from the parsed response and repacks it (called when IP preference is enabled).
func (h *Handler) filterIPPreference(ctx context.Context, pref *Preference, msg *dns.Msg, origWire []byte, qname string) ([]byte, bool) {
	var aIPs []string
	var aaaaIPs []string
	var otherAnswers []dns.RR

	for _, rr := range msg.Answer {
		switch r := rr.(type) {
		case *dns.A:
			aIPs = append(aIPs, r.A.String())
		case *dns.AAAA:
			aaaaIPs = append(aaaaIPs, r.AAAA.String())
		default:
			otherAnswers = append(otherAnswers, rr)
		}
	}

	bestA := ""
	if len(aIPs) > 1 {
		bestA = pref.PreferIPs(ctx, aIPs)
	} else if len(aIPs) == 1 {
		bestA = aIPs[0]
	}

	bestAAAA := ""
	if len(aaaaIPs) > 1 {
		bestAAAA = pref.PreferIPs(ctx, aaaaIPs)
	} else if len(aaaaIPs) == 1 {
		bestAAAA = aaaaIPs[0]
	}

	hasABest := bestA != ""
	hasAAAABest := bestAAAA != ""

	if hasABest || hasAAAABest {

		var newAnswers []dns.RR
		for _, rr := range msg.Answer {
			switch r := rr.(type) {
			case *dns.A:
				if r.A.String() == bestA {
					newAnswers = append(newAnswers, rr)
				}
			case *dns.AAAA:
				if r.AAAA.String() == bestAAAA {
					newAnswers = append(newAnswers, rr)
				}
			default:
				newAnswers = append(newAnswers, rr)
			}
		}
		msg.Answer = newAnswers

		wire, err := msg.Pack()
		if err != nil {
			return origWire, false
		}
		slog.Debug("DNS response filtered by IP preference",
			"qname", qname, "bestA", bestA, "bestAAAA", bestAAAA)
		return wire, true
	}

	if len(aIPs)+len(aaaaIPs) > 0 {
		slog.Warn("DNS IP preference probes all failed, returning original uncached",
			"qname", qname, "aCount", len(aIPs), "aaaaCount", len(aaaaIPs))
	}
	return origWire, false
}

// applyIPPreference selects the fastest IP and returns a repacked response; returns the original
// unchanged when preference is disabled. The hot path reuses the shared logic via
// isDNSCleanAndPrefer (avoiding a second Unpack); this is kept for tests / standalone calls.
func (h *Handler) applyIPPreference(ctx context.Context, responseWire []byte, qname string) ([]byte, bool) {
	cfg := h.cfg.Load()
	if cfg.preference == nil || !cfg.preference.enabled {
		return responseWire, false
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(responseWire); err != nil {
		return responseWire, false
	}
	return h.filterIPPreference(ctx, cfg.preference, msg, responseWire, qname)
}

func (h *Handler) BuildFakeResponse(queryWire []byte) []byte {
	return h.buildFakeResponse(queryWire)
}

func (h *Handler) Close() {
	h.cache.Close()
}

func (h *Handler) CacheGet(qname string, qtype uint16) []byte {
	return h.cache.Get(qname, qtype)
}

func (h *Handler) CacheSet(qname string, qtype uint16, wire []byte, ttl time.Duration) {
	h.cache.Set(qname, qtype, wire, ttl)
}

func (h *Handler) CacheLen() int {
	return h.cache.Len()
}

func (h *Handler) CacheClear() {
	h.cache.Clear()
}

func (h *Handler) CacheRemove(qname string, qtype uint16) {
	h.cache.Remove(qname, qtype)
}

func (h *Handler) CacheEntries() []CacheEntryInfo {
	return h.cache.Entries()
}

func (h *Handler) QueryUDP(ctx context.Context, queryWire []byte, host string, port int) ([]byte, error) {
	return h.queryUDP(ctx, queryWire, host, port)
}

func (h *Handler) IsDNSClean(wire []byte) bool {
	return h.isDNSClean(wire)
}

func encodeSOCKS5Addr(host string) (byte, []byte) {
	ip := net.ParseIP(host)
	if ip == nil {
		domain := []byte(host)
		buf := make([]byte, 1+len(domain))
		buf[0] = byte(len(domain))
		copy(buf[1:], domain)
		return 0x03, buf
	}
	if ip4 := ip.To4(); ip4 != nil {
		return 0x01, ip4
	}
	return 0x04, ip.To16()
}

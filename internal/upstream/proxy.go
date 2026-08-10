package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"smartproxy/internal/fwmark"
	"smartproxy/internal/netutil"
)

const proxyDialTimeout = 10 * time.Second

type ProxyScheme string

const (
	SchemeSOCKS5  ProxyScheme = "socks5"
	SchemeSOCKS5H ProxyScheme = "socks5h"
	SchemeSOCKS4  ProxyScheme = "socks4"
	SchemeHTTP    ProxyScheme = "http"
	SchemeHTTPS   ProxyScheme = "https"
	// SchemeSS connects to the remote SS server directly with the shadowsocks protocol
	// (classic AEAD encryption, see internal/upstream/ss.go). The URL looks like
	// ss://base64(method:password)@host:port, and plaintext ss://method:password@host:port is also accepted.
	SchemeSS ProxyScheme = "ss"
)

// Mode values for Proxy.EffectiveMode — the same three-state status marker shadowsocks uses
// for its sslocal mode. The effective mode is derived automatically from probing (scheme
// capability + independent TCP/UDP circuit breakers); it is never configured manually.
const (
	ModeTCPAndUDP = "tcp_and_udp"
	ModeTCPOnly   = "tcp_only"
	ModeUDPOnly   = "udp_only"
)

// UDPCapability describes how a node's UDP relay works, auto-detected from probing and real
// traffic. It is sticky (last-known-good): only success writes standard/raw, and a known
// standard node is never downgraded to raw by a transient failure (see setUDPCapability).
type UDPCapability string

const (
	UDPCapUnknown  UDPCapability = "unknown"  // not yet detected
	UDPCapStandard UDPCapability = "standard" // SOCKS5 UDP ASSOCIATE control channel established
	UDPCapRaw      UDPCapability = "raw"      // raw UDP relay at host:port, no control channel
	UDPCapNone     UDPCapability = "none"     // no working UDP relay (ASSOCIATE and raw both failed)
)

// rawRecheckInterval is how often a node detected as raw may re-attempt the standard
// ASSOCIATE path, so it can upgrade raw → standard if the upstream later starts supporting
// ASSOCIATE. The raw routing fast path keeps skipping the doomed handshake between rechecks.
const rawRecheckInterval = 10 * time.Minute

type Proxy struct {
	URL string
	// Name is the node's friendly name taken from the ss:// URL's #fragment
	// (e.g. ss://…@host:port#美国 洛杉矶), matching how shadowsocks-android names
	// imported profiles. Empty when the URL has no fragment. Purely cosmetic —
	// routing and identity use Scheme/Host/Port/Alias.
	Name     string
	Scheme   ProxyScheme
	Host     string
	Port     int
	Username string
	Password string
	// Plugin is the ?plugin= parameter of an ss:// URL (SIP003, ss-android export format
	// id;key=val;key=val). SmartProxy ships built-in obfs-local (http/tls, see obfs.go)
	// and v2ray-plugin/xray-plugin (all 5 Android modes of websocket/grpc/quic, see
	// v2ray.go); on TCP connect it wraps the matching transport under the SS encryption layer, and unknown plugins return a clear error.
	Plugin string
	// UDPInTCP selects the hev UDP-in-TCP relay (hev-socks5-server's private CMD=5
	// extension) for a socks5/socks5h node: UDP packets are framed over a TCP connection
	// instead of a UDP ASSOCIATE, so the node needs no UDP listener. It is set from the
	// config entry's udp_in_tcp field (the panel switch) OR the URL's ?udp_in_tcp=1 query
	// (imported links). The carrier TCP stream is plaintext framed UDP (GFW-fingerprintable),
	// so the node defaults to TCP manually down (applyUDPInTCPDefaults) and only relays TCP
	// once the user enables that circuit; UDP routing always takes the framed path
	// (see UDPAssociate).
	UDPInTCP bool
	health   ProxyHealth
	// udpCapability is how this node's UDP relay works, auto-detected (see UDPCapability).
	// It is written by successful relays (standard ASSOCIATE, raw fallback, ss) and read by
	// the raw routing fast path in socks5UDPAssociate; guarded by capMu.
	udpCapability UDPCapability
	// rawRecheckAfter is the earliest time a raw-detected node may re-attempt the standard
	// ASSOCIATE path (raw → standard recovery). Zero means due immediately (safety net). It is
	// bumped on first raw detection and after every recheck attempt; guarded by capMu.
	rawRecheckAfter time.Time
	capMu           sync.RWMutex
	// udpHealth is an independent UDP circuit breaker. TCP health (health) and UDP health
	// (udpHealth) never affect each other: a dead TCP path does not disable a working UDP
	// relay (the udp_only use case) and a dead UDP path does not disable TCP routing.
	udpHealth ProxyHealth

	// ssMethod is the encryption implementation for the ss:// scheme (classic AEAD or
	// none/plain), built once by NewProxy when parsing method:password; Method is immutable and safe for concurrent use.
	ssMethod shadowsocks.Method
}

// SchemeSupportsUDP reports whether the upstream's protocol can carry UDP at all. This is a
// static property of the scheme and never changes: only SOCKS5 / SOCKS5h / SS have a UDP
// relay concept; http/https/socks4 are TCP-only and are never UDP-probed. An SS node with a
// SIP003 plugin is still probeable: the plugin wraps only the TCP stream, but UDP goes
// straight to the server's UDP port, so it may work when the deployment exposes it. Plugin
// nodes default to UDP down (udpHealth manually disabled at construction, see NewProxy) and
// are only UDP-probed once the user releases the circuit.
func (p *Proxy) SchemeSupportsUDP() bool {
	switch p.Scheme {
	case SchemeSOCKS5, SchemeSOCKS5H, SchemeSS:
		return true
	}
	return false
}

// EffectiveMode returns the mode routing and reporting actually use, derived purely from the
// scheme and the independent TCP/UDP health circuits:
//   - non-UDP schemes (http/https/socks4) are always tcp_only;
//   - a UDP-capable scheme whose TCP and UDP circuits are both closed is tcp_and_udp;
//   - UDP circuit open (but TCP healthy) → tcp_only;
//   - TCP circuit open (but UDP healthy) → udp_only — auto-derived, never configured;
//   - both open → tcp_and_udp (neither single downgrade is meaningful; both circuit
//     snapshots already report the outage).
//
// There is no configured base: probing and routing read the same circuits, so a degraded
// node keeps getting probed on both paths (probeUDP/checkProxyTCP run regardless of the
// current states) and can detect recovery.
func (p *Proxy) EffectiveMode() string {
	if !p.SchemeSupportsUDP() {
		return ModeTCPOnly
	}
	// A udp_in_tcp node is udp_only by default, but through a manual TCP circuit pin
	// (applyUDPInTCPDefaults) rather than a hard-coded mode: once the user enables TCP the
	// mode derives from the dual circuits like any other socks5 node — only the UDP
	// transport differs (see UDPAssociate).
	tcpUp := p.health.IsAvailable()
	udpUp := p.udpHealth.IsAvailable()
	switch {
	case tcpUp && !udpUp:
		return ModeTCPOnly
	case !tcpUp && udpUp:
		return ModeUDPOnly
	default:
		return ModeTCPAndUDP
	}
}

// IsUDPOnly reports whether routing must treat the upstream as UDP-only (no TCP). This
// reflects the effective mode, so a UDP-capable node whose TCP path is down is skipped by
// TCP routing until its TCP circuit recovers.
func (p *Proxy) IsUDPOnly() bool { return p.EffectiveMode() == ModeUDPOnly }

// IsTCPOnly reports whether routing must treat the upstream as TCP-only (never UDP).
func (p *Proxy) IsTCPOnly() bool { return p.EffectiveMode() == ModeTCPOnly }

// applyUDPInTCPDefaults pins the TCP circuit down (manual) when the node is a hev
// UDP-in-TCP relay (socks5/socks5h only): the carrier TCP stream is plaintext framed UDP,
// which GFW can fingerprint, so the node does not proxy regular TCP until the user
// explicitly enables it (SetCircuitHealth tcp enable/auto). This mirrors the SIP003-plugin
// default (which pins UDP down) on the TCP side. A manual pin is preserved across reloads
// (Manager.restoreManualPins), so only freshly-built nodes pick up the default and a user's
// re-enable sticks.
func (p *Proxy) applyUDPInTCPDefaults() {
	if !p.UDPInTCP {
		return
	}
	if p.Scheme != SchemeSOCKS5 && p.Scheme != SchemeSOCKS5H {
		return
	}
	p.health.SetManualState(false)
}

// SupportsUDP reports whether routing may use this upstream to relay UDP (via UDPProxyConn
// or the ss UDP relay). Effective-mode based: a UDP-capable node whose UDP circuit is open
// downgrades to tcp_only and is skipped by UDP routing until UDP recovers.
func (p *Proxy) SupportsUDP() bool {
	if p.IsTCPOnly() {
		return false
	}
	return p.SchemeSupportsUDP()
}

// UDPCapability returns the last-known-good UDP capability marker (unknown before any
// successful relay; standard/raw after a working path is found; none only when a fresh
// node's UDP failed end to end). A zero value is normalized to unknown.
func (p *Proxy) UDPCapability() UDPCapability {
	p.capMu.RLock()
	defer p.capMu.RUnlock()
	if p.udpCapability == "" {
		return UDPCapUnknown
	}
	return p.udpCapability
}

// setUDPCapability records a UDP capability with sticky last-known-good semantics:
//   - standard is always an upgrade (unknown/raw/none → standard) and idempotent;
//   - raw is written only when the node is not already known standard — a known standard
//     node is never downgraded to raw by a transient ASSOCIATE failure;
//   - none is written only while the node is still unknown/none — a working standard/raw
//     path sticks even through later end-to-end failures (the udpHealth circuit carries
//     the outage, not this marker).
func (p *Proxy) setUDPCapability(c UDPCapability) {
	p.capMu.Lock()
	defer p.capMu.Unlock()
	switch c {
	case UDPCapStandard:
		p.udpCapability = UDPCapStandard
	case UDPCapRaw:
		if p.udpCapability != UDPCapStandard {
			firstRaw := p.udpCapability != UDPCapRaw
			p.udpCapability = UDPCapRaw
			if firstRaw {
				// Fresh raw detection: defer the first ASSOCIATE recheck so the routing
				// optimization is not immediately voided by one more doomed handshake.
				p.rawRecheckAfter = time.Now().Add(rawRecheckInterval)
			}
		}
	case UDPCapNone:
		// "" is a zero-value fresh proxy (no NewProxy path), treated as unknown.
		if p.udpCapability == "" || p.udpCapability == UDPCapUnknown || p.udpCapability == UDPCapNone {
			p.udpCapability = UDPCapNone
		}
	}
}

// rawRecheckDue reports whether a known-raw node should re-attempt the standard ASSOCIATE
// path. Without this, the raw routing fast path would skip ASSOCIATE forever and a node that
// later supports ASSOCIATE could never upgrade raw → standard.
func (p *Proxy) rawRecheckDue() bool {
	p.capMu.RLock()
	after := p.rawRecheckAfter
	p.capMu.RUnlock()
	return after.IsZero() || time.Now().After(after)
}

// scheduleRawRecheck defers the next ASSOCIATE recheck by rawRecheckInterval. It is called
// right before a raw node re-attempts ASSOCIATE, so a failed recheck (which falls back to raw
// relay) does not pay another doomed handshake on the very next association.
func (p *Proxy) scheduleRawRecheck() {
	p.capMu.Lock()
	p.rawRecheckAfter = time.Now().Add(rawRecheckInterval)
	p.capMu.Unlock()
}

// noteUDPCapabilityFailure records a failed UDP probe. It can only move an unknown/none
// node to none; a node that already established standard/raw keeps its last-known-good
// marker (the udpHealth circuit breaker reports the outage instead).
func (p *Proxy) noteUDPCapabilityFailure() {
	p.setUDPCapability(UDPCapNone)
}

// needsCapabilityClassify reports whether a real-traffic relay should be classified. It is
// true while the marker is unknown (first detection) or raw (an ASSOCIATE recheck may have
// just succeeded, upgrading raw → standard). A known standard node is never re-classified
// (no downgrade), and a none node is left for the probe to recover. setUDPCapability still
// enforces the sticky rules, so classifying an unchanged state is a no-op.
func (p *Proxy) needsCapabilityClassify() bool {
	switch p.UDPCapability() {
	case UDPCapUnknown, UDPCapRaw:
		return true
	}
	return false
}

// classifyUDPCapability records the capability from an established relay conn. The conn
// type tells the story: a standard SOCKS5 UDP ASSOCIATE carries a TCP control channel
// (tcpConn != nil); a raw relay (rawFallback or the udp_only/raw fast path) has none; any
// other UDP conn (ss) is a standard relay. setUDPCapability enforces the sticky rules.
func (p *Proxy) classifyUDPCapability(conn net.Conn) {
	switch c := conn.(type) {
	case *UDPProxyConn:
		if c.tcpConn != nil {
			p.setUDPCapability(UDPCapStandard)
		} else {
			p.setUDPCapability(UDPCapRaw)
		}
	default:
		p.setUDPCapability(UDPCapStandard)
	}
}

func (p *Proxy) IsAvailable() bool {
	return p.health.IsAvailable()
}

// IsUDPAvailable reports whether the independent UDP health circuit is closed. It is
// independent of IsAvailable (TCP), so a node can be TCP-healthy and UDP-broken, or
// UDP-healthy while its TCP path is down (udp_only).
func (p *Proxy) IsUDPAvailable() bool {
	return p.udpHealth.IsAvailable()
}

// pluginFromRawQuery extracts the ?plugin= SIP003 parameter directly from a URL's raw
// query string. It cannot use u.Query()/url.ParseQuery: Go's query parser silently drops
// the WHOLE query when a value contains a literal ';' (ss-android share links commonly use
// plugin=obfs-local;obfs=http;obfs-host=...), which would make the obfs plugin vanish and
// the node connect raw. We split on '&' only and unescape the value ourselves, so both the
// literal-';' form and the percent-encoded (%3B) form parse identically.
func pluginFromRawQuery(rawQuery string) string {
	for _, kv := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if k != "plugin" {
			continue
		}
		if unescaped, err := url.QueryUnescape(v); err == nil {
			return unescaped
		}
		return v
	}
	return ""
}

// boolFromRawQuery reports whether a raw query string sets key to a truthy value
// ("1", "true", "yes", "on"). Like pluginFromRawQuery it splits on '&' only — Go's
// url.Query() drops the whole query when any value contains a literal ';', which SIP003
// plugin values commonly do — so it is safe to run on any upstream URL.
func boolFromRawQuery(rawQuery, key string) bool {
	for _, kv := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if k != key {
			continue
		}
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

func NewProxy(proxyURL string) (*Proxy, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}

	scheme := ProxyScheme(strings.ToLower(u.Scheme))
	// Default ports follow the URI defaults of the reference clients: SOCKS 1080, HTTP 80,
	// shadowsocks 8388 (shadowsocks-rust Config::from_url uses port.unwrap_or(8388)).
	port := 1080
	switch {
	case u.Port() != "":
		port = parsePort(u.Port())
	case scheme == SchemeHTTP || scheme == SchemeHTTPS:
		port = 80
	case scheme == SchemeSS:
		port = 8388
	}

	p := &Proxy{
		URL:           proxyURL,
		Scheme:        scheme,
		Host:          u.Hostname(),
		Port:          port,
		udpCapability: UDPCapUnknown,
	}
	// The #fragment is the node's friendly name (shadowsocks-android reads the same
	// field as profile.name). url.Parse already percent-decodes Fragment, so use it
	// as-is; a missing fragment leaves the name empty.
	p.Name = strings.TrimSpace(u.Fragment)
	// udp_in_tcp selects the hev UDP-in-TCP relay for a socks5/socks5h node. Parsed
	// from the URL query so an imported link can carry it; the config entry's udp_in_tcp
	// field (the panel switch) is OR-ed in later by the manager (see rebuildFromConfig).
	if (scheme == SchemeSOCKS5 || scheme == SchemeSOCKS5H) && boolFromRawQuery(u.RawQuery, "udp_in_tcp") {
		p.UDPInTCP = true
		p.applyUDPInTCPDefaults()
	}
	if u.User != nil && scheme != SchemeSS {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}
	if scheme == SchemeSS {
		method, password, err := parseSSUserinfo(u.User)
		if err != nil && u.User == nil {
			// Legacy ss:// QR form: ss://base64(method:password@host:port) has no '@' in the URI,
			// so url.Parse leaves the whole base64 payload in Host. shadowsocks-rust
			// (Config::from_url) and shadowsocks-android (Profile.findAllUrls legacyPattern) both
			// accept it — decode the payload and recover method:password@host[:port].
			var hostPort string
			method, password, hostPort, err = parseSSLegacy(rawSSPayload(proxyURL))
			if err == nil {
				if h, hp, perr := net.SplitHostPort(hostPort); perr == nil {
					if pp, aerr := strconv.Atoi(hp); aerr == nil {
						p.Host = h // SplitHostPort already strips IPv6 brackets
						p.Port = pp
					}
				} else {
					p.Host = strings.Trim(hostPort, "[]")
				}
			}
		}
		if err != nil {
			return nil, err
		}
		ssMethod, err := newSSMethod(method, password)
		if err != nil {
			return nil, fmt.Errorf("invalid ss:// credentials for %q: %w", proxyURL, err)
		}
		p.ssMethod = ssMethod
		p.Username, p.Password = method, password
		// SIP003 plugin options: parsed and kept; at ssConnect time ssPlugin decides whether to run (built-in obfs-local) or error out.
		// Parsed from the raw query (not u.Query()) so a literal-';' plugin value survives (see pluginFromRawQuery).
		if plugin := pluginFromRawQuery(u.RawQuery); plugin != "" {
			p.Plugin = plugin
			// A plugin only obfuscates the TCP stream. Most deployments do not expose a UDP
			// relay, so a plugin node defaults to UDP down — equivalent to the user manually
			// disabling the UDP circuit. The dashboard badge can release it to automatic
			// (action=auto), which re-enables UDP probing; if the server's UDP port is
			// reachable directly the node then comes up as UDP-capable (see SchemeSupportsUDP).
			p.udpCapability = UDPCapNone
			p.udpHealth.SetManualState(false)
		}
	}
	slog.Info("upstream proxy loaded", "url", proxyURL, "name", p.Name)
	return p, nil
}

func parsePort(s string) int {
	var port int
	fmt.Sscanf(s, "%d", &port)
	return port
}

func (p *Proxy) Connect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	switch p.Scheme {
	case SchemeSOCKS5, SchemeSOCKS5H:
		return p.socks5Connect(ctx, targetHost, targetPort)
	case SchemeHTTP, SchemeHTTPS:
		return p.httpConnect(ctx, targetHost, targetPort)
	case SchemeSOCKS4:
		return p.socks4Connect(ctx, targetHost, targetPort)
	case SchemeSS:
		return p.ssConnect(ctx, targetHost, targetPort)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", p.Scheme)
	}
}

func (p *Proxy) UDPAssociate(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	// No effective-mode gate here: routing decides whether to call UDPAssociate
	// (SupportsUDP), while the health probe calls it regardless of the current circuits so a
	// degraded node can detect UDP recovery. Non-UDP schemes fail in the switch below.
	switch p.Scheme {
	case SchemeSOCKS5, SchemeSOCKS5H:
		// A udp_in_tcp node must be routed here first: socks5UDPAssociate's raw fast path
		// keys on IsUDPOnly(), which such a node satisfies by default (manual TCP-down) —
		// and that would skip the TCP handshake entirely, the exact opposite of what this
		// protocol requires. The framed path is mandatory for such nodes regardless of mode.
		if p.UDPInTCP {
			return p.socks5UDPInTCP(ctx)
		}
		return p.socks5UDPAssociate(ctx, targetHost, targetPort)
	case SchemeSS:
		return p.ssUDPAssociate(ctx, targetHost, targetPort)
	default:
		return nil, fmt.Errorf("UDP not supported for %s", p.Scheme)
	}
}

func (p *Proxy) socks5Connect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := p.socks5Handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	addr := encodeSocks5Addr(targetHost, targetPort)
	req := make([]byte, 3, 3+len(addr))
	req[0] = 0x05
	req[1] = 0x01
	req[2] = 0x00
	req = append(req, addr...)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed: rep=%d", resp[1])
	}
	if err := skipSOCKS5Addr(conn, resp[3]); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// rawUDPAssociate skips the SOCKS5 handshake and uses the upstream directly as a raw
// UDP relay. It relies on a UDP relay on the upstream's UDP port that "does not check
// the source and does not require ASSOCIATE" (e.g. shadowsocks-android's udp_only fallback instance), which forwards any frame carrying a SOCKS5 UDP header.
func (p *Proxy) rawUDPAssociate(raddr *net.UDPAddr) (*UDPProxyConn, error) {
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	slog.Debug("raw UDP relay established", "proxy", p.Host, "remoteAddr", raddr)
	return &UDPProxyConn{UDPConn: udpConn}, nil
}

// rawFallback tries a raw UDP relay at the upstream's own host:port after the standard
// SOCKS5 UDP ASSOCIATE flow failed (dial, handshake, request, any non-zero rep including
// 0x07 CommandNotSupported, or a bad bind reply). Raw UDP is fire-and-forget — packets drop
// silently if no relay listens there — so a failure here means the node has no working UDP
// relay at all.
func (p *Proxy) rawFallback(cause error) (*UDPProxyConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
	if err != nil {
		return nil, fmt.Errorf("UDP ASSOCIATE failed (%v) and raw UDP relay unreachable: %w", cause, err)
	}
	slog.Warn("UDP ASSOCIATE failed, falling back to raw UDP relay",
		"proxy", p.Host, "udpAddr", raddr, "cause", cause)
	conn, err := p.rawUDPAssociate(raddr)
	if err != nil {
		return nil, fmt.Errorf("UDP ASSOCIATE failed (%v) and raw UDP relay failed: %w", cause, err)
	}
	// No capability write here: a dialed raw socket is not proof the raw relay works end to
	// end (UDP is fire-and-forget). The marker is written only by an end-to-end success —
	// the health probe's classifyUDPCapability, or Manager on a real-traffic relay.
	return conn, nil
}

func (p *Proxy) socks5UDPAssociate(ctx context.Context, targetHost string, targetPort int) (*UDPProxyConn, error) {
	// Fast path: a udp_only upstream has no TCP listener to handshake over, and a node already
	// detected as raw-only (UDPCapability == raw) skips the doomed ASSOCIATE handshake — relay
	// straight to its own host:port as a raw UDP relay (the equivalent of shadowsocks-android's
	// udp_only fallback instance). This is the raw routing optimization: known raw nodes never
	// pay an ASSOCIATE attempt that is guaranteed to fail.
	//
	// A raw node whose recheck is due (rawRecheckInterval elapsed) falls through to the standard
	// ASSOCIATE path below instead, so it can upgrade raw → standard if the upstream later
	// starts supporting ASSOCIATE.
	if p.IsUDPOnly() || (p.UDPCapability() == UDPCapRaw && !p.rawRecheckDue()) {
		raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
		if err != nil {
			return nil, err
		}
		return p.rawUDPAssociate(raddr)
	}
	// Known-raw node whose recheck is due: schedule the next recheck now, so a failed recheck
	// (which falls back to the raw relay below) does not retry ASSOCIATE on every association.
	if p.UDPCapability() == UDPCapRaw {
		p.scheduleRawRecheck()
	}

	conn, err := p.dial(ctx)
	if err != nil {
		return p.rawFallback(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := p.socks5Handshake(conn); err != nil {
		conn.Close()
		return p.rawFallback(err)
	}
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return p.rawFallback(err)
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return p.rawFallback(err)
	}
	if resp[1] != 0x00 {
		conn.Close()
		// Any rep, including 0x07 (CommandNotSupported): the upstream's SOCKS5 may serve TCP
		// only, but the same host:port usually hosts a matching raw UDP relay — fall back to it.
		return p.rawFallback(fmt.Errorf("UDP ASSOCIATE rejected: rep=%d", resp[1]))
	}
	bndAddr, bndPort, err := readSOCKS5BindAddr(conn, resp[3])
	if err != nil {
		conn.Close()
		return p.rawFallback(err)
	}
	conn.SetDeadline(time.Time{})

	if bndAddr == "0.0.0.0" || bndAddr == "::" || bndAddr == "" || bndAddr == "[::]" {
		bndAddr = p.Host
	}

	slog.Debug("UDP ASSOCIATE response",
		"proxy", p.Host, "bindAddr", bndAddr, "bindPort", bndPort,
		"target", fmt.Sprintf("%s:%d", targetHost, targetPort))

	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bndAddr, fmt.Sprintf("%d", bndPort)))
	if err != nil {
		conn.Close()
		return p.rawFallback(err)
	}
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		slog.Error("UDP ASSOCIATE dial failed", "proxy", p.Host, "bindAddr", raddr, "error", err)
		conn.Close()
		return p.rawFallback(err)
	}
	slog.Debug("UDP ASSOCIATE established",
		"proxy", p.Host, "localAddr", udpConn.LocalAddr(), "remoteAddr", raddr)
	return &UDPProxyConn{UDPConn: udpConn, tcpConn: conn}, nil
}

// socks5UDPInTCP establishes a hev UDP-in-TCP relay (hev-socks5-server's private
// CMD=5 FWD_UDP extension): UDP datagrams are framed over the same TCP connection, so the
// node needs no UDP listener at all. It is selected explicitly per-node (UDPInTCP), so
// failures are returned as-is — there is deliberately no raw UDP fallback, because this
// node has no UDP path to fall back to.
func (p *Proxy) socks5UDPInTCP(ctx context.Context) (net.Conn, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := p.socks5Handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}
	// CMD=5 (HEV_SOCKS5_REQ_CMD_FWD_UDP) is a hev private extension — standard SOCKS5 only
	// defines 1=CONNECT, 2=BIND, 3=UDP_ASSOCIATE. The address block is an all-zero IPv4;
	// the server replies with the usual VER REP RSV ATYP BND.ADDR BND.PORT.
	req := []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("UDP-in-TCP handshake rejected: rep=%d", resp[1])
	}
	if err := skipSOCKS5Addr(conn, resp[3]); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})

	slog.Debug("UDP-in-TCP relay established", "proxy", p.Host)
	return newUDPInTCPConn(conn), nil
}

// udpInTCPConn adapts a hev UDP-in-TCP framed byte stream to the SOCKS5 UDP packet
// shape the rest of SmartProxy uses. Both formats share the exact same address block
// (ATYP + addr + port) and differ only in the leading 3 bytes:
//
//	SOCKS5 UDP packet : RSV(2) FRAG(1) ATYP ADDR PORT payload
//	hev frame         : datlen(2) hdrlen(1) ATYP ADDR PORT payload
//
// datlen/hdrlen are big-endian and hdrlen = 3 + len(addr block), so the conversion is a
// drop-in swap of the 3-byte prefix (same total length). Write translates SOCKS5 UDP packet
// → hev frame, Read translates the reverse.
type udpInTCPConn struct {
	conn net.Conn
}

func newUDPInTCPConn(conn net.Conn) *udpInTCPConn {
	return &udpInTCPConn{conn: conn}
}

func (u *udpInTCPConn) Read(p []byte) (int, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(u.conn, hdr[:]); err != nil {
		return 0, err
	}
	hdrLen := int(hdr[2])
	if hdrLen < 5 {
		return 0, fmt.Errorf("udp-over-tcp: malformed frame header (hdrlen=%d)", hdrLen)
	}
	addrLen := hdrLen - 3
	total := 3 + addrLen + int(binary.BigEndian.Uint16(hdr[0:2]))
	if total > len(p) {
		return 0, io.ErrShortBuffer
	}
	// Everything after the frame header is byte-identical to a SOCKS5 UDP packet's
	// addr block + payload; only prefix it with the RSV+FRAG zeros.
	p[0], p[1], p[2] = 0, 0, 0
	if _, err := io.ReadFull(u.conn, p[3:total]); err != nil {
		return 0, err
	}
	return total, nil
}

func (u *udpInTCPConn) Write(p []byte) (int, error) {
	if len(p) < 4 {
		return 0, fmt.Errorf("udp-over-tcp: SOCKS5 UDP packet too short")
	}
	addrLen := udpInTCPAddrLen(p[3:])
	if addrLen < 0 || 3+addrLen > len(p) {
		return 0, fmt.Errorf("udp-over-tcp: malformed SOCKS5 UDP address block")
	}
	hdrLen := 3 + addrLen
	// Drop RSV+FRAG, prepend datlen+hdrlen — the frame has the same total length.
	frame := make([]byte, len(p))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(p)-hdrLen))
	frame[2] = byte(hdrLen)
	copy(frame[3:], p[3:])
	if _, err := u.conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// udpInTCPAddrLen returns the on-wire length of a SOCKS5 UDP address block
// (ATYP + addr + port) given a slice starting at ATYP, or -1 if malformed.
func udpInTCPAddrLen(atyp []byte) int {
	if len(atyp) == 0 {
		return -1
	}
	switch atyp[0] {
	case 0x01:
		return 7
	case 0x04:
		return 19
	case 0x03:
		if len(atyp) < 2 {
			return -1
		}
		return 4 + int(atyp[1])
	default:
		return -1
	}
}

// ProbeTCP lets the UDP reuse pool verify a pooled conn. The TCP stream here carries framed
// data, not a control channel, so a probe read would consume a frame — always report healthy
// (TTL eviction is the fallback), matching ss UDP / raw UDP conns.
func (u *udpInTCPConn) ProbeTCP() error { return nil }

func (u *udpInTCPConn) Close() error                       { return u.conn.Close() }
func (u *udpInTCPConn) LocalAddr() net.Addr                { return u.conn.LocalAddr() }
func (u *udpInTCPConn) RemoteAddr() net.Addr               { return u.conn.RemoteAddr() }
func (u *udpInTCPConn) SetDeadline(t time.Time) error      { return u.conn.SetDeadline(t) }
func (u *udpInTCPConn) SetReadDeadline(t time.Time) error  { return u.conn.SetReadDeadline(t) }
func (u *udpInTCPConn) SetWriteDeadline(t time.Time) error { return u.conn.SetWriteDeadline(t) }

func (p *Proxy) socks5Handshake(rw io.ReadWriter) error {
	methods := []byte{0x00}
	if p.Username != "" && p.Password != "" {
		methods = append(methods, 0x02)
	}
	authReq := []byte{0x05, byte(len(methods))}
	authReq = append(authReq, methods...)
	if _, err := rw.Write(authReq); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(rw, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] == 0xFF {
		return errors.New("SOCKS5 handshake failed")
	}
	if buf[1] == 0x02 {
		if p.Username == "" || p.Password == "" {
			return errors.New("SOCKS5 auth required but no credentials")
		}
		authReq := []byte{1, byte(len(p.Username))}
		authReq = append(authReq, []byte(p.Username)...)
		authReq = append(authReq, byte(len(p.Password)))
		authReq = append(authReq, []byte(p.Password)...)
		if _, err := rw.Write(authReq); err != nil {
			return err
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(rw, authResp); err != nil {
			return err
		}
		if authResp[1] != 0 {
			return errors.New("SOCKS5 authentication failed")
		}
	}
	return nil
}

func encodeSocks5Addr(host string, port int) []byte {
	ip := net.ParseIP(host)
	if ip == nil {
		domain := []byte(host)
		buf := make([]byte, 4+len(domain))
		buf[0] = 0x03
		buf[1] = byte(len(domain))
		copy(buf[2:], domain)
		binary.BigEndian.PutUint16(buf[2+len(domain):], uint16(port))
		return buf
	}
	if ip4 := ip.To4(); ip4 != nil {
		buf := make([]byte, 7)
		buf[0] = 0x01
		copy(buf[1:], ip4)
		binary.BigEndian.PutUint16(buf[5:], uint16(port))
		return buf
	}
	buf := make([]byte, 19)
	buf[0] = 0x04
	copy(buf[1:], ip.To16())
	binary.BigEndian.PutUint16(buf[17:], uint16(port))
	return buf
}

func skipSOCKS5Addr(r io.Reader, atyp byte) error {
	switch atyp {
	case 0x01:
		_, err := io.ReadFull(r, make([]byte, 4+2))
		return err
	case 0x03:
		lenB := make([]byte, 1)
		if _, err := io.ReadFull(r, lenB); err != nil {
			return err
		}
		_, err := io.ReadFull(r, make([]byte, int(lenB[0])+2))
		return err
	case 0x04:
		_, err := io.ReadFull(r, make([]byte, 16+2))
		return err
	default:
		return fmt.Errorf("unsupported address type: %d", atyp)
	}
}

func readSOCKS5BindAddr(r io.Reader, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case 0x03:
		lenB := make([]byte, 1)
		if _, err := io.ReadFull(r, lenB); err != nil {
			return "", 0, err
		}
		buf := make([]byte, int(lenB[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(portBuf)), nil
}

func (p *Proxy) dial(ctx context.Context) (net.Conn, error) {
	addr := net.JoinHostPort(p.Host, fmt.Sprintf("%d", p.Port))
	d := net.Dialer{Timeout: proxyDialTimeout, Control: fwmark.Control}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(15 * time.Second)
		tcp.SetNoDelay(true)
		netutil.SetKeepAliveInterval(tcp, 15*time.Second)
	}
	return conn, nil
}

func (p *Proxy) httpConnect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	if p.Scheme == SchemeHTTPS {
		tlsCfg := &tls.Config{ServerName: p.Host}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	// net.JoinHostPort brackets IPv6 literals (e.g. [2001:db8::1]:443);
	// a raw fmt.Sprintf("%s:%d", host, port) would produce a malformed request-target.
	target := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if p.Username != "" && p.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			conn.Close()
			return nil, err
		}
		buf = append(buf, tmp[:n]...)
		if strings.Contains(string(buf), "\r\n\r\n") {
			break
		}
		if len(buf) > 65536 {
			conn.Close()
			return nil, fmt.Errorf("HTTP proxy response headers too large")
		}
	}
	statusLine := strings.SplitN(string(buf), "\r\n", 2)[0]
	parts := strings.Fields(statusLine)
	if len(parts) < 2 {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy returned malformed status line: %q", statusLine)
	}
	if parts[1] != "200" {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy returned %s", parts[1])
	}
	return conn, nil
}

func (p *Proxy) socks4Connect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	targetIP, err := resolveIPv4(ctx, targetHost)
	if err != nil {
		conn.Close()
		return nil, err
	}
	userID := p.Username
	// make([]byte, 9+len(userID)) is zero-initialized, so the null terminator
	// after USERID is already in place (byte at index 8+len(userID)).
	req := make([]byte, 9+len(userID))
	req[0] = 0x04
	req[1] = 0x01
	binary.BigEndian.PutUint16(req[2:], uint16(targetPort))
	copy(req[4:8], targetIP.To4())
	copy(req[8:], userID)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x5a {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 connect failed: code=%d", resp[1])
	}
	return conn, nil
}

func resolveIPv4(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	addr, err := netip.ParseAddr(host)
	if err == nil {
		if addr.Is4() {
			a := addr.As4()
			return net.IP(a[:]), nil
		}
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no IPv4 address for %s", host)
	}
	a := addrs[0].As4()
	return net.IP(a[:]), nil
}

type UDPProxyConn struct {
	*net.UDPConn
	tcpConn net.Conn
}

func (u *UDPProxyConn) Close() error {
	if u.tcpConn != nil {
		u.tcpConn.Close()
	}
	return u.UDPConn.Close()
}

// ProbeTCP lets the UDP reuse pool verify a connection is still usable. The SOCKS5 UDP
// ASSOCIATE TCP control channel is probed with a 5ms quick read: read timeout = healthy
// (the control channel should never carry data); data read or error = broken. Raw UDP / ss UDP have no control channel (tcpConn is nil), so they are always considered healthy.
func (u *UDPProxyConn) ProbeTCP() error {
	if u.tcpConn == nil {
		return nil
	}
	u.tcpConn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	_, probeErr := u.tcpConn.Read(make([]byte, 1))
	if probeErr != nil {
		if netErr, ok := probeErr.(net.Error); ok && netErr.Timeout() {
			u.UDPConn.SetDeadline(time.Time{})
			u.tcpConn.SetDeadline(time.Time{})
			return nil
		}
		return probeErr
	}
	return errors.New("unexpected data on UDP ASSOCIATE control channel")
}

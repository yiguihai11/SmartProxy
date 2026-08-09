package upstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"smartproxy/internal/safego"

	"smartproxy/internal/config"
)

type ProxyState int

const (
	StateClosed ProxyState = iota
	StateOpen
	StateHalfOpen
)

type ProxyHealth struct {
	mu                   sync.RWMutex
	state                ProxyState
	consecutiveFailures  int
	consecutiveSuccesses int
	lastAttempt          time.Time
	openSince            time.Time
	latency              time.Duration
	// manual pins the circuit to a fixed availability (true=force up, false=force down)
	// until ClearManualState. While set, probe results keep refreshing latency/lastAttempt
	// but never move state — that is what makes per-circuit manual disable/enable sticky
	// across health-check cycles. nil means fully automatic control.
	manual *bool
}

func (ph *ProxyHealth) Latency() time.Duration {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return ph.latency
}

// SetManualState pins a circuit to a fixed availability and keeps it pinned (sticky):
// probes keep recording latency/lastAttempt but the circuit cannot move on its own until
// ClearManualState. available=true forces the circuit up, false forces it down.
func (ph *ProxyHealth) SetManualState(available bool) {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	m := available
	ph.manual = &m
	if available {
		ph.state = StateClosed
		ph.consecutiveFailures = 0
		ph.consecutiveSuccesses = 0
		ph.openSince = time.Time{}
	} else {
		ph.state = StateOpen
		ph.consecutiveFailures = 0
		ph.consecutiveSuccesses = 0
		ph.openSince = time.Now()
	}
}

// ClearManualState returns a circuit to automatic health-check control, starting from
// closed (available). A real outage re-opens it on the next probe cycle.
func (ph *ProxyHealth) ClearManualState() {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	ph.manual = nil
	ph.state = StateClosed
	ph.consecutiveFailures = 0
	ph.consecutiveSuccesses = 0
	ph.openSince = time.Time{}
}

// IsManuallyDisabled reports whether the circuit is pinned down by SetManualState(false).
// Unlike IsAvailable (which is also false while a circuit is auto-open from probe failures),
// this distinguishes an explicit user "Disable" — rule routing must not use such a circuit.
func (ph *ProxyHealth) IsManuallyDisabled() bool {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return ph.manual != nil && !*ph.manual
}

func (ph *ProxyHealth) reset() {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	ph.state = StateClosed
	ph.consecutiveFailures = 0
	ph.consecutiveSuccesses = 0
	ph.lastAttempt = time.Time{}
	ph.openSince = time.Time{}
	ph.latency = 0
}

func (ph *ProxyHealth) IsAvailable() bool {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	if ph.state == StateClosed {
		return true
	}
	if ph.state == StateHalfOpen {
		return true
	}
	return false
}

type ProxyHealthSnapshot struct {
	State                string        `json:"state"`
	Available            bool          `json:"available"`
	Manual               bool          `json:"manual"` // pinned by SetManualState, not moving with probes
	Latency              time.Duration `json:"latency"`
	ConsecutiveFailures  int           `json:"consecutive_failures"`
	ConsecutiveSuccesses int           `json:"consecutive_successes"`
	LastAttempt          string        `json:"last_attempt,omitempty"`
	OpenSince            string        `json:"open_since,omitempty"`
}

func (ph *ProxyHealth) Snapshot() ProxyHealthSnapshot {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	state := "closed"
	if ph.state == StateOpen {
		state = "open"
	} else if ph.state == StateHalfOpen {
		state = "half_open"
	}
	s := ProxyHealthSnapshot{
		State:                state,
		Available:            ph.state != StateOpen,
		Manual:               ph.manual != nil,
		Latency:              ph.latency,
		ConsecutiveFailures:  ph.consecutiveFailures,
		ConsecutiveSuccesses: ph.consecutiveSuccesses,
	}
	if !ph.lastAttempt.IsZero() {
		s.LastAttempt = ph.lastAttempt.Format(time.RFC3339)
	}
	if !ph.openSince.IsZero() {
		s.OpenSince = ph.openSince.Format(time.RFC3339)
	}
	return s
}

type HealthChecker struct {
	cfg     atomic.Pointer[config.HealthCheckConf]
	proxies []*Proxy
	stopCh  chan struct{}
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewHealthChecker(cfg config.HealthCheckConf, proxies []*Proxy) *HealthChecker {
	ctx, cancel := context.WithCancel(context.Background())
	hc := &HealthChecker{
		proxies: proxies,
		stopCh:  make(chan struct{}),
		ctx:     ctx,
		cancel:  cancel,
	}
	hc.cfg.Store(&cfg)
	return hc
}

func (hc *HealthChecker) Start() {
	cfg := hc.cfg.Load()
	if !cfg.Enabled {
		return
	}
	if cfg.AutoDisableSingle && len(hc.proxies) <= 1 {
		slog.Info("health check disabled: only one upstream proxy")
		return
	}

	for _, p := range hc.proxies {
		hc.wg.Add(1)
		safego.Go("upstream.health.checkLoop", func() { hc.checkLoop(p) })
	}
}

func (hc *HealthChecker) Stop() {
	hc.cancel()
	close(hc.stopCh)
	hc.wg.Wait()
}

func (hc *HealthChecker) Reload(cfg config.HealthCheckConf, proxies []*Proxy) {
	hc.Stop()
	hc.cfg.Store(&cfg)
	hc.proxies = proxies
	hc.stopCh = make(chan struct{})
	hc.ctx, hc.cancel = context.WithCancel(context.Background())
	hc.Start()
}

func (hc *HealthChecker) checkLoop(p *Proxy) {
	defer hc.wg.Done()

	select {
	case <-time.After(time.Duration(time.Now().UnixNano()%2000) * time.Millisecond):
	case <-hc.stopCh:
		return
	}

	for {
		cfg := hc.cfg.Load()
		interval := time.Duration(cfg.Interval) * time.Second
		if interval <= 0 {
			interval = 60 * time.Second
		}

		hc.checkProxy(p)

		select {
		case <-time.After(interval):
		case <-hc.stopCh:
			return
		}
	}
}

// checkProxy probes a proxy. TCP and UDP use independent circuits. The probe direction is
// scheme-based (SchemeSupportsUDP): only SOCKS5/SOCKS5h/SS get the DNS UDP probe feeding
// udpHealth; every node gets the HTTP probe feeding health. There is no configured base mode
// to gate probing — a node whose UDP circuit is currently open still gets UDP probes so it
// can detect UDP recovery, and one whose TCP circuit is open still gets TCP probes.
func (hc *HealthChecker) checkProxy(p *Proxy) {
	if p.SchemeSupportsUDP() {
		hc.checkProxyUDP(p)
	}
	hc.checkProxyTCP(p)
}

func (hc *HealthChecker) checkProxyTCP(p *Proxy) {
	cfg := hc.cfg.Load()

	p.health.mu.RLock()
	state := p.health.state
	openSince := p.health.openSince
	p.health.mu.RUnlock()

	if state == StateOpen {
		if time.Since(openSince) < time.Duration(cfg.OpenCoolDown)*time.Second {
			return
		}
	}

	ctx, cancel := context.WithTimeout(hc.ctx, time.Duration(cfg.Timeout)*time.Second)
	defer cancel()

	start := time.Now()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port := 80
			if p := parsePort(portStr); p > 0 {
				port = p
			}
			return p.Connect(ctx, host, port)
		},
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", cfg.URL, nil)
	var success bool
	var doErr error
	if err == nil {
		resp, err := client.Do(req)
		doErr = err
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				success = true
			} else {
				doErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
			}
		}
	} else {
		doErr = err
	}

	latency := time.Since(start)

	if success {
		hc.RecordSuccess(p, latency)
	} else {
		hc.RecordFailure(p, doErr)
	}
}

// checkProxyUDP actively probes a node's UDP relay with a DNS query, feeding the
// independent udpHealth circuit. It honors the same open-cool-down gate as the TCP probe.
func (hc *HealthChecker) checkProxyUDP(p *Proxy) {
	cfg := hc.cfg.Load()

	p.udpHealth.mu.RLock()
	state := p.udpHealth.state
	openSince := p.udpHealth.openSince
	p.udpHealth.mu.RUnlock()

	if state == StateOpen {
		if time.Since(openSince) < time.Duration(cfg.OpenCoolDown)*time.Second {
			return
		}
	}

	ctx, cancel := context.WithTimeout(hc.ctx, time.Duration(cfg.Timeout)*time.Second)
	defer cancel()

	latency, conn, err := hc.probeUDP(p, ctx)
	if err != nil {
		// End-to-end UDP failure. On a still-unknown node this marks it none; a node that
		// already established standard/raw keeps its last-known-good marker (the circuit
		// breaker below reports the outage instead).
		p.noteUDPCapabilityFailure()
		hc.RecordUDPFailure(p, err)
		return
	}
	defer conn.Close()
	// The relay path worked end to end — record how it works (standard ASSOCIATE vs raw).
	p.classifyUDPCapability(conn)
	hc.RecordUDPSuccess(p, latency)
}

// probeUDP sends a real DNS A query through the proxy's UDP relay and requires a valid
// DNS response. It reuses the normal relay path (p.UDPAssociate), so the probe exercises
// exactly the route real UDP traffic takes: standard SOCKS5 UDP ASSOCIATE with the raw
// fallback for socks5, the raw relay for udp_only, and the ss UDP relay for ss://. A DNS
// response (matching TXID + QR bit) proves the node's UDP relay is alive end to end.
//
// On success the established conn is returned (not closed) so the caller can classify the
// relay type (standard vs raw) before closing it; on any failure the conn is closed here.
func (hc *HealthChecker) probeUDP(p *Proxy, ctx context.Context) (time.Duration, net.Conn, error) {
	cfg := hc.cfg.Load()
	dnsServer := cfg.UDPProbeDNS
	if dnsServer == "" {
		dnsServer = "1.1.1.1:53"
	}
	domain := cfg.UDPProbeDomain
	if domain == "" {
		domain = "dns.google"
	}
	host, portStr, err := net.SplitHostPort(dnsServer)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid udp_probe_dns %q: %w", dnsServer, err)
	}
	port := 53
	if p := parsePort(portStr); p > 0 {
		port = p
	}

	conn, err := p.UDPAssociate(ctx, host, port)
	if err != nil {
		return 0, nil, err
	}

	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	packed, err := query.Pack()
	if err != nil {
		conn.Close()
		return 0, nil, err
	}
	txid := query.Id

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	start := time.Now()
	if _, err := conn.Write(buildUDPFrame(host, port, packed)); err != nil {
		conn.Close()
		return 0, nil, err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return 0, nil, err
	}
	latency := time.Since(start)

	payload, err := parseUDPFrame(buf[:n])
	if err != nil {
		conn.Close()
		return 0, nil, err
	}
	var resp dns.Msg
	if err := resp.Unpack(payload); err != nil {
		conn.Close()
		return 0, nil, fmt.Errorf("invalid DNS response: %w", err)
	}
	if resp.Id != txid || !resp.Response {
		conn.Close()
		return 0, nil, fmt.Errorf("invalid DNS response (id=%d, response=%v)", resp.Id, resp.Response)
	}
	return latency, conn, nil
}

// buildUDPFrame wraps a payload in a SOCKS5 UDP relay header (RSV=0, FRAG=0, ATYP
// addr + port) addressed to host:port — the same framing internal/udp uses on the wire.
func buildUDPFrame(host string, port int, payload []byte) []byte {
	addr := encodeSocks5Addr(host, port)
	frame := make([]byte, 3+len(addr)+len(payload))
	copy(frame[3:], addr)
	copy(frame[3+len(addr):], payload)
	return frame
}

// parseUDPFrame strips a SOCKS5 UDP relay header and returns the payload. The header is
// RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT, so the payload starts at 3 + 1 + addr+port.
func parseUDPFrame(frame []byte) ([]byte, error) {
	if len(frame) < 4 {
		return nil, errors.New("short UDP frame")
	}
	if frame[0] != 0 || frame[1] != 0 || frame[2] != 0 {
		return nil, fmt.Errorf("bad UDP frame header: rsv/frag=%d %d %d", frame[0], frame[1], frame[2])
	}
	atyp := frame[3]
	var hdrLen int // ATYP + addr + port
	switch atyp {
	case 0x01:
		hdrLen = 1 + 4 + 2
	case 0x04:
		hdrLen = 1 + 16 + 2
	case 0x03:
		if len(frame) < 5 {
			return nil, errors.New("short UDP frame")
		}
		hdrLen = 1 + 1 + int(frame[4]) + 2
	default:
		return nil, fmt.Errorf("unsupported UDP frame address type: %d", atyp)
	}
	if len(frame) < 3+hdrLen {
		return nil, errors.New("short UDP frame")
	}
	return frame[3+hdrLen:], nil
}

// RecordSuccess records a TCP probe success on the TCP circuit (p.health).
func (hc *HealthChecker) RecordSuccess(p *Proxy, latency time.Duration) {
	hc.recordSuccess(p, &p.health, "tcp", latency)
}

// RecordUDPSuccess records a UDP probe success on the independent UDP circuit (p.udpHealth).
func (hc *HealthChecker) RecordUDPSuccess(p *Proxy, latency time.Duration) {
	hc.recordSuccess(p, &p.udpHealth, "udp", latency)
}

// RecordFailure records a TCP failure on the TCP circuit (p.health).
func (hc *HealthChecker) RecordFailure(p *Proxy, err error) {
	hc.recordFailure(p, &p.health, "tcp", err)
}

// RecordUDPFailure records a UDP failure on the independent UDP circuit (p.udpHealth).
func (hc *HealthChecker) RecordUDPFailure(p *Proxy, err error) {
	hc.recordFailure(p, &p.udpHealth, "udp", err)
}

func (hc *HealthChecker) recordSuccess(p *Proxy, ph *ProxyHealth, circuit string, latency time.Duration) {
	cfg := hc.cfg.Load()
	if !cfg.Enabled {
		return
	}
	ph.mu.Lock()
	defer ph.mu.Unlock()

	ph.lastAttempt = time.Now()
	if latency > 0 {
		if ph.latency == 0 {
			ph.latency = latency
		} else {
			ph.latency = (ph.latency*3 + latency) / 4
		}
	}
	if ph.manual != nil {
		// Manually pinned: keep refreshing latency/lastAttempt but never move state.
		return
	}

	switch ph.state {
	case StateClosed:
		ph.consecutiveFailures = 0
	case StateOpen:

	case StateHalfOpen:
		ph.consecutiveSuccesses++
		if ph.consecutiveSuccesses >= cfg.SuccessesThreshold {
			ph.state = StateClosed
			ph.consecutiveFailures = 0
			ph.consecutiveSuccesses = 0
			slog.Info("proxy recovered", "url", p.URL, "circuit", circuit, "latency", latency)
		}
	}
}

func (hc *HealthChecker) recordFailure(p *Proxy, ph *ProxyHealth, circuit string, err error) {
	cfg := hc.cfg.Load()
	if !cfg.Enabled {
		return
	}
	ph.mu.Lock()
	defer ph.mu.Unlock()

	ph.lastAttempt = time.Now()
	if ph.manual != nil {
		// Manually pinned: keep refreshing lastAttempt but never move state.
		return
	}

	switch ph.state {
	case StateClosed:
		ph.consecutiveFailures++
		if ph.consecutiveFailures >= cfg.FailuresThreshold {
			ph.state = StateOpen
			ph.openSince = time.Now()
			slog.Warn("proxy circuit opened", "url", p.URL, "circuit", circuit, "failures", ph.consecutiveFailures, "error", err)
		}
	case StateOpen:
		if time.Since(ph.openSince) >= time.Duration(cfg.OpenCoolDown)*time.Second {
			ph.state = StateHalfOpen
			ph.consecutiveSuccesses = 0
			// Keep consecutiveFailures at the count that opened the circuit: a circuit that
			// half-opens and re-opens repeatedly must keep showing a real failure count in the
			// dashboard, not a misleading 0 next to a "down" badge. Recovery resets it to 0
			// (recordSuccess in StateHalfOpen).
			slog.Info("proxy circuit half-open", "url", p.URL, "circuit", circuit)
		}
	case StateHalfOpen:
		ph.state = StateOpen
		ph.openSince = time.Now()
		ph.consecutiveSuccesses = 0
		slog.Warn("proxy circuit re-opened", "url", p.URL, "circuit", circuit, "error", err)
	}
}

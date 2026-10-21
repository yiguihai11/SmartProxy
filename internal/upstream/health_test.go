package upstream

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"smartproxy/internal/config"
)

func TestSetManualState_Disable(t *testing.T) {
	ph := &ProxyHealth{}
	if !ph.IsAvailable() {
		t.Fatal("expected available initially")
	}

	ph.SetManualState(false)
	if ph.IsAvailable() {
		t.Error("expected unavailable after SetManualState(false)")
	}
}

func TestSetManualState_Enable(t *testing.T) {
	ph := &ProxyHealth{}
	ph.SetManualState(false)
	if ph.IsAvailable() {
		t.Fatal("expected unavailable after disable")
	}

	ph.SetManualState(true)
	if !ph.IsAvailable() {
		t.Error("expected available after SetManualState(true)")
	}
}

func TestSetManualState_ResetsFailures(t *testing.T) {
	ph := &ProxyHealth{}
	// Simulate prior state
	ph.state = StateOpen
	ph.consecutiveFailures = 5

	ph.SetManualState(true)
	snap := ph.Snapshot()
	if snap.ConsecutiveFailures != 0 {
		t.Errorf("expected 0 failures after enable, got %d", snap.ConsecutiveFailures)
	}
}

func TestSetManualState_Snapshot(t *testing.T) {
	ph := &ProxyHealth{}
	ph.SetManualState(false)
	snap := ph.Snapshot()
	if snap.State != "open" {
		t.Errorf("expected state open, got %s", snap.State)
	}
	if snap.Available {
		t.Error("expected available=false")
	}

	ph.SetManualState(true)
	snap = ph.Snapshot()
	if snap.State != "closed" {
		t.Errorf("expected state closed, got %s", snap.State)
	}
	if !snap.Available {
		t.Error("expected available=true")
	}
}

func TestResetAutoOpened(t *testing.T) {
	// Auto-opened by probe failures (no manual pin) → resets to closed/available.
	ph := &ProxyHealth{}
	ph.state = StateOpen
	ph.consecutiveFailures = 2
	ph.openSince = time.Now()
	if !ph.resetAutoOpened() {
		t.Fatal("expected auto-open circuit to be reported as reset")
	}
	if !ph.IsAvailable() {
		t.Error("expected available after reset")
	}
	if s := ph.Snapshot(); s.State != "closed" || s.ConsecutiveFailures != 0 {
		t.Errorf("expected closed with 0 failures, got state=%s failures=%d", s.State, s.ConsecutiveFailures)
	}
	// Second call is a no-op.
	if ph.resetAutoOpened() {
		t.Error("closed circuit must not be reported as reset")
	}

	// Half-open auto → also reset.
	phHalf := &ProxyHealth{}
	phHalf.state = StateHalfOpen
	if !phHalf.resetAutoOpened() || !phHalf.IsAvailable() {
		t.Error("half-open circuit should reset to available")
	}

	// Manually pinned circuits are never touched, whichever way they are pinned.
	manualDown := &ProxyHealth{}
	manualDown.SetManualState(false) // state=open, manual=false
	if manualDown.resetAutoOpened() {
		t.Error("manual-down circuit must not be reset")
	}
	if !manualDown.IsManuallyDisabled() || manualDown.IsAvailable() {
		t.Error("manual-down pin must survive resetAutoOpened")
	}
	manualUp := &ProxyHealth{}
	manualUp.SetManualState(true) // state=closed, manual=true
	if manualUp.resetAutoOpened() {
		t.Error("manual-up circuit must not be reset")
	}
	if _, pinned := manualUp.ManualPin(); !pinned {
		t.Error("manual-up pin must survive resetAutoOpened")
	}
}

func TestSetManualState_Multiple(t *testing.T) {
	ph := &ProxyHealth{}
	ph.SetManualState(false)
	ph.SetManualState(true)
	ph.SetManualState(false)
	if ph.IsAvailable() {
		t.Error("expected unavailable after toggle disable")
	}
	// Latency should not be affected by SetManualState
	ph.SetManualState(false)
	_ = ph.Latency() // just ensure no panic
}

// TestManual_PinnedNotMovedByProbes: a circuit pinned via SetManualState must not move when
// the health checker records probe results — that is what makes manual disable sticky.
func TestManual_PinnedNotMovedByProbes(t *testing.T) {
	hc := NewHealthChecker(config.HealthCheckConf{Enabled: true}, nil)
	ph := &ProxyHealth{}
	ph.SetManualState(false) // force down

	// A probe success must NOT reopen a pinned-down circuit, but latency/lastAttempt still refresh.
	hc.recordSuccess(&Proxy{}, ph, "tcp", time.Millisecond)
	if ph.IsAvailable() {
		t.Fatal("manual down must survive probe success")
	}
	snap := ph.Snapshot()
	if !snap.Manual {
		t.Error("expected manual=true")
	}
	if snap.LastAttempt == "" {
		t.Error("expected lastAttempt still refreshed while pinned")
	}
	if snap.Latency != time.Millisecond {
		t.Errorf("expected latency refreshed, got %v", snap.Latency)
	}

	// Release back to auto: the next success closes the circuit normally.
	ph.ClearManualState()
	if snap := ph.Snapshot(); snap.Manual {
		t.Error("expected manual=false after ClearManualState")
	}
	if !ph.IsAvailable() {
		t.Fatal("expected available right after release to auto")
	}
	hc.recordSuccess(&Proxy{}, ph, "tcp", time.Millisecond)
	if !ph.IsAvailable() {
		t.Error("expected still available after a normal success")
	}
}

// TestManual_ForceUpSurvivesFailures: a pinned-up circuit stays closed across probe failures.
func TestManual_ForceUpSurvivesFailures(t *testing.T) {
	hc := NewHealthChecker(config.HealthCheckConf{Enabled: true}, nil)
	ph := &ProxyHealth{}
	ph.SetManualState(true) // force up

	for i := 0; i < 3; i++ {
		hc.recordFailure(&Proxy{}, ph, "tcp", errors.New("boom"))
	}
	if !ph.IsAvailable() {
		t.Fatal("manual up must survive probe failures")
	}
	if snap := ph.Snapshot(); snap.State != "closed" {
		t.Errorf("expected state closed, got %s", snap.State)
	}
}

// assertGateClosed / assertGateOpen 校验按电路分闸门的状态。
func assertGateClosed(t *testing.T, name string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	default:
		t.Fatalf("%s gate should be closed", name)
	}
}

func assertGateOpen(t *testing.T, name string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s gate should still be open", name)
	default:
	}
}

// TestFirstProbeDone_PerCircuitGates 回归冷启动硬失败:checkProxy 先探 UDP 后探 TCP,
// UDP 先成功时只能关闭 UDP 闸门和聚合闸门,绝不能替 TCP 闸门放行——否则 ConnectDefault
// 在所有 TCP 电路还是 unverified 时被放行,逐个 skip 后直接 "failed to connect via upstream"。
func TestFirstProbeDone_PerCircuitGates(t *testing.T) {
	hc := NewHealthChecker(config.HealthCheckConf{Enabled: true}, nil)
	p := &Proxy{}
	p.health.SetInitialUnverified()
	p.udpHealth.SetInitialUnverified()

	assertGateOpen(t, "tcp", hc.FirstTCPProbeDone())
	assertGateOpen(t, "udp", hc.FirstUDPProbeDone())
	assertGateOpen(t, "aggregate", hc.FirstProbeDone())

	hc.RecordUDPSuccess(p, time.Millisecond)
	assertGateOpen(t, "tcp after udp success", hc.FirstTCPProbeDone())
	assertGateClosed(t, "udp after udp success", hc.FirstUDPProbeDone())
	assertGateClosed(t, "aggregate after udp success", hc.FirstProbeDone())

	hc.RecordSuccess(p, time.Millisecond)
	assertGateClosed(t, "tcp after tcp success", hc.FirstTCPProbeDone())
}

// TestFirstProbeDone_StartDisabledOpensAll: 探测禁用/无节点/单节点时三条闸门都得放行,
// 不能让某个转发入口永远等到 800ms 超时。
func TestFirstProbeDone_StartDisabledOpensAll(t *testing.T) {
	hc := NewHealthChecker(config.HealthCheckConf{Enabled: false}, []*Proxy{{}})
	hc.Start()
	assertGateClosed(t, "tcp", hc.FirstTCPProbeDone())
	assertGateClosed(t, "udp", hc.FirstUDPProbeDone())
	assertGateClosed(t, "aggregate", hc.FirstProbeDone())

	// nil receiver 不拦路。
	var nilHC *HealthChecker
	assertGateClosed(t, "nil tcp", nilHC.FirstTCPProbeDone())
}

// TestCheckProxyTCP_SkipsManualDown: a TCP circuit pinned down (SetManualState(false)) must
// not be probed — for a udp_in_tcp node this protects the plaintext framed carrier from
// being exercised while TCP is disabled, and it mirrors the existing UDP-side gate.
func TestCheckProxyTCP_SkipsManualDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		ln.Accept()
		accepted <- struct{}{}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	p := &Proxy{Scheme: SchemeSOCKS5, Host: host, Port: port}
	p.health.SetManualState(false) // TCP manually disabled

	hc := NewHealthChecker(config.HealthCheckConf{
		Enabled: true, Timeout: 1,
		URL: "http://example.com/generate_204",
	}, []*Proxy{p})
	hc.checkProxyTCP(p)

	select {
	case <-accepted:
		t.Fatal("TCP probe ran despite a manually-disabled circuit")
	case <-time.After(150 * time.Millisecond):
		// good: the probe was skipped
	}
}

// TestReopenedCircuit_KeepsFailureCount: a circuit that opens, half-opens, then re-opens
// must keep showing the failure count that opened it — never a misleading 0 next to a
// "down" badge in the dashboard (regression for the open→half_open→reopen cycle zeroing it).
func TestReopenedCircuit_KeepsFailureCount(t *testing.T) {
	hc := NewHealthChecker(config.HealthCheckConf{
		Enabled:            true,
		FailuresThreshold:  2,
		SuccessesThreshold: 2,
		OpenCoolDown:       0, // cooldown passes on the next probe
	}, nil)
	ph := &ProxyHealth{}

	// 2 failures → open (failures=2)
	hc.recordFailure(&Proxy{}, ph, "tcp", errors.New("x"))
	hc.recordFailure(&Proxy{}, ph, "tcp", errors.New("x"))
	if snap := ph.Snapshot(); snap.State != "open" || snap.ConsecutiveFailures != 2 {
		t.Fatalf("want open/2, got state=%s failures=%d", snap.State, snap.ConsecutiveFailures)
	}

	// 1 probe success (threshold=2) → half_open; failure count preserved
	hc.recordSuccess(&Proxy{}, ph, "tcp", time.Millisecond)
	snap := ph.Snapshot()
	if snap.State != "half_open" {
		t.Fatalf("want half_open, got %s", snap.State)
	}
	if snap.ConsecutiveFailures != 2 {
		t.Errorf("half_open must keep failures=2, got %d", snap.ConsecutiveFailures)
	}

	// next failure while half_open → re-opened; still keeps failure count
	hc.recordFailure(&Proxy{}, ph, "tcp", errors.New("x"))
	snap = ph.Snapshot()
	if snap.State != "open" {
		t.Fatalf("want open (reopened), got %s", snap.State)
	}
	if snap.ConsecutiveFailures < 2 {
		t.Errorf("reopened must keep failures >= 2, got %d", snap.ConsecutiveFailures)
	}

	// recovery (2 successes) resets the counter back to 0
	hc.recordSuccess(&Proxy{}, ph, "tcp", time.Millisecond) // open -> half_open
	hc.recordSuccess(&Proxy{}, ph, "tcp", time.Millisecond) // half_open -> closed
	if snap := ph.Snapshot(); snap.State != "closed" || snap.ConsecutiveFailures != 0 {
		t.Errorf("recovery must reset to closed/0, got state=%s failures=%d", snap.State, snap.ConsecutiveFailures)
	}
}

// TestIsManuallyDisabled: only an explicit SetManualState(false) pin reports disabled.
// An auto-opened circuit (probe failures) must NOT — rule routing still tries it (warns
// and proceeds), while a manual Disable is honored as a hard stop.
func TestIsManuallyDisabled(t *testing.T) {
	ph := &ProxyHealth{}
	if ph.IsManuallyDisabled() {
		t.Fatal("fresh circuit must not be manually disabled")
	}
	ph.SetManualState(true)
	if ph.IsManuallyDisabled() {
		t.Fatal("forced-up circuit must not be manually disabled")
	}
	ph.SetManualState(false)
	if !ph.IsManuallyDisabled() {
		t.Fatal("forced-down circuit must be manually disabled")
	}
	ph.ClearManualState()
	if ph.IsManuallyDisabled() {
		t.Fatal("released circuit must not be manually disabled")
	}

	// auto-open (simulated probe failures) is NOT a manual disable
	ph.state = StateOpen
	ph.openSince = time.Now()
	if ph.IsManuallyDisabled() {
		t.Fatal("auto-open circuit must not count as manually disabled")
	}
	if ph.IsAvailable() {
		t.Fatal("auto-open circuit must still be unavailable")
	}
}

func TestParseAndSaveGeo(t *testing.T) {
	p := &Proxy{}
	body := []byte("fl=123\nip=103.24.56.78\nts=123456\nloc=hk\ncolo=HKG\n")
	parseAndSaveGeo(p, body)
	if p.CountryCode() != "HK" {
		t.Errorf("want HK, got %q", p.CountryCode())
	}
	if p.ExitIP() != "103.24.56.78" {
		t.Errorf("want 103.24.56.78, got %q", p.ExitIP())
	}
}

func TestParseAndSaveGeo_AutoCorrection(t *testing.T) {
	// Node was statically inferred as "HK" from alias name
	p := &Proxy{}
	p.SetCountryCode("HK")
	if p.CountryCode() != "HK" {
		t.Fatalf("expected initial country code HK, got %q", p.CountryCode())
	}

	// Real Cloudflare trace probe detects Japan exit IP and loc=JP
	body := []byte("fl=123\nip=153.120.45.67\nts=123456\nloc=JP\ncolo=NRT\n")
	parseAndSaveGeo(p, body)

	// Inferred country code must be auto-corrected by real probe observation
	if p.CountryCode() != "JP" {
		t.Errorf("expected auto-corrected country code JP, got %q", p.CountryCode())
	}
	if p.ExitIPv4() != "153.120.45.67" {
		t.Errorf("expected ExitIPv4 153.120.45.67, got %q", p.ExitIPv4())
	}

	// Unknown loc=XX from Cloudflare should NOT overwrite an existing valid country code
	bodyXX := []byte("fl=123\nip=153.120.45.68\nts=123456\nloc=XX\ncolo=NRT\n")
	parseAndSaveGeo(p, bodyXX)
	if p.CountryCode() != "JP" {
		t.Errorf("expected country code to remain JP when loc=XX, got %q", p.CountryCode())
	}

	// IPv6 auto-correction
	p6 := &Proxy{}
	p6.SetCountryCode("US")
	body6 := []byte("fl=456\nip=2400:cb00::1\nts=123456\nloc=SG\ncolo=SIN\n")
	parseAndSaveGeoIPv6(p6, body6)
	if p6.CountryCode() != "SG" {
		t.Errorf("expected IPv6 auto-corrected country code SG, got %q", p6.CountryCode())
	}
	if p6.ExitIPv6() != "2400:cb00::1" {
		t.Errorf("expected ExitIPv6 2400:cb00::1, got %q", p6.ExitIPv6())
	}
}

func TestProxyHealth_ResetFailures(t *testing.T) {
	// 1. Auto-opened circuit recovers on ResetFailures
	ph := &ProxyHealth{
		state:               StateOpen,
		consecutiveFailures: 5,
		openSince:           time.Now(),
	}
	ph.ResetFailures()
	if ph.state != StateClosed {
		t.Fatalf("expected state closed, got %v", ph.state)
	}
	if ph.consecutiveFailures != 0 {
		t.Fatalf("expected 0 consecutive failures, got %d", ph.consecutiveFailures)
	}

	// 2. Manually disabled circuit remains disabled
	phDisabled := &ProxyHealth{}
	phDisabled.SetManualState(false)
	phDisabled.consecutiveFailures = 3
	phDisabled.ResetFailures()
	if !phDisabled.IsManuallyDisabled() {
		t.Fatal("expected manually disabled circuit to remain disabled")
	}
	if phDisabled.state != StateOpen {
		t.Fatalf("expected manually disabled circuit state to remain open, got %v", phDisabled.state)
	}

	// 3. Closed circuit with consecutive failures resets failure count
	phClosed := &ProxyHealth{
		state:               StateClosed,
		consecutiveFailures: 2,
	}
	phClosed.ResetFailures()
	if phClosed.state != StateClosed {
		t.Fatalf("expected state closed, got %v", phClosed.state)
	}
	if phClosed.consecutiveFailures != 0 {
		t.Fatalf("expected 0 consecutive failures, got %d", phClosed.consecutiveFailures)
	}
}

func startIPv6MockSOCKS5(t *testing.T, succeed bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				n, err := c.Read(buf)
				if err != nil || n < 3 {
					return
				}
				// Reply auth OK
				c.Write([]byte{0x05, 0x00})
				n, err = c.Read(buf)
				if err != nil || n < 4 {
					return
				}
				if !succeed {
					// SOCKS5 reply General failure (0x01)
					c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				// SOCKS5 reply Success (0x00)
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				// Read HTTP request and reply HTTP/1.1 204 No Content
				n, err = c.Read(buf)
				if err == nil && n > 0 {
					c.Write([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
	}
}

func TestHealthChecker_ProbeIPv6(t *testing.T) {
	// 1. Success case: unverified node is probed and upgraded to IPv6CapSupported
	addrSuccess, doneSuccess := startIPv6MockSOCKS5(t, true)
	defer doneSuccess()

	host, portStr, _ := net.SplitHostPort(addrSuccess)
	port := parsePort(portStr)

	pSuccess := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   host,
		Port:   port,
	}

	// Strictly unverified by default:
	if pSuccess.IPv6Capability() != IPv6CapUnknown {
		t.Fatalf("expected initial capability to be unknown, got %v", pSuccess.IPv6Capability())
	}
	if pSuccess.SupportsIPv6() {
		t.Fatalf("expected SupportsIPv6() to be false by default for unverified node")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := probeIPv6(ctx, pSuccess)
	if err != nil {
		t.Fatalf("expected probeIPv6 to succeed, got %v", err)
	}
	if pSuccess.IPv6Capability() != IPv6CapSupported {
		t.Fatalf("expected capability to become supported, got %v", pSuccess.IPv6Capability())
	}
	if !pSuccess.SupportsIPv6() {
		t.Fatalf("expected SupportsIPv6() to be true after successful probe")
	}

	// 2. Failure case: node that fails IPv6 probe is marked IPv6CapUnsupported
	// and its IPv4 TCP health circuit breaker is NOT tripped.
	addrFail, doneFail := startIPv6MockSOCKS5(t, false)
	defer doneFail()

	hostFail, portStrFail, _ := net.SplitHostPort(addrFail)
	portFail := parsePort(portStrFail)

	pFail := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   hostFail,
		Port:   portFail,
	}

	if pFail.SupportsIPv6() {
		t.Fatalf("expected SupportsIPv6() to be false initially")
	}

	_, err = probeIPv6(ctx, pFail)
	if err == nil {
		t.Fatalf("expected probeIPv6 to fail on failing mock")
	}
	if pFail.IPv6Capability() != IPv6CapUnsupported {
		t.Fatalf("expected capability to become unsupported, got %v", pFail.IPv6Capability())
	}
	if pFail.SupportsIPv6() {
		t.Fatalf("expected SupportsIPv6() to remain false")
	}
	if pFail.health.consecutiveFailures != 0 {
		t.Fatalf("expected IPv4 health failures to be 0 (isolated), got %d", pFail.health.consecutiveFailures)
	}
}

func startIPv6TraceMockSOCKS5(t *testing.T, resp string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				n, err := c.Read(buf)
				if err != nil || n < 3 {
					return
				}
				// Reply auth OK
				c.Write([]byte{0x05, 0x00})
				n, err = c.Read(buf)
				if err != nil || n < 4 {
					return
				}
				// SOCKS5 reply Success (0x00)
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				// Read HTTP request and reply with trace response
				n, err = c.Read(buf)
				if err == nil && n > 0 {
					c.Write([]byte(resp))
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
	}
}

func TestHealthChecker_ProbeIPv6_GeoDiscovery(t *testing.T) {
	traceResp := "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nfl=123\nh=cp.cloudflare.com\nip=2606:4700::1111\nloc=JP\n"
	addr, done := startIPv6TraceMockSOCKS5(t, traceResp)
	defer done()

	host, portStr, _ := net.SplitHostPort(addr)
	port := parsePort(portStr)

	// 1. Initial proxy with unknown geo info resolves country code and IPv6 exit IP
	p := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   host,
		Port:   port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := probeIPv6(ctx, p)
	if err != nil {
		t.Fatalf("expected probeIPv6 to succeed, got %v", err)
	}
	if p.CountryCode() != "JP" {
		t.Fatalf("expected country code JP, got %q", p.CountryCode())
	}
	if p.ExitIP() != "2606:4700::1111" {
		t.Fatalf("expected exit IP 2606:4700::1111, got %q", p.ExitIP())
	}

	// 2. Proxy with existing IPv4 exit IP preserves IPv4 exit IP while updating country code
	p2 := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   host,
		Port:   port,
	}
	p2.SetGeoInfo("", "198.51.100.1")

	_, err = probeIPv6(ctx, p2)
	if err != nil {
		t.Fatalf("expected probeIPv6 to succeed on p2, got %v", err)
	}
	if p2.CountryCode() != "JP" {
		t.Fatalf("expected p2 country code JP, got %q", p2.CountryCode())
	}
	if p2.ExitIP() != "198.51.100.1" {
		t.Fatalf("expected p2 to preserve IPv4 exit IP 198.51.100.1, got %q", p2.ExitIP())
	}

	// 3. Pinned disabled IPv6 is skipped
	p3 := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   host,
		Port:   port,
	}
	p3.PinIPv6(false)
	_, err = probeIPv6(ctx, p3)
	if err == nil {
		t.Fatalf("expected probeIPv6 to error on pinned disabled IPv6")
	}
}

func TestHealthChecker_StopReloadConcurrentNoPanic(t *testing.T) {
	cfg := config.HealthCheckConf{
		Enabled:  true,
		Interval: 1,
		Timeout:  1,
	}
	proxies := []*Proxy{
		{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: 59991},
		{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: 59992},
	}
	hc := NewHealthChecker(cfg, proxies)
	hc.Start()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				hc.Reload(cfg, proxies)
				time.Sleep(5 * time.Millisecond)
				hc.Stop()
			}
		}()
	}
	wg.Wait()
}

func TestDeadNodeCircuitBreakerAndSchemeIsolation(t *testing.T) {
	cfg := config.HealthCheckConf{
		Enabled:            true,
		FailuresThreshold:  2,
		SuccessesThreshold: 1,
		OpenCoolDown:       10,
	}

	p := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   "1.2.3.4",
		Port:   1080,
		URL:    "socks5://1.2.3.4:1080",
	}
	hc := NewHealthChecker(cfg, []*Proxy{p})

	// 1. Verify dead node in StateOpen never flips to HalfOpen on failure
	hc.RecordFailure(p, errors.New("timeout 1"))
	hc.RecordFailure(p, errors.New("timeout 2"))
	snap := p.health.Snapshot()
	if snap.State != "open" {
		t.Fatalf("expected state to be open after 2 failures, got %v", snap.State)
	}
	if p.IsAvailable() {
		t.Fatalf("expected IsAvailable() to be false when StateOpen")
	}

	// Another failure while open must NOT flip to StateHalfOpen
	hc.RecordFailure(p, errors.New("timeout 3"))
	snap = p.health.Snapshot()
	if snap.State != "open" {
		t.Fatalf("subsequent failure in StateOpen must stay open, got %v", snap.State)
	}
	if p.IsAvailable() {
		t.Fatalf("dead node must remain unavailable after failure in StateOpen")
	}

	// 2. Successful probe recovers StateOpen -> StateClosed (with threshold=1)
	hc.RecordSuccess(p, 50*time.Millisecond)
	snap = p.health.Snapshot()
	if snap.State != "closed" {
		t.Fatalf("expected state to recover to closed on success with threshold=1, got %v", snap.State)
	}
	if !p.IsAvailable() {
		t.Fatalf("expected IsAvailable() to be true after recovery")
	}


	// 3. Verify non-UDP proxy schemes never report UDP available
	for _, scheme := range []ProxyScheme{SchemeHTTP, SchemeHTTPS, SchemeSOCKS4} {
		np := &Proxy{
			Scheme: scheme,
			URL:    string(scheme) + "://1.2.3.4:8080",
		}
		if np.SchemeSupportsUDP() {
			t.Fatalf("scheme %s must not support UDP", scheme)
		}
		if np.IsUDPAvailable() {
			t.Fatalf("scheme %s must not report UDP available", scheme)
		}
	}
}

func TestHealthChecker_ProbeIPv6_ZeroByteEOF(t *testing.T) {
	// Remote proxy accepts connection and sends SOCKS5 handshake, but closes immediately when probe request is sent
	addr, done := startIPv6TraceMockSOCKS5(t, "")
	defer done()

	host, portStr, _ := net.SplitHostPort(addr)
	port := parsePort(portStr)

	p := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   host,
		Port:   port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := probeIPv6(ctx, p)
	if err == nil {
		t.Fatalf("expected probeIPv6 to fail on 0-byte EOF, but got nil error")
	}
	if p.IPv6Capability() != IPv6CapUnsupported {
		t.Fatalf("expected capability to be IPv6CapUnsupported, got %v", p.IPv6Capability())
	}
}

func TestHealthChecker_ProbeIPv6_Non204Error(t *testing.T) {
	// Remote server returns HTTP 502 Bad Gateway instead of HTTP 204
	addr, done := startIPv6TraceMockSOCKS5(t, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	defer done()

	host, portStr, _ := net.SplitHostPort(addr)
	port := parsePort(portStr)

	p := &Proxy{
		Scheme: SchemeSOCKS5,
		Host:   host,
		Port:   port,
	}
	p.SetGeoInfo("US", "1.1.1.1") // already has geo, so it tests /generate_204

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := probeIPv6(ctx, p)
	if err == nil {
		t.Fatalf("expected probeIPv6 to fail on HTTP 502 status, got nil error")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("expected error mentioning status code 502, got %v", err)
	}
	if p.IPv6Capability() != IPv6CapUnsupported {
		t.Fatalf("expected capability to be IPv6CapUnsupported, got %v", p.IPv6Capability())
	}
}

func TestQueryCymruCountry_IPv4_and_IPv6(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := serverConn.Read(buf)
			if err != nil {
				return
			}
			payload, err := parseUDPFrame(buf[:n])
			if err != nil {
				return
			}
			var q dns.Msg
			if err := q.Unpack(payload); err != nil {
				return
			}
			resp := new(dns.Msg)
			resp.SetReply(&q)
			resp.Response = true
			if len(q.Question) > 0 {
				qName := q.Question[0].Name
				txtRecord := ""
				if strings.Contains(qName, "origin.asn.cymru.com") {
					txtRecord = "50053 | 185.239.141.0/24 | ES | ripencc | 2018-01-04"
				} else if strings.Contains(qName, "origin6.asn.cymru.com") {
					txtRecord = "50053 | 2a0d:6c2:24::/47 | RU | ripencc | 2018-08-02"
				}
				if txtRecord != "" {
					txt := &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   qName,
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Txt: []string{txtRecord},
					}
					resp.Answer = append(resp.Answer, txt)
				}
			}
			packed, err := resp.Pack()
			if err != nil {
				return
			}
			respFrame := buildUDPFrame("208.67.222.222", 53, packed)
			_, _ = serverConn.Write(respFrame)
		}
	}()

	// Test IPv4 -> ES
	cc4 := queryCymruCountry(clientConn, "208.67.222.222", 53, "185.239.141.248")
	if cc4 != "ES" {
		t.Errorf("expected IPv4 country code ES, got %q", cc4)
	}

	// Test IPv6 -> RU
	cc6 := queryCymruCountry(clientConn, "208.67.222.222", 53, "2a0d:6c2:24:815d::")
	if cc6 != "RU" {
		t.Errorf("expected IPv6 country code RU, got %q", cc6)
	}
}

func TestHealthChecker_ProtocolFilter(t *testing.T) {
	hc := NewHealthChecker(config.HealthCheckConf{Enabled: true}, nil)
	if !hc.IsIPv4Enabled() || !hc.IsIPv6Enabled() {
		t.Errorf("expected default true for both, got v4=%v v6=%v", hc.IsIPv4Enabled(), hc.IsIPv6Enabled())
	}

	// Disable v6
	hc.SetProtocolFilter(true, false)
	if !hc.IsIPv4Enabled() {
		t.Errorf("expected v4 true")
	}
	if hc.IsIPv6Enabled() {
		t.Errorf("expected v6 false")
	}

	// Disable v4
	hc.SetProtocolFilter(false, true)
	if hc.IsIPv4Enabled() {
		t.Errorf("expected v4 false")
	}
	if !hc.IsIPv6Enabled() {
		t.Errorf("expected v6 true")
	}

	// Gates should be closed when v4 is disabled
	select {
	case <-hc.FirstTCPProbeDone():
	default:
		t.Errorf("FirstTCPProbeDone should be closed when v4 is disabled")
	}
	select {
	case <-hc.FirstUDPProbeDone():
	default:
		t.Errorf("FirstUDPProbeDone should be closed when v4 is disabled")
	}
}



package upstream

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

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
		SuccessesThreshold: 1,
		OpenCoolDown:       0, // cooldown passes on the next probe
	}, nil)
	ph := &ProxyHealth{}

	// 2 failures → open (failures=2)
	hc.recordFailure(&Proxy{}, ph, "tcp", errors.New("x"))
	hc.recordFailure(&Proxy{}, ph, "tcp", errors.New("x"))
	if snap := ph.Snapshot(); snap.State != "open" || snap.ConsecutiveFailures != 2 {
		t.Fatalf("want open/2, got state=%s failures=%d", snap.State, snap.ConsecutiveFailures)
	}

	// next failure → half_open; the failure count must survive (not reset to 0)
	hc.recordFailure(&Proxy{}, ph, "tcp", errors.New("x"))
	snap := ph.Snapshot()
	if snap.State != "half_open" {
		t.Fatalf("want half_open, got %s", snap.State)
	}
	if snap.ConsecutiveFailures != 2 {
		t.Errorf("half_open must keep failures=2, got %d", snap.ConsecutiveFailures)
	}

	// next failure → re-opened; still keeps failures=2
	hc.recordFailure(&Proxy{}, ph, "tcp", errors.New("x"))
	snap = ph.Snapshot()
	if snap.State != "open" {
		t.Fatalf("want open (reopened), got %s", snap.State)
	}
	if snap.ConsecutiveFailures != 2 {
		t.Errorf("reopened must keep failures=2, got %d", snap.ConsecutiveFailures)
	}

	// recovery resets the counter back to 0
	hc.recordFailure(&Proxy{}, ph, "tcp", errors.New("x")) // open → half_open
	hc.recordSuccess(&Proxy{}, ph, "tcp", time.Millisecond)
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

package upstream

import (
	"testing"

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

// TestCheckProxy_SkipsUDPOnly verifies the TCP health probe never probes a udp_only
// upstream: an unreachable probe target would otherwise trip the circuit breaker and
// disable its UDP relay too.
func TestCheckProxy_SkipsUDPOnly(t *testing.T) {
	cfg := config.HealthCheckConf{
		Enabled:           true,
		URL:               "http://127.0.0.1:1/", // unreachable; would open the circuit if probed
		Interval:          1,
		Timeout:           1,
		FailuresThreshold: 1,
	}
	p := &Proxy{URL: "socks5://127.0.0.1:1234", UDPOnly: true}
	hc := NewHealthChecker(cfg, []*Proxy{p})
	defer hc.Stop()

	hc.checkProxy(p)
	if !p.IsAvailable() {
		t.Fatal("udp_only proxy must stay available: the TCP health probe must skip it")
	}
	snap := p.health.Snapshot()
	if snap.State != "closed" {
		t.Errorf("expected state closed, got %s", snap.State)
	}
}

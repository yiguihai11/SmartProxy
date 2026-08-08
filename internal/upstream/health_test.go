package upstream

import (
	"errors"
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

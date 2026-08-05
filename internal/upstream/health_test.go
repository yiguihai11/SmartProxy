package upstream

import (
	"testing"
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

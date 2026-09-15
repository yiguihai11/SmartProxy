package dns

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestResolvePingCmd_Fallback(t *testing.T) {
	// Pinging loopback with non-existent candidates should error cleanly
	_, err := resolvePingCmd([]string{"non_existent_ping_binary_xyz"}, "127.0.0.1")
	if err == nil {
		t.Error("expected error for non-existent ping binary, got nil")
	}
}

func TestCheckPingCommands(t *testing.T) {
	p := NewPreference(true, PreferPing, nil)
	if p == nil {
		t.Fatal("NewPreference returned nil")
	}
	// On this test system, if ping is available in system/Termux paths, hasPing should be true
	t.Logf("checkPingCommands: hasPing=%v pingPath=%q hasPing6=%v ping6Path=%q",
		p.hasPing, p.pingPath, p.hasPing6, p.ping6Path)
}

func TestPreferIPs_TCP(t *testing.T) {
	// Start a local TCP listener to act as target
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	p := &Preference{
		enabled:  true,
		mode:     PreferTCP,
		tcpPorts: []int{port},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got := p.PreferIPs(ctx, []string{"127.0.0.1", "127.0.0.2"})
	if got != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1 with open listener to be chosen, got %q", got)
	}
}

func TestPreferIPs_NoFallbackToTCP(t *testing.T) {
	// Start a local TCP listener to act as target
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	// When ping is unavailable, PreferPing does NOT fall back to TCP
	p := &Preference{
		enabled:  true,
		mode:     PreferPing,
		hasPing:  false,
		hasPing6: false,
		tcpPorts: []int{port},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got := p.PreferIPs(ctx, []string{"127.0.0.1", "127.0.0.2"})
	if got != "" {
		t.Errorf("expected empty result when ping is unavailable without TCP fallback, got %q", got)
	}
}

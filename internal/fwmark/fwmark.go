//go:build linux

// Package fwmark applies SO_MARK marks to the router's own outbound connections so
// routing rules can recognize and "exclude itself": in full-capture mode, packets
// with the mark bypass the TUN, preventing the router's own dialed traffic from
// coming back into tun0 and creating a loop.
package fwmark

import (
	"sync"
	"sync/atomic"
	"syscall"
)

// DefaultMark is the default mark value for the router's own outbound traffic
// (the low 24 bits are all ones). It can be changed via Configure.
const DefaultMark = 0xffffff

var (
	enabled atomic.Bool
	mu      sync.RWMutex
	mark    = DefaultMark
)

// Configure sets the mark value for the router's own outbound traffic (called with
// the configured output_mark when the TUN starts; 0 means disabled).
func Configure(m int) {
	mu.Lock()
	mark = m
	mu.Unlock()
	enabled.Store(m > 0)
}

// Mark returns the currently configured mark value (so the ip rule / nftables side
// can reference the same number).
func Mark() int {
	mu.RLock()
	defer mu.RUnlock()
	return mark
}

// Enable turns on marking the router's own outbound traffic (called when the TUN starts).
func Enable() { enabled.Store(true) }

// Disable turns off marking the router's own outbound traffic (called when the TUN stops).
func Disable() { enabled.Store(false) }

// Enabled returns whether marking is currently turned on.
func Enabled() bool { return enabled.Load() }

// Control is the callback for net.Dialer.Control: when enabled, it sets
// SO_MARK=current mark on the socket; when disabled, it returns nil (zero overhead).
func Control(network, address string, conn syscall.RawConn) error {
	if !enabled.Load() {
		return nil
	}
	var opErr error
	err := conn.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, Mark())
	})
	if err != nil {
		return err
	}
	return opErr
}

//go:build linux

package fwmark

import (
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestControl_DisabledNoop verifies that Control returns nil directly when disabled (does not touch the socket).
func TestControl_DisabledNoop(t *testing.T) {
	Configure(0)
	assert.False(t, Enabled())
	assert.NoError(t, Control("tcp", "1.2.3.4:80", nil))
}

// TestConfigure verifies that the mark value is configurable and the switch follows 0/non-zero.
func TestConfigure(t *testing.T) {
	Configure(0)
	assert.False(t, Enabled())
	assert.Equal(t, 0, Mark())

	Configure(0x12345)
	assert.True(t, Enabled())
	assert.Equal(t, 0x12345, Mark())

	Configure(0)
	assert.False(t, Enabled())
}

// TestControl_SetsMark verifies that once enabled, SO_MARK is actually set to the configured value on the socket.
// Requires root / CAP_NET_ADMIN; skipped without permission (not treated as a failure).
func TestControl_SetsMark(t *testing.T) {
	Configure(0xabcdef)
	defer Configure(0)

	d := net.Dialer{Control: Control}
	conn, err := d.Dial("udp", "127.0.0.1:9")
	if err != nil {
		t.Skipf("skip: cannot set SO_MARK (need root/CAP_NET_ADMIN): %v", err)
	}
	defer conn.Close()

	raw, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	if err := raw.Control(func(fd uintptr) {
		got, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
	}); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 0xabcdef, got)
}

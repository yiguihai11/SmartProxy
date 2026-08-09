//go:build !linux

package udp

import "syscall"

// setSocketBuffers is a no-op on non-Linux platforms where SO_RCVBUF/SO_SNDBUF cannot be set (or does not apply).
func setSocketBuffers(raw syscall.RawConn) error { return nil }

// setDisableUDPFragmentation is a no-op on non-Linux platforms without IP_MTU_DISCOVER.
func setDisableUDPFragmentation(raw syscall.RawConn) error { return nil }

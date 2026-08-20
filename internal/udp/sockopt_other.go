//go:build !linux

package udp

import (
	"syscall"

	"smartproxy/internal/fwmark"
)

// DirectUDPControl on non-Linux only applies fwmark routing (itself a no-op where
// unsupported); the buffer/fragmentation options have no non-Linux equivalent.
func DirectUDPControl(network, address string, raw syscall.RawConn) error {
	return fwmark.Control(network, address, raw)
}

// setSocketBuffers is a no-op on non-Linux platforms where SO_RCVBUF/SO_SNDBUF cannot be set (or does not apply).
func setSocketBuffers(raw syscall.RawConn) error { return nil }

// setDisableUDPFragmentation is a no-op on non-Linux platforms without IP_MTU_DISCOVER.
func setDisableUDPFragmentation(raw syscall.RawConn) error { return nil }

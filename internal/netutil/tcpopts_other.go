//go:build !linux

package netutil

import (
	"net"
	"time"
)

// SetKeepAliveInterval is a no-op on platforms without TCP_KEEPINTVL.
func SetKeepAliveInterval(*net.TCPConn, time.Duration) error { return nil }

// EnableTCPFastOpen is a no-op on platforms without TCP_FASTOPEN.
func EnableTCPFastOpen(*net.TCPListener) error { return nil }

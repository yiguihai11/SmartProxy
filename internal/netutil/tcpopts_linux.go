//go:build linux

package netutil

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// SetKeepAliveInterval sets TCP_KEEPINTVL — the interval between keepalive probes — on a
// TCP connection. Go's TCPConn.SetKeepAlivePeriod only sets TCP_KEEPIDLE and leaves
// TCP_KEEPINTVL at the kernel default (75s on Linux). Setting it to the same value as the
// idle period matches shadowsocks-rust (idle=interval=15s) and shrinks half-dead detection.
// Best-effort: failure is ignored, keepalive is an optimization not a requirement.
func SetKeepAliveInterval(tcp *net.TCPConn, d time.Duration) error {
	secs := int(d / time.Second)
	if secs < 1 {
		secs = 1
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, secs)
	}); err != nil {
		return err
	}
	return opErr
}

// EnableTCPFastOpen turns on TCP Fast Open on an already-listening TCP listener with 1024
// handshake slots (same rationale as shadowsocks-rust: net.Listen's backlog is 1024, so
// give TFO matching slots — LWN 508865 suggests 5, but a backlog-sized pool avoids dropped
// TFO handshakes under load). Must be called after Listen — macOS requires the option to be
// set after listen(), and doing so on Linux is harmless. Best-effort: kernels without TFO
// simply skip the option and the listener keeps working normally.
func EnableTCPFastOpen(ln *net.TCPListener) error {
	raw, err := ln.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 1024)
	}); err != nil {
		return err
	}
	return opErr
}

//go:build linux

package udp

import "syscall"

// udpSocketBufferSize is the target UDP socket send/receive buffer size (bytes).
// The actual value is capped by the kernel's net.core.rmem_max / wmem_max; this is a best-effort enlargement.
const udpSocketBufferSize = 1 << 20 // 1MB

// setSocketBuffers enlarges the UDP socket's SO_RCVBUF/SO_SNDBUF via RawConn to reduce burst packet loss.
// It prefers SO_RCVBUFFORCE/SO_SNDBUFFORCE (available to root, bypassing the net.core.rmem_max limit);
// for non-root it falls back to plain SO_RCVBUF/SO_SNDBUF (clamped by the kernel limit, best-effort).
func setSocketBuffers(raw syscall.RawConn) error {
	var opErr error
	if rerr := raw.Control(func(fd uintptr) {
		sock := int(fd)
		if e := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, udpSocketBufferSize); e != nil {
			if e2 := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_RCVBUF, udpSocketBufferSize); e2 != nil {
				opErr = e2
				return
			}
		}
		if e := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, udpSocketBufferSize); e != nil {
			if e2 := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_SNDBUF, udpSocketBufferSize); e2 != nil {
				opErr = e2
				return
			}
		}
	}); rerr != nil {
		return rerr
	}
	return opErr
}

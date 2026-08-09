//go:build linux

package udp

import "syscall"

// udpSocketBufferSize is the target UDP socket send/receive buffer size (bytes).
// The actual value is capped by the kernel's net.core.rmem_max / wmem_max; this is a best-effort enlargement.
const udpSocketBufferSize = 1 << 20 // 1MB

// setDisableUDPFragmentation disables IPv4 UDP fragmentation (IP_MTU_DISCOVER=IP_PMTUDISC_DO) on an
// outbound UDP socket: oversized datagrams fail fast with EMSGSIZE at the sender instead of being silently
// fragmented. Fragments of UDP are frequently dropped by NAT/DPI middleboxes, turning one lost fragment into
// a silently-dropped datagram and a full timeout (hundreds of ms) at the app layer — see docs/ss-rust-lessons.md
// §2.10. IPv4 first; an IPv6 socket rejects IPPROTO_IP-level options, so fall back to the v6 level (IPv6 does
// not source-fragment UDP anyway, so a v4-vacuous success on a v6 socket is harmless). Best-effort: a failure
// must not fail the dial, de-fragmentation is an optimization not a requirement.
func setDisableUDPFragmentation(raw syscall.RawConn) error {
	var opErr error
	if rerr := raw.Control(func(fd uintptr) {
		sock := int(fd)
		if e := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO); e != nil {
			if e2 := syscall.SetsockoptInt(sock, syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IP_PMTUDISC_DO); e2 != nil {
				opErr = e2
			}
		}
	}); rerr != nil {
		return rerr
	}
	return opErr
}

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

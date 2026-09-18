package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

func ParseHostPort(address string, defaultPort int) (string, int) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", defaultPort
	}

	if strings.HasPrefix(address, "[") {
		closeBracket := strings.LastIndex(address, "]")
		if closeBracket < 0 {
			return address, defaultPort
		}
		host := address[1:closeBracket]
		rest := address[closeBracket+1:]
		port := defaultPort
		if strings.HasPrefix(rest, ":") {
			fmt.Sscanf(rest[1:], "%d", &port)
		}
		return host, port
	}

	parts := strings.Split(address, ":")
	if len(parts) == 1 {
		return parts[0], defaultPort
	}

	var port int
	if _, err := fmt.Sscanf(parts[len(parts)-1], "%d", &port); err == nil {
		return strings.Join(parts[:len(parts)-1], ":"), port
	}
	return address, defaultPort
}

func ContainsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func SendEnhancedBlock(conn net.Conn, port int) {
	if port == 80 || port == 443 {
		if tcp, ok := getTCPConn(conn); ok {
			tcp.SetLinger(0)
		}
	}
	conn.Close()
}

// ResetConn 以 RST 语义强制关闭连接(任意端口,区别于 SendEnhancedBlock 仅 80/443):
// 真实内核 socket / 代理连接(getTCPConn 可解包)先 SetLinger(0) 让对端收到 RST,
// 其余类型(如 gVisor 应用侧连接)退化为普通 Close。用于「联网状态」页的主动掐断。
func ResetConn(conn net.Conn) {
	if tcp, ok := getTCPConn(conn); ok {
		tcp.SetLinger(0)
	}
	conn.Close()
}

func getTCPConn(conn net.Conn) (*net.TCPConn, bool) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		return tcp, true
	}

	type internalConn interface {
		UnderlyingConn() net.Conn
	}
	if ic, ok := conn.(internalConn); ok {
		return getTCPConn(ic.UnderlyingConn())
	}
	return nil, false
}

// specialPrefixes contains standard non-public, reserved, multicast, broadcast,
// and benchmark testing (Fake-IP) prefixes according to RFC 2544, RFC 1112, RFC 1122,
// RFC 6598, and RFC 919.
var specialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // RFC 1122 This host on this network
	netip.MustParsePrefix("100.64.0.0/10"),      // RFC 6598 Shared Address Space / CGNAT
	netip.MustParsePrefix("198.18.0.0/15"),      // RFC 2544 Benchmark testing / Fake-IP
	netip.MustParsePrefix("224.0.0.0/4"),        // RFC 1112 Multicast (224.0.0.0 - 239.255.255.255)
	netip.MustParsePrefix("240.0.0.0/4"),        // RFC 1112 Reserved for future use / Class E
	netip.MustParsePrefix("255.255.255.255/32"), // RFC 919 Limited broadcast
	netip.MustParsePrefix("100::/64"),           // RFC 6666 Discard prefix
	netip.MustParsePrefix("2001:2::/48"),        // RFC 5180 IPv6 Benchmark testing (RFC 2544 counterpart)
	netip.MustParsePrefix("64:ff9b::/96"),       // RFC 6052 IPv4/IPv6 Translation (NAT64 WKP)
	netip.MustParsePrefix("64:ff9b:1::/48"),     // RFC 8215 Local IPv4/IPv6 Translation
	netip.MustParsePrefix("ff00::/8"),           // RFC 4291 IPv6 Multicast
}

// IsLANAddr reports whether addr is a private, loopback, link-local, unspecified,
// multicast, broadcast, or reserved/benchmark (RFC 2544, RFC 6890) address.
func IsLANAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return true
	}
	for _, p := range specialPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// IsLANIP reports whether ip is a LAN, private, loopback, link-local, unspecified,
// multicast, broadcast, or reserved/benchmark IP address.
func IsLANIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if addr, ok := netip.AddrFromSlice(ip); ok {
		return IsLANAddr(addr)
	}
	return false
}

// IsLAN reports whether host (IP or host:port) is a LAN IP address.
// If host is a hostname or cannot be parsed as an IP, it returns false.
func IsLAN(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	trimmed := strings.Trim(host, "[]")
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return IsLANAddr(addr)
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		if addr, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
			return IsLANAddr(addr)
		}
	}
	return false
}

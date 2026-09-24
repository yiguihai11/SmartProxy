package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"unsafe"

	"github.com/sagernet/gvisor/pkg/tcpip"
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
	if conn == nil {
		return
	}
	if port == 80 || port == 443 {
		SetLingerZero(conn)
	}
	conn.Close()
}

// SetLingerZero attempts to configure SO_LINGER {enabled: true, timeout: 0} on conn.
// It supports:
// 1. *net.TCPConn (and any types implementing SetLinger(int) error)
// 2. Wrapped connections implementing UnderlyingConn() net.Conn
// 3. gVisor netstack connections (gLazyConn, gTCPConn, and Endpoint)
func SetLingerZero(conn any) {
	if conn == nil {
		return
	}

	if s, ok := conn.(interface{ SetLinger(int) error }); ok {
		_ = s.SetLinger(0)
		return
	}

	type internalConn interface {
		UnderlyingConn() net.Conn
	}
	if ic, ok := conn.(internalConn); ok {
		SetLingerZero(ic.UnderlyingConn())
		return
	}

	setGVisorLingerZero(conn)
}

// setGVisorLingerZero traverses struct wrappers (such as sing-tun's gLazyConn and gTCPConn)
// to locate the underlying tcpip.Endpoint and configure LingerOption{Enabled: true, Timeout: 0},
// causing the gVisor stack to emit an immediate TCP RST segment on Close().
func setGVisorLingerZero(conn any) {
	type socketOptionsGetter interface {
		SocketOptions() *tcpip.SocketOptions
	}
	if gso, ok := conn.(socketOptionsGetter); ok && gso != nil {
		gso.SocketOptions().SetLinger(tcpip.LingerOption{
			Enabled: true,
			Timeout: 0,
		})
		return
	}

	val := reflect.ValueOf(conn)
	for val.Kind() == reflect.Pointer || val.Kind() == reflect.Interface {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return
	}

	// 1. If wrapped in gLazyConn with unexported `tcpConn *gTCPConn`
	tcpConnField := val.FieldByName("tcpConn")
	if tcpConnField.IsValid() && tcpConnField.Kind() == reflect.Pointer && !tcpConnField.IsNil() {
		ptr := *(*unsafe.Pointer)(unsafe.Pointer(tcpConnField.UnsafeAddr()))
		if ptr != nil {
			inner := reflect.NewAt(tcpConnField.Type().Elem(), ptr).Interface()
			setGVisorLingerZero(inner)
			return
		}
	}

	// 2. If wrapped in gTCPConn with unexported `ep tcpip.Endpoint`
	epField := val.FieldByName("ep")
	if epField.IsValid() {
		ep := *(*tcpip.Endpoint)(unsafe.Pointer(epField.UnsafeAddr()))
		if ep != nil {
			ep.SocketOptions().SetLinger(tcpip.LingerOption{
				Enabled: true,
				Timeout: 0,
			})
			return
		}
	}
}

// ResetConn 以 RST 语义强制关闭连接:
// 真实内核 socket、代理连接及 gVisor 协议栈应用侧连接均配置 Linger(0) 让对端立即收到 TCP RST,
// 促使客户端即刻检测到断连并重建新流,避免悬挂超时。
func ResetConn(conn net.Conn) {
	if conn == nil {
		return
	}
	SetLingerZero(conn)
	conn.Close()
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

// unroutablePrefixes contains prefixes that are fundamentally unroutable as outbound
// destinations (RFC 1122 0.0.0.0/8, RFC 1112 multicast/reserved, RFC 919 broadcast, etc.).
// Outbound connections to these destinations cannot succeed on any public or private network
// and should fail immediately (e.g. TCP RST) rather than hanging until timeout.
var unroutablePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // RFC 1122 This host on this network
	netip.MustParsePrefix("224.0.0.0/4"),        // RFC 1112 Multicast (224.0.0.0 - 239.255.255.255)
	netip.MustParsePrefix("240.0.0.0/4"),        // RFC 1112 Reserved for future use / Class E
	netip.MustParsePrefix("255.255.255.255/32"), // RFC 919 Limited broadcast
	netip.MustParsePrefix("100::/64"),           // RFC 6666 Discard prefix
	netip.MustParsePrefix("ff00::/8"),           // RFC 4291 IPv6 Multicast
}

// IsUnroutableDestinationAddr reports whether addr is an unroutable destination IP address.
func IsUnroutableDestinationAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, p := range unroutablePrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// IsUnroutableDestination reports whether host (IP or host:port) is an unroutable destination.
// Returns false if host is a domain name.
func IsUnroutableDestination(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	trimmed := strings.Trim(host, "[]")
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return IsUnroutableDestinationAddr(addr)
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		if addr, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
			return IsUnroutableDestinationAddr(addr)
		}
	}
	return false
}

package netutil

import (
	"fmt"
	"net"
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

// IsLANIP reports whether ip is a private, loopback, link-local, or unspecified IP address.
func IsLANIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// IsLAN reports whether host (IP or host:port) is a LAN IP address.
// If host is a hostname or cannot be parsed as an IP, it returns false.
func IsLAN(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	trimmed := strings.Trim(host, "[]")
	if ip := net.ParseIP(trimmed); ip != nil {
		return IsLANIP(ip)
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
			return IsLANIP(ip)
		}
	}
	return false
}

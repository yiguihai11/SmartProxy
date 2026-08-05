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

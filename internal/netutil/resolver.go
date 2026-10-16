package netutil

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	systemDNSMu     sync.RWMutex
	configuredDNSV4 string
	configuredDNSV6 string
)

// SetSystemDNS updates the system DNS servers used by Go's default resolver.
// Called by the Android Kotlin layer with the user-configured or system DNS.
func SetSystemDNS(v4, v6 string) {
	systemDNSMu.Lock()
	defer systemDNSMu.Unlock()
	if v4 = strings.TrimSpace(v4); v4 != "" {
		if !strings.Contains(v4, ":") {
			v4 = net.JoinHostPort(v4, "53")
		}
		configuredDNSV4 = v4
	} else {
		configuredDNSV4 = ""
	}
	if v6 = strings.TrimSpace(v6); v6 != "" {
		if !strings.HasPrefix(v6, "[") && strings.Contains(v6, ":") {
			v6 = "[" + v6 + "]:53"
		}
		configuredDNSV6 = v6
	} else {
		configuredDNSV6 = ""
	}
}

// GetSystemDNS returns the configured IPv4 and IPv6 system DNS servers.
func GetSystemDNS() (string, string) {
	systemDNSMu.RLock()
	defer systemDNSMu.RUnlock()
	return configuredDNSV4, configuredDNSV6
}

func init() {
	// Configure net.DefaultResolver to use pure Go resolver with our custom dialer.
	// On Android, Go falls back to [::1]:53 and 127.0.0.1:53 because /etc/resolv.conf does not exist
	// and system properties are blocked by SELinux.
	// When Go attempts to dial any loopback address on port 53 (or when resolv.conf is missing),
	// we redirect the dial to the system-configured DNS server passed from Kotlin.
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			systemDNSMu.RLock()
			targetV4 := configuredDNSV4
			targetV6 := configuredDNSV6
			systemDNSMu.RUnlock()

			var d net.Dialer
			d.Timeout = 5 * time.Second

			if isLoopbackOrEmpty(address) {
				if (strings.HasPrefix(address, "[::1]") || strings.HasPrefix(address, "::1")) && targetV6 != "" {
					conn, err := d.DialContext(ctx, network, targetV6)
					if err == nil {
						return conn, nil
					}
					// If IPv6 dial fails (e.g. no IPv6 route), fall back to IPv4 DNS
				}
				if targetV4 != "" {
					return d.DialContext(ctx, network, targetV4)
				}
			}
			return d.DialContext(ctx, network, address)
		},
	}
}

func isLoopbackOrEmpty(address string) bool {
	address = strings.TrimSpace(address)
	if address == "" {
		return true
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}

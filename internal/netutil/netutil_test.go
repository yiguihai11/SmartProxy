package netutil

import (
	"net"
	"testing"
)

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		address     string
		defaultPort int
		wantHost    string
		wantPort    int
	}{
		{"", 53, "", 53},
		{"1.1.1.1", 53, "1.1.1.1", 53},
		{"1.1.1.1:5353", 53, "1.1.1.1", 5353},
		{"[::1]:5353", 53, "::1", 5353},
		{"[::1]", 53, "::1", 53},
		{"host:port", 53, "host:port", 53},
		{"example.com:8080", 53, "example.com", 8080},
		{"  1.1.1.1  ", 53, "1.1.1.1", 53},
	}

	for _, tt := range tests {
		host, port := ParseHostPort(tt.address, tt.defaultPort)
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("ParseHostPort(%q, %d) = (%q, %d), want (%q, %d)",
				tt.address, tt.defaultPort, host, port, tt.wantHost, tt.wantPort)
		}
	}
}

func TestIsLAN(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		// IPv4 Private (RFC 1918)
		{"10.0.0.1", true},
		{"10.255.255.254", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"192.168.0.1", true},
		{"192.168.1.1:80", true},
		{"192.168.254.254:53", true},

		// Loopback
		{"127.0.0.1", true},
		{"127.0.0.1:1080", true},
		{"::1", true},
		{"[::1]:8080", true},

		// Link-local
		{"169.254.1.1", true},
		{"fe80::1", true},
		{"[fe80::1]:53", true},

		// IPv6 ULA & Fake-IP (RFC 4193, fc00::/7 including fc00::/18)
		{"fc00::1", true},
		{"fc00::1:2:3", true},
		{"fd00::1", true},
		{"[fd12:3456:789a::1]:80", true},

		// IPv6 Benchmark testing (RFC 5180, 2001:2::/48)
		{"2001:2::1", true},
		{"[2001:2::cafe]:443", true},

		// IPv6 Discard & NAT64 (RFC 6666, RFC 6052, RFC 8215)
		{"100::1", true},
		{"[100::ffff]:80", true},
		{"64:ff9b::192.168.1.1", true},
		{"[64:ff9b:1::1]:443", true},

		// IPv4-mapped IPv6
		{"::ffff:198.18.3.243", true},
		{"[::ffff:198.18.3.243]:443", true},
		{"::ffff:192.168.1.1", true},

		// IPv6 with zone identifier (scoped link-local)
		{"fe80::1%wlan0", true},
		{"[fe80::1%wlan0]:8080", true},

		// Unspecified and Current network (RFC 1122)
		{"0.0.0.0", true},
		{"0.0.0.1", true},
		{"0.255.255.255:80", true},
		{"::", true},

		// Benchmark testing / Fake-IP (RFC 2544)
		{"198.18.0.1", true},
		{"198.18.3.243", true},
		{"198.18.3.243:443", true},
		{"198.19.255.254", true},

		// Multicast & Broadcast (RFC 1112, RFC 919)
		{"224.0.0.1", true},
		{"225.225.225.225", true},
		{"239.255.255.250:1900", true},
		{"240.0.0.1", true},
		{"255.255.255.255", true},
		{"255.255.255.255:80", true},

		// Shared Address Space / CGNAT (RFC 6598)
		{"100.64.0.1", true},
		{"100.127.255.254", true},

		// Public IPs (including documentation IPs used as test targets)
		{"8.8.8.8", false},
		{"1.1.1.1:53", false},
		{"114.114.114.114", false},
		{"211.95.133.210", false},
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"2001:4860:4860::8888", false},
		{"[2606:4700:4700::1111]:53", false},

		// Domains
		{"example.com", false},
		{"localhost", false},
		{"", false},
	}

	for _, tt := range tests {
		got := IsLAN(tt.host)
		if got != tt.want {
			t.Errorf("IsLAN(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestIsUnroutableDestination(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		// RFC 1122 0.0.0.0/8 (This host on this network / Tencent GCloudVoice cluster IDs)
		{"0.0.0.0", true},
		{"0.0.0.1", true},
		{"0.45.242.128", true},
		{"0.45.242.128:443", true},
		{"0.46.18.36", true},
		{"0.46.18.36:443", true},
		{"0.46.138.216", true},
		{"0.255.255.255", true},

		// Multicast & Broadcast (RFC 1112, RFC 919)
		{"224.0.0.1", true},
		{"239.255.255.250:1900", true},
		{"240.0.0.1", true},
		{"255.255.255.255", true},
		{"255.255.255.255:80", true},

		// IPv6 Discard & Multicast
		{"100::1", true},
		{"[ff02::1]:80", true},

		// Routable LAN/Private addresses (should NOT be marked unroutable; they can be reached via LAN)
		{"127.0.0.1", false},
		{"192.168.1.1", false},
		{"192.168.1.1:80", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"100.64.0.1", false}, // CGNAT

		// Public IPs
		{"8.8.8.8", false},
		{"1.1.1.1:53", false},
		{"114.114.114.114", false},
		{"182.50.13.100:443", false},
		{"2001:4860:4860::8888", false},

		// Domains & empty
		{"example.com", false},
		{"localhost", false},
		{"", false},
	}

	for _, tt := range tests {
		got := IsUnroutableDestination(tt.host)
		if got != tt.want {
			t.Errorf("IsUnroutableDestination(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

type mockLingerConn struct {
	net.Conn
	lingerSec int
	closed    bool
}

func (m *mockLingerConn) SetLinger(sec int) error {
	m.lingerSec = sec
	return nil
}

func (m *mockLingerConn) Close() error {
	m.closed = true
	return nil
}

func TestResetConn(t *testing.T) {
	// 1. Nil conn safe
	ResetConn(nil)

	// 2. Mock conn with SetLinger
	mc := &mockLingerConn{lingerSec: -1}
	ResetConn(mc)
	if mc.lingerSec != 0 {
		t.Errorf("expected lingerSec 0, got %d", mc.lingerSec)
	}
	if !mc.closed {
		t.Error("expected closed true")
	}

	// 3. net.Pipe fallback
	c1, c2 := net.Pipe()
	defer c2.Close()
	ResetConn(c1)
}


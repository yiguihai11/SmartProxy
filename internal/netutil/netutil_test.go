package netutil

import "testing"

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

		// IPv6 ULA (RFC 4193)
		{"fc00::1", true},
		{"fd00::1", true},
		{"[fd12:3456:789a::1]:80", true},

		// Unspecified
		{"0.0.0.0", true},
		{"::", true},

		// Public IPs
		{"8.8.8.8", false},
		{"1.1.1.1:53", false},
		{"114.114.114.114", false},
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

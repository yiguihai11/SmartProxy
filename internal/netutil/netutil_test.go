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

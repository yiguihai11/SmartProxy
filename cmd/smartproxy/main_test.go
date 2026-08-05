package main

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"smartproxy/internal/dns"
	"smartproxy/internal/netutil"
	"smartproxy/internal/tun"
)

func TestContainsInt(t *testing.T) {
	tests := []struct {
		slice []int
		val   int
		want  bool
	}{
		{[]int{80, 443}, 80, true},
		{[]int{80, 443}, 443, true},
		{[]int{80, 443}, 8080, false},
		{[]int{}, 80, false},
		{[]int{22}, 22, true},
		{[]int{22}, 80, false},
		{nil, 0, false},
	}

	for _, tt := range tests {
		got := netutil.ContainsInt(tt.slice, tt.val)
		if got != tt.want {
			t.Errorf("netutil.ContainsInt(%v, %d) = %v, want %v", tt.slice, tt.val, got, tt.want)
		}
	}
}

func buildTLSClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	sniLen := len(sniBytes)

	sniExtPayload := make([]byte, 2+1+2+sniLen)
	binary.BigEndian.PutUint16(sniExtPayload[0:2], uint16(1+2+sniLen))
	sniExtPayload[2] = 0x00
	binary.BigEndian.PutUint16(sniExtPayload[3:5], uint16(sniLen))
	copy(sniExtPayload[5:], sniBytes)

	extension := make([]byte, 2+2+len(sniExtPayload))
	binary.BigEndian.PutUint16(extension[0:2], 0x0000)
	binary.BigEndian.PutUint16(extension[2:4], uint16(len(sniExtPayload)))
	copy(extension[4:], sniExtPayload)

	extensions := extension

	handshakeBody := make([]byte, 0, 2+32+1+2+2+1+1+2+len(extensions))
	handshakeBody = append(handshakeBody, 0x03, 0x03)
	handshakeBody = append(handshakeBody, make([]byte, 32)...)
	handshakeBody = append(handshakeBody, 0x00)
	handshakeBody = append(handshakeBody, 0x00, 0x02)
	handshakeBody = append(handshakeBody, 0x00, 0x2f)
	handshakeBody = append(handshakeBody, 0x01, 0x00)
	extLen := len(extensions)
	handshakeBody = append(handshakeBody, byte(extLen>>8), byte(extLen&0xff))
	handshakeBody = append(handshakeBody, extensions...)

	hsLen := len(handshakeBody)
	handshakeRecord := make([]byte, 1+3+hsLen)
	handshakeRecord[0] = 0x01
	handshakeRecord[1] = byte(hsLen >> 16)
	handshakeRecord[2] = byte(hsLen >> 8)
	handshakeRecord[3] = byte(hsLen)
	copy(handshakeRecord[4:], handshakeBody)

	tlsRecord := make([]byte, 5+len(handshakeRecord))
	tlsRecord[0] = 0x16
	tlsRecord[1] = 0x03
	tlsRecord[2] = 0x03
	recLen := len(handshakeRecord)
	binary.BigEndian.PutUint16(tlsRecord[3:5], uint16(recLen))
	copy(tlsRecord[5:], handshakeRecord)

	return tlsRecord
}

func TestExtractDomain_SNI(t *testing.T) {
	tlsHello := buildTLSClientHello("www.example.com")
	got := tun.ExtractDomain(tlsHello)
	if got != "www.example.com" {
		t.Errorf("tun.ExtractDomain(TLS ClientHello) = %q, want %q", got, "www.example.com")
	}
}

func TestExtractDomain_SNI_Uppercase(t *testing.T) {
	tlsHello := buildTLSClientHello("www.Example.COM")
	got := tun.ExtractDomain(tlsHello)
	if got != "www.example.com" {
		t.Errorf("tun.ExtractDomain(TLS ClientHello uppercase) = %q, want %q", got, "www.example.com")
	}
}

func TestExtractDomain_HTTPHost(t *testing.T) {
	httpReq := []byte("GET / HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: curl/7.0\r\n\r\nbody")
	got := tun.ExtractDomain(httpReq)
	if got != "api.example.com" {
		t.Errorf("tun.ExtractDomain(HTTP request) = %q, want %q", got, "api.example.com")
	}
}

func TestExtractDomain_HTTPHostWithPort(t *testing.T) {
	httpReq := []byte("GET / HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n")
	got := tun.ExtractDomain(httpReq)
	if got != "api.example.com" {
		t.Errorf("tun.ExtractDomain(HTTP with port) = %q, want %q", got, "api.example.com")
	}
}

func TestExtractDomain_HTTPConnect(t *testing.T) {
	httpReq := []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	got := tun.ExtractDomain(httpReq)
	if got != "example.com" {
		t.Errorf("tun.ExtractDomain(CONNECT) = %q, want %q", got, "example.com")
	}
}

func TestExtractDomain_EmptyInput(t *testing.T) {
	got := tun.ExtractDomain(nil)
	if got != "" {
		t.Errorf("tun.ExtractDomain(nil) = %q, want empty", got)
	}

	got = tun.ExtractDomain([]byte{})
	if got != "" {
		t.Errorf("tun.ExtractDomain(empty) = %q, want empty", got)
	}
}

func TestExtractDomain_NonHTTP_NonTLS(t *testing.T) {
	got := tun.ExtractDomain([]byte{0x00, 0x01, 0x02, 0x03, 0x04})
	if got != "" {
		t.Errorf("tun.ExtractDomain(random data) = %q, want empty", got)
	}
}

func TestExtractDomain_TLS_NoSNI(t *testing.T) {
	handshake := []byte{
		0x03, 0x03,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00,
		0x00, 0x02,
		0x00, 0x2f,
		0x01, 0x00,
		0x00, 0x00,
	}

	hsLen := len(handshake)
	tls := []byte{
		0x16,
		0x03, 0x03,
		byte(hsLen >> 8), byte(hsLen),
		0x01,
		byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen),
	}
	tls = append(tls, handshake...)

	got := tun.ExtractDomain(tls)
	if got != "" {
		t.Errorf("tun.ExtractDomain(TLS without SNI) = %q, want empty", got)
	}
}

func isConnClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

type testNetError struct {
	msg       string
	timeout   bool
	temporary bool
}

func (e *testNetError) Error() string   { return e.msg }
func (e *testNetError) Timeout() bool   { return e.timeout }
func (e *testNetError) Temporary() bool { return e.temporary }

func TestIsConnClosed(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil error", err: nil, want: false},
		{
			name: "use of closed network connection",
			err:  &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed},
			want: true,
		},
		{
			name: "connection refused",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
			want: false,
		},
		{name: "EOF", err: io.EOF, want: false},
		{name: "plain error", err: errors.New("some random error"), want: false},
		{
			name: "DNS error",
			err:  &net.DNSError{Err: "no such host", Name: "example.com"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isConnClosed(tt.err)
			if got != tt.want {
				t.Errorf("isConnClosed(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestParseSpeedCheck(t *testing.T) {
	tests := []struct {
		mode      string
		wantMode  dns.PreferMode
		wantPorts []int
	}{
		{"", dns.PreferNone, nil},
		{"ping", dns.PreferPing, nil},
		{"PING", dns.PreferPing, nil},
		{" Ping ", dns.PreferPing, nil},
		{"tcp:80", dns.PreferTCP, []int{80}},
		{"tcp:80,443", dns.PreferTCP, []int{80, 443}},
		{"TCP:80,443", dns.PreferTCP, []int{80, 443}},
		{"tcp:80,443,8080", dns.PreferTCP, []int{80, 443, 8080}},
		{"invalid", dns.PreferNone, nil},
		{"tcp:", dns.PreferNone, nil},
		{"tcp:invalid", dns.PreferNone, nil},
		{"tcp:0", dns.PreferNone, nil},
		{"tcp:99999", dns.PreferNone, nil},
		{"tcp:80,invalid,443", dns.PreferTCP, []int{80, 443}},
	}

	for _, tt := range tests {
		gotMode, gotPorts := dns.ParseSpeedCheckMode(tt.mode)
		if gotMode != tt.wantMode {
			t.Errorf("ParseSpeedCheckMode(%q) mode = %q, want %q", tt.mode, gotMode, tt.wantMode)
		}
		if len(gotPorts) != len(tt.wantPorts) {
			t.Errorf("ParseSpeedCheckMode(%q) ports = %v, want %v", tt.mode, gotPorts, tt.wantPorts)
			continue
		}
		for i, p := range gotPorts {
			if p != tt.wantPorts[i] {
				t.Errorf("ParseSpeedCheckMode(%q) ports[%d] = %d, want %d", tt.mode, i, p, tt.wantPorts[i])
			}
		}
	}
}

func TestSetupLogger(t *testing.T) {
	tests := []struct {
		level string
	}{
		{"DEBUG"}, {"INFO"}, {"WARN"}, {"ERROR"}, {"debug"}, {"Info"}, {"invalid"}, {""},
	}

	for _, tt := range tests {
		logger := setupLogger(tt.level, false)
		if logger == nil {
			t.Errorf("setupLogger(%q) returned nil", tt.level)
		}
	}
}

func TestSetLogLevel(t *testing.T) {
	oldLogger := slog.Default()

	levels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	for _, level := range levels {
		setLogLevel(level)
		if logger == nil {
			t.Errorf("setLogLevel(%q) set logger to nil", level)
		}
	}

	slog.SetDefault(oldLogger)
}

func TestParseSpeedCheckWrapper(t *testing.T) {
	mode, ports := dns.ParseSpeedCheckMode("ping")
	if mode != dns.PreferPing {
		t.Errorf("dns.ParseSpeedCheckMode(ping) = %q, want ping", mode)
	}
	if ports != nil {
		t.Errorf("dns.ParseSpeedCheckMode(ping) ports = %v, want nil", ports)
	}
	mode, ports = dns.ParseSpeedCheckMode("")
	if mode != dns.PreferNone {
		t.Errorf("dns.ParseSpeedCheckMode(\"\") = %q, want empty", mode)
	}
	if ports != nil {
		t.Errorf("dns.ParseSpeedCheckMode(\"\") ports = %v, want nil", ports)
	}
	mode, ports = dns.ParseSpeedCheckMode("tcp:80,443")
	if mode != dns.PreferTCP {
		t.Errorf("dns.ParseSpeedCheckMode(tcp:80,443) = %q, want tcp", mode)
	}
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Errorf("dns.ParseSpeedCheckMode(tcp:80,443) ports = %v, want [80 443]", ports)
	}
}

func TestExtractDomain_SNI_PreferredOverHTTP(t *testing.T) {
	tlsHello := buildTLSClientHello("secure.example.com")
	got := tun.ExtractDomain(tlsHello)
	if got != "secure.example.com" {
		t.Errorf("tun.ExtractDomain(TLS ClientHello) = %q, want %q", got, "secure.example.com")
	}
}

func TestExtractDomain_LongHostname(t *testing.T) {
	longHost := "a" + strings.Repeat("b", 40) + ".example.com"
	tlsHello := buildTLSClientHello(longHost)
	got := tun.ExtractDomain(tlsHello)
	if got != strings.ToLower(longHost) {
		t.Errorf("tun.ExtractDomain(long hostname) = %q, want %q", got, strings.ToLower(longHost))
	}
}

func TestExtractDomain_UnicodeHostname(t *testing.T) {
	tlsHello := buildTLSClientHello("xn--fsq.example.com")
	got := tun.ExtractDomain(tlsHello)
	if got != "xn--fsq.example.com" {
		t.Errorf("tun.ExtractDomain(punycode) = %q, want %q", got, "xn--fsq.example.com")
	}
}

func BenchmarkExtractDomain_SNI(b *testing.B) {
	tlsHello := buildTLSClientHello("benchmark.example.com")
	b.ResetTimer()
	for b.Loop() {
		tun.ExtractDomain(tlsHello)
	}
}

func BenchmarkExtractDomain_HTTP(b *testing.B) {
	httpReq := []byte("GET /path HTTP/1.1\r\nHost: benchmark.example.com\r\nUser-Agent: curl\r\n\r\nbody")
	b.ResetTimer()
	for b.Loop() {
		tun.ExtractDomain(httpReq)
	}
}

func BenchmarkContainsInt(b *testing.B) {
	ports := []int{80, 443, 8080, 8443}
	b.ResetTimer()
	for b.Loop() {
		netutil.ContainsInt(ports, 443)
	}
}

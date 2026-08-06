package upstream

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ---------- URL / credentials parsing ----------

func TestParseSSUserinfo(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantM   string
		wantP   string
		wantErr bool
		errSub  string
	}{
		{name: "plaintext", url: "ss://aes-128-gcm:password@1.2.3.4:8388", wantM: "aes-128-gcm", wantP: "password"},
		{name: "base64url raw", url: "ss://" + b64url("aes-256-gcm:s3cret") + "@1.2.3.4:8388", wantM: "aes-256-gcm", wantP: "s3cret"},
		{name: "base64 std padded", url: "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw")) + "@1.2.3.4:8388", wantM: "chacha20-ietf-poly1305", wantP: "pw"},
		{name: "password with colon preserved", url: "ss://aes-128-gcm:pa:ss@1.2.3.4:8388", wantM: "aes-128-gcm", wantP: "pa:ss"},
		{name: "missing creds", url: "ss://1.2.3.4:8388", wantErr: true, errSub: "missing method:password"},
		{name: "missing colon", url: "ss://aes-128-gcm@1.2.3.4:8388", wantErr: true, errSub: "must be method:password"},
		{name: "empty method", url: "ss://:password@1.2.3.4:8388", wantErr: true, errSub: "missing method"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("url parse failed: %v", err)
			}
			m, p, err := parseSSUserinfo(u.User)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got none", tt.errSub)
				}
				if !strings.Contains(err.Error(), tt.errSub) {
					t.Fatalf("error %q does not contain %q", err, tt.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m != tt.wantM || p != tt.wantP {
				t.Errorf("got method=%q password=%q, want method=%q password=%q", m, p, tt.wantM, tt.wantP)
			}
		})
	}
}

func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestNewProxySS(t *testing.T) {
	cred := b64url("aes-128-gcm:password")
	p, err := NewProxy("ss://" + cred + "@proxy.example.com:8388")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	if p.Scheme != SchemeSS {
		t.Errorf("scheme = %q, want %q", p.Scheme, SchemeSS)
	}
	if p.Host != "proxy.example.com" || p.Port != 8388 {
		t.Errorf("host:port = %s:%d, want proxy.example.com:8388", p.Host, p.Port)
	}
	if p.Username != "aes-128-gcm" || p.Password != "password" {
		t.Errorf("credentials = %q:%q, want aes-128-gcm:password", p.Username, p.Password)
	}
	if p.ssMethod == nil {
		t.Error("ssMethod not initialized")
	}
	if !p.SupportsUDP() {
		t.Error("ss proxy should support UDP")
	}
}

func TestNewProxySSInvalid(t *testing.T) {
	if _, err := NewProxy("ss://aes-128-gcm@proxy.example.com:8388"); err == nil {
		t.Error("expected error for missing password")
	}
	if _, err := NewProxy("ss://not-a-cipher:password@proxy.example.com:8388"); err == nil {
		t.Error("expected error for unknown cipher")
	}
	if _, err := NewProxy("ss://proxy.example.com:8388"); err == nil {
		t.Error("expected error for missing userinfo")
	}
}

// ---------- SOCKS5 UDP frame parsing ----------

func TestParseSOCKS5UDPFrame(t *testing.T) {
	// 0.0.0.0:0-style RSV|FRAG|ATYP|ADDR|PORT|payload
	frameIPv4 := append([]byte{0, 0, 0, 0x01, 1, 2, 3, 4, 0x01, 0xbb}, []byte("ipv4-payload")...)
	frameIPv6 := append([]byte{0, 0, 0, 0x04}, net.ParseIP("2001:db8::1").To16()...)
	frameIPv6 = append(frameIPv6, 0x01, 0xbb)
	frameIPv6 = append(frameIPv6, []byte("ipv6-payload")...)
	frameDomain := append([]byte{0, 0, 0, 0x03, byte(len("example.com"))}, []byte("example.com")...)
	frameDomain = append(frameDomain, 0x1f, 0x90)
	frameDomain = append(frameDomain, []byte("domain-payload")...)

	tests := []struct {
		name     string
		frame    []byte
		wantHost string
		wantPort int
		wantPld  string
		wantErr  bool
	}{
		{"ipv4", frameIPv4, "1.2.3.4", 443, "ipv4-payload", false},
		{"ipv6", frameIPv6, "2001:db8::1", 443, "ipv6-payload", false},
		{"domain", frameDomain, "example.com", 8080, "domain-payload", false},
		{"too short", []byte{0, 0, 0}, "", 0, "", true},
		{"fragmented", []byte{0, 0, 1, 0x01, 0, 0, 0, 0, 0, 0}, "", 0, "", true},
		{"short ipv4", []byte{0, 0, 0, 0x01, 0, 0, 0}, "", 0, "", true},
		{"short ipv6", []byte{0, 0, 0, 0x04, 1, 2, 3, 4}, "", 0, "", true},
		{"truncated domain", []byte{0, 0, 0, 0x03, 20, 0x61}, "", 0, "", true},
		{"bad atyp", []byte{0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0}, "", 0, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, payload, err := parseSOCKS5UDPFrame(tt.frame)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tt.wantHost || port != tt.wantPort || string(payload) != tt.wantPld {
				t.Errorf("got host=%q port=%d payload=%q, want host=%q port=%d payload=%q",
					host, port, payload, tt.wantHost, tt.wantPort, tt.wantPld)
			}
		})
	}
}

func TestEncodeSocks5UDPHeader(t *testing.T) {
	dest := M.ParseSocksaddrHostPort("8.8.8.8", 53)
	hdr, err := encodeSocks5UDPHeader(dest)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	want := append([]byte{0, 0, 0}, encodeSocks5Addr("8.8.8.8", 53)...)
	if string(hdr) != string(want) {
		t.Errorf("header = % x, want % x", hdr, want)
	}
}

// ---------- UDP relay adapter (real sing-shadowsocks over real sockets) ----------

// TestSSUDPConnRoundTrip validates ssUDPConn against a real sing Method over a
// real UDP socket: client Write(SOCKS5 frame) encrypts to an SS UDP datagram,
// the server bounces the exact datagram back, and client Read decrypts it back
// into a full SOCKS5 UDP response frame.
//
// The echo works because each SS UDP packet is self-contained (random salt +
// AEAD(addr|payload), fixed zero nonce): decrypting the replayed datagram on the
// client side is a valid decryption of its own ciphertext.
func TestSSUDPConnRoundTrip(t *testing.T) {
	const method = "aes-128-gcm"
	const password = "roundtrip-secret"

	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer serverUDP.Close()

	clientUDP, err := net.DialUDP("udp", nil, serverUDP.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer clientUDP.Close()

	// Raw datagram echo: bounce every packet back to its source.
	go func() {
		rbuf := make([]byte, 65535)
		for {
			n, src, err := serverUDP.ReadFromUDP(rbuf)
			if err != nil {
				return
			}
			if _, err := serverUDP.WriteToUDP(rbuf[:n], src); err != nil {
				return
			}
		}
	}()

	clientMethod, err := shadowaead.New(method, nil, password)
	if err != nil {
		t.Fatalf("client method: %v", err)
	}

	conn := &ssUDPConn{NetPacketConn: clientMethod.DialPacketConn(clientUDP)}
	defer conn.Close()

	// Build a SOCKS5 UDP frame: RSV|FRAG|ATYP|ADDR|PORT|payload
	payload := []byte("hello over ss udp")
	frame := append([]byte{0, 0, 0}, encodeSocks5Addr("8.8.8.8", 53)...)
	frame = append(frame, payload...)

	n, err := conn.Write(frame)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(frame) {
		t.Errorf("Write returned %d, want %d", n, len(frame))
	}

	resp := make([]byte, 2048)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, err = conn.Read(resp)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	got := resp[:n]

	wantHdr := append([]byte{0, 0, 0}, encodeSocks5Addr("8.8.8.8", 53)...)
	want := append(wantHdr, payload...)
	if string(got) != string(want) {
		t.Errorf("response frame mismatch:\n got % x\nwant % x", got, want)
	}
}

// ---------- TCP connect (real sing-shadowsocks server via shadowaead.Service) ----------

type echoSSHandler struct{}

func (echoSSHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	dest := metadata.Destination
	target, err := net.Dial("tcp", dest.String())
	if err != nil {
		return err
	}
	defer target.Close()
	go io.Copy(target, conn)
	_, err = io.Copy(conn, target)
	return err
}

func (echoSSHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return nil
}

func (echoSSHandler) NewError(ctx context.Context, err error) {
}

// TestSSConnectTCP runs Proxy.Connect against an in-process shadowsocks server
// and round-trips a payload through the full SS AEAD encryption path.
func TestSSConnectTCP(t *testing.T) {
	const method = "aes-128-gcm"
	const password = "tcp-secret"

	// Plain TCP echo target.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen failed: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	echoAddr := echoLn.Addr().(*net.TCPAddr)

	// Shadowsocks server (same wire format sing-shadowsocks itself uses).
	svc, err := shadowaead.NewService(method, nil, password, 60, echoSSHandler{})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	ssLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ss listen failed: %v", err)
	}
	defer ssLn.Close()
	go func() {
		for {
			c, err := ssLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = svc.NewConnection(context.Background(), c, M.Metadata{})
			}(c)
		}
	}()
	ssPort := ssLn.Addr().(*net.TCPAddr).Port

	cred := b64url(method + ":" + password)
	p, err := NewProxy(fmt.Sprintf("ss://%s@127.0.0.1:%d", cred, ssPort))
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := p.Connect(ctx, "127.0.0.1", echoAddr.Port)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer conn.Close()

	msg := "hello shadowsocks tcp"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(got) != msg {
		t.Errorf("echo = %q, want %q", got, msg)
	}
}

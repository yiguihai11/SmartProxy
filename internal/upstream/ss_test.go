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

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// base64 PSKs for the 2022 tests: 16 bytes (aes-128) and 32 bytes (aes-256 / chacha20).
// Keys that are too short are rejected outright by shadowaead_2022.New, so exact lengths are required.
var (
	key2022b64  = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	key2022b64b = base64.StdEncoding.EncodeToString([]byte("0123456789abcdefghijklmnopqrstuv"))
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
		{name: "aead method-only no password", url: "ss://aes-128-gcm@1.2.3.4:8388", wantM: "aes-128-gcm", wantP: ""},
		{name: "none method-only", url: "ss://none@1.2.3.4:8388", wantM: "none", wantP: ""},
		{name: "none base64 of method:", url: "ss://" + b64url("none:") + "@1.2.3.4:8388", wantM: "none", wantP: ""},
		{name: "2022 b64url key", url: "ss://" + b64url("2022-blake3-aes-128-gcm:"+key2022b64) + "@1.2.3.4:8388", wantM: "2022-blake3-aes-128-gcm", wantP: key2022b64},
		{name: "2022 plaintext key", url: "ss://2022-blake3-aes-128-gcm:" + key2022b64 + "@1.2.3.4:8388", wantM: "2022-blake3-aes-128-gcm", wantP: key2022b64},
		{name: "2022 multi psk", url: "ss://2022-blake3-aes-256-gcm:" + key2022b64 + ":" + key2022b64b + "@1.2.3.4:8388", wantM: "2022-blake3-aes-256-gcm", wantP: key2022b64 + ":" + key2022b64b},
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

func TestNewProxySSNone(t *testing.T) {
	for _, u := range []string{
		"ss://none@proxy.example.com:8388",
		"ss://plain@proxy.example.com:8388",
		"ss://" + b64url("none:") + "@proxy.example.com:8388",
	} {
		p, err := NewProxy(u)
		if err != nil {
			t.Fatalf("NewProxy(%q) failed: %v", u, err)
		}
		if p.ssMethod == nil {
			t.Errorf("%q: ssMethod not initialized", u)
		}
		if p.Username != "none" && p.Username != "plain" {
			t.Errorf("%q: method = %q, want none/plain", u, p.Username)
		}
		if !p.SupportsUDP() {
			t.Errorf("%q: ss proxy should support UDP", u)
		}
	}
}

func TestNewProxySS2022(t *testing.T) {
	tests := []struct {
		method string
		key    string
	}{
		{"2022-blake3-aes-128-gcm", key2022b64},
		{"2022-blake3-aes-256-gcm", key2022b64b},
		{"2022-blake3-chacha20-poly1305", key2022b64b},
	}
	for _, tt := range tests {
		u := fmt.Sprintf("ss://%s@proxy.example.com:8388", b64url(tt.method+":"+tt.key))
		p, err := NewProxy(u)
		if err != nil {
			t.Fatalf("NewProxy(%q) failed: %v", u, err)
		}
		if p.ssMethod == nil {
			t.Errorf("%s: ssMethod not initialized", tt.method)
		}
		if p.Username != tt.method || p.Password != tt.key {
			t.Errorf("%s: credentials = %q:%q, want %q:%q", tt.method, p.Username, p.Password, tt.method, tt.key)
		}
		if !p.SupportsUDP() {
			t.Errorf("%s: ss proxy should support UDP", tt.method)
		}
	}

	// Unpadded keys (ss-android exports may drop the trailing ==) must also decode.
	unpadded := strings.TrimRight(key2022b64, "=")
	u := fmt.Sprintf("ss://%s@proxy.example.com:8388", b64url("2022-blake3-aes-128-gcm:"+unpadded))
	if _, err := NewProxy(u); err != nil {
		t.Fatalf("unpadded key NewProxy failed: %v", err)
	}

	// Invalid keys: empty, non-base64, or too short.
	if _, err := NewProxy("ss://2022-blake3-aes-128-gcm:@proxy.example.com:8388"); err == nil {
		t.Error("expected error for empty 2022 key")
	}
	if _, err := NewProxy("ss://2022-blake3-aes-128-gcm:key..key@proxy.example.com:8388"); err == nil {
		t.Error("expected error for non-base64 2022 key")
	}
	short := base64.StdEncoding.EncodeToString([]byte("abcdefgh")) // 8 bytes < 16
	if _, err := NewProxy("ss://2022-blake3-aes-128-gcm:" + short + "@proxy.example.com:8388"); err == nil {
		t.Error("expected error for too-short 2022 key")
	}
}

func TestNewProxySSPlugin(t *testing.T) {
	// ss-android exported link with a plugin: userinfo is still base64(method:password),
	// and the plugin is placed in ?plugin= as id;key=val;key=val (URL-escaped).
	pluginSpec := "obfs-local;obfs=http;obfs-host=www.bing.com"
	u := fmt.Sprintf("ss://%s@proxy.example.com:8388?plugin=%s", b64url("aes-128-gcm:secret"), url.QueryEscape(pluginSpec))
	p, err := NewProxy(u)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	if p.Plugin != pluginSpec {
		t.Errorf("plugin = %q, want %q", p.Plugin, pluginSpec)
	}

	// obfs-local is built in: parse out the obfs config (http, obfs-host, default GET /).
	cfg, err := p.ssPlugin()
	if err != nil {
		t.Fatalf("ssPlugin: %v", err)
	}
	if cfg == nil || cfg.obfs != "http" || cfg.host != "www.bing.com" || cfg.method != "GET" || cfg.uri != "/" {
		t.Errorf("obfs config = %+v", cfg)
	}

	// A SIP003 plugin has no UDP channel (obfs only wraps the TCP stream), so a plugin node
	// is TCP-only: UDPAssociate must fail fast with a clear error instead of sending bare SS
	// UDP straight to the server.
	local, err := NewProxy("ss://" + b64url("aes-128-gcm:secret") + "@127.0.0.1:8388?plugin=" + url.QueryEscape(pluginSpec))
	if err != nil {
		t.Fatalf("NewProxy local failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := local.UDPAssociate(ctx, "example.com", 80); err == nil {
		conn.Close()
		t.Error("UDPAssociate with obfs-local must fail (plugin nodes are TCP-only)")
	} else if !strings.Contains(err.Error(), "not supported with a SIP003 plugin") {
		t.Errorf("unexpected UDPAssociate error: %v", err)
	}
}

func TestNewProxySSUnsupportedPlugin(t *testing.T) {
	// Unknown plugin binaries (v2ray-plugin is now built in; use another name to test) are not recognized: Connect reports a clear error.
	u := fmt.Sprintf("ss://%s@proxy.example.com:8388?plugin=%s", b64url("aes-128-gcm:secret"), url.QueryEscape("unknown-plugin;foo=bar"))
	p, err := NewProxy(u)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	if _, err := p.ssPlugin(); err == nil {
		t.Error("expected error for unsupported plugin")
	} else if !strings.Contains(err.Error(), "unsupported SIP003 plugin") {
		t.Errorf("unexpected ssPlugin error: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := p.Connect(ctx, "example.com", 80); err == nil || !strings.Contains(err.Error(), "unsupported SIP003 plugin") {
		t.Errorf("Connect: expected unsupported plugin error, got %v", err)
	}
}

func TestNewProxySSNoPlugin(t *testing.T) {
	p, err := NewProxy("ss://" + b64url("aes-128-gcm:secret") + "@proxy.example.com:8388")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	if p.Plugin != "" {
		t.Errorf("plugin = %q, want empty", p.Plugin)
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
// The echo works because each SS UDP packet is self-contained: an AEAD packet carries
// its own salt + AEAD(addr|payload) (fixed zero nonce), a none packet is plaintext
// addr|payload — in both cases bouncing the raw datagram back lets the client decrypt its own packet.
func TestSSUDPConnRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		newMethod func() (shadowsocks.Method, error)
	}{
		{
			name: "aead",
			newMethod: func() (shadowsocks.Method, error) {
				return shadowaead.New("aes-128-gcm", nil, "roundtrip-secret")
			},
		},
		{
			name: "none",
			newMethod: func() (shadowsocks.Method, error) {
				return shadowsocks.NewNone(), nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			clientMethod, err := tt.newMethod()
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
		})
	}
}

// echoSSUDPHandler echoes each received UDP packet back to the client unchanged. Unlike
// raw-bounce, it goes through a real NAT packet conn: ReadPacket gives payload + target
// address, and WritePacket re-encapsulates via serverPacketWriter using the server-side session before sending to the client (session-based, so the original packet cannot be bounced back).
type echoSSUDPHandler struct{}

func (echoSSUDPHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	return nil
}

func (echoSSUDPHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	for {
		// serverPacketWriter ExtendHeaders a session header + up to ~900B padding in front of
		// the payload when replying; headroom must be reserved or the buffer panics when it starts at offset 0.
		front := N.CalculateFrontHeadroom(conn)
		rear := N.CalculateRearHeadroom(conn)
		buff := buf.NewSize(front + 65535 + rear)
		buff.Resize(front, 0)
		dest, err := conn.ReadPacket(buff)
		if err != nil {
			buff.Release()
			return err
		}
		if err := conn.WritePacket(buff, dest); err != nil {
			buff.Release()
			return err
		}
	}
}

func (echoSSUDPHandler) NewError(ctx context.Context, err error) {
}

// testSSUDPServerConn adapts *net.UDPConn to sing's N.PacketConn, used as the
// underlying connection for the 2022 server-side NewPacket: ReadPacket reads a
// datagram, and WritePacket sends the already-encapsulated datagram to the given destination (the client address).
type testSSUDPServerConn struct {
	udp *net.UDPConn
}

func (c *testSSUDPServerConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, src, err := c.udp.ReadFromUDP(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNet(src), nil
}

func (c *testSSUDPServerConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	_, err := c.udp.WriteToUDP(buffer.Bytes(), destination.UDPAddr())
	return err
}

func (c *testSSUDPServerConn) Close() error                  { return c.udp.Close() }
func (c *testSSUDPServerConn) LocalAddr() net.Addr           { return c.udp.LocalAddr() }
func (c *testSSUDPServerConn) SetDeadline(t time.Time) error { return c.udp.SetDeadline(t) }
func (c *testSSUDPServerConn) SetReadDeadline(t time.Time) error {
	return c.udp.SetReadDeadline(t)
}
func (c *testSSUDPServerConn) SetWriteDeadline(t time.Time) error {
	return c.udp.SetWriteDeadline(t)
}

// TestSSUDPConnRoundTrip2022 validates ssUDPConn against a real AEAD-2022
// service over a real UDP socket. 2022 UDP is session-based (client/server hold
// independent sessions), so the server must decrypt via shadowaead_2022.Service and
// re-encrypt before replying — it cannot bounce the raw datagram like classic AEAD/none. Full client path: NewProxy → ssUDPAssociate → ssUDPConn.
func TestSSUDPConnRoundTrip2022(t *testing.T) {
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer serverUDP.Close()

	svc, err := shadowaead_2022.NewServiceWithPassword("2022-blake3-aes-128-gcm", key2022b64, 60, echoSSUDPHandler{}, nil)
	if err != nil {
		t.Fatalf("NewServiceWithPassword failed: %v", err)
	}
	serverConn := &testSSUDPServerConn{udp: serverUDP}
	go func() {
		for {
			buff := buf.NewSize(65535)
			n, src, err := serverUDP.ReadFromUDP(buff.FreeBytes())
			if err != nil {
				buff.Release()
				return
			}
			buff.Truncate(n)
			_ = svc.NewPacket(context.Background(), serverConn, buff, M.Metadata{Source: M.SocksaddrFromNet(src)})
		}
	}()

	ssPort := serverUDP.LocalAddr().(*net.UDPAddr).Port
	u := fmt.Sprintf("ss://%s@127.0.0.1:%d", b64url("2022-blake3-aes-128-gcm:"+key2022b64), ssPort)
	p, err := NewProxy(u)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	conn, err := p.ssUDPAssociate(context.Background(), "8.8.8.8", 53)
	if err != nil {
		t.Fatalf("ssUDPAssociate failed: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello over ss 2022 udp")
	frame := append([]byte{0, 0, 0}, encodeSocks5Addr("8.8.8.8", 53)...)
	frame = append(frame, payload...)

	if n, err := conn.Write(frame); err != nil {
		t.Fatalf("Write failed: %v", err)
	} else if n != len(frame) {
		t.Errorf("Write returned %d, want %d", n, len(frame))
	}

	resp := make([]byte, 2048)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, err := conn.Read(resp)
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
// (classic AEAD via shadowaead.Service, or plaintext via NoneService) and
// round-trips a payload through the full SS wire path.
func TestSSConnectTCP(t *testing.T) {
	tests := []struct {
		name   string
		newSvc func() (shadowsocks.Service, error)
		newURL func(port int) string
	}{
		{
			name: "aead",
			newSvc: func() (shadowsocks.Service, error) {
				return shadowaead.NewService("aes-128-gcm", nil, "tcp-secret", 60, echoSSHandler{})
			},
			newURL: func(port int) string {
				return fmt.Sprintf("ss://%s@127.0.0.1:%d", b64url("aes-128-gcm:tcp-secret"), port)
			},
		},
		{
			name: "none",
			newSvc: func() (shadowsocks.Service, error) {
				return shadowsocks.NewNoneService(60, echoSSHandler{}), nil
			},
			newURL: func(port int) string {
				return fmt.Sprintf("ss://none@127.0.0.1:%d", port)
			},
		},
		{
			name: "2022",
			newSvc: func() (shadowsocks.Service, error) {
				return shadowaead_2022.NewServiceWithPassword("2022-blake3-aes-128-gcm", key2022b64, 60, echoSSHandler{}, nil)
			},
			newURL: func(port int) string {
				return fmt.Sprintf("ss://%s@127.0.0.1:%d", b64url("2022-blake3-aes-128-gcm:"+key2022b64), port)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			svc, err := tt.newSvc()
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

			p, err := NewProxy(tt.newURL(ssPort))
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
		})
	}
}

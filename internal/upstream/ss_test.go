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

// 2022 测试用的 base64 PSK:16 字节(aes-128)与 32 字节(aes-256 / chacha20)。
// 太短的 key 会被 shadowaead_2022.New 直接拒绝,所以必须用精确长度。
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

	// 无 padding 的 key(ss-android 导出可能不带 ==)也必须能解码。
	unpadded := strings.TrimRight(key2022b64, "=")
	u := fmt.Sprintf("ss://%s@proxy.example.com:8388", b64url("2022-blake3-aes-128-gcm:"+unpadded))
	if _, err := NewProxy(u); err != nil {
		t.Fatalf("unpadded key NewProxy failed: %v", err)
	}

	// 无效 key:空、非 base64、长度不足。
	if _, err := NewProxy("ss://2022-blake3-aes-128-gcm:@proxy.example.com:8388"); err == nil {
		t.Error("expected error for empty 2022 key")
	}
	if _, err := NewProxy("ss://2022-blake3-aes-128-gcm:key..key@proxy.example.com:8388"); err == nil {
		t.Error("expected error for non-base64 2022 key")
	}
	short := base64.StdEncoding.EncodeToString([]byte("abcdefgh")) // 8 字节 < 16
	if _, err := NewProxy("ss://2022-blake3-aes-128-gcm:" + short + "@proxy.example.com:8388"); err == nil {
		t.Error("expected error for too-short 2022 key")
	}
}

func TestNewProxySSPlugin(t *testing.T) {
	// ss-android 导出的带插件链接:userinfo 仍是 base64(method:password),
	// 插件放在 ?plugin=,值为 id;key=val;key=val(需 URL 转义)。
	pluginSpec := "obfs-local;obfs=http;obfs-host=www.bing.com"
	u := fmt.Sprintf("ss://%s@proxy.example.com:8388?plugin=%s", b64url("aes-128-gcm:secret"), url.QueryEscape(pluginSpec))
	p, err := NewProxy(u)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	if p.Plugin != pluginSpec {
		t.Errorf("plugin = %q, want %q", p.Plugin, pluginSpec)
	}

	// 只解析、不执行:连接时报明确错误,且不发起任何网络请求。
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := p.Connect(ctx, "example.com", 80); err == nil {
		t.Error("expected plugin error from Connect")
	} else if !strings.Contains(err.Error(), "SIP003 plugin") {
		t.Errorf("unexpected Connect error: %v", err)
	}
	if _, err := p.UDPAssociate(ctx, "example.com", 80); err == nil {
		t.Error("expected plugin error from UDPAssociate")
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
// The echo works because each SS UDP packet is self-contained: AEAD 包自带 salt +
// AEAD(addr|payload)(固定 zero nonce),none 包为明文 addr|payload —— 两种情况把
// 原始数据报弹回后,客户端都能解出自己的包。
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

// echoSSUDPHandler 把收到的每个 UDP 包原样回显给客户端。与 raw-bounce 不同,
// 它走真实的 NAT packet conn:ReadPacket 给出 payload + 目标地址,WritePacket 由
// serverPacketWriter 用服务器侧会话重新封包再发给客户端(会话式,不能弹回原包)。
type echoSSUDPHandler struct{}

func (echoSSUDPHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	return nil
}

func (echoSSUDPHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	for {
		// serverPacketWriter 回包时要在 payload 前 ExtendHeader(会话头 + 最多
		// ~900B padding),必须预留 headroom,否则 buffer 起始位置为 0 时 panic。
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

// testSSUDPServerConn 把 *net.UDPConn 适配成 sing 的 N.PacketConn,作为 2022
// 服务端 NewPacket 的底层连接:ReadPacket 读入数据报,WritePacket 把已封好的
// 数据报发往指定目标(即客户端地址)。
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
// service over a real UDP socket. 2022 UDP 是会话式(客户端/服务端各持独立会话),
// 服务端必须用 shadowaead_2022.Service 解包后再回写,不能像经典 AEAD/none 那样
// 把原始数据报弹回。完整走 NewProxy → ssUDPAssociate → ssUDPConn 的客户端路径。
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

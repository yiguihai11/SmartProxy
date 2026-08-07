package upstream

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ss:// upstream: SmartProxy connects to the remote SS server directly with the
// shadowsocks protocol, no external sslocal process. TCP goes through Method.DialConn
// for an encrypted tunnel; UDP goes through Method.DialPacketConn, using
// sing-shadowsocks' per-packet destination model to convert the upstream SOCKS5-UDP frames into SS UDP packets.
//
// Supports classic AEAD (password-derived key), AEAD-2022 (base64 key), and the unencrypted none/plain.

// ssSupportedMethods lists the supported classic AEAD + AEAD-2022 ciphers.
// shadowaead.New / shadowaead_2022.New from sing-shadowsocks do not error on unknown
// methods (leaving a nil constructor); we validate here so typos don't panic at connect.
var ssSupportedMethods = map[string]bool{
	// Classic AEAD (SIP004, password-derived key)
	"aes-128-gcm":             true,
	"aes-192-gcm":             true,
	"aes-256-gcm":             true,
	"chacha20-ietf-poly1305":  true,
	"xchacha20-ietf-poly1305": true,
	// AEAD-2022 (SIP022, key is a base64-encoded binary PSK; multiple PSKs joined with :)
	"2022-blake3-aes-128-gcm":       true,
	"2022-blake3-aes-256-gcm":       true,
	"2022-blake3-chacha20-poly1305": true,
}

// newSSMethod builds the SS encryption implementation: classic AEAD (password-derived key),
// AEAD-2022 (base64 key) or unencrypted none/plain. none/plain is a single method
// (shadowsocks-rust's CipherKind::NONE alias); the wire format is a plaintext address header + payload, no password needed.
func newSSMethod(method, password string) (shadowsocks.Method, error) {
	switch method {
	case "none", "plain":
		return shadowsocks.NewNone(), nil
	}
	if !ssSupportedMethods[method] {
		return nil, fmt.Errorf("unsupported shadowsocks method %q (supported: none/plain, aes-128/192/256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305, 2022-blake3-aes-128/256-gcm, 2022-blake3-chacha20-poly1305)", method)
	}
	if strings.HasPrefix(method, "2022-") {
		return newSSMethod2022(method, password)
	}
	return shadowaead.New(method, nil, password)
}

// newSSMethod2022 builds the AEAD-2022 Method. 2022 key semantics differ from classic
// AEAD: the key is not password-derived but a base64-encoded binary PSK (16/32 bytes),
// with multiple PSKs joined by ':'. sing's shadowaead_2022.NewWithPassword only accepts
// padded StdEncoding; we also accept the unpadded variant (ss-android exports may drop '=').
func newSSMethod2022(method, password string) (shadowsocks.Method, error) {
	if password == "" {
		return nil, fmt.Errorf("shadowsocks-2022 method %q requires a base64 key", method)
	}
	parts := strings.Split(password, ":")
	pskList := make([][]byte, 0, len(parts))
	for _, part := range parts {
		kb, err := decodeBase64Key(part)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks-2022 key %q: %w", part, err)
		}
		pskList = append(pskList, kb)
	}
	return shadowaead_2022.New(method, pskList, nil)
}

// decodeBase64Key tries Std / URL (padded) and Raw variants in order to decode a base64 key.
func decodeBase64Key(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if kb, err := enc.DecodeString(s); err == nil {
			return kb, nil
		}
	}
	return nil, errors.New("invalid base64 key")
}

// parseSSUserinfo parses the userinfo (method:password) of an ss:// URL.
// The standard form is base64 (unpadded, URL-safe); plaintext method:password is also accepted.
func parseSSUserinfo(user *url.Userinfo) (method, password string, err error) {
	if user == nil {
		return "", "", errors.New("ss:// URL is missing method:password credentials")
	}
	// url.Parse splits userinfo at the first colon into username/password; any further
	// colons get percent-encoded. Username()/Password() recover them (password decoded, colon preserved).
	username := user.Username()
	pw, hasPw := user.Password()
	raw := username
	if hasPw {
		raw = username + ":" + pw
	}
	// shadowsocks URI spec: userinfo is base64-encoded (usually unpadded), so pure base64
	// has no colon and hasPw is false (raw is the encoded string); a colon means plaintext
	// method:password. Note: the decoded result must contain ':' (the method:password
	// structure) to be valid — otherwise a plaintext method name like "none" decodes to garbage.
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if decoded, derr := enc.DecodeString(raw); derr == nil {
			if strings.IndexByte(string(decoded), ':') >= 0 {
				raw = string(decoded)
			}
			break
		}
	}
	i := strings.IndexByte(raw, ':')
	if i < 0 {
		// No colon: it's the method name itself (e.g. "none"), no password needed. AEAD
		// methods missing a password error out in newSSMethod / shadowaead.New.
		return raw, "", nil
	}
	method = raw[:i]
	password = raw[i+1:]
	if method == "" {
		return "", "", errors.New("ss:// credentials missing method")
	}
	return method, password, nil
}

// ssPluginKind reports the SIP003 plugin binary name configured for this ss upstream:
//
//	""            - no plugin configured
//	"obfs-local"  - built-in simple-obfs (http/tls, see obfs.go)
//	"v2ray-plugin" / "xray-plugin" - built-in v2ray transport (websocket/grpc/quic, see v2ray.go)
//
// Unknown plugin binaries return a clear error so a plugin the user expects is not silently ignored.
func (p *Proxy) ssPluginKind() (string, error) {
	if p.Plugin == "" {
		return "", nil
	}
	parts, err := splitPluginOptions(p.Plugin)
	if err != nil {
		return "", fmt.Errorf("ss proxy %q: %w", p.URL, err)
	}
	if len(parts) == 0 || parts[0] == "" {
		return "", fmt.Errorf("ss proxy %q: empty plugin options", p.URL)
	}
	switch parts[0] {
	case "obfs-local":
		return "obfs-local", nil
	case "v2ray-plugin", "xray-plugin":
		return parts[0], nil
	default:
		return "", fmt.Errorf("ss proxy %q: unsupported SIP003 plugin %q (SmartProxy ships obfs-local http/tls and v2ray-plugin/xray-plugin websocket/grpc/quic)", p.URL, parts[0])
	}
}

// ssPlugin parses the obfs-local plugin options of this ss upstream. Returns (nil, nil) when unconfigured or not an obfs plugin.
func (p *Proxy) ssPlugin() (*obfsConfig, error) {
	if p.Plugin == "" {
		return nil, nil
	}
	cfg, err := parsePluginOptions(p.Plugin)
	if err != nil {
		return nil, fmt.Errorf("ss proxy %q: %w", p.URL, err)
	}
	if cfg.host == "" {
		cfg.host = p.Host // default obfs-host to the SS server host
	}
	cfg.port = p.Port // HTTP Host header carries the SS port when not 80 (matching obfs-local)
	return cfg, nil
}

// ssConnect establishes an SS encrypted tunnel (TCP) to the target host:port.
func (p *Proxy) ssConnect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	kind, err := p.ssPluginKind()
	if err != nil {
		return nil, err
	}
	if p.ssMethod == nil {
		return nil, fmt.Errorf("ss proxy %q has no method", p.URL)
	}
	var conn net.Conn
	switch kind {
	case "obfs-local":
		obfs, err := p.ssPlugin()
		if err != nil {
			return nil, err
		}
		conn, err = p.dial(ctx) // TCP connect to the SS server (fwmark + keepalive)
		if err != nil {
			return nil, err
		}
		// Built-in obfs-http/tls: wrap an obfuscation transport between TCP and the SS encryption layer.
		if conn, err = wrapObfs(conn, obfs); err != nil {
			return nil, err // conn is already closed when wrapObfs fails
		}
	case "v2ray-plugin", "xray-plugin":
		vp, err := p.v2rayPlugin()
		if err != nil {
			return nil, err
		}
		// Connect to the SS server through the v2ray-core transport layer: websocket+mux
		// goes over a mux session stream; grpc/quic/websocket without mux use the raw transport connection.
		if conn, err = p.dialV2ray(ctx, vp); err != nil {
			return nil, err
		}
	default:
		conn, err = p.dial(ctx)
		if err != nil {
			return nil, err
		}
	}
	dest := M.ParseSocksaddrHostPort(targetHost, uint16(targetPort))
	ssConn, err := p.ssMethod.DialConn(conn, dest)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ss handshake to %s failed: %w", p.URL, err)
	}
	return ssConn, nil
}

// ssUDPAssociate creates a UDP relay session to the SS server and returns a connection
// satisfying SmartProxy's upstream UDP contract (net.Conn + full SOCKS5-UDP frames).
func (p *Proxy) ssUDPAssociate(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	// The plugin only obfuscates TCP (SIP003 semantics); SS UDP bypasses the plugin and
	// connects directly to the server's UDP port. We still validate the plugin kind to avoid silently ignoring a mistyped plugin name.
	if _, err := p.ssPluginKind(); err != nil {
		return nil, err
	}
	if p.ssMethod == nil {
		return nil, fmt.Errorf("ss proxy %q has no method", p.URL)
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
	if err != nil {
		return nil, err
	}
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	slog.Debug("ss UDP relay established", "proxy", p.URL, "serverAddr", raddr)
	return &ssUDPConn{NetPacketConn: p.ssMethod.DialPacketConn(udpConn)}, nil
}

// ssUDPConn adapts sing-shadowsocks' UDP packet conn to SmartProxy's upstream UDP contract:
//   - Write takes a full SOCKS5-UDP frame (RSV|FRAG|ATYP|DST.ADDR|DST.PORT|payload),
//     parses the destination, and sends via WritePacket (each SS packet carries its own
//     destination address);
//   - Read gets payload + source destination from ReadPacket, prepends the SOCKS5 UDP
//     response header, and returns the full frame.
//
// Since sing's clientPacketConn carries the destination per packet, a single UDP connection
// can serve any destination (matching a SOCKS5 upstream serving many targets on one UDP
// socket), so it can safely go into the UDP reuse pool.
type ssUDPConn struct {
	N.NetPacketConn
}

// Write input is a full SOCKS5-UDP frame; returning len(b) means the whole frame was handled.
func (c *ssUDPConn) Write(b []byte) (int, error) {
	host, port, payload, err := parseSOCKS5UDPFrame(b)
	if err != nil {
		return 0, err
	}
	dest := M.ParseSocksaddrHostPort(host, uint16(port))
	// Reserve headroom for the encryption header and trailing tag as declared by the
	// specific packet conn: classic AEAD has a salt+addr header + 16B tag; 2022 adds a
	// session/padding header (up to ~900B). WritePacket panics if capacity is insufficient.
	front := N.CalculateFrontHeadroom(c.NetPacketConn)
	if _, ok := c.NetPacketConn.(N.FrontHeadroom); !ok {
		// nonePacketConn only implements the deprecated Headroom(), not FrontHeadroom, so
		// Calculate returns 0; its WritePacket also ExtendHeaders an address header, so add MaxSocksaddrLength as a floor.
		front = M.MaxSocksaddrLength
	}
	rear := N.CalculateRearHeadroom(c.NetPacketConn)
	buff := buf.NewSize(front + len(payload) + rear)
	buff.Resize(front, 0)
	if _, err := buff.Write(payload); err != nil {
		buff.Release()
		return 0, err
	}
	if err := c.WritePacket(buff, dest); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read returns a full SOCKS5-UDP frame (SOCKS5 response header + raw payload).
func (c *ssUDPConn) Read(b []byte) (int, error) {
	buff := buf.NewSize(65535)
	dest, err := c.ReadPacket(buff)
	if err != nil {
		buff.Release()
		return 0, err
	}
	payload := buff.Bytes()
	hdr, herr := encodeSocks5UDPHeader(dest)
	if herr != nil {
		buff.Release()
		return 0, herr
	}
	if len(b) < len(hdr) {
		buff.Release()
		return 0, io.ErrShortBuffer
	}
	n := copy(b[len(hdr):], payload)
	copy(b, hdr)
	buff.Release()
	return len(hdr) + n, nil
}

// RemoteAddr has no usable remote address on the upstream side, so it returns the SS server address.
func (c *ssUDPConn) RemoteAddr() net.Addr {
	return c.LocalAddr()
}

// ProbeTCP: ss UDP has no TCP control channel, so it is always considered healthy (TTL eviction as fallback).
func (c *ssUDPConn) ProbeTCP() error {
	return nil
}

// parseSOCKS5UDPFrame parses a SOCKS5 UDP frame and returns the target host, port and payload.
func parseSOCKS5UDPFrame(frame []byte) (host string, port int, payload []byte, err error) {
	if len(frame) < 4 {
		return "", 0, nil, errors.New("SOCKS5 UDP frame too short")
	}
	if frame[2] != 0 { // FRAG
		return "", 0, nil, errors.New("SOCKS5 UDP fragmentation not supported")
	}
	atyp := frame[3]
	var headerLen int
	switch atyp {
	case 0x01:
		if len(frame) < 10 {
			return "", 0, nil, errors.New("short SOCKS5 UDP IPv4 frame")
		}
		host = net.IP(frame[4:8]).String()
		headerLen = 4 + 4
	case 0x04:
		if len(frame) < 22 {
			return "", 0, nil, errors.New("short SOCKS5 UDP IPv6 frame")
		}
		host = net.IP(frame[4:20]).String()
		headerLen = 4 + 16
	case 0x03:
		if len(frame) < 5 {
			return "", 0, nil, errors.New("short SOCKS5 UDP domain frame")
		}
		domainLen := int(frame[4])
		if len(frame) < 5+domainLen+2 {
			return "", 0, nil, errors.New("truncated SOCKS5 UDP domain frame")
		}
		host = string(frame[5 : 5+domainLen])
		headerLen = 4 + 1 + domainLen
	default:
		return "", 0, nil, fmt.Errorf("unsupported SOCKS5 address type: %d", atyp)
	}
	port = int(binary.BigEndian.Uint16(frame[headerLen : headerLen+2]))
	return host, port, frame[headerLen+2:], nil
}

// encodeSocks5UDPHeader builds a SOCKS5 UDP response header (RSV|FRAG|ATYP|ADDR|PORT) from the destination address returned by SS.
func encodeSocks5UDPHeader(dest M.Socksaddr) ([]byte, error) {
	host := dest.Fqdn
	if host == "" {
		host = dest.Addr.String()
	}
	addr := encodeSocks5Addr(host, int(dest.Port))
	hdr := make([]byte, 3, 3+len(addr))
	hdr[0], hdr[1], hdr[2] = 0, 0, 0 // RSV, RSV, FRAG
	return append(hdr, addr...), nil
}

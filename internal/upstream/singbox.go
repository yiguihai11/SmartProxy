package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"smartproxy/internal/singbox"
	"smartproxy/internal/trace"
)

// isSingBoxURL reports whether the URL or config is handled by singbox.
func isSingBoxURL(link string) bool {
	link = strings.TrimSpace(link)
	if strings.HasPrefix(link, "{") {
		return true
	}
	lower := strings.ToLower(link)
	for _, scheme := range []string{
		"vless://", "vmess://", "trojan://", "hysteria2://", "hy2://", "tuic://",
	} {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	return false
}

// maskSingBoxURL returns a safe-to-log string without sensitive credentials.
func maskSingBoxURL(link string) string {
	link = strings.TrimSpace(link)
	if strings.HasPrefix(link, "{") {
		var meta struct {
			Tag    string `json:"tag"`
			Type   string `json:"type"`
			Server string `json:"server"`
			Port   int    `json:"server_port"`
		}
		_ = json.Unmarshal([]byte(link), &meta)
		if meta.Type != "" {
			return fmt.Sprintf("singbox://%s@%s:%d#%s", meta.Type, meta.Server, meta.Port, meta.Tag)
		}
		return "singbox://{...}"
	}
	if strings.HasPrefix(strings.ToLower(link), "vmess://") {
		return "vmess://" + MaskPassword
	}
	u, err := url.Parse(link)
	if err != nil {
		return "<invalid-singbox-url>"
	}
	if u.User != nil {
		masked := *u
		masked.User = url.User(MaskPassword)
		return masked.String()
	}
	return link
}

// uniqueSingBoxTag generates a collision-free tag for sing-box outbound table.
func uniqueSingBoxTag(baseTag, proxyURL string) string {
	h := sha256.Sum256([]byte(proxyURL))
	hashSuffix := hex.EncodeToString(h[:4])
	if baseTag == "" {
		return fmt.Sprintf("sb-%s", hashSuffix)
	}
	return fmt.Sprintf("%s-%s", baseTag, hashSuffix)
}

// singboxConnect establishes a TCP tunnel through sing-box outbound.
func (p *Proxy) singboxConnect(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	if p.singboxTag == "" {
		return nil, fmt.Errorf("proxy %q has no singbox tag", MaskProxyURL(p.URL))
	}
	target := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	trace.Log(ctx).Debug("singbox connecting TCP", "tag", p.singboxTag, "target", target)
	return singbox.GlobalEngine().DialContext(ctx, p.singboxTag, "tcp", target)
}

// singboxUDPAssociate creates a UDP session through sing-box outbound.
func (p *Proxy) singboxUDPAssociate(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	if p.singboxTag == "" {
		return nil, fmt.Errorf("proxy %q has no singbox tag", MaskProxyURL(p.URL))
	}
	target := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	trace.Log(ctx).Debug("singbox associating UDP", "tag", p.singboxTag, "target", target)
	pc, err := singbox.GlobalEngine().ListenPacket(ctx, p.singboxTag, target)
	if err != nil {
		return nil, err
	}
	return &singboxUDPConn{pc: pc, proxy: p}, nil
}

// singboxUDPConn adapts sing-box net.PacketConn to SmartProxy's upstream UDP contract
// (net.Conn + SOCKS5 UDP framed packets).
type singboxUDPConn struct {
	pc    net.PacketConn
	proxy *Proxy
}

func (c *singboxUDPConn) Proxy() *Proxy {
	return c.proxy
}

func (c *singboxUDPConn) Write(b []byte) (int, error) {
	host, port, payload, err := parseSOCKS5UDPFrame(b)
	if err != nil {
		return 0, err
	}
	dest := M.ParseSocksaddrHostPort(host, uint16(port))

	if npc, ok := c.pc.(N.NetPacketConn); ok {
		front := N.CalculateFrontHeadroom(npc)
		rear := N.CalculateRearHeadroom(npc)
		buff := buf.NewSize(front + len(payload) + rear)
		buff.Resize(front, 0)
		if _, err := buff.Write(payload); err != nil {
			buff.Release()
			return 0, err
		}
		if err := npc.WritePacket(buff, dest); err != nil {
			return 0, err
		}
		return len(b), nil
	}

	var addr net.Addr = dest
	if dest.IsIP() {
		addr = dest.UDPAddr()
	}
	if _, err := c.pc.WriteTo(payload, addr); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *singboxUDPConn) Read(b []byte) (int, error) {
	if npc, ok := c.pc.(N.NetPacketConn); ok {
		buff := buf.NewSize(65535)
		dest, err := npc.ReadPacket(buff)
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
		if len(b) < len(hdr)+len(payload) {
			buff.Release()
			return 0, io.ErrShortBuffer
		}
		copy(b, hdr)
		copy(b[len(hdr):], payload)
		buff.Release()
		return len(hdr) + len(payload), nil
	}

	tmp := make([]byte, 65535)
	n, fromAddr, err := c.pc.ReadFrom(tmp)
	if err != nil {
		return 0, err
	}
	var dest M.Socksaddr
	if sa, ok := fromAddr.(M.Socksaddr); ok {
		dest = sa
	} else if fromAddr != nil {
		dest = M.ParseSocksaddr(fromAddr.String())
	}
	hdr, herr := encodeSocks5UDPHeader(dest)
	if herr != nil {
		return 0, herr
	}
	if len(b) < len(hdr)+n {
		return 0, io.ErrShortBuffer
	}
	copy(b, hdr)
	copy(b[len(hdr):], tmp[:n])
	return len(hdr) + n, nil
}

func (c *singboxUDPConn) Close() error                       { return c.pc.Close() }
func (c *singboxUDPConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *singboxUDPConn) RemoteAddr() net.Addr               { return c.pc.LocalAddr() }
func (c *singboxUDPConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *singboxUDPConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *singboxUDPConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
func (c *singboxUDPConn) ProbeTCP() error                    { return nil }

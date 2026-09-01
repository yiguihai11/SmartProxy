package udp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"smartproxy/internal/safego"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/dns"
	"smartproxy/internal/rules"
	"smartproxy/internal/upstream"
)

const maxUDPSessions = 500

var (
	ActiveSessions  atomic.Int32
	ProxyBytesUp    atomic.Int64
	ProxyBytesDown  atomic.Int64
	DirectBytesUp   atomic.Int64
	DirectBytesDown atomic.Int64
)

// udpSessionKey is the unique identifier of a UDP session. A value struct (netip.Addr + port)
// is used instead of a per-packet string concatenation allocation of clientAddr.String()+"->"+targetAddr
// to reduce hot-path overhead. Session identity semantics are fully equivalent to the old string key (including IPv6 zone).
type udpSessionKey struct {
	clientIP   netip.Addr
	clientPort uint16
	targetIP   string
	targetPort uint16
}

// String is used for logging and as the singleflight key (called only on the session creation path, not on the per-packet hot path).
func (k udpSessionKey) String() string {
	return net.JoinHostPort(k.clientIP.String(), strconv.Itoa(int(k.clientPort))) +
		"->" + net.JoinHostPort(k.targetIP, strconv.Itoa(int(k.targetPort)))
}

// SetSocketBuffers best-effort enlarges the UDP socket send/receive buffers to reduce burst packet loss.
func SetSocketBuffers(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return setSocketBuffers(raw)
}

// sessionKeyFor builds a session key from the packet source and destination addresses.
func sessionKeyFor(clientAddr net.Addr, ip string, port int) udpSessionKey {
	ua := clientAddr.(*net.UDPAddr)
	k := udpSessionKey{
		clientPort: uint16(ua.Port),
		targetIP:   ip,
		targetPort: uint16(port),
	}
	if a, ok := netip.AddrFromSlice(ua.IP); ok {
		k.clientIP = a.WithZone(ua.Zone)
	}
	return k
}

type udpSession struct {
	remoteConn net.Conn
	lastActive atomic.Int64
	timeout    time.Duration
	clientAddr net.Addr
	key        udpSessionKey
	isProxy    bool
	closeOnce  sync.Once

	respHeader []byte // pre-built SOCKS5 UDP response header (used on the direct path)
}

type Handler struct {
	chnroute       *chnroute.Trie
	ruleEngine     *rules.Engine
	upstreamMgr    *upstream.Manager
	dnsHandler     *dns.Handler
	clientIP       string
	clientIPParsed net.IP // clientIP parsed once, avoiding a net.ParseIP allocation per packet
	conn           net.PacketConn

	relaxedUDPOrigin bool
	idleTimeout      time.Duration

	sessionsMu   sync.RWMutex
	sessions     map[udpSessionKey]*udpSession
	sessionCount atomic.Int32
	createGroup  singleflight.Group // serializes session creation for the same target, avoiding duplicate dials on concurrent first packets
	stopCh       chan struct{}
	closed       atomic.Bool
}

var udpBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 65535)
		return &buf
	},
}

func NewHandler(cn *chnroute.Trie, re *rules.Engine,
	mgr *upstream.Manager, dh *dns.Handler,
	clientIP string, conn net.PacketConn,
	relaxedUDPOrigin bool, idleTimeout time.Duration) *Handler {

	return &Handler{
		chnroute:         cn,
		ruleEngine:       re,
		upstreamMgr:      mgr,
		dnsHandler:       dh,
		clientIP:         clientIP,
		clientIPParsed:   net.ParseIP(clientIP),
		conn:             conn,
		relaxedUDPOrigin: relaxedUDPOrigin,
		idleTimeout:      idleTimeout,
		sessions:         make(map[udpSessionKey]*udpSession),
		stopCh:           make(chan struct{}),
	}
}

func (h *Handler) HandlePacket(ctx context.Context, data []byte, clientAddr net.Addr) {
	if h.closed.Load() {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in UDP handler", "panic", r)
		}
	}()
	srcIP := clientAddr.(*net.UDPAddr).IP
	clientIP := h.clientIPParsed // already parsed at construction time, avoiding a net.ParseIP allocation per packet

	if !srcIP.Equal(clientIP) && !(srcIP.IsLoopback() && clientIP.IsLoopback()) {
		if !h.relaxedUDPOrigin {
			slog.Warn("UDP packet from unexpected source, dropping",
				"source", srcIP, "expected", h.clientIP)
			return
		}
		//slog.Warn("UDP packet from unexpected source, allowing anyway (relaxed check)",
		//	"source", srcIP, "expected", h.clientIP)
	}

	if len(data) < 4 {
		return
	}
	frag := data[2]
	if frag != 0 {
		slog.Debug("UDP fragment not supported, dropping")
		return
	}
	atyp := data[3]

	var ip string
	var headerLen int
	// domain 只在 ATYP=0x03(DOMAIN 型目标)时非空。它是规则匹配的键:block/proxy domain
	// 规则需要它,不能像以前那样在 SelectProxy 里恒传 ""。ip 在 DOMAIN 型时仍是原始域名
	// (dial/ASSOCIATE 需要域名),IsIPBlocked 对域名返回 false,互不干扰。
	var domain string

	switch atyp {
	case 0x01:
		if len(data) < 10 {
			return
		}
		ip = net.IP(data[4:8]).String()
		headerLen = 4 + 4
	case 0x04:
		if len(data) < 22 {
			return
		}
		ip = net.IP(data[4:20]).String()
		headerLen = 4 + 16
	case 0x03:
		if len(data) < 5 {
			return
		}
		domainLen := int(data[4])
		if len(data) < 5+domainLen+2 {
			return
		}
		domain = string(data[5 : 5+domainLen])
		ip = domain
		headerLen = 4 + 1 + domainLen
	default:
		slog.Warn("unsupported address type in UDP header", "atyp", atyp)
		return
	}

	port := int(binary.BigEndian.Uint16(data[headerLen : headerLen+2]))
	payload := data[headerLen+2:]
	targetAddr := net.JoinHostPort(ip, strconv.Itoa(port))

	key := sessionKeyFor(clientAddr, ip, port)
	h.sessionsMu.RLock()
	sess, ok := h.sessions[key]
	h.sessionsMu.RUnlock()
	if ok {
		sess.lastActive.Store(time.Now().Unix())
		var toSend []byte
		if sess.isProxy {
			toSend = data
		} else {
			toSend = payload
		}
		// 并发安全(8 worker 共享同一条上游 TCP):net.TCPConn.Write 整个调用持运行时
		// fdMutex 写锁,多 goroutine 写被串行化,帧不会交错。前提是【一帧一次 Write】——
		// 别把 toSend 拆成两次 Write 或套共享 bufio.Writer,否则该保证失效(ponytail: 无需
		// 应用层写锁,运行时已串行;heV 帧自描述、乱序无影响)。
		if _, err := sess.remoteConn.Write(toSend); err != nil {
			slog.Debug("failed to write to remote in 0-RTT path", "error", err)
			h.closeSession(sess)
			h.sessionsMu.Lock()
			delete(h.sessions, key)
			h.sessionsMu.Unlock()
		} else {
			if sess.isProxy {
				ProxyBytesUp.Add(int64(len(toSend)))
			} else {
				DirectBytesUp.Add(int64(len(toSend)))
			}
		}
		return
	}

	slog.Debug("UDP packet (new session)", "from", clientAddr, "to", targetAddr)

	if h.ruleEngine.IsPortBlocked(port) {
		slog.Info("UDP blocked port", "port", port)
		return
	}
	if h.ruleEngine.IsIPBlocked(ip) {
		slog.Info("UDP blocked IP", "ip", ip)
		return
	}
	if domain != "" && h.ruleEngine.IsDomainBlocked(domain) {
		slog.Info("UDP blocked domain", "domain", domain)
		return
	}

	if port == 53 {
		if !h.dnsHandler.Enabled() {
			slog.Debug("DNS passthrough mode: forwarding raw UDP packet")
			h.handleGenericUDP(ctx, payload, data, clientAddr, ip, port, domain)
			return
		}
		h.handleDNS(ctx, payload, clientAddr, ip, port, ip, port)
		return
	}

	h.handleGenericUDP(ctx, payload, data, clientAddr, ip, port, domain)
}

func (h *Handler) handleGenericUDP(ctx context.Context, payload, fullData []byte, clientAddr net.Addr, ip string, port int, domain string) {
	targetAddr := net.JoinHostPort(ip, strconv.Itoa(port))
	key := sessionKeyFor(clientAddr, ip, port)

	// Concurrent first packets for the same target create only one session: singleflight serializes the dial to avoid duplicate connections and leaks.
	v, err, _ := h.createGroup.Do(key.String(), func() (interface{}, error) {
		return h.createUDPSession(ctx, clientAddr, ip, port, key, domain)
	})
	if err != nil {
		slog.Error("failed to create UDP session", "target", targetAddr, "error", err)
		return
	}
	sess := v.(*udpSession)

	var toSend []byte
	if sess.isProxy {
		toSend = fullData
	} else {
		toSend = payload
	}
	if _, err := sess.remoteConn.Write(toSend); err != nil {
		sess.remoteConn.Close()
		return
	}
	if sess.isProxy {
		ProxyBytesUp.Add(int64(len(toSend)))
	} else {
		DirectBytesUp.Add(int64(len(toSend)))
	}
}

// createUDPSession dials and registers a UDP session (called only via handleGenericUDP's singleflight, guaranteeing at most one creation per key).
// domain 来自 UDP 帧的 ATYP=0x03 目标,交给规则匹配:proxy/block domain 规则在 UDP 入口
// 也要命中(以前恒传 "" 使这类规则对 UDP 无效)。
func (h *Handler) createUDPSession(ctx context.Context, clientAddr net.Addr, ip string, port int, key udpSessionKey, domain string) (*udpSession, error) {
	result, selected := h.upstreamMgr.SelectProxy(ip, port, domain, h.ruleEngine)

	var remoteConn net.Conn
	var err error
	isProxy := false

	if result == "direct" || (result == "fallback" && h.isDomestic(ip)) {
		// 直连 UDP socket 选项(fwmark/缓冲/禁分片)与 TUN 路径共用 DirectUDPControl,
		// 保证两端直连行为一致。
		d := net.Dialer{Timeout: 5 * time.Second, Control: DirectUDPControl}
		remoteConn, err = d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	} else if selected != nil {
		remoteConn, err = selected.UDPAssociate(ctx, ip, port)
		isProxy = true
	} else {
		remoteConn, err = h.upstreamMgr.UDPAssociateSelected(ctx, ip, port, selected)
		isProxy = true
	}
	if err != nil {
		return nil, err
	}

	timeout := h.getSessionTimeout(port)
	sess := &udpSession{
		remoteConn: remoteConn,
		timeout:    timeout,
		clientAddr: clientAddr,
		key:        key,
		isProxy:    isProxy,
	}
	if !isProxy {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			parsedIP = net.IPv4(0, 0, 0, 0)
		}
		sess.respHeader = buildResponseHeader(ip, port, parsedIP)
	}
	sess.lastActive.Store(time.Now().Unix())

	if h.sessionCount.Load() >= maxUDPSessions {
		slog.Warn("too many UDP sessions to upstream, dropping oldest",
			"count", h.sessionCount.Load(), "max", maxUDPSessions)
		// Recycle the most idle session (rather than an arbitrary one) to avoid evicting active sessions
		h.sessionsMu.Lock()
		var evictKey udpSessionKey
		var evict *udpSession
		for k, s := range h.sessions {
			if evict == nil || s.lastActive.Load() < evict.lastActive.Load() {
				evict = s
				evictKey = k
			}
		}
		if evict != nil {
			delete(h.sessions, evictKey)
		}
		h.sessionsMu.Unlock()
		if evict != nil {
			h.closeSession(evict)
		}
	}
	h.sessionCount.Add(1)
	ActiveSessions.Add(1)
	h.sessionsMu.Lock()
	h.sessions[key] = sess
	h.sessionsMu.Unlock()
	safego.Go("udp.handler.pipeDownstream", func() { h.pipeDownstream(sess) })
	return sess, nil
}

func (h *Handler) getSessionTimeout(port int) time.Duration {
	if h.idleTimeout > 0 {
		return h.idleTimeout
	}
	return 60 * time.Second
}

func (h *Handler) pipeDownstream(sess *udpSession) {
	defer func() {
		slog.Debug("pipeDownstream exiting", "key", sess.key.String())
		h.closeSession(sess)
		h.sessionsMu.Lock()
		delete(h.sessions, sess.key)
		h.sessionsMu.Unlock()
	}()
	bufPtr := udpBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer udpBufPool.Put(bufPtr)

	// No per-packet ReadDeadline: idle session reaping is handled by StartCleaner based on lastActive
	// (the cleaner closes remoteConn, which unblocks the pending Read), saving one runtime timer per packet.
	if !sess.isProxy {
		// direct path: prepend the pre-built respHeader to the data
		hdrLen := len(sess.respHeader)
		for {
			n, err := sess.remoteConn.Read(buf[hdrLen:])
			if err != nil {
				slog.Debug("Read from remote failed", "key", sess.key.String(), "error", err)
				return
			}
			sess.lastActive.Store(time.Now().Unix())
			DirectBytesDown.Add(int64(n))

			copy(buf, sess.respHeader)
			if _, err := h.conn.WriteTo(buf[:hdrLen+n], sess.clientAddr); err != nil {
				slog.Debug("WriteTo client failed", "key", sess.key.String(), "error", err)
				return
			}
		}
	} else {
		// proxy path: upstream replies already carry the SOCKS5 header; pass them through as-is
		for {
			n, err := sess.remoteConn.Read(buf)
			if err != nil {
				slog.Debug("Read from remote (proxy) failed", "key", sess.key.String(), "error", err)
				return
			}
			sess.lastActive.Store(time.Now().Unix())
			ProxyBytesDown.Add(int64(n))
			if _, err := h.conn.WriteTo(buf[:n], sess.clientAddr); err != nil {
				slog.Debug("WriteTo client (proxy) failed", "key", sess.key.String(), "error", err)
				return
			}
		}
	}
}

func (h *Handler) closeSession(sess *udpSession) {
	sess.closeOnce.Do(func() {
		h.sessionCount.Add(-1)
		ActiveSessions.Add(-1)
		if sess.remoteConn != nil {
			sess.remoteConn.Close()
		}
	})
}

func (h *Handler) ActiveSessionCount() int {
	return int(h.sessionCount.Load())
}

func (h *Handler) StartCleaner() {
	safego.Go("udp.handler.cleaner", func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now().Unix()
				// Collect sessions to be recycled to avoid network closes while holding the lock
				h.sessionsMu.Lock()
				var toClose []*udpSession
				for k, sess := range h.sessions {
					if now-sess.lastActive.Load() > int64(sess.timeout.Seconds()) {
						slog.Debug("recycling UDP session", "key", sess.key.String(), "timeout", sess.timeout)
						delete(h.sessions, k)
						toClose = append(toClose, sess)
					}
				}
				h.sessionsMu.Unlock()
				for _, sess := range toClose {
					h.closeSession(sess)
				}
				if cnt := h.sessionCount.Load(); cnt > 200 {
					slog.Info("UDP session count high", "count", cnt, "max", maxUDPSessions)
				}
			case <-h.stopCh:
				h.sessionsMu.Lock()
				for k, sess := range h.sessions {
					delete(h.sessions, k)
					h.closeSession(sess)
				}
				h.sessionsMu.Unlock()
				return
			}
		}
	})
}

func (h *Handler) Close() {
	h.closed.Store(true)
	close(h.stopCh)
}

func (h *Handler) isDomestic(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return h.chnroute.Contains(parsed)
}

func (h *Handler) handleDNS(ctx context.Context, payload []byte, clientAddr net.Addr,
	origIP string, origPort int, realIP string, realPort int) {
	// 完整 DNS 管线(static/block/cache/private-IP 直连/domestic-foreign 分流)统一在
	// dns.Handler.HandleDNS 内,与 TUN 路径共用同一条管线、行为一致。此前 SOCKS5 在
	// 这里重复 static/block/cache/private 前置(HandleDNS 内部已做),已删除;
	// private 目标的直连分支也移入 HandleDNS,避免两条路各自实现。
	response := h.dnsHandler.HandleDNS(ctx, payload, realIP, realPort, h.ruleEngine)
	if response != nil {
		h.sendDNSResponse(response, clientAddr, origIP, origPort)
	} else {
		slog.Warn("DNS handler returned nil, no response sent to client",
			"client", clientAddr, "dnsTarget", fmt.Sprintf("%s:%d", realIP, realPort))
	}
}

func (h *Handler) sendDNSResponse(response []byte, clientAddr net.Addr, targetIP string, targetPort int) {
	parsed := net.ParseIP(targetIP)
	header := buildResponseHeader(targetIP, targetPort, parsed)
	h.conn.WriteTo(append(header, response...), clientAddr)
}

func buildResponseHeader(ip string, port int, parsed net.IP) []byte {
	if parsed != nil && parsed.To4() != nil {
		hdr := make([]byte, 10)
		binary.BigEndian.PutUint16(hdr[0:2], 0)
		hdr[2] = 0
		hdr[3] = 0x01
		copy(hdr[4:8], parsed.To4())
		binary.BigEndian.PutUint16(hdr[8:10], uint16(port))
		return hdr
	}

	hdr := make([]byte, 22)
	binary.BigEndian.PutUint16(hdr[0:2], 0)
	hdr[2] = 0
	hdr[3] = 0x04
	if parsed != nil {
		copy(hdr[4:20], parsed.To16())
	} else {

		copy(hdr[4:20], net.IPv6unspecified)
	}
	binary.BigEndian.PutUint16(hdr[20:22], uint16(port))
	return hdr
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

var dnsMsgPool = sync.Pool{
	New: func() interface{} { return new(mdns.Msg) },
}

func extractDNSQname(payload []byte) string {
	msg := dnsMsgPool.Get().(*mdns.Msg)
	*msg = mdns.Msg{}
	defer dnsMsgPool.Put(msg)
	if err := msg.Unpack(payload); err != nil {
		return ""
	}
	if len(msg.Question) == 0 {
		return ""
	}
	qname := strings.TrimSuffix(msg.Question[0].Name, ".")
	return strings.ToLower(qname)
}

func unpackDNSMsg(wire []byte) (*mdns.Msg, error) {
	msg := new(mdns.Msg)
	err := msg.Unpack(wire)
	return msg, err
}

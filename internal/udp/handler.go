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
	"smartproxy/internal/config"
	"smartproxy/internal/dns"
	"smartproxy/internal/dpi"
	"smartproxy/internal/quic"
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

// udpOutbound 是会话当前出向。framed=false 表示直连 socket(读写都是纯 payload,回包由
// pipeDownstream 套 respHeader);framed=true 表示 UDP-capable 上游(读写都带 SOCKS5 UDP
// header,整帧透传)。直连被 QUIC 判死热切代理时整体换一份(framed=true)。
type udpOutbound struct {
	conn   net.Conn
	framed bool
}

type udpSession struct {
	snap atomic.Pointer[udpOutbound] // 当前出向;判死热切时原子替换(读写无锁取当前值)
	wd   *quic.Watchdog              // B 路径(国外 QUIC 先直连判死观察)非 nil;其余会话恒 nil

	lastActive atomic.Int64
	timeout    time.Duration
	clientAddr net.Addr
	key        udpSessionKey
	closeOnce  sync.Once

	respHeader []byte // pre-built SOCKS5 UDP response header (used while direct)
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

	// QUIC 智能(被动 SNI 识别 + GFW 黑洞判死)配置快照;Enabled=false 时整条 UDP 路径与
	// 历史行为一致(不嗅探、不先直连判死)。
	quicEnabled     bool
	quicPorts       []int
	quicHold        time.Duration
	quicMaxBuffered int
	quicDummy       bool
	quicTimeout     time.Duration

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
	relaxedUDPOrigin bool, idleTimeout time.Duration,
	q config.SmartProxyQuicConf) *Handler {

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
		quicEnabled:      q.Enabled,
		quicPorts:        append([]int(nil), q.Ports...),
		quicHold:         time.Duration(q.HoldMs) * time.Millisecond,
		quicMaxBuffered:  q.MaxBuffered,
		quicDummy:        q.Dummy,
		quicTimeout:      time.Duration(q.TimeoutMs) * time.Millisecond,
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
		// forwardTo 按会话当前出向取帧:直连写纯 payload(顺带喂 QUIC 判死观察),代理写整
		// 帧。并发安全(8 worker 共享同一条上游 TCP):net.TCPConn.Write 整个调用持运行时
		// fdMutex 写锁,多 goroutine 写被串行化,帧不会交错。前提是【一帧一次 Write】。
		if !h.forwardTo(sess, payload, data) {
			slog.Debug("failed to write to remote in established session", "key", key.String())
			h.dropSession(sess)
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
		return h.createUDPSession(ctx, clientAddr, ip, port, key, domain, payload)
	})
	if err != nil {
		slog.Error("failed to create UDP session", "target", targetAddr, "error", err)
		return
	}
	sess := v.(*udpSession)

	if !h.forwardTo(sess, payload, fullData) {
		slog.Debug("failed to write first packet to remote", "target", targetAddr)
		h.dropSession(sess)
	}
}

// createUDPSession dials and registers a UDP session (called only via handleGenericUDP's singleflight, guaranteeing at most one creation per key).
// domain 来自 UDP 帧的 ATYP=0x03 目标,交给规则匹配:proxy/block domain 规则在 UDP 入口
// 也要命中(以前恒传 "" 使这类规则对 UDP 无效)。firstPayload 是触发建会话的那包原始
// datagram(QUIC 智能仅在其"IP 型 + QUIC 端口 + fallback 国外"候选上做首包嗅探)。
func (h *Handler) createUDPSession(ctx context.Context, clientAddr net.Addr, ip string, port int, key udpSessionKey, domain string, firstPayload []byte) (*udpSession, error) {
	// B 路径的 watchdog 判死回调经它取会话;会话构造完才赋值。判死只会在 Begin 之后
	// (超时)或客户端重传喂入时触发,必晚于赋值,回调拿到的 sess 恒非 nil。
	var sessHolder *udpSession

	result, selected := h.upstreamMgr.SelectProxy(ip, port, domain, h.ruleEngine)

	// framed=false → 直连(读写纯 payload,回包套 respHeader);true → UDP-capable 上游
	// (读写整帧)。wd 仅在 B(国外 QUIC 先直连判死观察)非 nil。
	var remoteConn net.Conn
	var err error
	framed := false
	var wd *quic.Watchdog

	switch {
	case result == "direct" || (result == "fallback" && h.isDomestic(ip)):
		// 直连 UDP socket 选项(fwmark/缓冲/禁分片)与 TUN 路径共用 DirectUDPControl,
		// 保证两端直连行为一致。
		d := net.Dialer{Timeout: 5 * time.Second, Control: DirectUDPControl}
		remoteConn, err = d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	case result != "fallback":
		if selected != nil {
			remoteConn, err = selected.UDPAssociate(ctx, ip, port)
		} else {
			remoteConn, err = h.upstreamMgr.UDPAssociateSelected(ctx, ip, port, selected)
		}
		framed = true
	default:
		// fallback + 国外:普通国外 UDP 走代理;QUIC 候选先进 routeForeignFallback 嗅探
		remoteConn, framed, wd, err = h.routeForeignFallback(ctx, ip, port, domain, key, firstPayload, &sessHolder)
	}
	if err != nil {
		return nil, err
	}

	timeout := h.getSessionTimeout(port)
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		parsedIP = net.IPv4(0, 0, 0, 0)
	}
	sess := &udpSession{
		timeout:    timeout,
		clientAddr: clientAddr,
		key:        key,
		wd:         wd,
	}
	sess.snap.Store(&udpOutbound{conn: remoteConn, framed: framed})
	if !framed {
		sess.respHeader = buildResponseHeader(ip, port, parsedIP)
	}
	if wd != nil {
		sessHolder = sess
		wd.Begin() // 直连就绪:开启判死计时(重传/超时判死回调此时才可能触发)
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

// routeForeignFallback 处理 fallback + 非国内的 UDP 目标(createUDPSession 的 last resort):
//   - 非 QUIC 端口 / 域名型目标(无 IP 可直连)→ 走默认 UDP-capable 上游(历史行为);
//   - QUIC 端口且 IP 型:首包短窗嗅探,确认 QUIC 后尽力抠外层 SNI 复走域名规则;
//   - 域名规则未命中 → B:国外 QUIC 先直连 + 判死 watchdog(Initial 重传 OR timeout_ms 零
//     回包 → 判 GFW 黑洞 → 回调把会话出向热切为 UDP-capable 上游)。
//
// 返回 (conn, framed, wd, err)。wd 非 nil 仅 B 路径。
func (h *Handler) routeForeignFallback(ctx context.Context, ip string, port int, domain string,
	key udpSessionKey, firstPayload []byte, sessRef **udpSession) (net.Conn, bool, *quic.Watchdog, error) {

	if !h.quicEnabled || !intInList(h.quicPorts, port) || domain != "" {
		rc, err := h.upstreamMgr.UDPAssociateSelected(ctx, ip, port, nil)
		return rc, true, nil, err
	}

	sniff := quic.NewSniff(h.quicHold, h.quicMaxBuffered)
	sniff.Ingest(firstPayload)
	if !sniff.QUIC() {
		slog.Info("UDP QUIC flow: non-QUIC payload on QUIC port, proxying",
			"target", net.JoinHostPort(ip, strconv.Itoa(port)))
		rc, err := h.upstreamMgr.UDPAssociateSelected(ctx, ip, port, nil)
		return rc, true, nil, err
	}
	sni := sniff.SNI()
	if e := sniff.ECH(); e != nil && e.Real {
		sni = "" // 真 ECH:外层 SNI 是混淆占位,域名规则作废
	}
	if sni != "" {
		r2, s2 := h.upstreamMgr.SelectProxy(ip, port, sni, h.ruleEngine)
		switch r2 {
		case "direct":
			slog.Info("UDP QUIC flow: domain rule direct, no blackhole watch",
				"target", net.JoinHostPort(ip, strconv.Itoa(port)), "sni", sni)
			d := net.Dialer{Timeout: 5 * time.Second, Control: DirectUDPControl}
			rc, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
			return rc, false, nil, err
		case "fallback":
			// 域名 ACL 未命中 → 国外 QUIC 目标,落 B 直连判死观察
		default:
			slog.Info("UDP QUIC flow: domain rule proxy",
				"target", net.JoinHostPort(ip, strconv.Itoa(port)), "sni", sni)
			if s2 != nil {
				rc, err := s2.UDPAssociate(ctx, ip, port)
				return rc, true, nil, err
			}
			rc, err := h.upstreamMgr.UDPAssociateSelected(ctx, ip, port, s2)
			return rc, true, nil, err
		}
	}

	// B 落地:国外 QUIC 先直连 + 判死 watchdog;哑包按开关先垫。
	d := net.Dialer{Timeout: 5 * time.Second, Control: DirectUDPControl}
	rc, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, false, nil, err
	}
	if h.quicDummy {
		if _, derr := rc.Write(quic.NewDummyDatagram()); derr != nil {
			slog.Debug("UDP QUIC dummy write failed", "target", net.JoinHostPort(ip, strconv.Itoa(port)), "error", derr)
		}
	}
	snipedSNI := sni // 判死日志带 SNI;可能为空(未抠到 / ECH)
	wd := quic.NewWatchdog(h.quicTimeout, func(reason string) {
		args := []any{"target", net.JoinHostPort(ip, strconv.Itoa(port)), "reason", reason}
		if snipedSNI != "" {
			args = append(args, "sni", snipedSNI)
		}
		slog.Info("UDP QUIC flow judged dead (GFW blackhole), switching to proxy", args...)
		h.quicFlowDead(*sessRef, key, ip, port)
	})
	trialArgs := []any{"target", net.JoinHostPort(ip, strconv.Itoa(port)), "timeout_ms", int(h.quicTimeout / time.Millisecond)}
	if sni != "" {
		trialArgs = append(trialArgs, "sni", sni)
	}
	slog.Info("UDP QUIC flow: direct trial (blackhole watch)", trialArgs...)
	return rc, false, wd, nil
}

// quicFlowDead 是 B 路径判死回调:会话出向从直连热切为默认 UDP-capable 上游。判死只发生
// 一次(Watchdog 内部保证),重复回调/会话已清理时安全返回。
func (h *Handler) quicFlowDead(sess *udpSession, key udpSessionKey, ip string, port int) {
	if sess == nil {
		return
	}
	h.sessionsMu.RLock()
	_, present := h.sessions[key]
	h.sessionsMu.RUnlock()
	if !present {
		return // 会话已清理(cleaner/reader 退出),不复活它
	}
	old := sess.snap.Load()
	if old == nil || old.framed {
		return // 早已是代理或已关闭
	}
	pconn, err := h.upstreamMgr.UDPAssociateSelected(context.Background(), ip, port, nil)
	if err != nil {
		slog.Warn("QUIC flow dead but UDP proxy fallback dial failed, staying direct",
			"target", net.JoinHostPort(ip, strconv.Itoa(port)), "error", err)
		return
	}
	sess.snap.Store(&udpOutbound{conn: pconn, framed: true})
	old.conn.Close() // 解除直连 reader 阻塞;reader 见出向已换 → 续读代理
	slog.Info("UDP QUIC flow switched to proxy after blackhole", "target", net.JoinHostPort(ip, strconv.Itoa(port)))
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
	// (the cleaner closes the current outbound, which unblocks the pending Read), saving one runtime timer per packet.
	//
	// 每轮取当前出向:直连读 payload(套 respHeader),代理读整帧透传。QUIC 判死热切会关闭旧
	// 直连解除本阻塞 Read;此时重取出向发现 conn 已换 → 继续读新代理 conn,不回退、不误删。
	hdrLen := len(sess.respHeader)
	for {
		out := sess.snap.Load()
		conn := out.conn
		var n int
		var err error
		if out.framed {
			n, err = conn.Read(buf)
		} else {
			n, err = conn.Read(buf[hdrLen:])
		}
		if err != nil {
			if sess.snap.Load().conn != conn {
				continue // 出向被热切替换(旧 conn 关闭解除阻塞):读新出向
			}
			if out.framed {
				slog.Debug("Read from remote (proxy) failed", "key", sess.key.String(), "error", err)
			} else {
				slog.Debug("Read from remote failed", "key", sess.key.String(), "error", err)
			}
			return
		}
		sess.lastActive.Store(time.Now().Unix())
		if out.framed {
			ProxyBytesDown.Add(int64(n))
			if _, err := h.conn.WriteTo(buf[:n], sess.clientAddr); err != nil {
				slog.Debug("WriteTo client (proxy) failed", "key", sess.key.String(), "error", err)
				return
			}
		} else {
			// 直连观察中的 QUIC 流:任意服务器回包 = 流存活,解除判死。之前这里漏喂
			// OnServerReply,reply 标志恒不置位 → timeout_ms 后活流也被误判死热切代理。
			// Monitoring() 仅在首个回包前为 true,保证 alive 日志每流只打一次。
			if wd := sess.wd; wd != nil {
				if wd.Monitoring() {
					slog.Info("UDP QUIC flow: direct alive (server replied), keeping direct",
						"target", net.JoinHostPort(sess.key.targetIP, strconv.Itoa(int(sess.key.targetPort))))
				}
				wd.OnServerReply()
			}
			DirectBytesDown.Add(int64(n))
			copy(buf, sess.respHeader)
			if _, err := h.conn.WriteTo(buf[:hdrLen+n], sess.clientAddr); err != nil {
				slog.Debug("WriteTo client failed", "key", sess.key.String(), "error", err)
				return
			}
		}
	}
}

func (h *Handler) closeSession(sess *udpSession) {
	sess.closeOnce.Do(func() {
		h.sessionCount.Add(-1)
		ActiveSessions.Add(-1)
		if sess.wd != nil {
			sess.wd.Stop() // 终止判死计时,防会话拆除后超时回调复活出向
		}
		if ob := sess.snap.Load(); ob != nil && ob.conn != nil {
			ob.conn.Close()
		}
	})
}

// forwardTo 把客户端一包转发到会话当前出向:代理写整帧(fullData),直连写纯 payload
// (payload)并顺带解密喂 QUIC 判死观察。喂后即判死 → 出向已被回调热切代理,本包改走代理帧。
// 写失败若正逢热切关闭旧直连(竞态窗口)→ 按新出向重发一次;仍失败返回 false 由调用方清会话。
// 计数(ProxyBytesUp/DirectBytesUp)在成功路径维护,保证与 internal/udp 语义一致。
func (h *Handler) forwardTo(sess *udpSession, payload, fullData []byte) bool {
	out := sess.snap.Load()
	if out.framed {
		if _, err := out.conn.Write(fullData); err != nil {
			return h.writeRetry(sess, out, payload, fullData)
		}
		ProxyBytesUp.Add(int64(len(fullData)))
		return true
	}

	if sess.wd != nil && sess.wd.Monitoring() {
		dcid, segs, _ := dpi.DecryptInitialDatagram(payload)
		if len(segs) > 0 {
			sess.wd.OnClientDatagram(dcid, segs)
		}
		if sess.wd.Dead() {
			// 判死回调已把出向热切代理并关闭旧直连;本包交给代理帧(回调经 quicFlowDead
			// 建的上游会自己处理这条流)。
			now := sess.snap.Load()
			if now.framed {
				if _, err := now.conn.Write(fullData); err != nil {
					return false
				}
				ProxyBytesUp.Add(int64(len(fullData)))
			}
			return true
		}
	}
	if _, err := out.conn.Write(payload); err != nil {
		return h.writeRetry(sess, out, payload, fullData)
	}
	DirectBytesUp.Add(int64(len(payload)))
	return true
}

// writeRetry 处理写失败:出向未被热切替换(conn 未变)是真错误 → false;已替换 → 按新出向
// 帧语义重发一次。竞态窗口只在判死热切的瞬间存在,一次重试即收敛。
func (h *Handler) writeRetry(sess *udpSession, out *udpOutbound, payload, fullData []byte) bool {
	now := sess.snap.Load()
	if now.conn == out.conn {
		return false
	}
	if now.framed {
		if _, err := now.conn.Write(fullData); err != nil {
			return false
		}
		ProxyBytesUp.Add(int64(len(fullData)))
		return true
	}
	if _, err := now.conn.Write(payload); err != nil {
		return false
	}
	DirectBytesUp.Add(int64(len(payload)))
	return true
}

// dropSession 关闭会话并把它从 sessions 表移除(写失败等会话级错误用)。
func (h *Handler) dropSession(sess *udpSession) {
	h.closeSession(sess)
	h.sessionsMu.Lock()
	if _, ok := h.sessions[sess.key]; ok {
		delete(h.sessions, sess.key)
	}
	h.sessionsMu.Unlock()
}

// intInList 报告 v 是否在 list 内(QUIC 端口白名单,量小线性扫)。
func intInList(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
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

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"smartproxy/internal/config"
	"smartproxy/internal/dns"
	"smartproxy/internal/dpi"
	"smartproxy/internal/fwmark"
	"smartproxy/internal/netutil"
	"smartproxy/internal/quic"
	"smartproxy/internal/relay"
	"smartproxy/internal/route"
	"smartproxy/internal/rules"
	"smartproxy/internal/safego"
	"smartproxy/internal/udp"

	"smartproxy/internal/upstream"
)

type TUNHandler struct {
	config      atomic.Pointer[config.Config]
	router      *route.Router
	ruleEng     *rules.Engine
	upstreamMgr *upstream.Manager
	dnsHandler  *dns.Handler

	// uidResolver 反向回调(Android 侧实现):按连接反查所属 app UID,命中
	// config.TUN.BlockedUIDs 即拦截。startRouter 时注入一次,之后只读。
	uidResolverFn atomic.Pointer[UIDResolverFunc]

	// connStats 连接监控(「联网状态」页数据源):懒开关,页面打开才采集。
	// 指针字段:NewConnStats 分配共享实例,handler 与 liveTCP 同持;原子字段
	// (atomic.Bool/Int32)按值拷贝会被 go vet 拒(copylocks)。
	connStats *ConnStats

	// liveTCP 活跃 TCP 连接句柄注册表(「联网状态」页封禁时按 ACL 扫描掐断)。
	// 与 connStats 共享同一 ConnStats,掐断时可即时移除统计记录。
	liveTCP *liveTCP

	udpSessions   sync.Map
	cleanerOnce   sync.Once
	cleanerStopCh chan struct{}
	closeOnce     sync.Once

	// Cleanup functions for the "selective source routing" installed when auto_route=false (executed when the TUN closes)
	selectiveCleanupMu sync.Mutex
	selectiveCleanup   []func()
}

// Compile-time assertion: TUNHandler must implement the singtun.Handler interface.
// If the signatures of the three callback methods (PrepareConnection / NewConnectionEx / NewPacketConnectionEx)
// do not match sing-tun, this will fail to compile.
var _ singtun.Handler = (*TUNHandler)(nil)

// maxUDPSessions bounds the TUN UDP session table (udpSessions). SOCKS5's UDP handler
// already caps at 500 (internal/udp); without a matching cap here a flood of distinct UDP
// destinations would grow the map — one goroutine + one remote conn per session — until OOM.
const maxUDPSessions = 500

func NewHandler(cfg *config.Config, r *route.Router, re *rules.Engine, um *upstream.Manager, dh *dns.Handler) *TUNHandler {
	h := &TUNHandler{
		router:        r,
		ruleEng:       re,
		upstreamMgr:   um,
		dnsHandler:    dh,
		cleanerStopCh: make(chan struct{}),
	}
	// connStats 指针字段:NewConnStats 分配共享实例,handler 与 liveTCP 同持
	// (掐断时 Remove 统计记录才作用在同一张表上)。
	h.connStats = NewConnStats()
	h.liveTCP = newLiveTCP(h.connStats)
	h.config.Store(cfg)
	return h
}

func (h *TUNHandler) startUDPCleaner() {
	h.cleanerOnce.Do(func() {
		safego.Go("tun.udpCleaner", func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					now := time.Now().Unix()
					h.udpSessions.Range(func(key, value any) bool {
						sess := value.(*tunUdpSession)
						if now-sess.lastActive.Load() > int64(sess.timeout.Seconds()) {
							sess.signalClose()
							h.udpSessions.Delete(key)
						}
						return true
					})
				case <-h.cleanerStopCh:
					h.udpSessions.Range(func(key, value any) bool {
						sess := value.(*tunUdpSession)
						sess.signalClose()
						h.udpSessions.Delete(key)
						return true
					})
					return
				}
			}
		})
	})
}

func (h *TUNHandler) Close() {
	h.closeOnce.Do(func() {
		close(h.cleanerStopCh)
		h.cleanSelectiveRoutes()
		fwmark.Disable()
	})
}

func (h *TUNHandler) setSelectiveCleanup(cleanups []func()) {
	h.selectiveCleanupMu.Lock()
	h.selectiveCleanup = append(h.selectiveCleanup, cleanups...)
	h.selectiveCleanupMu.Unlock()
}

func (h *TUNHandler) cleanSelectiveRoutes() {
	h.selectiveCleanupMu.Lock()
	cleanups := h.selectiveCleanup
	h.selectiveCleanup = nil
	h.selectiveCleanupMu.Unlock()
	for _, fn := range cleanups {
		fn()
	}
}

func (h *TUNHandler) ReloadConfig(cfg *config.Config) {
	h.config.Store(cfg)
}

// SetConnStatsEnabled 开关连接监控(「联网状态」页):页面打开采集、关闭即停。
// 关闭时数据路径零开销(handler 只在 enabled 时登记/包装连接)。
func (h *TUNHandler) SetConnStatsEnabled(on bool) {
	h.connStats.SetEnabled(on)
}

// ConnectionStats 返回按 app(uid)分组的连接快照 JSON(供 UI 每秒轮询)。
func (h *TUNHandler) ConnectionStats() string {
	return h.connStats.Snapshot()
}

// SetConnStatsPin 固定某 app(uid)的连接不被 idle 清扫(「联网状态」页展开某应用
// 明细时);-1 解除,解除后按 connStatsIdleRemove(5s)正常淡出。
func (h *TUNHandler) SetConnStatsPin(uid int32) {
	h.connStats.SetPin(uid)
}

// KillBlockedConnections 在 ACL 规则变更(Reload)后扫描现存连接,命中新封锁目标
// (域名/IP)的立即掐断 —— 让「加入 ACL」除了拒绝新连接,对现存连接也即时生效。
// 由 ACL reloader 回调调用(任何 ACL 变更都触发,幂等:只掐命中的)。
func (h *TUNHandler) KillBlockedConnections() {
	for _, hd := range h.liveTCP.snapshot() {
		host := hd.hostValue()
		blocked := (host != "" && h.ruleEng.IsDomainBlocked(host)) || h.ruleEng.IsIPBlocked(hd.ip)
		if blocked {
			slog.Info("TUN killed connection blocked by ACL", "host", host, "ip", hd.ip, "port", hd.port)
			hd.kill()
			// 立即注销,不等 relay 返回;relay 侧的 defer remove 幂等(已删则无操作)。
			h.liveTCP.remove(hd)
		}
	}
	h.udpSessions.Range(func(key, value any) bool {
		sess := value.(*tunUdpSession)
		if h.ruleEng.IsIPBlocked(sess.ip) {
			slog.Info("TUN killed UDP session blocked by ACL", "ip", sess.ip)
			sess.signalClose()
		}
		return true
	})
}

func (h *TUNHandler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext singtun.DirectRouteContext, timeout time.Duration) (singtun.DirectRouteDestination, error) {
	return nil, nil
}

func (h *TUNHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	host := destination.Addr.String()
	port := int(destination.Port)

	// Logged once per connection; at tens of thousands of connections/second, INFO is pure overhead, so the hot path is demoted to Debug
	slog.Debug("TUN new connection", "src", source, "dst", destination)

	if h.ruleEng == nil || h.router == nil {
		slog.Error("TUN handler not fully initialized (ruleEng or router is nil), closing connection")
		conn.Close()
		if onClose != nil {
			onClose(fmt.Errorf("handler not initialized"))
		}
		return
	}

	if h.ruleEng.IsPortBlocked(port) {
		slog.Info("TUN blocked port by rule", "port", port)
		if port == 80 || port == 443 {
			netutil.SendEnhancedBlock(conn, port)
		} else {
			conn.Close()
		}
		if onClose != nil {
			onClose(nil)
		}
		return
	}
	if h.ruleEng.IsIPBlocked(host) {
		slog.Info("TUN blocked IP by rule", "ip", host)
		if port == 80 || port == 443 {
			netutil.SendEnhancedBlock(conn, port)
		} else {
			conn.Close()
		}
		if onClose != nil {
			onClose(nil)
		}
		return
	}
	if h.isUIDBlocked(6, source, destination) {
		slog.Info("TUN blocked UID by per-app rule", "src", source, "dst", destination)
		// 复用现有 block 模式:80/443 SetLinger(0)→RST,其余直接 Close(gvisor 半握手关闭
		// 同样发 RST),被拦应用立刻看到连接被拒,而不是黑洞卡死。
		netutil.SendEnhancedBlock(conn, port)
		if onClose != nil {
			onClose(nil)
		}
		return
	}

	// 连接监控(「联网状态」页):懒开启,仅页面打开时采集。resolveUID 一次;
	// 与 isUIDBlocked 重复回调仅发生在「页面开着 + 名单非空」,连接建立频率低可接受。
	// 包装后 conn 交由下游(smart/普通转发)复用,字节全程计数。
	var rec *connRecord
	if h.connStats.Enabled() {
		uid := h.resolveUID(6, source, destination)
		rec = h.connStats.begin(uid, 6, host, port)
		if rec != nil {
			conn = h.connStats.wrapTCP(conn, rec)
		}
	}
	// 活跃连接登记(「联网状态」页封禁时按 ACL 扫描掐断):必须在 wrap 之后,
	// 句柄持有的 app conn 与下游 relay 用的是同一个对象。rec 可空(页面未开)。
	hd := h.liveTCP.add(conn, host, port, rec)

	smartEnabled := h.config.Load().SmartProxy.Enabled && netutil.ContainsInt(h.config.Load().SmartProxy.Ports, port)

	if !smartEnabled {
		remote, isProxy, err := h.router.EstablishConnection(ctx, host, port, "", h.ruleEng)
		if err != nil {
			slog.Error("TUN failed to establish connection", "host", host, "port", port, "error", err)
			// 成功路径的 remove 在 relay goroutine 的 defer 里;失败分支不建 goroutine,
			// 必须在这里手动摘表,否则代理故障时每个失败连接漏一个句柄,liveTCP 只增不减。
			h.liveTCP.remove(hd)
			conn.Close()
			if onClose != nil {
				onClose(err)
			}
			return
		}
		safego.Go("tun.handleConnect", func() {
			hd.setRemote(remote)
			defer h.liveTCP.remove(hd)
			relay.TCPRelay(ctx, conn, remote, isProxy, nil)
			conn.Close()
			remote.Close()
			if onClose != nil {
				onClose(nil)
			}
		})
		return
	}

	safego.Go("tun.handleSmartConnect", func() {
		h.handleSmartConnect(ctx, conn, host, port, rec, hd)
		if onClose != nil {
			onClose(nil)
		}
	})
}

func (h *TUNHandler) handleSmartConnect(ctx context.Context, conn net.Conn, host string, port int, rec *connRecord, hd *tcpHandle) {
	defer conn.Close()
	defer h.liveTCP.remove(hd)

	firstPkt, err := ReadClientHello(conn, 3*time.Second)
	if err != nil {
		if err != io.EOF {
			slog.Info("TUN error reading first packet", "error", err)
		}
		return
	}

	domain := ExtractDomain(firstPkt)
	h.connStats.setHost(rec, domain)
	hd.setHost(domain)
	if domain != "" {
		// Logged once per connection; the hot path is demoted to Debug
		slog.Debug("extracted domain", "domain", domain)
		if h.ruleEng.IsDomainBlocked(domain) {
			slog.Info("TUN blocked domain (static rule)", "domain", domain)
			netutil.SendEnhancedBlock(conn, port)
			return
		}
	}

	isDomestic := h.router.IsDomesticByIP(host)
	if isDomestic {
		remote, isProxy, err := h.router.EstablishConnection(ctx, host, port, domain, h.ruleEng)
		if err != nil {
			slog.Error("TUN failed to establish domestic connection", "host", host, "port", port, "domain", domain, "error", err)
			return
		}
		defer remote.Close()
		hd.setRemote(remote)
		if len(firstPkt) > 0 {
			if _, err := remote.Write(firstPkt); err != nil {
				slog.Debug("TUN error forwarding first packet", "error", err)
				return
			}
		}
		slog.Info("TUN domestic connection established", "host", host, "port", port, "domain", domain)
		relay.TCPRelay(ctx, conn, remote, isProxy, nil)
		return
	}

	remote, prefix, isProxy, err := h.router.SmartConnectWithFallback(ctx, host, port, domain, firstPkt, h.ruleEng)
	if err != nil {
		slog.Error("TUN smart connect failed", "host", host, "port", port, "domain", domain, "error", err)
		return
	}
	defer remote.Close()
	hd.setRemote(remote)
	slog.Info("TUN smart connection established", "host", host, "port", port, "domain", domain)
	relay.TCPRelay(ctx, conn, remote, isProxy, prefix)
}

func (h *TUNHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	host := destination.Addr.String()
	port := int(destination.Port)

	slog.Debug("TUN new packet connection", "src", source, "dst", destination)

	if h.ruleEng == nil {
		slog.Error("TUN handler not fully initialized (ruleEng is nil), closing packet connection")
		conn.Close()
		if onClose != nil {
			onClose(fmt.Errorf("handler not initialized"))
		}
		return
	}

	if h.ruleEng.IsPortBlocked(port) {
		conn.Close()
		if onClose != nil {
			onClose(nil)
		}
		return
	}
	if h.ruleEng.IsIPBlocked(host) {
		conn.Close()
		if onClose != nil {
			onClose(nil)
		}
		return
	}

	// DNS handler 启用时 53 端口走内置 DNS 管线;关闭时按普通 UDP 转发(passthrough),
	// 与 SOCKS5 入口的 DNS 分流一致——不能无条件进 handleDNS(HandleDNS 返回 nil 会静默丢包)。
	if port == 53 && h.dnsHandler != nil && h.dnsHandler.Enabled() {
		safego.Go("tun.handleDNS", func() {
			h.handleDNS(ctx, conn, host, port)
			if onClose != nil {
				onClose(nil)
			}
		})
		return
	}

	// 禁止联网:53 端口先放给 DNS 管线(被拦应用能解析、但数据连不上 → 直观的"无网络"),
	// 其余 UDP 命中已拦 UID 直接丢,不建会话不转发。
	if h.isUIDBlocked(17, source, destination) {
		slog.Info("TUN blocked UID by per-app rule", "src", source, "dst", destination)
		conn.Close()
		if onClose != nil {
			onClose(nil)
		}
		return
	}

	// 连接监控(同 TCP):UDP 一律不解析域名(设计定稿),host 落目标 IP。
	if h.connStats.Enabled() {
		uid := h.resolveUID(17, source, destination)
		rec := h.connStats.begin(uid, 17, host, port)
		if rec != nil {
			conn = h.connStats.wrapUDP(conn, rec)
		}
	}

	safego.Go("tun.handleGenericUDP", func() {
		h.handleGenericUDP(ctx, conn, source, destination)
		if onClose != nil {
			onClose(nil)
		}
	})
}

type tunUdpSession struct {
	lastActive atomic.Int64
	timeout    time.Duration
	closeCh    chan struct{}
	closeOnce  sync.Once
	ip         string // 目标 IP(「封禁」按 ACL 扫描掐断用)
}

func (s *tunUdpSession) signalClose() {
	s.closeOnce.Do(func() {
		// 与 SOCKS5 UDP 会话共用 udp.ActiveSessions,面板 udp_sessions 才一致。
		udp.ActiveSessions.Add(-1)
		close(s.closeCh)
	})
}

// storeUDPSession records a TUN UDP session under key, evicting the least-recently-active
// session when the table is at capacity so it stays bounded under a destination flood.
func (h *TUNHandler) storeUDPSession(key string, sess *tunUdpSession) {
	if h.countUDPSessions() >= maxUDPSessions {
		h.evictLeastRecentUDPSession()
	}
	h.udpSessions.Store(key, sess)
}

func (h *TUNHandler) countUDPSessions() int {
	n := 0
	h.udpSessions.Range(func(_, _ any) bool { n++; return true })
	return n
}

// evictLeastRecentUDPSession closes and removes the session that was active longest ago.
// Its own select unblocks via closeCh and its deferred cleanup runs normally.
func (h *TUNHandler) evictLeastRecentUDPSession() {
	var victimKey any
	var victimLast int64 = 1 << 62
	h.udpSessions.Range(func(key, value any) bool {
		if act := value.(*tunUdpSession).lastActive.Load(); act < victimLast {
			victimLast = act
			victimKey = key
		}
		return true
	})
	if victimKey != nil {
		if v, ok := h.udpSessions.LoadAndDelete(victimKey); ok {
			v.(*tunUdpSession).signalClose()
		}
	}
}

type udpRemoteEntry struct {
	conn        net.Conn
	dst         M.Socksaddr
	isProxy     bool
	proxyHeader []byte // pre-built SOCKS5 UDP header (only used on the proxy path)

	// QUIC 黑洞判死观察(仅 B 路径的直连 remote 非 nil):直连期间喂客户端 datagram
	// 做 Initial 重传检测、回包解除;判死回调把该 dst 热切换成代理 remote。重传检测按
	// 每包解出的 DCID 分组,无需单独存流 DCID。
	wd *quic.Watchdog
}

func (h *TUNHandler) handleGenericUDP(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr) {
	defer conn.Close()

	if h.upstreamMgr == nil || h.router == nil || h.ruleEng == nil {
		slog.Error("handleGenericUDP: handler not fully initialized (upstreamMgr, router, or ruleEng is nil)")
		return
	}

	timeout := h.getUDPTimeout(int(destination.Port))
	sess := &tunUdpSession{
		ip:      destination.Addr.String(),
		timeout: timeout,
		closeCh: make(chan struct{}),
	}
	sess.lastActive.Store(time.Now().Unix())
	udp.ActiveSessions.Add(1)

	// key 必须带源:每个(源 app, 目标)UDP 流是独立 conn/会话,只按目标做 key 时,
	// 多 App 打同一目标(共用 DNS、同 CDN 的 QUIC)会 Store 互相覆盖、defer Delete 互删,
	// 被覆盖的会话对 cleaner/evict 不可见(500 上限失效),只能等 gVisor 5 分钟超时才死。
	sessKey := source.String() + "->" + destination.String()
	h.storeUDPSession(sessKey, sess)
	h.startUDPCleaner()
	defer h.udpSessions.Delete(sessKey)
	defer sess.signalClose()

	var (
		mu       sync.Mutex
		remotes  = make(map[string]*udpRemoteEntry)
		remoteWg sync.WaitGroup // tracks remoteUDPReader goroutines (one per dialed remote)
		sendWg   sync.WaitGroup // tracks the udpSend goroutine
		errCh    = make(chan error, 8)
	)

	// QUIC 智能配置快照(每次会话读当前值;判死窗口/嗅探预算/哑包开关)。
	q := h.config.Load().SmartProxy.Quic
	quicHold := time.Duration(q.HoldMs) * time.Millisecond
	quicTimeout := time.Duration(q.TimeoutMs) * time.Millisecond

	// dialDirect 打开一条直连 UDP socket(fwmark/1MB 缓冲/禁分片与 SOCKS5 路径共用
	// DirectUDPControl,dial 超时对齐 5s)。
	dialDirect := func(host string, port int) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second, Control: udp.DirectUDPControl}
		return d.DialContext(ctx, "udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	}

	// newProxyRemote 建一条走 UDP-capable 上游的代理 remote。dst 为该条 UDP 流的真实目标
	// (每包 pktDst),回包按它写回 tun;proxySel==nil 走聚合默认 fallback(判死/黑名单命中
	// 时传 nil 强制走默认上游)。
	newProxyRemote := func(dst M.Socksaddr, host string, port int, proxySel *upstream.Proxy) (*udpRemoteEntry, error) {
		var remote net.Conn
		var err error
		if proxySel == nil {
			remote, err = h.upstreamMgr.UDPAssociate(ctx, host, port, "", h.ruleEng)
		} else {
			remote, err = proxySel.UDPAssociate(ctx, host, port)
		}
		if err != nil {
			return nil, err
		}
		entry := &udpRemoteEntry{conn: remote, dst: dst, isProxy: true}
		entry.proxyHeader = buildSocks5UDPHeader(host, port)
		remoteWg.Add(1)
		safego.Go("tun.remoteUDPReader", func() {
			defer remoteWg.Done()
			defer remote.Close()
			h.remoteUDPReader(conn, entry, errCh)
		})
		return entry, nil
	}

	// startDirectRemote 建一条直连 remote 并启动回包 reader。wd 非 nil 时该 remote 处于
	// QUIC 判死观察(哑包按开关先垫、Begin 启动计时)。
	startDirectRemote := func(dst M.Socksaddr, host string, port int, wd *quic.Watchdog) (*udpRemoteEntry, error) {
		rc, err := dialDirect(host, port)
		if err != nil {
			return nil, err
		}
		entry := &udpRemoteEntry{conn: rc, dst: dst, isProxy: false, wd: wd}
		if q.Dummy && wd != nil { // 哑包垫首(GFW 首包启发对抗);失败不致命
			if _, werr := rc.Write(quic.NewDummyDatagram()); werr != nil {
				slog.Debug("TUN QUIC dummy write failed", "error", werr)
			}
		}
		if wd != nil {
			wd.Begin()
		}
		remoteWg.Add(1)
		safego.Go("tun.remoteUDPReader", func() {
			defer remoteWg.Done()
			defer rc.Close()
			h.remoteUDPReader(conn, entry, errCh)
		})
		return entry, nil
	}

	// switchToProxy 判死回调:把 remotes[key] 从直连热切换成代理。若 remotes[key] 已非
	// 判死前的直连(会话被并发替换/清理),丢弃新建代理不破坏现状;代理回包地址沿用旧
	// 直连的 dst,保证只切换出向路径、回包路径不变。
	switchToProxy := func(key, host string, port int) {
		pentry, err := newProxyRemote(destination, host, port, nil)
		if err != nil {
			slog.Warn("QUIC flow dead but proxy fallback dial failed, staying direct",
				"dst", destination, "error", err)
			return
		}
		mu.Lock()
		cur, ok := remotes[key]
		if !ok || cur.isProxy { // 会话已清理 / 早已是代理(竞态重复切换)
			mu.Unlock()
			pentry.conn.Close()
			return
		}
		pentry.dst = cur.dst
		remotes[key] = pentry
		mu.Unlock()
		// 关掉旧直连:其 reader 见 wd.Dead 静默退出,不会经 errCh 误杀整个会话
		cur.conn.Close()
		slog.Info("UDP QUIC flow switched to proxy after blackhole", "dst", destination)
	}

	dialRemote := func(dst M.Socksaddr, firstDgram []byte) (*udpRemoteEntry, error) {
		host := dst.Addr.String()
		port := int(dst.Port)

		result, selected := h.upstreamMgr.SelectProxy(host, port, "", h.ruleEng)
		switch {
		case result == "direct":
			return startDirectRemote(dst, host, port, nil) // ACL 强制直连
		case result != "fallback":
			return newProxyRemote(dst, host, port, selected) // ACL 指定代理
		}

		// fallback:chnroute 国内直连;判死过/国外再按 QUIC 智能决策
		if h.router.IsDomesticByIP(host) {
			return startDirectRemote(dst, host, port, nil) // 国内直连,无判死观察
		}
		if h.router.IsIPBlacklisted(host, port) {
			slog.Info("UDP target on dynamic blacklist, going proxy", "dst", dst)
			return newProxyRemote(dst, host, port, nil)
		}
		if !q.Enabled || !intIn(q.Ports, port) {
			return newProxyRemote(dst, host, port, nil) // 普通国外 UDP 走代理(现状)
		}

		// B 候选(国外 + QUIC 端口):首包短窗嗅探确认 QUIC,并尽力抠 SNI 走域名规则
		sniff := quic.NewSniff(quicHold, q.MaxBuffered)
		sniff.Ingest(firstDgram)
		if !sniff.QUIC() {
			slog.Info("UDP QUIC flow: non-QUIC payload on QUIC port, proxying", "dst", dst)
			return newProxyRemote(dst, host, port, nil) // 该端口上的非 QUIC 载荷(罕见)照旧代理
		}
		sni := sniff.SNI()
		if e := sniff.ECH(); e != nil && e.Real {
			sni = "" // 真 ECH:外层 SNI 是混淆占位,域名规则作废
		}
		if sni != "" {
			r2, s2 := h.upstreamMgr.SelectProxy(host, port, sni, h.ruleEng)
			switch r2 {
			case "direct":
				slog.Info("UDP QUIC flow: domain rule direct, no blackhole watch",
					"dst", dst, "sni", sni)
				return startDirectRemote(dst, host, port, nil) // 域名规则强制直连
			case "fallback":
				// 域名 ACL 未命中 → 国外 QUIC 目标,落到下方 B 直连判死观察
			default:
				slog.Info("UDP QUIC flow: domain rule proxy", "dst", dst, "sni", sni)
				return newProxyRemote(dst, host, port, s2) // 域名规则指定代理
			}
		}

		// B 落地:国外 QUIC 先直连、挂判死 watchdog。判死条件 = Initial 重传 OR
		// timeout_ms 窗口内零服务器回包;回包即活。判死 → 写动态黑名单(IP+SNI)+
		// 热切换该 dst 到 UDP-capable 上游。
		key := dst.String()
		snipedSNI := sni // 判死回调写域名黑名单用(可能为空)
		wd := quic.NewWatchdog(quicTimeout, func(reason string) {
			args := []any{"dst", dst, "reason", reason}
			if snipedSNI != "" {
				args = append(args, "sni", snipedSNI)
			}
			slog.Info("UDP QUIC flow judged dead (GFW blackhole), switching to proxy", args...)
			h.router.BlacklistIP(host, port, "quic:"+reason)
			if snipedSNI != "" {
				h.router.BlacklistDomain(snipedSNI, port, "quic:"+reason)
			}
			switchToProxy(key, host, port)
		})
		entry, err := startDirectRemote(dst, host, port, wd)
		if err != nil {
			wd.Stop()
			return nil, err
		}
		trialArgs := []any{"dst", dst, "timeout_ms", int(quicTimeout / time.Millisecond)}
		if sni != "" {
			trialArgs = append(trialArgs, "sni", sni)
		}
		slog.Info("UDP QUIC flow: direct trial (blackhole watch)", trialArgs...)
		return entry, nil
	}

	getOrCreateRemote := func(dst M.Socksaddr, firstDgram []byte) (*udpRemoteEntry, error) {
		key := dst.String()

		// Fast path: the destination already exists, return under the lock without dialing
		mu.Lock()
		if entry, ok := remotes[key]; ok {
			mu.Unlock()
			return entry, nil
		}
		mu.Unlock()

		// Slow path: dial outside the lock (up to 10s), without blocking forwarding to other destinations in the same session
		entry, err := dialRemote(dst, firstDgram)
		if err != nil {
			return nil, err
		}

		// Double-check: a concurrent dial may have already created the same destination, so reuse the existing connection and close the redundant one just created
		mu.Lock()
		if existing, ok := remotes[key]; ok {
			mu.Unlock()
			entry.conn.Close()
			return existing, nil
		}
		remotes[key] = entry
		mu.Unlock()
		return entry, nil
	}

	sendWg.Add(1)
	safego.Go("tun.udpSend", func() {
		defer sendWg.Done()
		for {
			buffer := buf.NewPacket()
			pktDst, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				// Non-blocking: once the main select exits nobody drains errCh, and a full
				// channel must not wedge the sender forever (it would also stall sendWg.Wait).
				select {
				case errCh <- err:
				default:
				}
				return
			}

			sess.lastActive.Store(time.Now().Unix())

			entry, err := getOrCreateRemote(pktDst, buffer.Bytes())
			if err != nil {
				slog.Debug("TUN UDP no remote for", "dst", pktDst, "error", err)
				buffer.Release()
				continue
			}

			if entry.isProxy {
				pktBufPtr := relay.UDPBufPool.Get().(*[]byte)
				pktBuf := *pktBufPtr
				proxyHeader := entry.proxyHeader
				copy(pktBuf, proxyHeader)
				payload := buffer.Bytes()
				payloadLen := len(payload)
				copy(pktBuf[len(proxyHeader):], payload)
				if _, err := entry.conn.Write(pktBuf[:len(proxyHeader)+payloadLen]); err != nil {
					relay.UDPBufPool.Put(pktBufPtr)
					buffer.Release()
					select {
					case errCh <- err:
					default:
					}
					return
				}
				// 上行计数:代理帧带 SOCKS5 header,语义与 internal/udp 一致
				udp.ProxyBytesUp.Add(int64(len(proxyHeader) + payloadLen))
				relay.UDPBufPool.Put(pktBufPtr)
			} else {
				// QUIC 判死观察中:每包先解密喂 watchdog(仅 Monitoring 期;判死条件 = Initial
				// 重传 OR 超时零回包,已见回包即退出本分支)。喂完即判死 → 回调已把该 dst 热切
				// 代理并关闭旧直连,本包丢弃,后续包走新代理。
				if wd := entry.wd; wd != nil && wd.Monitoring() {
					dcid, segs, _ := dpi.DecryptInitialDatagram(buffer.Bytes())
					if len(segs) > 0 {
						wd.OnClientDatagram(dcid, segs)
					}
					if wd.Dead() {
						buffer.Release()
						continue
					}
				}
				if _, err := entry.conn.Write(buffer.Bytes()); err != nil {
					// 写失败若正逢判死热切关闭旧直连(竞态窗口),属预期:丢本包,下一包自动
					// 走代理 remote,不误杀整个会话。
					if entry.wd != nil && entry.wd.Dead() {
						buffer.Release()
						continue
					}
					buffer.Release()
					select {
					case errCh <- err:
					default:
					}
					return
				}
				// 上行计数:直连写纯 payload
				udp.DirectBytesUp.Add(int64(len(buffer.Bytes())))
			}
			buffer.Release()
		}
	})

	select {
	case <-ctx.Done():
	case <-errCh:
	case <-sess.closeCh:
		slog.Debug("TUN UDP session closed by cleaner", "key", sessKey)
	}

	// Shut the sender down first: closing the tun packet conn makes its ReadPacket fail, and
	// sendWg.Wait() guarantees the sender has exited — so no dialRemote can Add(1) to
	// remoteWg any more, which would otherwise race with the Wait below (WaitGroup misuse
	// panic) or leak a freshly-dialed remote that the close loop has already walked past.
	// Any remote the sender finished dialing is already recorded in remotes by the time it
	// exits, so the close loop below covers it.
	conn.Close()
	sendWg.Wait()

	mu.Lock()
	for _, entry := range remotes {
		entry.conn.Close()
	}
	mu.Unlock()
	remoteWg.Wait()
}

func (h *TUNHandler) remoteUDPReader(tunConn N.PacketConn, entry *udpRemoteEntry, errCh chan<- error) {
	pktBufPtr := relay.UDPBufPool.Get().(*[]byte)
	rawBuf := *pktBufPtr
	defer relay.UDPBufPool.Put(pktBufPtr)
	for {
		n, err := entry.conn.Read(rawBuf)
		if err != nil {
			// QUIC 判死直连被热切/主动关闭属预期:静默退出,不让 errCh 误杀整个会话
			// (switchToProxy 已用代理 remote 接管回包)。
			if entry.wd != nil && entry.wd.Dead() {
				return
			}
			select {
			case errCh <- err:
			default:
			}
			return
		}
		if !entry.isProxy && entry.wd != nil {
			// 首个服务器回包 = 流存活、保持直连,打一条日志(Monitoring 仅在首个回包前
			// 为 true → 每流只打一次);再解除判死。
			if entry.wd.Monitoring() {
				slog.Info("UDP QUIC flow: direct alive (server replied), keeping direct", "dst", entry.dst)
			}
			entry.wd.OnServerReply() // 任意服务器回包 = 流存活,解除判死
		}
		payloadStart := 0
		if entry.isProxy {
			if n < 4 {
				continue
			}
			atyp := rawBuf[3]
			switch atyp {
			case 0x01:
				payloadStart = 4 + 4 + 2
			case 0x03:
				if n < 5 {
					continue
				}
				payloadStart = 4 + 1 + int(rawBuf[4]) + 2
			case 0x04:
				payloadStart = 4 + 16 + 2
			}
			if payloadStart >= n {
				continue
			}
			// 下行计数:代理回包带 SOCKS5 header,语义与 internal/udp 一致
			udp.ProxyBytesDown.Add(int64(n))
		} else {
			// 下行计数:直连回包是纯 payload
			udp.DirectBytesDown.Add(int64(n))
		}
		// Use buf.As instead of buf.With: With does not set end, so Bytes() returns an empty slice, which would write the UDP reply as an empty datagram.
		respBuf := buf.As(rawBuf[payloadStart:n])
		if err := tunConn.WritePacket(respBuf, entry.dst); err != nil {
			respBuf.Release()
			select {
			case errCh <- err:
			default:
			}
			return
		}
		respBuf.Release()
	}
}

func (h *TUNHandler) getUDPTimeout(port int) time.Duration {
	switch port {
	case 53:
		return 5 * time.Second
	case 123:
		return 10 * time.Second
	case 443:
		return 60 * time.Second
	default:
		return 60 * time.Second
	}
}

func (h *TUNHandler) handleDNS(ctx context.Context, conn N.PacketConn, host string, port int) {
	defer conn.Close()

	if h.dnsHandler == nil || h.ruleEng == nil {
		slog.Error("handleDNS: handler not fully initialized (dnsHandler or ruleEng is nil)")
		return
	}

	for {
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			slog.Debug("DNS SetReadDeadline failed", "error", err)
			return
		}
		buffer := buf.NewPacket()
		addr, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return
		}
		payload := buffer.Bytes()

		response := h.dnsHandler.HandleDNS(ctx, payload, host, port, h.ruleEng)
		buffer.Release()

		if response != nil {
			// Use buf.As instead of buf.With: With does not set end, so Bytes() returns an empty slice, which would write the DNS response as an empty datagram.
			respBuf := buf.As(response)
			if err := conn.WritePacket(respBuf, addr); err != nil {
				slog.Debug("DNS write response failed", "error", err)
			}
			respBuf.Release()
		}
	}
}

var NewTUN = singtun.New
var NewTUNStack = singtun.NewStack

func (h *TUNHandler) Start(ctx context.Context, cfg config.TUNConfig) (singtun.Tun, singtun.Stack, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}

	isFdMode := cfg.FileDescriptor != 0
	if isFdMode {
		if cfg.MTU <= 0 {
			slog.Warn("fd mode: MTU not set, defaulting to 1500 — ensure this matches the OS TUN configuration")
			cfg.MTU = 1500
		}
		if cfg.Name == "" {
			cfg.Name = "tun"
		}
	}

	var inet4 []netip.Prefix
	for _, s := range cfg.Inet4Address {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid IPv4 prefix %s: %w", s, err)
		}
		inet4 = append(inet4, p)
	}
	var inet6 []netip.Prefix
	for _, s := range cfg.Inet6Address {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid IPv6 prefix %s: %w", s, err)
		}
		inet6 = append(inet6, p)
	}

	// fd 模式(Android VpnService)下接口监控全程零消费:NativeTun.Start() 在
	// FileDescriptor != 0 时直接 return nil,RegisterMyInterface 永不调用;RegisterCallback
	// 需要 AutoRoute && android 而 fd 模式引擎已强制 AutoRoute=false;Close / UpdateRouteOptions
	// 也都判 FileDescriptor 短路。而 NewNetworkUpdateMonitor 在 Android 上会先探测 netlink
	// socket(monitor_linux.go 的 "banned by Google" 检查),SELinux untrusted_app 域不放行
	// netlink 时直接 ErrNetlinkBanned 让整条隧道起不来(真机实测报错)。所以 fd 模式跳过这两步,
	// 传 nil——monitor 只在非 fd 模式(t. 开原生 tun0)时按原样创建。
	var interfaceMonitor singtun.DefaultInterfaceMonitor
	if !isFdMode {
		// NativeTun.Start() (t.Start() below) internally calls options.InterfaceMonitor.
		// RegisterMyInterface, which must be non-nil or it will panic with a nil pointer. It is built with sing's default
		// implementation plus a NOP logger; this project does not register interface-change callbacks, so the monitor stays lazy.
		networkMonitor, err := singtun.NewNetworkUpdateMonitor(logger.NOP())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create network monitor: %w", err)
		}
		interfaceMonitor, err = singtun.NewDefaultInterfaceMonitor(networkMonitor, logger.NOP(), singtun.DefaultInterfaceMonitorOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create interface monitor: %w", err)
		}
	}

	tunOpts := singtun.Options{
		Name:             cfg.Name,
		MTU:              uint32(cfg.MTU),
		Inet4Address:     inet4,
		Inet6Address:     inet6,
		AutoRoute:        cfg.AutoRoute,
		FileDescriptor:   cfg.FileDescriptor,
		InterfaceMonitor: interfaceMonitor,
	}

	t, err := NewTUN(tunOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TUN: %w", err)
	}

	// t.Start() does two things: netlink.LinkSetUp brings the interface UP, and it installs
	// the auto_route source policy routes/rules (setRoute + setRules inside NativeTun.Start).
	// Previously omitting this call left tun0 DOWN and auto_route routing inactive, requiring a manual ip link set tun0 up.
	// In fd mode, NativeTun.Start() returns nil immediately (no-op) when FileDescriptor != 0, so mobile platforms are unaffected.
	if err := t.Start(); err != nil {
		t.Close()
		return nil, nil, fmt.Errorf("failed to start TUN: %w", err)
	}

	// When auto_route=false, install selective routing so that only traffic whose source address is in the TUN subnet
	// goes through tun0 (equivalent to the source-rule part of sing-tun auto_route, but without installing the full
	// from 0.0.0.0 hijack), which is safe for server/SSH scenarios. In fd mode routing is managed by the OS VPN, so it is skipped; Linux only.
	if !cfg.AutoRoute && !isFdMode {
		h.installSelectiveRoutes(cfg.Name, inet4, inet6)
	}

	// output_mark: set SO_MARK on the router's own outbound connections so routing rules can identify
	// and exclude the router itself (prevents loops). Only meaningful when auto_route=true (full hijack) and not in fd mode:
	// marking + ip rule (fwmark→main) + nftables exclude ports let the router itself and SSH bypass the TUN.
	// A failure to install must abort startup (otherwise it is a full hijack with no exclusion, and the server will hang).
	if cfg.OutputMark > 0 && cfg.AutoRoute && !isFdMode {
		fwmark.Configure(cfg.OutputMark)
		cleanup, err := installSelfExclude(cfg.OutputMark, cfg.RouteExcludePorts)
		if err != nil {
			t.Close()
			fwmark.Disable()
			return nil, nil, fmt.Errorf("install self-exclude rules: %w", err)
		}
		h.setSelectiveCleanup([]func(){cleanup})
	}

	stackType := cfg.Stack
	if stackType == "" {
		stackType = "gvisor"
	}

	// UDPTimeout/ICMPTimeout must be non-zero: sing-tun's gvisor UDP forwarder panics
	// directly in udpnat2.New when timeout==0 (previously omitted, causing the TUN to fail to start).
	stackOpts := singtun.StackOptions{
		Context:     ctx,
		Tun:         t,
		TunOptions:  tunOpts,
		Handler:     h,
		UDPTimeout:  5 * time.Minute,
		ICMPTimeout: 30 * time.Second,
	}

	s, err := NewTUNStack(stackType, stackOpts)
	if err != nil {
		t.Close()
		return nil, nil, fmt.Errorf("failed to create stack %s: %w", stackType, err)
	}

	if err := s.Start(); err != nil {
		s.Close()
		t.Close()
		return nil, nil, fmt.Errorf("failed to start stack: %w", err)
	}

	name, err := t.Name()
	if err != nil {
		slog.Warn("TUN interface started but failed to get name", "error", err)
		name = "(unknown)"
	}
	slog.Info("TUN interface started", "name", name, "stack", stackType)
	return t, s, nil
}

// clientHelloBufPool recycles the pre-read buffer used by ReadClientHello.
// Most TLS/HTTP first packets are far smaller than 4096 bytes, so the pooled
// buffer is only used transiently and the actual payload is copied into a
// caller-owned slice of the exact size.
var clientHelloBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 4096)
		return &buf
	},
}

func ReadClientHello(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	bufPtr := clientHelloBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer clientHelloBufPool.Put(bufPtr)

	if _, err := io.ReadFull(conn, buf[:5]); err != nil {
		return nil, err
	}

	if buf[0] >= 0x14 && buf[0] <= 0x17 {
		recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
		if recordLen > len(buf)-5 {
			// Oversized TLS record: read into a dedicated buffer.
			payload := make([]byte, recordLen)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return nil, err
			}
			out := make([]byte, 5+recordLen)
			copy(out, buf[:5])
			copy(out[5:], payload)
			return out, nil
		}
		if _, err := io.ReadFull(conn, buf[5:5+recordLen]); err != nil {
			return nil, err
		}
		out := make([]byte, 5+recordLen)
		copy(out, buf[:5+recordLen])
		return out, nil
	}

	n := 5
	for n < len(buf) {
		nn, err := conn.Read(buf[n:])
		n += nn
		if err != nil {
			break
		}
		if bytes.Contains(buf[:n], []byte("\r\n\r\n")) {
			break
		}
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

func ExtractDomain(firstPkt []byte) string {
	if len(firstPkt) == 0 {
		return ""
	}
	if sni := dpi.ExtractSNI(firstPkt); sni != "" {
		return strings.ToLower(sni)
	}
	if httpHost := dpi.ExtractHTTPHost(firstPkt); httpHost != "" {
		return strings.ToLower(httpHost)
	}
	return ""
}

func buildSocks5UDPHeader(host string, port int) []byte {
	ip := net.ParseIP(host)
	if ip == nil {
		domain := []byte(host)
		buf := make([]byte, 4+1+len(domain)+2)
		buf[0] = 0
		buf[1] = 0
		buf[2] = 0
		buf[3] = 0x03
		buf[4] = byte(len(domain))
		copy(buf[5:], domain)
		binary.BigEndian.PutUint16(buf[5+len(domain):], uint16(port))
		return buf
	}
	if ip4 := ip.To4(); ip4 != nil {
		buf := make([]byte, 4+4+2)
		buf[0] = 0
		buf[1] = 0
		buf[2] = 0
		buf[3] = 0x01
		copy(buf[4:8], ip4)
		binary.BigEndian.PutUint16(buf[8:10], uint16(port))
		return buf
	}
	buf := make([]byte, 4+16+2)
	buf[0] = 0
	buf[1] = 0
	buf[2] = 0
	buf[3] = 0x04
	copy(buf[4:20], ip.To16())
	binary.BigEndian.PutUint16(buf[20:22], uint16(port))
	return buf
}

// intIn 报告 v 是否在 int 切片内(QUIC 端口白名单用,量小不引 sort)。
func intIn(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

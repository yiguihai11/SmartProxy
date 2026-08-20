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

	smartEnabled := h.config.Load().SmartProxy.Enabled && netutil.ContainsInt(h.config.Load().SmartProxy.Ports, port)

	if !smartEnabled {
		remote, isProxy, err := h.router.EstablishConnection(ctx, host, port, "", h.ruleEng)
		if err != nil {
			slog.Error("TUN failed to establish connection", "host", host, "port", port, "error", err)
			conn.Close()
			if onClose != nil {
				onClose(err)
			}
			return
		}
		safego.Go("tun.handleConnect", func() {
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
		h.handleSmartConnect(ctx, conn, host, port)
		if onClose != nil {
			onClose(nil)
		}
	})
}

func (h *TUNHandler) handleSmartConnect(ctx context.Context, conn net.Conn, host string, port int) {
	defer conn.Close()

	firstPkt, err := ReadClientHello(conn, 3*time.Second)
	if err != nil {
		if err != io.EOF {
			slog.Info("TUN error reading first packet", "error", err)
		}
		return
	}

	domain := ExtractDomain(firstPkt)
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

	safego.Go("tun.handleGenericUDP", func() {
		h.handleGenericUDP(ctx, conn, destination)
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
}

func (h *TUNHandler) handleGenericUDP(ctx context.Context, conn N.PacketConn, destination M.Socksaddr) {
	defer conn.Close()

	if h.upstreamMgr == nil || h.router == nil || h.ruleEng == nil {
		slog.Error("handleGenericUDP: handler not fully initialized (upstreamMgr, router, or ruleEng is nil)")
		return
	}

	timeout := h.getUDPTimeout(int(destination.Port))
	sess := &tunUdpSession{
		timeout: timeout,
		closeCh: make(chan struct{}),
	}
	sess.lastActive.Store(time.Now().Unix())
	udp.ActiveSessions.Add(1)

	sessKey := destination.String()
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

	dialRemote := func(dst M.Socksaddr) (*udpRemoteEntry, error) {
		host := dst.Addr.String()
		port := int(dst.Port)

		result, selected := h.upstreamMgr.SelectProxy(host, port, "", h.ruleEng)

		var remote net.Conn
		var err error
		isProxy := false

		if result == "direct" || (result == "fallback" && h.router.IsDomesticByIP(host)) {
			// 直连 UDP socket 选项(fwmark/1MB 缓冲/禁分片)与 SOCKS5 路径共用
			// udp.DirectUDPControl,保证两端直连 socket 行为一致;dial 超时也对齐 5s。
			d := net.Dialer{Timeout: 5 * time.Second, Control: udp.DirectUDPControl}
			remote, err = d.DialContext(ctx, "udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
		} else {
			isProxy = true
			if selected == nil {
				remote, err = h.upstreamMgr.UDPAssociate(ctx, host, port, "", h.ruleEng)
			} else {
				remote, err = selected.UDPAssociate(ctx, host, port)
			}
		}
		if err != nil {
			return nil, err
		}

		entry := &udpRemoteEntry{conn: remote, dst: dst, isProxy: isProxy}
		if isProxy {
			entry.proxyHeader = buildSocks5UDPHeader(host, port)
		}
		remoteWg.Add(1)
		safego.Go("tun.remoteUDPReader", func() {
			defer remoteWg.Done()
			defer remote.Close()
			h.remoteUDPReader(conn, entry, errCh)
		})
		return entry, nil
	}

	getOrCreateRemote := func(dst M.Socksaddr) (*udpRemoteEntry, error) {
		key := dst.String()

		// Fast path: the destination already exists, return under the lock without dialing
		mu.Lock()
		if entry, ok := remotes[key]; ok {
			mu.Unlock()
			return entry, nil
		}
		mu.Unlock()

		// Slow path: dial outside the lock (up to 10s), without blocking forwarding to other destinations in the same session
		entry, err := dialRemote(dst)
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

			entry, err := getOrCreateRemote(pktDst)
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
				if _, err := entry.conn.Write(buffer.Bytes()); err != nil {
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
			select {
			case errCh <- err:
			default:
			}
			return
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

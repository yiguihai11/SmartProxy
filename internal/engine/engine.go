package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"smartproxy/internal/admin"
	"smartproxy/internal/safego"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/config"
	"smartproxy/internal/dns"
	"smartproxy/internal/fwmark"
	"smartproxy/internal/netutil"
	"smartproxy/internal/relay"
	"smartproxy/internal/route"
	"smartproxy/internal/rules"
	"smartproxy/internal/socks5"
	"smartproxy/internal/tun"
	"smartproxy/internal/udp"
	"smartproxy/internal/upstream"
)

type Engine struct {
	Config      atomic.Pointer[config.Config]
	Chnroute    *chnroute.Trie
	RuleEng     *rules.Engine
	UpstreamMgr *upstream.Manager
	Router      *route.Router
	DNSHandler  *dns.Handler
	TUNHandler  *tun.TUNHandler

	tunDev      interface{}
	tunStack    interface{}
	listener    net.Listener
	cancel      context.CancelFunc
	stopOnce    sync.Once
	adminServer *admin.Server
	reloadFn    func()
	configPath  string
	// clientSem caps concurrent SOCKS5 client handlers. Without it a burst of TCP
	// connects spawns an unbounded number of goroutines (one per conn) and exhausts
	// fds. The accept loop blocks on this before spawning, which throttles accept.
	clientSem chan struct{}
}

func New(cfg *config.Config, cfgDir string) (*Engine, error) {
	if !filepath.IsAbs(cfg.Routing.ChnrouteFile) {
		cfg.Routing.ChnrouteFile = filepath.Join(cfgDir, cfg.Routing.ChnrouteFile)
	}
	if !filepath.IsAbs(cfg.Routing.ACLFile) {
		cfg.Routing.ACLFile = filepath.Join(cfgDir, cfg.Routing.ACLFile)
	}

	cn, err := chnroute.Load(cfg.Routing.ChnrouteFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load chnroute: %w", err)
	}

	ruleEng, err := rules.New(cfg.Routing.ACLFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load ACL rules: %w", err)
	}

	upstreamCfg := upstream.UpstreamConfig{
		Default:     cfg.Upstream.Default,
		HealthCheck: cfg.Upstream.HealthCheck,
	}
	for _, p := range cfg.Upstream.Proxies {
		upstreamCfg.Proxies = append(upstreamCfg.Proxies, upstream.ProxyEntry{
			Alias:    p.Alias,
			URL:      p.URL,
			UDPInTCP: p.UDPInTCP,
		})
	}
	upstreamMgr, err := upstream.NewManager(upstreamCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to setup upstream manager: %w", err)
	}

	smartTimeout := time.Duration(cfg.SmartProxy.Timeout) * time.Second
	blacklistTTL := time.Duration(cfg.SmartProxy.BlacklistTTL) * time.Second
	router := route.New(cn, upstreamMgr, cfg.SmartProxy.Enabled, smartTimeout, cfg.SmartProxy.Ports, blacklistTTL)
	router.StartCleanup(60 * time.Second)

	preferMode, preferPorts := dns.ParseSpeedCheckMode(cfg.DNS.SpeedCheckMode)
	dnsHandler := dns.NewHandler(
		cfg.DNS.Cache.Size, cfg.DNS.Cache.TTL,
		cfg.DNS.Foreign.IPv4, cfg.DNS.Foreign.IPv6,
		cn, upstreamMgr,
		cfg.DNS.QueryTimeout, dns.BlockedIPv4, dns.BlockedIPv6,
		preferMode != dns.PreferNone, preferMode, preferPorts,
		cfg.DNS.Enabled,
	)
	dnsHandler.SetStaticRecords(cfg.DNS.StaticRecordsMap())

	eng := &Engine{
		Chnroute:    cn,
		RuleEng:     ruleEng,
		UpstreamMgr: upstreamMgr,
		Router:      router,
		DNSHandler:  dnsHandler,
		TUNHandler:  tun.NewHandler(cfg, router, ruleEng, upstreamMgr, dnsHandler),
		clientSem:   make(chan struct{}, maxConcurrentClients),
	}
	eng.Config.Store(cfg)
	return eng, nil
}

// SetUIDResolver 把 Android 侧的 UID 反查回调透传给 TUN handler(mobile 包注入,
// 供 per-app「禁止联网」拦截使用)。nil 时功能关闭。
func (e *Engine) SetUIDResolver(f tun.UIDResolverFunc) {
	e.TUNHandler.SetUIDResolver(f)
}

// SetConnStatsEnabled 开关连接监控(「联网状态」页):页面打开采集、关闭即停。
func (e *Engine) SetConnStatsEnabled(on bool) {
	e.TUNHandler.SetConnStatsEnabled(on)
}

// ConnectionStats 返回按 app(uid)分组的连接快照 JSON(供 UI 每秒轮询)。
func (e *Engine) ConnectionStats() string {
	return e.TUNHandler.ConnectionStats()
}

// SetConnStatsPin 固定「正在查看」的 app 的连接不被 idle 清扫(「联网状态」页
// 展开某应用明细时);-1 解除,解除后按 5s 宽限正常淡出。
func (e *Engine) SetConnStatsPin(uid int32) {
	e.TUNHandler.SetConnStatsPin(uid)
}

// BlockConnection 把某条连接的目标(域名/IP)加入 ACL 封锁列表并立即生效:追加
// `block domain <d>` / `block ip <ip>` 到 acl.txt(去重),fsnotify 触发 RuleEng.Reload,
// reloader 回调随即 KillBlockedConnections 掐断现存匹配连接。域名小写化、去尾点;
// IP 剥离 IPv6 方括号。持久化在 acl.txt,重启保留。
func (e *Engine) BlockConnection(host string) error {
	aclPath := e.Config.Load().Routing.ACLFile
	if aclPath == "" {
		return fmt.Errorf("acl_file not configured")
	}
	value := strings.Trim(strings.TrimSpace(host), "[]")
	typ := "domain"
	if net.ParseIP(value) != nil {
		typ = "ip"
	} else {
		value = strings.ToLower(strings.TrimSuffix(value, "."))
	}
	line := "block " + typ + " " + value

	// 去重:已存在的行直接返回(不写文件就不触发 reload,零副作用)。
	exist, err := aclLineExists(aclPath, line)
	if err != nil {
		return err
	}
	if exist {
		slog.Info("ACL block already present", "line", line)
		return nil
	}

	f, err := os.OpenFile(aclPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open acl file for append: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString("\n" + line + "\n"); err != nil {
		return fmt.Errorf("append acl entry: %w", err)
	}
	slog.Info("ACL block appended", "path", aclPath, "line", line)
	return nil
}

// aclLineExists 检查 acl 文件是否已含该行(忽略首尾空白;文件不存在视为未含)。
func aclLineExists(path, want string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == want {
			return true, nil
		}
	}
	return false, sc.Err()
}

// KillBlockedConnections 透传给 TUN handler:ACL 变更后掐断现存命中封锁目标的连接。
func (e *Engine) KillBlockedConnections() {
	e.TUNHandler.KillBlockedConnections()
}

// maxConcurrentClients bounds the SOCKS5 client handler goroutines (see clientSem).
const maxConcurrentClients = 1024

func (e *Engine) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	isFdMode := e.Config.Load().TUN.FileDescriptor != 0
	if isFdMode {
		e.Config.Load().TUN.AutoRoute = false
	}

	if e.Config.Load().TUN.Enabled {
		tunDev, tunStack, err := e.TUNHandler.Start(ctx, e.Config.Load().TUN)
		if err != nil {
			// 失败也要清掉 New() 里已起的后台 goroutine(router cleanup、上游 health
			// 探测、DNS);只 cancel() 它们不会停,配置错误重试一次叠一套、持续空拨测。
			e.Stop()
			return fmt.Errorf("failed to start TUN: %w", err)
		}
		e.tunDev = tunDev
		e.tunStack = tunStack
	}

	// SOCKS5 listener is gated solely by listen.port: 0 disables it in any mode
	// (Android fd-mode default). >0 binds regardless of fd/desktop — enabling a
	// LAN-shared proxy on the phone. Empty listen.auth (=null or blank creds)
	// means the listener requires no client authentication.
	if lc := e.Config.Load().Listen; lc.Port > 0 {
		listenAddr := net.JoinHostPort(lc.Host, strconv.Itoa(lc.Port))
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			// e.Stop() 按正确顺序关 tunDev→tunStack→TUNHandler,并停掉 New() 起的后台
			// goroutine——替代原先只关 tun 的半截清理(那版漏了 health 探测/cleanup)。
			e.Stop()
			return fmt.Errorf("failed to listen: %w", err)
		}
		e.listener = ln
		if tcpl, ok := ln.(*net.TCPListener); ok {
			if err := netutil.EnableTCPFastOpen(tcpl); err != nil {
				slog.Warn("TCP_FASTOPEN not enabled on SOCKS5 listener", "err", err)
			}
		}
		slog.Info("SOCKS5 server listening", "addr", ln.Addr())
		safego.Go("engine.serve", func() { e.serve(ctx) })
	} else {
		slog.Info("SOCKS5 listener disabled (listen.port=0)")
	}

	lc := e.Config.Load().Listen
	if sockPath := lc.AdminSocket; sockPath != "" || lc.AdminPort > 0 {
		e.adminServer = admin.New(sockPath, e.Router, e.UpstreamMgr, e.DNSHandler, e.Chnroute)
		if auth := lc.AdminAuth; auth != nil {
			e.adminServer.SetAdminAuth(auth)
		}
		if e.reloadFn != nil {
			e.adminServer.SetReloadConfig(e.reloadFn)
			e.adminServer.SetConfigSrc(func() *config.Config { return e.Config.Load() })
			e.adminServer.SetConfigPath(e.configPath)
		}
		e.adminServer.SetTCPPort(lc.AdminPort)
		e.adminServer.SetRefreshInterval(lc.AdminRefreshInterval)
		// Extra SANs land in the auto-generated self-signed cert, so a LAN IP in
		// admin_cert_sans is covered without supplying admin_cert_file/admin_key_file.
		e.adminServer.SetTLS(lc.AdminCertFile, lc.AdminKeyFile, lc.AdminHTTPS, lc.AdminCertSANs...)
		if err := e.adminServer.Start(); err != nil {
			slog.Warn("admin server failed to start", "socket", sockPath, "error", err)
		}
	}
	return nil
}

func (e *Engine) AdminServer() *admin.Server {
	return e.adminServer
}

func (e *Engine) serve(ctx context.Context) {
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			if isConnClosed(err) {
				return
			}
			slog.Error("accept error", "error", err)
			continue
		}
		// Backpressure: when maxConcurrentClients handlers are busy, block accept
		// instead of spawning an unbounded goroutine per connection.
		select {
		case e.clientSem <- struct{}{}:
		case <-ctx.Done():
			conn.Close()
			return
		}
		safego.Go("engine.handleClient", func() {
			defer func() { <-e.clientSem }()
			e.handleClient(ctx, conn)
		})
	}
}

func (e *Engine) handleClient(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})

	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(15 * time.Second)
		tcp.SetNoDelay(true)
		netutil.SetKeepAliveInterval(tcp, 15*time.Second)
	}

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	localIP := localAddr.IP.String()

	rawIP := remoteAddr.IP.String()
	clientIP := rawIP
	if strings.HasPrefix(rawIP, "::ffff:") {
		clientIP = rawIP[7:]
	}
	slog.Debug("new connection", "remote", remoteAddr, "client_ip", clientIP)

	auth := e.Config.Load().Listen.Auth
	serverUser := ""
	serverPass := ""
	if auth != nil {
		serverUser = auth.Username
		serverPass = auth.Password
	}

	if err := socks5.Handshake(conn, serverUser, serverPass); err != nil {
		slog.Warn("handshake failed", "remote", remoteAddr, "error", err)
		return
	}
	// Clear the handshake deadline; it does not affect the subsequent long-lived relay connection
	conn.SetDeadline(time.Time{})

	req, err := socks5.ReceiveRequest(conn)
	if err != nil {
		slog.Error("failed to read request", "remote", remoteAddr, "error", err)
		if pe, ok := err.(*socks5.ProtocolError); ok {
			socks5.SendReply(conn, pe.Reply, localIP, 0)
		}
		return
	}
	slog.Debug("request", "cmd", req.Command.String(), "dst", net.JoinHostPort(req.Host, strconv.Itoa(req.Port)))

	switch req.Command {
	case socks5.CommandConnect:
		e.handleConnect(ctx, conn, req)
	case socks5.CommandUDPAssociate:
		e.handleUDPAssociate(ctx, conn, clientIP)
	default:
		slog.Info("unsupported command", "cmd", req.Command.String())
		socks5.SendReply(conn, socks5.ReplyCmdNotSupported, localIP, 0)
	}
}

func (e *Engine) handleConnect(ctx context.Context, conn net.Conn, req *socks5.Request) {
	host := req.Host
	port := req.Port
	localIP := conn.LocalAddr().(*net.TCPAddr).IP.String()

	if e.RuleEng.IsPortBlocked(port) {
		slog.Info("blocked port by rule", "port", port)
		if port == 80 || port == 443 {
			socks5.SendReply(conn, socks5.ReplySuccess, localIP, 0)
			netutil.SendEnhancedBlock(conn, port)
			return
		}
		socks5.SendReply(conn, socks5.ReplyNotAllowed, localIP, 0)
		return
	}
	if e.RuleEng.IsIPBlocked(host) {
		slog.Info("blocked IP by rule", "ip", host)
		if port == 80 || port == 443 {
			socks5.SendReply(conn, socks5.ReplySuccess, localIP, 0)
			netutil.SendEnhancedBlock(conn, port)
			return
		}
		socks5.SendReply(conn, socks5.ReplyNotAllowed, localIP, 0)
		return
	}

	ip := net.ParseIP(host)
	isDomestic := false
	if ip != nil {
		isDomestic = e.Chnroute.Contains(ip)
	}
	smartEnabled := e.Config.Load().SmartProxy.Enabled && netutil.ContainsInt(e.Config.Load().SmartProxy.Ports, port)

	if !smartEnabled {
		// 非 smart 路径的 domain 规则:host 不是 IP 时它就是 CONNECT 的域名(SOCKS5
		// ATYP=0x03),必须作为 domain 传给规则匹配,否则 block/proxy domain 规则在这里
		// 永不命中(之前恒传 "" 是缺口)。拦截语义与上面的 IP/port 分支一致。
		domain := ""
		if net.ParseIP(host) == nil {
			domain = host
			if e.RuleEng.IsDomainBlocked(host) {
				slog.Info("blocked domain by rule", "domain", host)
				if port == 80 || port == 443 {
					socks5.SendReply(conn, socks5.ReplySuccess, localIP, 0)
					netutil.SendEnhancedBlock(conn, port)
					return
				}
				socks5.SendReply(conn, socks5.ReplyNotAllowed, localIP, 0)
				return
			}
		}
		remote, isProxy, err := e.Router.EstablishConnection(ctx, host, port, domain, e.RuleEng)
		if err != nil {
			slog.Error("failed to establish connection", "host", host, "port", port, "domain", domain, "error", err)
			socks5.SendReply(conn, replyForConnError(err), localIP, 0)
			return
		}
		defer remote.Close()
		if err := socks5.SendReply(conn, socks5.ReplySuccess, localIP, 0); err != nil {
			return
		}
		e.relayTCP(ctx, conn, remote, isProxy, nil)
		return
	}

	if err := socks5.SendReply(conn, socks5.ReplySuccess, localIP, 0); err != nil {
		return
	}
	firstPkt, err := tun.ReadClientHello(conn, 3*time.Second)
	if err != nil {
		slog.Debug("error reading first packet", "error", err)
		return
	}

	domain := tun.ExtractDomain(firstPkt)
	if domain != "" {
		slog.Debug("extracted domain", "domain", domain)
		if e.RuleEng.IsDomainBlocked(domain) {
			slog.Info("blocked domain (static rule)", "domain", domain)
			netutil.SendEnhancedBlock(conn, port)
			return
		}
	}

	if isDomestic {
		remote, isProxy, err := e.Router.EstablishConnection(ctx, host, port, domain, e.RuleEng)
		if err != nil {
			slog.Error("failed to establish domestic connection", "host", host, "port", port, "domain", domain, "error", err)
			return
		}
		defer remote.Close()
		if len(firstPkt) > 0 {
			if _, err := remote.Write(firstPkt); err != nil {
				return
			}
		}
		e.relayTCP(ctx, conn, remote, isProxy, nil)
		return
	}

	remote, prefix, isProxy, err := e.Router.SmartConnectWithFallback(ctx, host, port, domain, firstPkt, e.RuleEng)
	if err != nil {
		slog.Error("smart connect failed", "host", host, "port", port, "domain", domain, "error", err)
		return
	}
	defer remote.Close()
	slog.Info("smart connection established", "host", host, "port", port, "domain", domain)
	e.relayTCP(ctx, conn, remote, isProxy, prefix)
}

func getOutboundIPv4() net.IP {
	d := net.Dialer{Timeout: 2 * time.Second, Control: fwmark.Control}
	conn, err := d.Dial("udp4", "1.0.0.1:80")
	if err != nil {
		return getInterfaceIPv4()
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}

func getOutboundIPv6() net.IP {
	d := net.Dialer{Timeout: 2 * time.Second, Control: fwmark.Control}
	conn, err := d.Dial("udp6", "[2606:4700:4700::1111]:80")
	if err != nil {

		if ip := getInterfaceIPv6(); ip != nil {
			return ip
		}
		return net.ParseIP("::1")
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}

func getInterfaceIPv4() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return net.IPv4(127, 0, 0, 1)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				return ip4
			}
		}
	}
	return net.IPv4(127, 0, 0, 1)
}

func getInterfaceIPv6() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip := ipnet.IP; ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip
			}
		}
	}
	return nil
}

// Bounded worker pool parameters for UDP packet handling: replaces the "one goroutine per
// packet" approach, eliminating goroutine creation overhead while limiting concurrency and
// memory usage (drops packets when the queue is full, which UDP permits).
const (
	udpWorkerCount  = 8   // number of workers: determines how many blocking operations (DNS/session setup) can be tolerated at once
	udpJobQueueSize = 128 // job queue length; drops packets when full
)

// udpJob carries a pending UDP packet and its owning pool buffer (returned to the pool after processing).
type udpJob struct {
	data []byte
	buf  *[]byte // buffer owned by UDPBufPool, returned to the pool after HandlePacket finishes
	addr net.Addr
}

func (e *Engine) handleUDPAssociate(ctx context.Context, conn net.Conn, clientIP string) {
	var udpConn net.PacketConn
	var err error

	udpConn, err = net.ListenPacket("udp", ":0")
	tcpLocal := conn.LocalAddr().(*net.TCPAddr)
	if err != nil {
		slog.Warn("failed to create dual-stack UDP socket, trying IPv4", "error", err)
		udpConn, err = net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			slog.Error("failed to create UDP socket", "error", err)
			socks5.SendReply(conn, socks5.ReplyGeneralFailure, tcpLocal.IP.String(), 0)
			return
		}
	}
	// Enlarge the UDP socket send/receive buffers to reduce burst packet loss (best-effort, bounded by kernel limits)
	if u, ok := udpConn.(*net.UDPConn); ok {
		if err := udp.SetSocketBuffers(u); err != nil {
			slog.Debug("failed to enlarge UDP socket buffers", "error", err)
		}
	}

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	bindHost := localAddr.IP.String()

	if tcpLocal.IP.To4() != nil {

		if bindHost == "0.0.0.0" || bindHost == "::" {
			// BND 必须广告「客户端能到达且源校验能过」的地址。UDP socket 绑 0.0.0.0,
			// 所以客户端实际连到的本地 IP 必可达——loopback 客户端应广告 127.0.0.1
			// (源校验比对的 clientIP 就是 loopback)。getOutboundIPv4 会返回出站接口 IP:
			// 在 VPN 手机上是 TUN 网段 IP,loopback 客户端按它发 UDP 源地址变成该 IP,
			// 与 clientIP(127.0.0.1)不匹配 → 全部丢包,直连 UDP 流量不走的直接原因。
			if ip4 := tcpLocal.IP.To4(); ip4 != nil && !ip4.IsUnspecified() {
				bindHost = ip4.String()
			} else {
				bindHost = getOutboundIPv4().String()
				if bindHost == "" || bindHost == "<nil>" {
					bindHost = "127.0.0.1"
				}
			}
		}
	} else {

		if bindHost == "0.0.0.0" || bindHost == "::" {
			if !tcpLocal.IP.IsUnspecified() {
				bindHost = tcpLocal.IP.String()
			} else {
				bindHost = getOutboundIPv6().String()
				if bindHost == "" || bindHost == "<nil>" {
					bindHost = "::1"
				}
			}
		}
	}

	if err := socks5.SendReply(conn, socks5.ReplySuccess, bindHost, localAddr.Port); err != nil {
		udpConn.Close()
		return
	}

	slog.Debug("UDP ASSOCIATE bound", "addr", localAddr, "client", clientIP, "bindHost", bindHost)

	udpHandler := udp.NewHandler(e.Chnroute, e.RuleEng,
		e.UpstreamMgr, e.DNSHandler, clientIP, udpConn,
		e.Config.Load().Listen.RelaxedUDPOriginCheck,
		time.Duration(e.Config.Load().Listen.UDPAssociateIdleTimeout)*time.Second)
	udpHandler.StartCleaner()
	defer udpHandler.Close()

	var lastActive atomic.Int64
	lastActive.Store(time.Now().Unix())

	jobs := make(chan udpJob, udpJobQueueSize)
	var workerWg sync.WaitGroup
	for i := 0; i < udpWorkerCount; i++ {
		workerWg.Add(1)
		safego.Go("engine.udpWorker", func() {
			defer workerWg.Done()
			for job := range jobs {
				udpHandler.HandlePacket(ctx, job.data, job.addr)
				relay.UDPBufPool.Put(job.buf)
			}
		})
	}
	// On exit, wait for workers to drain the queue (udpConn.Close has already unblocked the read loop and closed jobs)
	defer workerWg.Wait()

	safego.Go("engine.udpRead", func() {
		defer close(jobs)
		for {
			// Each packet is read directly into a buffer fetched from the pool; buffer ownership is
			// transferred to the worker along with the packet, avoiding one copy. The buffer must be
			// >= 65535 bytes to avoid truncating UDP datagrams.
			bufPtr := relay.UDPBufPool.Get().(*[]byte)
			buf := *bufPtr
			n, addr, err := udpConn.ReadFrom(buf)
			if err != nil {
				relay.UDPBufPool.Put(bufPtr)
				if isConnClosed(err) {
					return
				}
				slog.Debug("UDP read error", "error", err)
				return
			}
			lastActive.Store(time.Now().Unix())
			slog.Debug("received UDP packet from client", "addr", addr, "len", n)
			select {
			case jobs <- udpJob{data: buf[:n], buf: bufPtr, addr: addr}:
			default:
				// Queue full: UDP permits dropping packets, so return the buffer to the pool directly
				relay.UDPBufPool.Put(bufPtr)
			}
		}
	})

	timeout := e.Config.Load().Listen.UDPAssociateIdleTimeout
	if timeout > 0 {
		idleTimeout := time.Duration(timeout) * time.Second
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				slog.Debug("TCP connection closed, stopping UDP session", "client", clientIP)
				udpConn.Close()
				return
			case <-ticker.C:
				if time.Since(time.Unix(lastActive.Load(), 0)) > idleTimeout {
					if udpHandler.ActiveSessionCount() > 0 {
						slog.Debug("UDP session idle but upstream active, keeping alive",
							"activeSessions", udpHandler.ActiveSessionCount())
						lastActive.Store(time.Now().Unix())
						continue
					}
					slog.Debug("UDP ASSOCIATE idle timeout, closing",
						"client", clientIP, "timeout", idleTimeout)
					conn.Close()
					udpConn.Close()
					return
				}
			}
		}
	}

	<-ctx.Done()
	slog.Debug("TCP connection closed, stopping UDP session", "client", clientIP)
	udpConn.Close()
}

func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		slog.Info("[Go-Engine] Engine.Stop() entered")
		if e.cancel != nil {
			slog.Info("[Go-Engine] Cancelling context...")
			e.cancel()
		}
		if e.Router != nil {
			slog.Info("[Go-Engine] Stopping Router cleanup...")
			e.Router.StopCleanup()
		}
		if e.listener != nil {
			slog.Info("[Go-Engine] Closing listener...")
			e.listener.Close()
		}
		// 先关 tunDev(即 fd 模式下的 establish fd / 桌面 tun0)再关 gvisor 栈:
		// VPN 连接第一时间终止 → Android 状态栏图标立刻消失;fd 先关也让栈的读循环
		// 立即出错退出,剩余 drain 更快,避免"点击关闭后好几秒图标才消失"。连接直接
		// RST 而非 FIN,主动停止/重启可接受(重启路径 500ms 留白后重建)。
		if e.tunDev != nil {
			if closer, ok := e.tunDev.(interface{ Close() error }); ok {
				slog.Info("[Go-Engine] Closing tunDev file descriptor...")
				closer.Close()
				slog.Info("[Go-Engine] tunDev file descriptor closed")
			}
		}
		if e.tunStack != nil {
			if closer, ok := e.tunStack.(interface{ Close() error }); ok {
				slog.Info("[Go-Engine] Closing tunStack...")
				closer.Close()
				slog.Info("[Go-Engine] tunStack closed")
			}
		}
		if e.TUNHandler != nil {
			slog.Info("[Go-Engine] Closing TUNHandler...")
			e.TUNHandler.Close()
		}
		if e.DNSHandler != nil {
			slog.Info("[Go-Engine] Closing DNSHandler...")
			e.DNSHandler.Close()
		}
		if e.UpstreamMgr != nil {
			slog.Info("[Go-Engine] Stopping upstream manager...")
			e.UpstreamMgr.Stop()
			slog.Info("[Go-Engine] upstream manager stopped")
		}
		if e.adminServer != nil {
			slog.Info("[Go-Engine] Stopping adminServer...")
			e.adminServer.Stop()
			slog.Info("[Go-Engine] adminServer stopped")
		}
		slog.Info("[Go-Engine] Engine.Stop() completed")
	})
}
func (e *Engine) relayTCP(ctx context.Context, client, remote net.Conn, isProxy bool, prefix []byte) {
	// ActiveConns 由 relay.TCPRelay 内部统一结算(与 TUN 入口共用同一实现)。
	relay.TCPRelay(ctx, client, remote, isProxy, prefix)
}

func (e *Engine) SetReloadFn(fn func()) {
	e.reloadFn = fn
}

func (e *Engine) SetConfigPath(path string) {
	e.configPath = path
}

func isConnClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

func replyForConnError(err error) socks5.Reply {
	if err == nil {
		return socks5.ReplySuccess
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return socks5.ReplyTTLExpired
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		msg := opErr.Error()
		switch {
		case strings.Contains(msg, "connection refused"):
			return socks5.ReplyConnRefused
		case strings.Contains(msg, "no route to host"):
			return socks5.ReplyNetUnreachable
		case strings.Contains(msg, "no such host"), strings.Contains(msg, "host is down"):
			return socks5.ReplyHostUnreachable
		}
	}
	return socks5.ReplyGeneralFailure
}

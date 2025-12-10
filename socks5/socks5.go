package socks5

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	SOCKS5_VERSION = 0x05

	// 命令类型
	CMD_CONNECT   = 0x01
	CMD_BIND      = 0x02
	CMD_UDP_ASSOC = 0x03

	// 地址类型
	ATYPE_IPV4   = 0x01
	ATYPE_DOMAIN = 0x03
	ATYPE_IPV6   = 0x04

	// 回应状态
	REP_SUCCESS                    = 0x00
	REP_GENERAL_FAILURE            = 0x01
	REP_CONNECTION_FORBIDDEN       = 0x02
	REP_NETWORK_UNREACHABLE        = 0x03
	REP_HOST_UNREACHABLE           = 0x04
	REP_CONNECTION_REFUSED         = 0x05
	REP_TTL_EXPIRED                = 0x06
	REP_COMMAND_NOT_SUPPORTED      = 0x07
	REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08
)

// formatNetworkAddress 格式化网络地址，正确处理IPv6地址
// IPv6地址需要用方括号包围：[2001:4860:4860::8844]:53
func formatNetworkAddress(addr string, port uint16) string {
	ip := net.ParseIP(addr)
	if ip != nil && ip.To4() == nil {
		// 这是一个IPv6地址
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	// IPv4或域名，直接使用
	return fmt.Sprintf("%s:%d", addr, port)
}

// Logger 日志接口
type Logger interface {
	Printf(format string, v ...interface{})
	Print(v ...interface{})
}

// PrependingConn is a net.Conn that allows prepending data to the read stream.
// This is useful for "pushing back" data that was read during a probe.
type PrependingConn struct {
	net.Conn
	prependedData []byte
	mu            sync.Mutex
}

// Read reads data from the connection. It will first read from the prepended buffer.
func (c *PrependingConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.prependedData) > 0 {
		n := copy(p, c.prependedData)
		c.prependedData = c.prependedData[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// SOCKS5Server SOCKS5 服务器
type SOCKS5Server struct {
	listener            net.Listener
	wg                  sync.WaitGroup
	logger              *log.Logger
	router              *Router
	detector            *TrafficDetector
	configPath          string
	rateLimiter         *RateLimiter
	authManager         *AuthManager
	blacklist           *BlacklistManager
	probingPorts        []int
	smartProxyEnabled   bool
	smartProxyTimeoutMs int
}

type Connection struct {
	clientConn   net.Conn
	targetConn   net.Conn
	logger       *log.Logger
	server       *SOCKS5Server
	username     string // 认证用户名，空表示未认证
	targetAddr   string // 目标地址 (host:port)
	targetHost   string // 目标主机名
	detectedHost string // 检测到的主机名 (HTTP Host或HTTPS SNI)
	protocol     string // 协议类型 (HTTP/HTTPS/Unknown)

	// 新增：缓存初始请求数据
	initialData       []byte // 缓存的第一个数据包
	initialDataCached bool   // 是否已缓存
}

func NewSOCKS5ServerWithConfig(port int, configPath string, probingPorts []int) (*SOCKS5Server, error) {
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on port %d: %v", port, err)
	}

	// 创建 logger
	logger := log.New(os.Stdout, "[SOCKS5] ", log.LstdFlags)

	// -- Begin: Load smart_proxy config and initialize blacklist --
	var blacklist *BlacklistManager
	var smartProxyProbingPorts []int
	var smartProxyEnabled bool
	var smartProxyTimeoutMs int

	type smartProxyConfig struct {
		SmartProxy struct {
			Enabled                bool  `json:"enabled"`
			TimeoutMs              int   `json:"timeout_ms"`
			BlacklistExpiryMinutes int   `json:"blacklist_expiry_minutes"`
			ProbingPorts           []int `json:"probing_ports"`
		} `json:"smart_proxy"`
	}

	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		logger.Printf("Warning: Could not read config file at %s for smart_proxy settings: %v", configPath, err)
	} else {
		var spc smartProxyConfig
		if err := json.Unmarshal(configData, &spc); err != nil {
			logger.Printf("Warning: Could not parse smart_proxy settings from config: %v", err)
		} else {
			if spc.SmartProxy.Enabled {
				logger.Printf("SmartProxy is enabled.")
				smartProxyEnabled = true
				smartProxyTimeoutMs = spc.SmartProxy.TimeoutMs
				blacklist = NewBlacklistManager(spc.SmartProxy.BlacklistExpiryMinutes, logger)

				// 解析探测端口配置
				smartProxyProbingPorts = spc.SmartProxy.ProbingPorts

				// Overwrite probingPorts from parameter with the one from config if smart proxy is enabled
				if len(smartProxyProbingPorts) > 0 {
					probingPorts = smartProxyProbingPorts
				}
			} else {
				logger.Printf("SmartProxy is disabled.")
			}
		}
	}
	// -- End: Load smart_proxy config and initialize blacklist --

	// 初始化路由器
	router, err := NewRouter(configPath)
	if err != nil {
		logger.Printf("Failed to initialize router: %v", err)
		// 继续运行，但没有路由功能
		router = nil
	}

	// 初始化流量检测器
	detector := NewTrafficDetector(logger)

	// 初始化限速器
	rateLimiter := NewRateLimiter(logger)

	// 初始化认证管理器（默认不要求认证）
	authManager := NewAuthManager(false, nil, logger)

	// User and rate limit configuration is now loaded and applied from main.go
	server := &SOCKS5Server{
		listener:            listener,
		logger:              logger,
		router:              router,
		detector:            detector,
		configPath:          configPath,
		rateLimiter:         rateLimiter,
		authManager:         authManager,
		blacklist:           blacklist,
		probingPorts:        probingPorts,
		smartProxyEnabled:   smartProxyEnabled,
		smartProxyTimeoutMs: smartProxyTimeoutMs,
	}

	// 打印系统统计信息
	if router != nil {
		stats := router.GetStats()
		logger.Printf("Router loaded: %d rules, %d IP rules, %d China rules (IPv4: %d nodes, IPv6: %d nodes)",
			stats["total_rules"], stats["ip_rules"], stats["china_rules"], stats["ipv4_nodes"], stats["ipv6_nodes"])
		logger.Printf("IPv4/IPv6 support: ✓, Actions - Direct: %d, Proxy: %d, Block: %d",
			stats["allow"], stats["deny"], stats["block"])
	}
	logger.Printf("Traffic detector: ✓ (HTTP/HTTPS/SNI detection)")

	return server, nil
}

// isClosedConnectionError 检查是否是连接关闭的错误
func isClosedConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// 检查是否包含"closed network connection"字符串
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "closed network connection")
}

func (s *SOCKS5Server) Start() error {
	s.logger.Printf("SOCKS5 server started on %s", s.listener.Addr())

	for {
		clientConn, err := s.listener.Accept()
		if err != nil {
			// 检查是否是关闭信号导致的错误
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.logger.Printf("Accept timeout: %v", err)
				continue
			}
			// 如果是连接被关闭的错误，不再继续循环
			if opErr, ok := err.(*net.OpError); ok && opErr.Op == "accept" {
				if isClosedConnectionError(opErr.Err) {
					s.logger.Printf("Server shutting down...")
					return nil
				}
			}
			s.logger.Printf("Failed to accept connection: %v", err)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(clientConn)
		}()
	}
}

func (s *SOCKS5Server) Stop() error {
	if s.listener != nil {
		err := s.listener.Close()
		s.wg.Wait()
		return err
	}
	return nil
}

func (s *SOCKS5Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// 从对象池获取连接对象
	conn := connectionPool.Get()

	// 初始化连接对象
	conn.clientConn = clientConn
	conn.logger = s.logger
	conn.server = s

	// 确保连接对象在函数结束时被重置并放回池中
	defer func() {
		conn.clientConn = nil
		conn.targetConn = nil
		conn.username = ""
		conn.targetAddr = ""
		conn.targetHost = ""
		conn.detectedHost = ""
		conn.protocol = ""
		connectionPool.Put(conn)
	}()

	s.logger.Printf("New connection from %s", clientConn.RemoteAddr())

	// 认证协商
	if err := conn.handleAuthentication(); err != nil {
		s.logger.Printf("Authentication failed: %v", err)
		return
	}

	// 检查连接限制（仅对已认证用户）
	if conn.username != "" {
		clientIP, _, err := net.SplitHostPort(conn.clientConn.RemoteAddr().String())
		if err != nil {
			clientIP = conn.clientConn.RemoteAddr().String()
		}

		if err := s.authManager.CheckConnectionLimit(conn.username, clientIP); err != nil {
			s.logger.Printf("Connection limit check failed for %s: %v", conn.username, err)
			return
		}
	}

	// 处理连接请求
	if err := conn.handleRequest(); err != nil {
		s.logger.Printf("Request failed: %v", err)
		return
	}

	// 连接结束后释放连接计数
	defer func() {
		if conn.username != "" {
			s.authManager.ReleaseConnection(conn.username)
		}
	}()
}

// handleRequest 处理SOCKS5连接请求，并使用预检测和路由来建立连接
func (c *Connection) handleRequest() error {
	// 1. 解析SOCKS5请求头以获取目标地址和端口
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.clientConn, header); err != nil {
		return fmt.Errorf("failed to read request header: %v", err)
	}

	version, cmd, atype := header[0], header[1], header[3]
	if version != SOCKS5_VERSION {
		return fmt.Errorf("unsupported SOCKS version: %d", version)
	}
	if cmd != CMD_CONNECT {
		return c.sendReply(REP_COMMAND_NOT_SUPPORTED, "127.0.0.1", 1080)
	}

	targetAddr, targetPort, err := c.parseAddress(atype)
	if err != nil {
		return err // an error reply has already been sent by parseAddress
	}

	// 2. 设置连接的基本信息
	c.targetAddr = formatNetworkAddress(targetAddr, targetPort)
	if host, _, err := net.SplitHostPort(targetAddr); err == nil {
		c.targetHost = host
	} else {
		c.targetHost = targetAddr
	}
	c.logger.Printf("Connection request: %s -> %s (%s)", c.getClientInfo(), c.targetAddr, c.targetHost)

	// 3. 核心逻辑：检测SNI并根据路由规则建立连接
	finalTargetConn, err := c.detectAndConnect(targetAddr, targetPort)
	if err != nil {
		c.logger.Printf("Failed to establish connection for %s: %v", c.getClientInfo(), err)
		// Since a fake success reply was already sent, we can't send a SOCKS error.
		// We just close the connection by returning.
		return nil
	}
	defer finalTargetConn.Close()
	c.targetConn = finalTargetConn

	// 4. 开始双向转发数据
	c.logger.Printf("CONNECTED: %s -> %s", c.getAccessInfo(), c.targetAddr)
	return c.relay()
}

// parseAddress 解析SOCKS5请求中的地址部分
func (c *Connection) parseAddress(atype byte) (addr string, port uint16, err error) {
	switch atype {
	case ATYPE_IPV4:
		addrBytes := make([]byte, 4)
		if _, err = io.ReadFull(c.clientConn, addrBytes); err != nil {
			return "", 0, fmt.Errorf("failed to read IPv4 address: %v", err)
		}
		addr = net.IP(addrBytes).String()
	case ATYPE_IPV6:
		addrBytes := make([]byte, 16)
		if _, err = io.ReadFull(c.clientConn, addrBytes); err != nil {
			return "", 0, fmt.Errorf("failed to read IPv6 address: %v", err)
		}
		addr = net.IP(addrBytes).String()
	case ATYPE_DOMAIN:
		lenByte := make([]byte, 1)
		if _, err = io.ReadFull(c.clientConn, lenByte); err != nil {
			return "", 0, fmt.Errorf("failed to read domain length: %v", err)
		}
		domainLen := int(lenByte[0])
		domain := make([]byte, domainLen)
		if _, err = io.ReadFull(c.clientConn, domain); err != nil {
			return "", 0, fmt.Errorf("failed to read domain: %v", err)
		}
		addr = string(domain)
	default:
		err = c.sendReply(REP_ADDRESS_TYPE_NOT_SUPPORTED, "127.0.0.1", 1080)
		return "", 0, err
	}

	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(c.clientConn, portBytes); err != nil {
		return "", 0, fmt.Errorf("failed to read port: %v", err)
	}
	port = binary.BigEndian.Uint16(portBytes)
	return addr, port, nil
}

// executeConnectionAction 根据路由匹配结果执行连接操作
// 返回目标连接和错误
func (c *Connection) executeConnectionAction(result MatchResult, targetAddr string, targetPort uint16, logContext string) (net.Conn, error) {
	accessInfo := c.getAccessInfo()

	switch result.Action {
	case ActionBlock:
		return nil, fmt.Errorf("blocked by rule for %s", c.targetAddr)

	case ActionProxy:
		proxy := c.server.router.GetProxyNode(result.ProxyNode)
		if proxy == nil {
			return nil, fmt.Errorf("proxy node '%s' not found", result.ProxyNode)
		}
		c.logger.Printf("PROXY by %s: %s -> %s via %s", logContext, accessInfo, c.targetAddr, proxy.Name)
		return c.connectThroughProxy(proxy, targetAddr, targetPort)

	case ActionAllow:
		c.logger.Printf("ALLOW by %s: %s -> %s", logContext, accessInfo, c.targetAddr)

		// 纯粹直连，不回退代理
		target := formatNetworkAddress(targetAddr, targetPort)
		conn, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("direct connection failed: %v", err)
		}

		return conn, nil

	default:
		if c.server.smartProxyEnabled && c.server.isProbingPort(int(targetPort)) {
			// 检查是否在黑名单中
			if c.server.blacklist != nil && !c.server.blacklist.IsBlacklisted(targetAddr) {

				// 尝试直连
				target := formatNetworkAddress(targetAddr, targetPort)
				conn, err := net.DialTimeout("tcp", target, time.Duration(c.server.smartProxyTimeoutMs)*time.Millisecond)
				if err != nil {
					return nil, fmt.Errorf("direct connection failed: %v", err)
				}

				return conn, nil
			}
		}
		defaultProxy := c.server.router.GetDefaultProxy()
		if defaultProxy == nil {
			return nil, fmt.Errorf("no default proxy available")
		}
		c.logger.Printf("Using default proxy: %s -> %s via %s", accessInfo, c.targetAddr, defaultProxy.Name)
		return c.connectThroughProxy(defaultProxy, targetAddr, targetPort)

	}
}

// detectAndConnect 执行 "提前响应-检测-路由-连接" 的核心逻辑
func (c *Connection) detectAndConnect(targetAddr string, targetPort uint16) (net.Conn, error) {
	// 1. 包装客户端连接以支持数据"回放"
	prependingClientConn := &PrependingConn{Conn: c.clientConn}
	c.clientConn = prependingClientConn

	// 2. 发送"虚假"成功响应以解锁客户端
	if err := c.sendReply(REP_SUCCESS, "0.0.0.0", 0); err != nil {
		return nil, fmt.Errorf("failed to send temporary success reply: %v", err)
	}

	// 3. 检测 SNI/Host（针对探测端口）
	var detectedHost string
	shouldProbe := c.server.smartProxyEnabled && c.server.isProbingPort(int(targetPort))

	if shouldProbe {
		// 读取初始数据包
		buf := bufferPool.Get()
		defer bufferPool.Put(buf)

		c.clientConn.SetReadDeadline(time.Now().Add(1300 * time.Millisecond))
		n, err := prependingClientConn.Conn.Read(buf)
		c.clientConn.SetReadDeadline(time.Time{})

		// ⭐ 缓存初始数据（关键修改）
		if n > 0 {
			c.initialData = make([]byte, n)
			copy(c.initialData, buf[:n])
			c.initialDataCached = true
			c.logger.Printf("Cached %d bytes of initial data for potential retry", n)

			// 预置数据回连接（供正常流程使用）
			prependingClientConn.mu.Lock()
			prependingClientConn.prependedData = make([]byte, n)
			copy(prependingClientConn.prependedData, buf[:n])
			prependingClientConn.mu.Unlock()
		}

		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("could not read initial data for detection: %v", err)
		}

		// 检测主机名
		if n > 0 {
			if result := c.server.detector.DetectTraffic(buf[:n]); result != nil {
				hostname := ""
				if result.Type == TrafficTypeHTTPS && result.SNI != "" {
					hostname = result.SNI
				} else if result.Type == TrafficTypeHTTP && result.Hostname != "" {
					hostname = result.Hostname
				}
				if hostname != "" {
					c.logger.Printf("SNI/Host detected for port %d: %s", targetPort, hostname)
					detectedHost = hostname
					c.detectedHost = hostname
				}
			}
		}
	}

	// 4. 路由匹配
	result := c.server.router.MatchRule(targetAddr, detectedHost, int(targetPort))

	// 5. 根据匹配结果执行连接
	logContext := "rule"
	if result.Match {
		if detectedHost != "" {
			logContext += " (detected: " + detectedHost + ")"
		}
	} else {
		logContext = "default"
		result.Action = ActionDeny
	}

	return c.executeConnectionAction(result, targetAddr, targetPort, logContext)
}

func (c *Connection) sendReply(rep byte, bindAddr string, bindPort int) error {
	// 修复：为了兼容简单客户端（它们可能只处理IPv4响应），
	// 我们总是返回一个IPv4地址作为绑定地址。
	// 这确保了响应总是10字节长。
	addrType := byte(ATYPE_IPV4)
	addrBody := net.IPv4(0, 0, 0, 0).To4()
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(bindPort))

	// 获取服务器的实际监听端口（如果需要）
	if listenAddr, ok := c.server.listener.Addr().(*net.TCPAddr); ok && bindPort == 0 {
		binary.BigEndian.PutUint16(portBytes, uint16(listenAddr.Port))
	}

	// 构建回复
	// [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
	response := []byte{SOCKS5_VERSION, rep, 0x00, addrType}
	response = append(response, addrBody...)
	response = append(response, portBytes...)

	_, err := c.clientConn.Write(response)
	return err
}

// getAddrSpec prepares the address part of a SOCKS5 request.
func getAddrSpec(addr string) (byte, []byte, error) {
	ip := net.ParseIP(addr)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ATYPE_IPV4, ip4, nil
		}
		return ATYPE_IPV6, ip.To16(), nil
	}

	if len(addr) > 255 {
		return 0, nil, fmt.Errorf("domain name too long: %s", addr)
	}
	return ATYPE_DOMAIN, append([]byte{byte(len(addr))}, []byte(addr)...), nil
}

// drainReply reads and discards the remainder of a SOCKS5 reply.
func drainReply(conn io.Reader, atyp byte) error {
	var addrLen int
	switch atyp {
	case ATYPE_IPV4:
		addrLen = 4
	case ATYPE_IPV6:
		addrLen = 16
	case ATYPE_DOMAIN:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return fmt.Errorf("failed to read domain length while draining reply: %v", err)
		}
		addrLen = int(lenByte[0])
	default:
		return fmt.Errorf("unknown address type %d in reply", atyp)
	}

	// Read and discard address and port
	totalLen := addrLen + 2 // +2 for port
	if _, err := io.CopyN(ioutil.Discard, conn, int64(totalLen)); err != nil {
		return fmt.Errorf("failed to drain reply: %v", err)
	}

	return nil
}

func (c *Connection) relay() error {
	// 创建上下文管理连接生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 并发处理客户端到目标和目标到客户端的数据流
	clientToTargetDone := make(chan error, 1)
	targetToClientDone := make(chan error, 1)

	// 客户端到目标（带流量检测和动态路由）
	go c.relayClientToTarget(ctx, clientToTargetDone)

	// 目标到客户端（带限速）
	go c.relayTargetToClient(ctx, targetToClientDone)

	// 等待任一方向结束
	select {
	case err := <-clientToTargetDone:
		c.logger.Printf("Client to target relay finished: %v", err)
		cancel()
	case err := <-targetToClientDone:
		c.logger.Printf("Target to client relay finished: %v", err)
		cancel()
	}

	// 等待另一个方向也结束
	<-clientToTargetDone
	<-targetToClientDone

	c.logger.Printf("Connection closed")
	return nil
}

// relayClientToTarget 处理客户端到目标的数据流
func (c *Connection) relayClientToTarget(ctx context.Context, done chan error) {
	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		default:
		}

		n, err := c.clientConn.Read(buf)
		if err != nil {
			done <- err
			return
		}

		// 应用上传限速
		if !c.applyUploadRateLimit(int64(n)) {
			continue // 超过限速，丢弃数据
		}

		// 转发数据到目标
		if _, err := c.targetConn.Write(buf[:n]); err != nil {
			done <- err
			return
		}
	}
}

// relayTargetToClient 处理目标到客户端的数据流
func (c *Connection) relayTargetToClient(ctx context.Context, done chan error) {
	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		default:
		}

		n, err := c.targetConn.Read(buf)
		if err != nil {
			// 检查连接是否被重置（GFW干扰）
			if opErr, ok := err.(*net.OpError); ok {
				if syscallErr, ok := opErr.Err.(*os.SyscallError); ok {
					if errno, ok := syscallErr.Err.(syscall.Errno); ok && errno == 104 {
						if c.server.blacklist != nil && c.targetHost != "" {
							c.logger.Printf("⚠️  Direct connection to %s reset by peer (errno 104), switching to proxy", c.targetHost)
							c.server.blacklist.Add(c.targetHost)

							// 尝试切换到代理连接
							if proxyConn, proxyErr := c.switchToProxyAndReplay(); proxyErr == nil {
								// 成功切换到代理，更新目标连接并继续读取
								c.targetConn.Close()
								c.targetConn = proxyConn
								c.logger.Printf("✅ Successfully switched to proxy for %s", c.targetHost)
								continue // 继续循环，从代理连接读取数据
							} else {
								c.logger.Printf("❌ Failed to switch to proxy: %v", proxyErr)
							}
						}
					}
				}
			}
			done <- err
			return
		}

		// 应用下载限速
		if !c.applyDownloadRateLimit(int64(n)) {
			continue
		}

		// 转发数据到客户端
		if _, err := c.clientConn.Write(buf[:n]); err != nil {
			done <- err
			return
		}
	}
}

// switchToProxyAndReplay 切换到代理连接并重放缓存的数据
func (c *Connection) switchToProxyAndReplay() (net.Conn, error) {
	// 解析目标地址
	targetHost, targetPort, err := net.SplitHostPort(c.targetAddr)
	if err != nil {
		// 如果解析失败，可能已经是 host:port 格式
		parts := strings.Split(c.targetAddr, ":")
		if len(parts) == 2 {
			targetHost = parts[0]
			port, parseErr := strconv.ParseUint(parts[1], 10, 16)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse target port: %v", parseErr)
			}
			targetPort = fmt.Sprintf("%d", port)
		} else {
			return nil, fmt.Errorf("failed to parse target address: %v", err)
		}
	}

	// 解析端口号
	portUint16, err := strconv.ParseUint(targetPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port: %v", err)
	}

	// 获取默认代理
	proxy := c.server.router.GetDefaultProxy()
	if proxy == nil {
		return nil, fmt.Errorf("no proxy available")
	}

	// 建立代理连接
	proxyConn, err := c.connectThroughProxy(proxy, targetHost, uint16(portUint16))
	if err != nil {
		return nil, fmt.Errorf("failed to connect through proxy: %v", err)
	}

	// 重放缓存的初始数据
	if c.initialDataCached && len(c.initialData) > 0 {
		c.logger.Printf("🔄 Replaying %d bytes of cached data to proxy connection", len(c.initialData))
		if _, writeErr := proxyConn.Write(c.initialData); writeErr != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("failed to replay data to proxy: %v", writeErr)
		}
	}

	return proxyConn, nil
}

// applyUploadRateLimit 应用上传限速
func (c *Connection) applyUploadRateLimit(bytes int64) bool {
	if c.server.rateLimiter == nil {
		return true
	}

	rateLimitKey := c.getRateLimitKey()
	return c.server.rateLimiter.CheckUploadLimit(rateLimitKey, bytes)
}

// applyDownloadRateLimit 应用下载限速
func (c *Connection) applyDownloadRateLimit(bytes int64) bool {
	if c.server.rateLimiter == nil {
		return true
	}

	rateLimitKey := c.getRateLimitKey()
	return c.server.rateLimiter.CheckDownloadLimit(rateLimitKey, bytes)
}

// getRateLimitKey 获取限速键，优先使用用户名
func (c *Connection) getRateLimitKey() string {
	if c.username != "" {
		return c.username
	}
	return c.clientConn.RemoteAddr().String()
}

// setUsername 设置认证用户名
func (c *Connection) setUsername(username string) {
	c.username = username
}

// getClientInfo 获取客户端信息字符串
func (c *Connection) getClientInfo() string {
	clientAddr := c.clientConn.RemoteAddr().String()

	if c.username != "" {
		return fmt.Sprintf("user:%s@%s", c.username, clientAddr)
	}
	return fmt.Sprintf("anonymous@%s", clientAddr)
}

// getAccessInfo 获取访问信息字符串
func (c *Connection) getAccessInfo() string {
	info := c.getClientInfo()

	if c.detectedHost != "" && c.detectedHost != c.targetHost {
		return fmt.Sprintf("%s (detected: %s)", info, c.detectedHost)
	}
	return info
}

func (c *Connection) logConnectionChoice(connType string, proxyNode *ProxyNode, targetAddr string, targetPort uint16) {
	accessInfo := c.getAccessInfo()
	target := formatNetworkAddress(targetAddr, targetPort)
	if connType == "proxy" && proxyNode != nil {
		c.logger.Printf("OPTIMAL_PATH: %s -> %s via proxy %s (%s)", accessInfo, target, proxyNode.Name, proxyNode.Address)
	} else {
		c.logger.Printf("OPTIMAL_PATH: %s -> %s via %s", accessInfo, target, connType)
	}
}

// handleAuthentication 处理SOCKS5认证
func (c *Connection) handleAuthentication() error {
	username, err := c.server.authManager.HandleAuthentication(c.clientConn)
	if err != nil {
		return err
	}

	// 设置认证的用户名
	c.setUsername(username)

	if username != "" {
		c.logger.Printf("User authenticated: %s (%s)", username, c.getClientInfo())
	} else {
		c.logger.Printf("Anonymous connection (%s)", c.getClientInfo())
	}

	return nil
}

// GetRateLimiter 获取限速器实例
func (s *SOCKS5Server) GetRateLimiter() *RateLimiter {
	return s.rateLimiter
}

// ConfigureRateLimits 配置限速规则
func (s *SOCKS5Server) ConfigureRateLimits(uploadBps, downloadBps int64) {
	if s.rateLimiter != nil {
		s.rateLimiter.SetGlobalLimits(uploadBps, downloadBps)
		s.logger.Printf("Rate limits configured: upload=%d bps, download=%d bps", uploadBps, downloadBps)
	}
}

// AddRateLimitRule 添加限速规则
func (s *SOCKS5Server) AddRateLimitRule(rule *RateLimitRule) error {
	if s.rateLimiter == nil {
		return fmt.Errorf("rate limiter not initialized")
	}

	err := s.rateLimiter.AddRule(rule)
	if err != nil {
		s.logger.Printf("Failed to add rate limit rule: %v", err)
		return err
	}

	s.logger.Printf("Added rate limit rule: %s", rule.ID)
	return nil
}

// GetRateLimitStats 获取限速统计
func (s *SOCKS5Server) GetRateLimitStats() map[string]*RateLimitStats {
	if s.rateLimiter == nil {
		return make(map[string]*RateLimitStats)
	}
	return s.rateLimiter.GetStats()
}

// EnableAuthentication 启用用户认证
func (s *SOCKS5Server) EnableAuthentication(requireAuth bool) {
	if s.authManager != nil {
		s.authManager.requireAuth = requireAuth
		if requireAuth {
			s.logger.Printf("User authentication enabled")
		} else {
			s.logger.Printf("User authentication disabled")
		}
	}
}

// AddUser 添加用户
func (s *SOCKS5Server) AddUser(username, password, role string) error {
	if s.authManager == nil {
		return fmt.Errorf("auth manager not initialized")
	}
	return s.authManager.AddUser(username, password, role)
}

// RemoveUser 移除用户
func (s *SOCKS5Server) RemoveUser(username string) error {
	if s.authManager == nil {
		return fmt.Errorf("auth manager not initialized")
	}
	return s.authManager.RemoveUser(username)
}

// ListUsers 列出所有用户
func (s *SOCKS5Server) ListUsers() []*User {
	if s.authManager == nil {
		return make([]*User, 0)
	}
	return s.authManager.ListUsers()
}

// GetAuthManager 获取认证管理器
func (s *SOCKS5Server) GetAuthManager() *AuthManager {
	return s.authManager
}

// GetRouter 获取路由器实例，用于DNS模块
func (s *SOCKS5Server) GetRouter() *Router {
	return s.router
}

// GetBlacklistManager 获取黑名单管理器实例
func (s *SOCKS5Server) GetBlacklistManager() *BlacklistManager {
	return s.blacklist
}

// isProbingPort 检查端口是否在需要嗅探的列表中
func (s *SOCKS5Server) isProbingPort(port int) bool {
	if s.probingPorts == nil {
		return false
	}
	for _, p := range s.probingPorts {
		if p == port {
			return true
		}
	}
	return false
}

// connectThroughProxy 通过指定的代理节点建立连接
func (c *Connection) connectThroughProxy(proxy *ProxyNode, targetAddr string, targetPort uint16) (net.Conn, error) {
	if proxy == nil {
		return nil, fmt.Errorf("proxy node is nil")
	}

	c.logger.Printf("DEBUG: Connecting via proxy: %s (%s)", proxy.Name, proxy.Address)

	// 1. 连接到代理服务器
	proxyConn, err := net.DialTimeout("tcp", proxy.Address, 5*time.Second)
	if err != nil {
		c.logger.Printf("DEBUG: Failed to connect to proxy '%s' at %s: %v", proxy.Name, proxy.Address, err)

		// 检测连接超时
		if strings.Contains(err.Error(), "dial tcp") && strings.Contains(err.Error(), "i/o timeout") {
			return nil, fmt.Errorf("proxy '%s' connection timeout - %s unreachable", proxy.Name, proxy.Address)
		}

		return nil, fmt.Errorf("failed to connect to proxy '%s' at %s: %v", proxy.Name, proxy.Address, err)
	}
	c.logger.Printf("DEBUG: Successfully connected to proxy: %s (%s)", proxy.Name, proxy.Address)

	// 2. SOCKS5 握手
	// 客户端问候: Version 5, 1 auth method, 0x02 for user/pass or 0x00 for no auth
	authMethod := byte(0x00) // 默认无认证
	if proxy.Username != nil && *proxy.Username != "" {
		authMethod = byte(0x02) // 用户名/密码认证
	}

	handshake := []byte{SOCKS5_VERSION, 1, authMethod}
	if _, err := proxyConn.Write(handshake); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("failed to send handshake to proxy: %v", err)
	}

	// 读取代理服务器的回复
	resp := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, resp); err != nil {
		c.logger.Printf("DEBUG: Proxy handshake reply read failed: %v", err)
		proxyConn.Close()
		return nil, fmt.Errorf("failed to read handshake reply from proxy: %v", err)
	}
	c.logger.Printf("DEBUG: Proxy handshake reply: version=%d, method=%d", resp[0], resp[1])
	if resp[0] != SOCKS5_VERSION || resp[1] != authMethod {
		c.logger.Printf("DEBUG: Proxy handshake failed: expected version=%d method=%d, got version=%d method=%d", SOCKS5_VERSION, authMethod, resp[0], resp[1])
		proxyConn.Close()
		return nil, fmt.Errorf("proxy handshake failed, unsupported auth method")
	}
	c.logger.Printf("DEBUG: Proxy handshake successful")

	// 3. 如果需要，执行用户名/密码认证
	if authMethod == 0x02 {
		user := ""
		pass := ""
		if proxy.Username != nil {
			user = *proxy.Username
		}
		if proxy.Password != nil {
			pass = *proxy.Password
		}
		// 构建认证请求
		authReq := []byte{0x01, byte(len(user))}
		authReq = append(authReq, []byte(user)...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, []byte(pass)...)

		if _, err := proxyConn.Write(authReq); err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("failed to send auth request to proxy: %v", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(proxyConn, authResp); err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("failed to read auth reply from proxy: %v", err)
		}
		if authResp[0] != 0x01 || authResp[1] != 0x00 {
			proxyConn.Close()
			return nil, fmt.Errorf("proxy authentication failed")
		}
	}

	// 4. 发送连接请求到代理
	// [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
	req := []byte{SOCKS5_VERSION, CMD_CONNECT, 0x00}
	addrType, addrBody, err := getAddrSpec(targetAddr)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("failed to get address spec for target: %v", err)
	}
	req = append(req, addrType)
	req = append(req, addrBody...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, targetPort)
	req = append(req, portBytes...)

	if _, err := proxyConn.Write(req); err != nil {
		c.logger.Printf("DEBUG: Failed to send connect request to proxy: %v", err)
		proxyConn.Close()
		return nil, fmt.Errorf("failed to send connect request to proxy: %v", err)
	}
	c.logger.Printf("DEBUG: Sent connect request to proxy, reading reply...")

	// 5. 读取代理的最终回复
	finalResp := make([]byte, 4) // VER, REP, RSV, ATYP
	if _, err := io.ReadFull(proxyConn, finalResp); err != nil {
		c.logger.Printf("DEBUG: Failed to read final reply from proxy: %v", err)
		proxyConn.Close()
		return nil, fmt.Errorf("failed to read final reply from proxy: %v", err)
	}
	c.logger.Printf("DEBUG: Proxy final reply: version=%d, response=%d, rsv=%d, atyp=%d", finalResp[0], finalResp[1], finalResp[2], finalResp[3])
	if finalResp[0] != SOCKS5_VERSION || finalResp[1] != REP_SUCCESS {
		c.logger.Printf("DEBUG: Proxy connect command failed: expected version=%d response=%d, got version=%d response=%d", SOCKS5_VERSION, REP_SUCCESS, finalResp[0], finalResp[1])
		proxyConn.Close()
		return nil, fmt.Errorf("proxy connect command failed with code %d", finalResp[1])
	}
	c.logger.Printf("DEBUG: Proxy connect command successful")
	// 忽略剩余的 BND.ADDR 和 BND.PORT
	// 这部分需要根据 ATYP 读取并丢弃
	if err := drainReply(proxyConn, finalResp[3]); err != nil {
		c.logger.Printf("DEBUG: Failed to drain final reply from proxy: %v", err)
		proxyConn.Close()
		return nil, fmt.Errorf("failed to drain final reply from proxy: %v", err)
	}
	c.logger.Printf("DEBUG: Proxy connection established successfully")

	return proxyConn, nil
}

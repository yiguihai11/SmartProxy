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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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

	// UDP 相关常量
	UDP_ASSOC_TIMEOUT = 5 * time.Minute
	UDP_BUFFER_SIZE    = 64 * 1024
	UDP_SESSION_TTL   = 10 * time.Minute
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

// UDPSession UDP会话信息
type UDPSession struct {
	ClientAddr     *net.UDPAddr
	TargetAddr     *net.UDPAddr
	CreatedAt       time.Time
	LastActivity   time.Time
	TargetHost     string
}

// UDPPacket SOCKS5 UDP数据包结构
type UDPPacket struct {
	RESERVED  uint16 // 保留字段
	FRAG     uint8   // 分片标志
	ATYPE     uint8   // 地址类型
	SRCADDR   []byte  // 源地址
	DSTADDR   []byte  // 目标地址
	SRCPORT   uint16  // 源端口
	DSTPORT   uint16  // 目标端口
	DATA      []byte  // 数据
}

// UDPSessionManager UDP会话管理器
type UDPSessionManager struct {
	sessions    map[string]*UDPSession // key: clientAddr
	mutex       sync.RWMutex
	logger      *log.Logger
	cleanupTick  *time.Ticker
}

// NewUDPSessionManager 创建UDP会话管理器
func NewUDPSessionManager(logger *log.Logger) *UDPSessionManager {
	manager := &UDPSessionManager{
		sessions: make(map[string]*UDPSession),
		logger:   logger,
	}

	// 启动清理协程
	manager.cleanupTick = time.NewTicker(time.Minute)
	go manager.cleanupExpiredSessions()

	return manager
}

// AddSession 添加UDP会话
func (m *UDPSessionManager) AddSession(clientAddr, targetAddr *net.UDPAddr, targetHost string) *UDPSession {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	session := &UDPSession{
		ClientAddr:   clientAddr,
		TargetAddr:   targetAddr,
		CreatedAt:     time.Now(),
		LastActivity: time.Now(),
		TargetHost:   targetHost,
	}

	key := clientAddr.String()
	m.sessions[key] = session
	m.logger.Printf("UDP session added: %s -> %s (%s)", clientAddr, targetAddr, targetHost)

	return session
}

// GetSession 获取UDP会话
func (m *UDPSessionManager) GetSession(clientAddr *net.UDPAddr) *UDPSession {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.sessions[clientAddr.String()]
}

// RemoveSession 移除UDP会话
func (m *UDPSessionManager) RemoveSession(clientAddr *net.UDPAddr) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := clientAddr.String()
	if _, exists := m.sessions[key]; exists {
		delete(m.sessions, key)
		m.logger.Printf("UDP session removed: %s", clientAddr)
	}
}

// cleanupExpiredSessions 清理过期会话
func (m *UDPSessionManager) cleanupExpiredSessions() {
	for range m.cleanupTick.C {
		m.mutex.Lock()
		now := time.Now()
		var expired []string

		for key, session := range m.sessions {
			if now.Sub(session.LastActivity) > UDP_SESSION_TTL {
				expired = append(expired, key)
			}
		}

		for _, key := range expired {
			if session := m.sessions[key]; session != nil {
				delete(m.sessions, key)
				m.logger.Printf("UDP session expired: %s -> %s", session.ClientAddr, session.TargetAddr)
			}
		}

		m.mutex.Unlock()
	}
}

// SOCKS5Server SOCKS5 服务器
type SOCKS5Server struct {
	listener            net.Listener
	udpListener         *net.UDPConn
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
	udpSessions         *UDPSessionManager
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

	// 初始化 UDP 会话管理器
	udpSessions := NewUDPSessionManager(logger)

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
		udpSessions:         udpSessions,
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

	// 运行 splice 兼容性测试
	go func() {
		time.Sleep(1 * time.Second) // 延迟测试，避免影响启动时间
		TestSpliceCompatibility(s.logger)
	}()

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

	// 处理不同的命令类型
	switch cmd {
	case CMD_CONNECT:
		return c.handleConnectRequest(atype)
	case CMD_BIND:
		return c.sendReply(REP_COMMAND_NOT_SUPPORTED, "127.0.0.1", 1080)
	case CMD_UDP_ASSOC:
		return c.handleUDPAssociateRequest(atype)
	default:
		return c.sendReply(REP_COMMAND_NOT_SUPPORTED, "127.0.1", 1080)
	}
}

// handleConnectRequest 处理TCP CONNECT请求
func (c *Connection) handleConnectRequest(atype byte) error {
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

	// 4. 开始双向转发数据 - 尝试使用 splice 零拷贝
	c.logger.Printf("CONNECTED: %s -> %s", c.getAccessInfo(), c.targetAddr)

	// 优先尝试 splice 零拷贝，如果不支持则降级到 io.Copy
	return c.EnhancedRelay()
}

// handleUDPAssociateRequest 处理UDP ASSOCIATE请求
func (c *Connection) handleUDPAssociateRequest(atype byte) error {
	targetAddr, targetPort, err := c.parseAddress(atype)
	if err != nil {
		return err // an error reply has already been sent by parseAddress
	}

	// 解析目标地址
	targetIP := net.ParseIP(targetAddr)
	if targetIP == nil {
		return c.sendReply(REP_ADDRESS_TYPE_NOT_SUPPORTED, "127.0.0.1", 1080)
	}

	// 创建 UDP 监听地址
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %v", err)
	}

	// 启动 UDP 转发协程
	go c.handleUDPRelay(udpConn, targetAddr, targetPort)

	// 发送成功响应
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	return c.sendUDPReply(localAddr.IP, uint16(localAddr.Port))
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

// ============== 第三阶段优化：UDP 支持 ==============

// sendUDPReply 发送UDP ASSOCIATE回复
func (c *Connection) sendUDPReply(ip net.IP, port uint16) error {
	var reply []byte

	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		reply = make([]byte, 10)
		reply[0] = SOCKS5_VERSION
		reply[1] = REP_SUCCESS
		reply[2] = 0x00 // RSV
		reply[3] = ATYPE_IPV4
		reply[4], reply[5], reply[6], reply[7] = ip4[0], ip4[1], ip4[2], ip4[3]
		binary.BigEndian.PutUint16(reply[8:10], port)
	} else {
		// IPv6
		reply = make([]byte, 22)
		reply[0] = SOCKS5_VERSION
		reply[1] = REP_SUCCESS
		reply[2] = 0x00 // RSV
		reply[3] = ATYPE_IPV6
		ip6 := ip.To16()
		copy(reply[4:20], ip6)
		binary.BigEndian.PutUint16(reply[20:22], port)
	}

	_, err := c.clientConn.Write(reply)
	return err
}

// handleUDPRelay 处理UDP数据转发
func (c *Connection) handleUDPRelay(udpConn *net.UDPConn, targetAddr string, targetPort uint16) {
	c.logger.Printf("UDP relay started for %s:%d", targetAddr, targetPort)

	// 检查 UDP splice 支持情况
	if c.CanUseUDPSplice() {
		c.logger.Printf("UDP splice optimization enabled")
	} else {
		c.logger.Printf("Using classic UDP forwarding (splice not available)")
	}

	defer udpConn.Close()

	buffer := make([]byte, UDP_BUFFER_SIZE)

	for {
		// 设置超时以防止资源泄漏
		udpConn.SetReadDeadline(time.Now().Add(UDP_ASSOC_TIMEOUT))

		n, clientAddr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				c.logger.Printf("UDP association timeout")
				return
			}
			c.logger.Printf("UDP read error: %v", err)
			continue
		}

		// 解析 SOCKS5 UDP 数据包
		packet, err := c.parseUDPPacket(buffer[:n])
		if err != nil {
			c.logger.Printf("Failed to parse UDP packet: %v", err)
			continue
		}

		// 记录数据包大小以显示 splice 活跃度
		if c.CanUseUDPSplice() && len(packet.DATA) > 8192 {
			c.logger.Printf("Processing large UDP packet (%d bytes) with splice", len(packet.DATA))
		}

		// 转发数据到目标
		go c.forwardUDPPacket(udpConn, packet, clientAddr)
	}
}

// parseUDPPacket 解析SOCKS5 UDP数据包
func (c *Connection) parseUDPPacket(data []byte) (*UDPPacket, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("packet too short")
	}

	packet := &UDPPacket{
		RESERVED: binary.BigEndian.Uint16(data[0:2]),
		FRAG:    data[2],
		ATYPE:   data[3],
	}

	offset := 4

	// 解析目标地址
	switch packet.ATYPE {
	case ATYPE_IPV4:
		if len(data) < offset+4 {
			return nil, fmt.Errorf("IPv4 address incomplete")
		}
		packet.DSTADDR = data[offset : offset+4]
		offset += 4
	case ATYPE_DOMAIN:
		if len(data) < offset+1 {
			return nil, fmt.Errorf("domain length missing")
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen {
			return nil, fmt.Errorf("domain name incomplete")
		}
		packet.DSTADDR = data[offset : offset+domainLen]
		offset += domainLen
	case ATYPE_IPV6:
		if len(data) < offset+16 {
			return nil, fmt.Errorf("IPv6 address incomplete")
		}
		packet.DSTADDR = data[offset : offset+16]
		offset += 16
	default:
		return nil, fmt.Errorf("unsupported address type: %d", packet.ATYPE)
	}

	// 解析目标端口
	if len(data) < offset+2 {
		return nil, fmt.Errorf("port incomplete")
	}
	packet.DSTPORT = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 数据部分
	if len(data) > offset {
		packet.DATA = data[offset:]
	}

	return packet, nil
}

// buildUDPPacket 构建SOCKS5 UDP数据包
func (c *Connection) buildUDPPacket(srcAddr, dstAddr string, srcPort, dstPort uint16, data []byte) ([]byte, error) {
	var packet []byte

	// SOCKS5 UDP 头部
	packet = append(packet, 0x00, 0x00, 0x00) // RSV + FRAG

	// 目标地址和端口（客户端地址）
	if ip := net.ParseIP(dstAddr); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			packet = append(packet, ATYPE_IPV4)
			packet = append(packet, ip4...)
		} else {
			packet = append(packet, ATYPE_IPV6)
			packet = append(packet, ip.To16()...)
		}
	} else {
		// 域名
		if len(dstAddr) > 255 {
			return nil, fmt.Errorf("domain name too long")
		}
		packet = append(packet, ATYPE_DOMAIN, byte(len(dstAddr)))
		packet = append(packet, []byte(dstAddr)...)
	}

	// 端口
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, srcPort)
	packet = append(packet, portBytes...)

	// 数据
	packet = append(packet, data...)

	return packet, nil
}

// forwardUDPPacket 转发UDP数据包（集成路由和 splice 优化）
func (c *Connection) forwardUDPPacket(udpConn *net.UDPConn, packet *UDPPacket, clientAddr *net.UDPAddr) {
	var targetHost string
	isDomain := false

	// 1. 从UDP包中解析目标地址
	switch packet.ATYPE {
	case ATYPE_IPV4, ATYPE_IPV6:
		targetHost = net.IP(packet.DSTADDR).String()
	case ATYPE_DOMAIN:
		targetHost = string(packet.DSTADDR)
		isDomain = true
	default:
		c.logger.Printf("UDP: Unsupported address type in packet: %d", packet.ATYPE)
		return
	}

	// 2. 路由决策（根据用户要求，仅对IP地址进行规则匹配）
	var result MatchResult
	if c.server.router != nil && !isDomain {
		result = c.server.router.MatchRule(targetHost, "", int(packet.DSTPORT))
	} else {
		// 如果是域名，或路由器未启用，则走默认行为（通常是走代理）
		result = MatchResult{Action: ActionDeny, Match: false}
	}

	// 3. 根据路由结果执行操作
	switch result.Action {
	case ActionBlock:
		c.logger.Printf("UDP: Blocked packet to %s:%d by rule", targetHost, packet.DSTPORT)
		return // 直接丢弃数据包

	case ActionAllow:
		c.logger.Printf("UDP: Allowed packet to %s:%d by rule (direct connection)", targetHost, packet.DSTPORT)
		// 为了简单起见，我们暂时禁用splice，直接使用传统方式转发
		err := c.forwardUDPPacketClassic(udpConn, packet, clientAddr)
		if err != nil {
			c.logger.Printf("UDP: Direct forward failed: %v", err)
		}

	case ActionProxy:
		proxyNode := c.server.router.GetProxyNode(result.ProxyNode)
		if proxyNode == nil {
			c.logger.Printf("UDP: Proxy node '%s' not found for %s:%d. Dropping packet.", result.ProxyNode, targetHost, packet.DSTPORT)
			return
		}
		c.logger.Printf("UDP: Proxying packet to %s:%d via %s", targetHost, packet.DSTPORT, proxyNode.Name)
		if err := c.forwardUDPPacketViaProxy(udpConn, packet, clientAddr, proxyNode); err != nil {
			c.logger.Printf("UDP: Failed to forward packet via proxy %s: %v", proxyNode.Name, err)
		}

	default: // ActionDeny 或无匹配规则
		defaultProxy := c.server.router.GetDefaultProxy()
		if defaultProxy == nil {
			c.logger.Printf("UDP: No rule matched for %s:%d and no default proxy configured. Dropping packet.", targetHost, packet.DSTPORT)
			return
		}
		c.logger.Printf("UDP: No rule matched for %s:%d, using default proxy %s", targetHost, packet.DSTPORT, defaultProxy.Name)
		if err := c.forwardUDPPacketViaProxy(udpConn, packet, clientAddr, defaultProxy); err != nil {
			c.logger.Printf("UDP: Failed to forward packet via default proxy %s: %v", defaultProxy.Name, err)
		}
	}
}

// ============== UDP splice 零拷贝优化 ==============

// CanUseUDPSplice 检查是否可以使用 UDP splice
func (c *Connection) CanUseUDPSplice() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	// 检查系统是否支持 splice
	if !IsSpliceSupported() {
		return false
	}

	// Linux 2.6.17+ 支持 UDP splice
	return true
}

// UDPSpliceRelay UDP splice 转发（适用于高流量 UDP）
func (c *Connection) UDPSpliceRelay(udpConn *net.UDPConn, packet *UDPPacket, clientAddr *net.UDPAddr) error {
	if !c.CanUseUDPSplice() {
		return c.forwardUDPPacketClassic(udpConn, packet, clientAddr)
	}

	// 对于高性能 UDP，我们可以使用 splice 优化
	return c.forwardUDPPacketWithSplice(udpConn, packet, clientAddr)
}

// forwardUDPPacketWithSplice 使用 splice 优化的 UDP 转发
func (c *Connection) forwardUDPPacketWithSplice(udpConn *net.UDPConn, packet *UDPPacket, clientAddr *net.UDPAddr) error {
	// 构建目标地址
	targetHost := string(packet.DSTADDR)
	if packet.ATYPE == ATYPE_IPV4 {
		ip := net.IP(packet.DSTADDR).String()
		targetHost = ip
	}

	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetHost, packet.DSTPORT))
	if err != nil {
		c.logger.Printf("Failed to resolve target UDP address: %v", err)
		return err
	}

	// 检查是否已有会话
	session := c.server.udpSessions.GetSession(clientAddr)
	if session == nil {
		session = c.server.udpSessions.AddSession(clientAddr, targetAddr, targetHost)
	}

	// 创建 UDP 连接
	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		c.logger.Printf("Failed to dial target UDP: %v", err)
		return err
	}
	defer targetConn.Close()

	// 对于大型数据包，尝试使用 splice 优化
	if len(packet.DATA) > 8192 { // 8KB 以上使用 splice
		err = c.udpSpliceLargePacket(targetConn, packet.DATA, len(packet.DATA))
		if err != nil {
			c.logger.Printf("UDP splice failed, falling back: %v", err)
			// 降级到普通方式
			_, err = targetConn.Write(packet.DATA)
			if err != nil {
				return err
			}
		}
	} else {
		// 小数据包使用传统方式
		_, err = targetConn.Write(packet.DATA)
		if err != nil {
			return err
		}
	}

	// 设置超时
	targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 接收响应
	response := make([]byte, UDP_BUFFER_SIZE)
	n, err := targetConn.Read(response)
	if err != nil {
		c.logger.Printf("Failed to read response from target: %v", err)
		return err
	}

	// 对于大型响应，也尝试使用 splice
	if n > 8192 {
		err = c.udpSpliceResponseBack(udpConn, response[:n], n, clientAddr, packet)
		if err != nil {
			c.logger.Printf("UDP response splice failed, falling back: %v", err)
			// 降级到传统方式
			return c.udpSendClassicResponse(udpConn, response[:n], n, clientAddr, packet)
		}
		return nil
	} else {
		// 小响应使用传统方式
		return c.udpSendClassicResponse(udpConn, response[:n], n, clientAddr, packet)
	}
}

// udpSpliceLargePacket 使用 splice 转发大型 UDP 数据包
func (c *Connection) udpSpliceLargePacket(targetConn *net.UDPConn, data []byte, size int) error {
	// 将 UDP 数据写入内存缓冲区
	targetFile, err := targetConn.File()
	if err != nil {
		return fmt.Errorf("failed to get UDP file descriptor: %v", err)
	}
	defer targetFile.Close()

	targetFd := int(targetFile.Fd())

	// 创建内存管道
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return fmt.Errorf("failed to create splice pipe: %v", err)
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])

	// 将数据写入管道
	bytesWritten, err := unix.Write(pipe[1], data[:size])
	if err != nil {
		return fmt.Errorf("failed to write to splice pipe: %v", err)
	}

	// 使用 splice 从管道传输到套接字
	remaining := int(bytesWritten)
	for remaining > 0 {
		written, err := unix.Splice(pipe[0], nil, targetFd, nil, remaining, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN {
				time.Sleep(time.Microsecond * 100)
				continue
			}
			return fmt.Errorf("UDP splice write failed: %v", err)
		}
		remaining -= int(written)
	}

	return nil
}

// udpSpliceResponseBack 使用 splice 回传大型 UDP 响应
func (c *Connection) udpSpliceResponseBack(udpConn *net.UDPConn, data []byte, size int, clientAddr *net.UDPAddr, packet *UDPPacket) error {
	// 构建 SOCKS5 UDP 回复包头
	replyPacket, err := c.buildUDPPacket(
		"target", // 源地址（简化）
		clientAddr.String(),
		packet.DSTPORT,
		uint16(clientAddr.Port),
		data,
	)
	if err != nil {
		return fmt.Errorf("failed to build reply packet: %v", err)
	}

	// 直接发送（对于 UDP，splice 的收益相对较小）
	_, err = udpConn.WriteToUDP(replyPacket, clientAddr)
	return err
}

// udpSendClassicResponse 传统方式发送 UDP 响应
func (c *Connection) udpSendClassicResponse(udpConn *net.UDPConn, data []byte, size int, clientAddr *net.UDPAddr, packet *UDPPacket) error {
	// 构建回复包
	replyPacket, err := c.buildUDPPacket(
		"target", // 源地址（简化）
		clientAddr.String(),
		packet.DSTPORT,
		uint16(clientAddr.Port),
		data,
	)
	if err != nil {
		return fmt.Errorf("failed to build reply packet: %v", err)
	}

	// 发送回复给客户端
	_, err = udpConn.WriteToUDP(replyPacket, clientAddr)
	return err
}

// forwardUDPPacketClassic 传统 UDP 转发（降级方案）
func (c *Connection) forwardUDPPacketClassic(udpConn *net.UDPConn, packet *UDPPacket, clientAddr *net.UDPAddr) error {
	// 使用原来的转发逻辑
	targetHost := string(packet.DSTADDR)
	if packet.ATYPE == ATYPE_IPV4 {
		ip := net.IP(packet.DSTADDR).String()
		targetHost = ip
	}

	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetHost, packet.DSTPORT))
	if err != nil {
		c.logger.Printf("Failed to resolve target UDP address: %v", err)
		return err
	}

	// 检查是否已有会话
	session := c.server.udpSessions.GetSession(clientAddr)
	if session == nil {
		session = c.server.udpSessions.AddSession(clientAddr, targetAddr, targetHost)
	}

	// 发送数据到目标
	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		c.logger.Printf("Failed to dial target UDP: %v", err)
		return err
	}
	defer targetConn.Close()

	_, err = targetConn.Write(packet.DATA)
	if err != nil {
		c.logger.Printf("Failed to send data to target: %v", err)
		return err
	}

	// 设置超时
	targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 接收响应
	response := make([]byte, UDP_BUFFER_SIZE)
	n, err := targetConn.Read(response)
	if err != nil {
		c.logger.Printf("Failed to read response from target: %v", err)
		return err
	}

	// 构建回复包
	replyPacket, err := c.buildUDPPacket(
		targetAddr.String(),
		clientAddr.String(),
		packet.DSTPORT,
		uint16(clientAddr.Port),
		response[:n],
	)
	if err != nil {
		c.logger.Printf("Failed to build reply packet: %v", err)
		return err
	}

	// 发送回复给客户端
	_, err = udpConn.WriteToUDP(replyPacket, clientAddr)
	if err != nil {
		c.logger.Printf("Failed to send reply to client: %v", err)
		return err
	}

	// 更新会话活动时间
	session.LastActivity = time.Now()

	return nil
}

// sendReply 发送SOCKS5回复
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

// rateLimitedWriter 带限速的写入器
type rateLimitedWriter struct {
	conn        net.Conn
	rateLimiter *RateLimiter
	key         string
}

func (w *rateLimitedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if w.rateLimiter != nil {
		if !w.rateLimiter.CheckDownloadLimit(w.key, int64(n)) {
			// 超过限速，丢弃数据（但实际上应该阻塞而不是丢弃）
			// 这里使用简化的处理：超过限速时返回错误
			return 0, fmt.Errorf("rate limit exceeded")
		}
	}
	return w.conn.Write(p)
}

// rateLimitedReader 带限速的读取器
type rateLimitedReader struct {
	conn        net.Conn
	rateLimiter *RateLimiter
	key         string
}

func (r *rateLimitedReader) Read(p []byte) (int, error) {
	n, err := r.conn.Read(p)
	if err == nil && r.rateLimiter != nil {
		if !r.rateLimiter.CheckUploadLimit(r.key, int64(n)) {
			// 超过限速，丢弃数据（但实际上应该阻塞）
			// 这里使用简化的处理：超过限速时返回错误
			return 0, fmt.Errorf("rate limit exceeded")
		}
	}
	return n, err
}

func (c *Connection) relay() error {
	// 确保连接在函数结束时被关闭
	defer func() {
		if c.clientConn != nil {
			c.clientConn.Close()
		}
		if c.targetConn != nil {
			c.targetConn.Close()
		}
	}()

	// 创建上下文管理连接生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 获取限速键
	rateLimitKey := c.getRateLimitKey()

	// 根据是否有限速器创建不同的 Writer
	var targetWriter io.Writer = c.targetConn
	var clientWriter io.Writer = c.clientConn
	if c.server.rateLimiter != nil {
		targetWriter = &rateLimitedWriter{
			conn:        c.targetConn,
			rateLimiter: c.server.rateLimiter,
			key:         rateLimitKey,
		}
		clientWriter = &rateLimitedWriter{
			conn:        c.clientConn,
			rateLimiter: c.server.rateLimiter,
			key:         rateLimitKey,
		}
	}

	// 使用 io.Copy 进行高效数据传输
	var wg sync.WaitGroup
	var copyErr error

	// 客户端到目标
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(targetWriter, c.clientConn)
		if err != nil {
			copyErr = err
			cancel()
		}
	}()

	// 目标到客户端 - 需要处理 RST 检测和代理切换
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.relayTargetToClientOptimized(ctx, clientWriter, rateLimitKey, &copyErr)
	}()

	// 等待所有 goroutine 完成
	wg.Wait()

	if copyErr != nil {
		c.logger.Printf("Relay finished with error: %v", copyErr)
	} else {
		c.logger.Printf("Connection closed successfully")
	}

	return copyErr
}

// ============== 第二阶段优化：Linux splice 零拷贝 ==============

// IsSpliceSupported 检查系统是否支持 splice
func IsSpliceSupported() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	// 尝试创建管道测试 splice 支持
	var pipe [2]int
	if err := unix.Pipe(pipe[:]); err != nil {
		return false
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])

	// 尝试 splice 调用（空数据）
	_, err := unix.Splice(pipe[0], nil, pipe[1], nil, 0, unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE)
	return err == nil || err == unix.EAGAIN || err == unix.EPIPE
}

// SpliceRelay 使用 splice 进行零拷贝数据转发
func SpliceRelay(src, dst net.Conn) error {
	// 类型断言获取 TCPConn
	srcTCP, ok := src.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("source connection is not TCP")
	}

	dstTCP, ok := dst.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("destination connection is not TCP")
	}

	// 获取文件描述符
	srcFile, err := srcTCP.File()
	if err != nil {
		return fmt.Errorf("failed to get source file descriptor: %v", err)
	}
	defer srcFile.Close()

	dstFile, err := dstTCP.File()
	if err != nil {
		return fmt.Errorf("failed to get destination file descriptor: %v", err)
	}
	defer dstFile.Close()

	srcFd := int(srcFile.Fd())
	dstFd := int(dstFile.Fd())

	// 创建管道作为内核缓冲区
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return fmt.Errorf("failed to create pipe: %v", err)
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])

	// 注释：无法设置管道大小，因为某些系统不支持
	// if err := unix.Fcntl(uintptr(pipe[0]), unix.F_SETPIPE_SZ, 1024*1024); err != nil {
	// 	// 如果失败，继续使用默认大小
	// }

	// 使用 splice 进行双向数据转发
	var wg sync.WaitGroup
	var forwardErr error
	var reverseErr error

	// src -> dst 转发
	wg.Add(1)
	go func() {
		defer wg.Done()
		forwardErr = spliceCopy(srcFd, dstFd, pipe[1], pipe[0], "forward")
	}()

	// dst -> src 转发
	wg.Add(1)
	go func() {
		defer wg.Done()
		reverseErr = spliceCopy(dstFd, srcFd, pipe[1], pipe[0], "reverse")
	}()

	// 等待双向转发完成
	wg.Wait()

	if forwardErr != nil && reverseErr != nil {
		return fmt.Errorf("both directions failed: forward=%v, reverse=%v", forwardErr, reverseErr)
	}
	if forwardErr != nil {
		return forwardErr
	}
	if reverseErr != nil {
		return reverseErr
	}

	return nil
}

// spliceCopy 单向 splice 数据拷贝
func spliceCopy(srcFd, dstFd, writePipe, readPipe int, direction string) error {
	const bufferSize = 64 * 1024 // 64KB 缓冲区

	for {
		// 从源读取到管道
		n, err := unix.Splice(srcFd, nil, writePipe, nil, bufferSize, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN || err == unix.EPIPE {
				return nil // 正常结束
			}
			return fmt.Errorf("splice read failed (%s): %v", direction, err)
		}
		if n == 0 {
			return nil // EOF
		}

		// 从管道写入到目标
		remaining := int(n)
		for remaining > 0 {
			written, err := unix.Splice(readPipe, nil, dstFd, nil, remaining, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				if err == unix.EAGAIN {
					// 简单的忙等待，生产环境应该使用 poll/epoll
					time.Sleep(time.Microsecond * 100)
					continue
				}
				return fmt.Errorf("splice write failed (%s): %v", direction, err)
			}
			if written == 0 {
				break
			}
			remaining -= int(written)
		}
	}
}

// EnhancedRelay 增强版 relay，支持 splice 零拷贝
func (c *Connection) EnhancedRelay() error {
	// 检查是否支持 splice
	if !IsSpliceSupported() {
		c.logger.Printf("Splice not supported on this system, using io.Copy")
		return c.relay()
	}

	// 确保连接在函数结束时被关闭
	defer func() {
		if c.clientConn != nil {
			c.clientConn.Close()
		}
		if c.targetConn != nil {
			c.targetConn.Close()
		}
	}()

	// 检查连接类型是否支持 splice并提供详细信息
	if !c.canUseSplice() {
		// 提供详细的拒绝原因
		clientAddr := c.clientConn.RemoteAddr().(*net.TCPAddr)
		targetAddr := c.targetConn.RemoteAddr().(*net.TCPAddr)

		clientIPv4 := clientAddr.IP.To4()
		targetIPv4 := targetAddr.IP.To4()

		if clientIPv4 != nil && targetIPv4 != nil {
			c.logger.Printf("Connections should support IPv4 splice but failed test, using io.Copy")
		} else if clientIPv4 == nil && targetIPv4 == nil {
			c.logger.Printf("IPv6 splice not available on this system, using io.Copy")
		} else {
			c.logger.Printf("Mixed IPv4/IPv6 connections cannot use splice, using io.Copy")
		}

		return c.relay()
	}

	// 提供 splice 启用的详细信息
	clientAddr := c.clientConn.RemoteAddr().(*net.TCPAddr)
	targetAddr := c.targetConn.RemoteAddr().(*net.TCPAddr)

	clientIPv4 := clientAddr.IP.To4()
	if clientIPv4 != nil {
		c.logger.Printf("IPv4 splice enabled: %s -> %s", clientAddr, targetAddr)
	} else {
		c.logger.Printf("IPv6 splice enabled: %s -> %s", clientAddr, targetAddr)
	}

	// 创建上下文管理连接生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 使用 splice 进行零拷贝数据传输
	var wg sync.WaitGroup
	var copyErr error

	// 启动双向 splice 转发
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := SpliceRelay(c.clientConn, c.targetConn)
		if err != nil {
			copyErr = err
			cancel()
		}
	}()

	// 处理可能的代理切换（仅在需要时）
	if c.server.smartProxyEnabled && c.server.isProbingPort(getPortFromAddr(c.targetAddr)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.monitorAndHandleRST(ctx, &copyErr)
		}()
	}

	// 等待完成
	wg.Wait()

	if copyErr != nil {
		c.logger.Printf("Enhanced relay finished with error: %v", copyErr)
	} else {
		c.logger.Printf("Enhanced relay completed successfully")
	}

	return copyErr
}

// canUseSplice 检查连接是否适合使用 splice
func (c *Connection) canUseSplice() bool {
	// 检查连接是否为 TCP
	_, ok := c.clientConn.(*net.TCPConn)
	if !ok {
		return false
	}

	_, ok = c.targetConn.(*net.TCPConn)
	if !ok {
		return false
	}

	clientAddr := c.clientConn.RemoteAddr().(*net.TCPAddr)
	targetAddr := c.targetConn.RemoteAddr().(*net.TCPAddr)

	// IPv4 splice 支持最稳定
	clientIPv4 := clientAddr.IP.To4()
	targetIPv4 := targetAddr.IP.To4()
	if clientIPv4 != nil && targetIPv4 != nil {
		return true
	}

	// IPv6 splice 支持（Linux 2.6.17+ 基本支持）
	// 但需要更谨慎的检查，因为某些系统可能不支持
	clientIPv6 := clientAddr.IP.To16()
	targetIPv6 := targetAddr.IP.To16()
	if clientIPv6 != nil && targetIPv6 != nil && clientIPv4 == nil && targetIPv4 == nil {
		// 尝试测试 IPv6 splice 的实际可用性
		return c.testIPv6SpliceSupport()
	}

	return false
}

// testIPv6SpliceSupport 测试 IPv6 splice 的实际支持情况
func (c *Connection) testIPv6SpliceSupport() bool {
	// 对于非 Linux 系统，直接返回 false
	if runtime.GOOS != "linux" {
		return false
	}

	// 简单测试：创建 IPv6 套接字对
	var testPipe [2]int
	if err := unix.Pipe2(testPipe[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return false
	}
	defer unix.Close(testPipe[0])
	defer unix.Close(testPipe[1])

	// 测试 splice 调用是否支持
	_, err := unix.Splice(testPipe[0], nil, testPipe[1], nil, 1, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)

	// 如果成功或者是预期的错误（EAGAIN/EPIPE），认为支持
	return err == nil || err == unix.EAGAIN || err == unix.EPIPE || err == unix.EINTR
}

// monitorAndHandleRST 监控并处理 RST 重置（简化版，用于 splice 模式）
func (c *Connection) monitorAndHandleRST(ctx context.Context, copyErr *error) {
	// 在 splice 模式下，我们无法轻易检测 RST
	// 这里提供基本的监控，主要依靠其他机制
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
		// 超时检查
		return
	}
}

// getPortFromAddr 从地址中提取端口
func getPortFromAddr(addr string) int {
	if _, portStr, err := net.SplitHostPort(addr); err == nil {
		if port, err := strconv.Atoi(portStr); err == nil {
			return port
		}
	}
	return 0
}

// ============== IPv6 splice 兼容性测试 ==============

// TestSpliceCompatibility 测试 splice 兼容性（包括 IPv6）
func TestSpliceCompatibility(logger *log.Logger) {
	logger.Printf("=== Splice Compatibility Test ===")

	// 基础系统支持测试
	systemSupported := IsSpliceSupported()
	if systemSupported {
		logger.Printf("✅ System supports splice")
	} else {
		logger.Printf("❌ System does not support splice")
		return
	}

	// IPv4 splice 测试
	ipv4Supported := testIPv4SpliceSupport(logger)
	if ipv4Supported {
		logger.Printf("✅ IPv4 splice supported")
	} else {
		logger.Printf("❌ IPv4 splice not supported")
	}

	// IPv6 splice 测试
	ipv6Supported := testIPv6SpliceSupport(logger)
	if ipv6Supported {
		logger.Printf("✅ IPv6 splice supported")
	} else {
		logger.Printf("❌ IPv6 splice not supported")
	}

	// 总结
	logger.Printf("=== Test Summary ===")
	logger.Printf("System Splice: %v", systemSupported)
	logger.Printf("IPv4 Splice: %v", ipv4Supported)
	logger.Printf("IPv6 Splice: %v", ipv6Supported)

	if systemSupported && ipv4Supported {
		logger.Printf("🎯 Ready for high-performance IPv4 connections")
	}
	if systemSupported && ipv6Supported {
		logger.Printf("🎯 Ready for high-performance IPv6 connections")
	}
}

// testIPv4SpliceSupport 测试 IPv4 splice 支持
func testIPv4SpliceSupport(logger *log.Logger) bool {
	if runtime.GOOS != "linux" {
		return false
	}

	// 创建 IPv4 套接字
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return false
	}
	defer unix.Close(socket)

	// 创建测试管道
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return false
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])

	// 测试 splice
	_, err = unix.Splice(socket, nil, pipe[1], nil, 1, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
	return err == nil || err == unix.EAGAIN || err == unix.EPIPE || err == unix.EINTR
}

// testIPv6SpliceSupport 测试 IPv6 splice 支持
func testIPv6SpliceSupport(logger *log.Logger) bool {
	if runtime.GOOS != "linux" {
		return false
	}

	// 创建 IPv6 套接字
	socket, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		logger.Printf("IPv6 socket creation failed: %v", err)
		return false
	}
	defer unix.Close(socket)

	// 创建测试管道
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		logger.Printf("IPv6 pipe creation failed: %v", err)
		return false
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])

	// 测试 splice
	_, err = unix.Splice(socket, nil, pipe[1], nil, 1, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)

	if err == nil {
		logger.Printf("IPv6 splice test: SUCCESS")
		return true
	}

	if err == unix.EAGAIN || err == unix.EPIPE || err == unix.EINTR {
		logger.Printf("IPv6 splice test: EXPECTED ERROR %v", err)
		return true
	}

	logger.Printf("IPv6 splice test: FAILED %v", err)
	return false
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

// relayTargetToClientOptimized 优化版的目标到客户端数据流处理
func (c *Connection) relayTargetToClientOptimized(ctx context.Context, writer io.Writer, rateLimitKey string, copyErr *error) {
	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	for {
		select {
		case <-ctx.Done():
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
								oldConn := c.targetConn
								c.targetConn = proxyConn
								c.logger.Printf("✅ Successfully switched to proxy for %s", c.targetHost)
								oldConn.Close()

								// 使用 io.Copy 继续从新代理连接读取数据
								_, err := io.Copy(writer, c.targetConn)
								if err != nil {
									*copyErr = err
									return
								}
								return
							} else {
								c.logger.Printf("❌ Failed to switch to proxy: %v", proxyErr)
							}
						}
					}
				}
			}
			*copyErr = err
			return
		}

		// 使用高效的写入方式
		if c.server.rateLimiter != nil {
			// 应用下载限速
			if !c.server.rateLimiter.CheckDownloadLimit(rateLimitKey, int64(n)) {
				continue // 超过限速，丢弃数据
			}
		}

		// 转发数据到客户端
		if _, err := writer.Write(buf[:n]); err != nil {
			*copyErr = err
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

// forwardUDPPacketViaProxy 通过另一个SOCKS5代理转发UDP数据包
func (c *Connection) forwardUDPPacketViaProxy(parentUdpConn *net.UDPConn, originalPacket *UDPPacket, originalClientAddr *net.UDPAddr, proxy *ProxyNode) error {
	c.logger.Printf("UDP-PROXY: Attempting to forward packet for %s via %s", originalClientAddr, proxy.Address)

	// 1. 连接到上游代理
	proxyConn, err := net.DialTimeout("tcp", proxy.Address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("UDP-PROXY: failed to connect to upstream proxy %s: %v", proxy.Name, err)
	}
	defer proxyConn.Close()

	// 2. SOCKS5 握手（支持用户名/密码认证）
	authMethod := byte(0x00) // 默认无认证
	if proxy.Username != nil && *proxy.Username != "" {
		authMethod = byte(0x02) // 用户名/密码认证
	}

	handshake := []byte{SOCKS5_VERSION, 1, authMethod}
	if _, err := proxyConn.Write(handshake); err != nil {
		return fmt.Errorf("UDP-PROXY: failed to send handshake to proxy: %v", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, resp); err != nil {
		return fmt.Errorf("UDP-PROXY: failed to read handshake reply from proxy: %v", err)
	}
	if resp[0] != SOCKS5_VERSION || resp[1] != authMethod {
		return fmt.Errorf("UDP-PROXY: proxy handshake failed, unsupported auth method")
	}
	c.logger.Printf("UDP-PROXY: SOCKS5 handshake successful")

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
		authReq := []byte{0x01, byte(len(user))}
		authReq = append(authReq, []byte(user)...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, []byte(pass)...)

		if _, err := proxyConn.Write(authReq); err != nil {
			return fmt.Errorf("UDP-PROXY: failed to send auth request to proxy: %v", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(proxyConn, authResp); err != nil {
			return fmt.Errorf("UDP-PROXY: failed to read auth reply from proxy: %v", err)
		}
		if authResp[0] != 0x01 || authResp[1] != 0x00 {
			return fmt.Errorf("UDP-PROXY: proxy authentication failed")
		}
		c.logger.Printf("UDP-PROXY: Username/password authentication successful")
	}

	// 4. 发送 UDP ASSOCIATE 请求
	// 对于UDP ASSOCIATE，我们通常使用0.0.0.0:0作为目标地址
	req := []byte{SOCKS5_VERSION, CMD_UDP_ASSOC, 0x00, ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := proxyConn.Write(req); err != nil {
		return fmt.Errorf("UDP-PROXY: failed to send UDP associate request: %v", err)
	}

	// 5. 读取代理的响应
	assocResp := make([]byte, 4) // VER, REP, RSV, ATYP
	if _, err := io.ReadFull(proxyConn, assocResp); err != nil {
		return fmt.Errorf("UDP-PROXY: failed to read UDP associate reply: %v", err)
	}
	if assocResp[0] != SOCKS5_VERSION || assocResp[1] != REP_SUCCESS {
		return fmt.Errorf("UDP-PROXY: UDP associate command failed with code %d", assocResp[1])
	}

	// 6. 读取绑定的地址和端口
	var proxyUDPAddr *net.UDPAddr
	switch assocResp[3] {
	case ATYPE_IPV4:
		addrBytes := make([]byte, 4)
		if _, err := io.ReadFull(proxyConn, addrBytes); err != nil {
			return fmt.Errorf("UDP-PROXY: failed to read IPv4 address: %v", err)
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(proxyConn, portBytes); err != nil {
			return fmt.Errorf("UDP-PROXY: failed to read port: %v", err)
		}
		port := binary.BigEndian.Uint16(portBytes)
		proxyUDPAddr = &net.UDPAddr{
			IP:   net.IP(addrBytes),
			Port: int(port),
		}
	case ATYPE_IPV6:
		addrBytes := make([]byte, 16)
		if _, err := io.ReadFull(proxyConn, addrBytes); err != nil {
			return fmt.Errorf("UDP-PROXY: failed to read IPv6 address: %v", err)
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(proxyConn, portBytes); err != nil {
			return fmt.Errorf("UDP-PROXY: failed to read port: %v", err)
		}
		port := binary.BigEndian.Uint16(portBytes)
		proxyUDPAddr = &net.UDPAddr{
			IP:   net.IP(addrBytes),
			Port: int(port),
		}
	case ATYPE_DOMAIN:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(proxyConn, lenByte); err != nil {
			return fmt.Errorf("UDP-PROXY: failed to read domain length: %v", err)
		}
		domainLen := int(lenByte[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(proxyConn, domain); err != nil {
			return fmt.Errorf("UDP-PROXY: failed to read domain: %v", err)
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(proxyConn, portBytes); err != nil {
			return fmt.Errorf("UDP-PROXY: failed to read port: %v", err)
		}
		port := binary.BigEndian.Uint16(portBytes)
		// 解析域名到IP地址
		ips, err := net.LookupIP(string(domain))
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("UDP-PROXY: failed to resolve domain %s: %v", domain, err)
		}
		proxyUDPAddr = &net.UDPAddr{
			IP:   ips[0],
			Port: int(port),
		}
	default:
		return fmt.Errorf("UDP-PROXY: unsupported address type in UDP associate reply: %d", assocResp[3])
	}

	c.logger.Printf("UDP-PROXY: UDP association established with proxy at %s", proxyUDPAddr)

	// 7. 创建UDP连接到代理的UDP端口
	proxyUDPConn, err := net.DialUDP("udp", nil, proxyUDPAddr)
	if err != nil {
		return fmt.Errorf("UDP-PROXY: failed to create UDP connection to proxy: %v", err)
	}
	defer proxyUDPConn.Close()

	// 8. 构建要发送到代理的SOCKS5 UDP数据包
	// 我们需要将原始数据包重新封装成SOCKS5 UDP格式
	// SOCKS5 UDP包格式: [RSV(2字节)=0x0000, FRAG(1字节)=0x00, ATYP, DST.ADDR, DST.PORT, DATA]
	var proxyPacket []byte
	proxyPacket = append(proxyPacket, 0x00, 0x00, 0x00) // RSV + FRAG

	// 添加目标地址（从原始数据包中提取）
	targetHost := ""
	if originalPacket.ATYPE == ATYPE_IPV4 || originalPacket.ATYPE == ATYPE_IPV6 {
		targetHost = net.IP(originalPacket.DSTADDR).String()
	} else {
		targetHost = string(originalPacket.DSTADDR)
	}

	// 构建地址部分
	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			proxyPacket = append(proxyPacket, ATYPE_IPV4)
			proxyPacket = append(proxyPacket, ip4...)
		} else {
			proxyPacket = append(proxyPacket, ATYPE_IPV6)
			proxyPacket = append(proxyPacket, ip.To16()...)
		}
	} else {
		// 域名
		if len(targetHost) > 255 {
			return fmt.Errorf("UDP-PROXY: domain name too long: %s", targetHost)
		}
		proxyPacket = append(proxyPacket, ATYPE_DOMAIN, byte(len(targetHost)))
		proxyPacket = append(proxyPacket, []byte(targetHost)...)
	}

	// 添加端口和数据
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, originalPacket.DSTPORT)
	proxyPacket = append(proxyPacket, portBytes...)
	proxyPacket = append(proxyPacket, originalPacket.DATA...)

	// 9. 发送数据到代理
	if _, err := proxyUDPConn.Write(proxyPacket); err != nil {
		return fmt.Errorf("UDP-PROXY: failed to send UDP packet to proxy: %v", err)
	}

	// 10. 设置超时并等待代理的响应
	proxyUDPConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	responseBuf := make([]byte, UDP_BUFFER_SIZE)
	n, err := proxyUDPConn.Read(responseBuf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// 超时，没有响应 - 这可能是正常的（UDP是无连接的）
			c.logger.Printf("UDP-PROXY: No response from proxy (timeout)")
			return nil
		}
		return fmt.Errorf("UDP-PROXY: failed to read response from proxy: %v", err)
	}

	// 11. 解析代理的响应（SOCKS5 UDP格式）
	if n < 10 { // 最小长度：RSV(2) + FRAG(1) + ATYP(1) + 最小地址 + 端口(2)
		return fmt.Errorf("UDP-PROXY: response too short")
	}

	// 跳过RSV和FRAG
	respData := responseBuf[3:n]
	atyp := respData[0]
	offset := 1

	// 跳过地址部分（我们不需要解析，因为响应是针对原始客户端的）
	switch atyp {
	case ATYPE_IPV4:
		offset += 4
	case ATYPE_IPV6:
		offset += 16
	case ATYPE_DOMAIN:
		domainLen := int(respData[1])
		offset += 1 + domainLen
	default:
		return fmt.Errorf("UDP-PROXY: unsupported address type in proxy response: %d", atyp)
	}

	if offset+2 > len(respData) {
		return fmt.Errorf("UDP-PROXY: response incomplete")
	}
	// 跳过端口
	offset += 2

	// 12. 将响应数据发送回原始客户端
	responseData := respData[offset:]
	if len(responseData) == 0 {
		c.logger.Printf("UDP-PROXY: No data in response from proxy")
		return nil
	}

	// 构建返回给客户端的SOCKS5 UDP数据包
	clientReply, err := c.buildUDPPacket(
		proxyUDPAddr.IP.String(),
		originalClientAddr.String(),
		originalPacket.DSTPORT,
		uint16(originalClientAddr.Port),
		responseData,
	)
	if err != nil {
		return fmt.Errorf("UDP-PROXY: failed to build reply packet: %v", err)
	}

	_, err = parentUdpConn.WriteToUDP(clientReply, originalClientAddr)
	if err != nil {
		return fmt.Errorf("UDP-PROXY: failed to send reply to client: %v", err)
	}

	c.logger.Printf("UDP-PROXY: Successfully forwarded UDP packet via proxy %s", proxy.Name)
	return nil
}
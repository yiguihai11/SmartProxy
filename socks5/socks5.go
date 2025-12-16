package socks5

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"smartproxy/logger"
	"strconv"
	"strings"
	"sync"
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

	// UDP 相关常量
	UDP_ASSOC_TIMEOUT = 5 * time.Minute
	UDP_BUFFER_SIZE   = 64 * 1024
	UDP_SESSION_TTL   = 10 * time.Minute
	// DNS 查询通常很小，使用较小的缓冲区
	DNS_BUFFER_SIZE = 512
	// UDP空闲超时配置
	UDP_IDLE_TIMEOUT   = 30 * time.Second // 空闲超时时间
	UDP_MAX_IDLE_COUNT = 3                // 最大允许空闲次数（30秒 x 3 = 90秒）
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

// generateSessionID generates a unique session ID for SOCKS5 connections
func generateSessionID() string {
	// Generate 8 random bytes
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if random generation fails
		return fmt.Sprintf("sess-%d", time.Now().UnixNano())
	}
	// Format as hex with "sess-" prefix
	return "sess-" + hex.EncodeToString(b)
}

// logInfo logs with session ID
func (c *Connection) logInfo(format string, args ...interface{}) {
	c.logger.WithField("session_id", c.sessionID).Info(format, args...)
}

// logWarn logs with session ID
func (c *Connection) logWarn(format string, args ...interface{}) {
	c.logger.WithField("session_id", c.sessionID).Warn(format, args...)
}

// logError logs with session ID
func (c *Connection) logError(format string, args ...interface{}) {
	c.logger.WithField("session_id", c.sessionID).Error(format, args...)
}

// logDebug logs with session ID
func (c *Connection) logDebug(format string, args ...interface{}) {
	c.logger.WithField("session_id", c.sessionID).Debug(format, args...)
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
	ClientAddr   *net.UDPAddr
	TargetAddr   *net.UDPAddr
	CreatedAt    time.Time
	LastActivity time.Time
	TargetHost   string
	// 空闲超时管理
	idleTimeout      time.Duration // 空闲超时时间
	maxIdleCount     int           // 最大允许空闲次数
	currentIdleCount int           // 当前空闲次数
	timeoutTimer     *time.Timer   // 超时计时器
	closing          bool          // 是否正在关闭
}

// UDPPacket SOCKS5 UDP数据包结构
type UDPPacket struct {
	RESERVED uint16 // 保留字段
	FRAG     uint8  // 分片标志
	ATYPE    uint8  // 地址类型
	SRCADDR  []byte // 源地址
	DSTADDR  []byte // 目标地址
	SRCPORT  uint16 // 源端口
	DSTPORT  uint16 // 目标端口
	DATA     []byte // 数据
}

// UDPSessionManager UDP会话管理器
type UDPSessionManager struct {
	sessions    map[string]*UDPSession // key: clientAddr
	mutex       sync.RWMutex
	logger      *logger.SlogLogger
	cleanupTick *time.Ticker
	// Full Cone NAT 支持
	fullConeMap   map[string]*FullConeMapping // key: internalAddr -> mapping
	fullConeMutex sync.RWMutex
}

// FullConeMapping Full Cone NAT映射
type FullConeMapping struct {
	InternalAddr    *net.UDPAddr
	ExternalConn    *net.UDPConn // 用于接收响应的外部连接
	ExternalPort    int          // 外部端口
	CreatedAt       time.Time
	LastActivity    time.Time
	TargetEndpoints map[string]bool // 记录已通信的目标端点
}

// NewUDPSessionManager 创建UDP会话管理器
func NewUDPSessionManager(logger *logger.SlogLogger) *UDPSessionManager {
	manager := &UDPSessionManager{
		sessions:    make(map[string]*UDPSession),
		fullConeMap: make(map[string]*FullConeMapping),
		logger:      logger,
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
		ClientAddr:       clientAddr,
		TargetAddr:       targetAddr,
		CreatedAt:        time.Now(),
		LastActivity:     time.Now(),
		TargetHost:       targetHost,
		idleTimeout:      UDP_IDLE_TIMEOUT,
		maxIdleCount:     UDP_MAX_IDLE_COUNT,
		currentIdleCount: 0,
		timeoutTimer:     nil,
		closing:          false,
	}

	// 启动空闲超时计时器
	session.startIdleTimer(m)

	key := clientAddr.String()
	m.sessions[key] = session
	m.logger.Info("UDP session added: %s -> %s (%s), idle timeout: %v", clientAddr, targetAddr, targetHost, UDP_IDLE_TIMEOUT)

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
	if session, exists := m.sessions[key]; exists {
		// 停止空闲计时器
		session.stopIdleTimer()
		delete(m.sessions, key)
		m.logger.Info("UDP session removed: %s", clientAddr)
	}
}

// GetSessionCount 获取当前UDP会话数
func (m *UDPSessionManager) GetSessionCount() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	// 返回Full Cone映射数（当前实现使用Full Cone NAT）
	return len(m.fullConeMap)
}

// Stop 停止UDP会话管理器
func (m *UDPSessionManager) Stop() {
	if m.cleanupTick != nil {
		m.cleanupTick.Stop()
	}

	// 关闭所有UDP连接
	m.mutex.Lock()
	for _, session := range m.sessions {
		if session.timeoutTimer != nil {
			session.timeoutTimer.Stop()
		}
	}
	m.sessions = make(map[string]*UDPSession)
	m.mutex.Unlock()

	// 关闭所有Full Cone NAT映射
	m.fullConeMutex.Lock()
	for _, mapping := range m.fullConeMap {
		if mapping.ExternalConn != nil {
			mapping.ExternalConn.Close()
		}
	}
	m.fullConeMap = make(map[string]*FullConeMapping)
	m.fullConeMutex.Unlock()

	m.logger.Info("UDP session manager stopped")
}

// startIdleTimer 启动空闲计时器
func (s *UDPSession) startIdleTimer(manager *UDPSessionManager) {
	if s.timeoutTimer != nil {
		s.timeoutTimer.Stop()
	}

	s.timeoutTimer = time.AfterFunc(s.idleTimeout, func() {
		manager.handleSessionTimeout(s)
	})
}

// stopIdleTimer 停止空闲计时器
func (s *UDPSession) stopIdleTimer() {
	if s.timeoutTimer != nil {
		s.timeoutTimer.Stop()
		s.timeoutTimer = nil
	}
}

// updateActivity 更新活动时间并重置计时器
func (s *UDPSession) updateActivity(manager *UDPSessionManager) {
	if s.closing {
		return
	}

	now := time.Now()
	s.LastActivity = now
	s.currentIdleCount = 0 // 有活动就重置计数
	s.startIdleTimer(manager)
}

// handleSessionTimeout 处理会话超时
func (m *UDPSessionManager) handleSessionTimeout(session *UDPSession) {
	if session.closing {
		return
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 检查会话是否仍然存在
	key := session.ClientAddr.String()
	if currentSession, exists := m.sessions[key]; !exists || currentSession != session {
		return // 会话已不存在
	}

	session.currentIdleCount++

	// 检查空闲次数
	if session.currentIdleCount >= session.maxIdleCount {
		m.logger.Info("UDP session %s: idle timeout reached (%d times, total %v), closing",
			session.ClientAddr, session.currentIdleCount, time.Since(session.CreatedAt))
		m.closeSession(session)
		return
	}

	// 发送警告并继续等待
	m.logger.Info("UDP session %s: idle warning (%d/%d), waiting for activity",
		session.ClientAddr, session.currentIdleCount, session.maxIdleCount)

	// 重启计时器继续监控
	session.startIdleTimer(m)
}

// closeSession 关闭会话
func (m *UDPSessionManager) closeSession(session *UDPSession) {
	session.closing = true
	session.stopIdleTimer()

	key := session.ClientAddr.String()
	delete(m.sessions, key)

	m.logger.Info("UDP session closed due to inactivity: %s -> %s (total time: %v)",
		session.ClientAddr, session.TargetAddr, time.Since(session.CreatedAt))
}

// cleanupExpiredSessions 清理过期会话
func (m *UDPSessionManager) cleanupExpiredSessions() {
	for range m.cleanupTick.C {
		now := time.Now()
		var expiredSessions []string
		var expiredMappings []string

		// 清理普通UDP会话
		m.mutex.Lock()
		for key, session := range m.sessions {
			if now.Sub(session.LastActivity) > UDP_SESSION_TTL {
				expiredSessions = append(expiredSessions, key)
			}
		}

		for _, key := range expiredSessions {
			if session := m.sessions[key]; session != nil {
				delete(m.sessions, key)
				m.logger.Debug("UDP session expired: %s -> %s", session.ClientAddr, session.TargetAddr)
			}
		}
		m.mutex.Unlock()

		// 清理Full Cone NAT映射
		m.fullConeMutex.Lock()
		for key, mapping := range m.fullConeMap {
			if now.Sub(mapping.LastActivity) > UDP_SESSION_TTL {
				expiredMappings = append(expiredMappings, key)
				if mapping.ExternalConn != nil {
					mapping.ExternalConn.Close()
				}
			}
		}

		for _, key := range expiredMappings {
			if mapping := m.fullConeMap[key]; mapping != nil {
				delete(m.fullConeMap, key)
				m.logger.Debug("Full Cone mapping expired: %s -> external port %d", mapping.InternalAddr, mapping.ExternalPort)
			}
		}
		m.fullConeMutex.Unlock()
	}
}

// CreateFullConeMapping 创建Full Cone NAT映射
func (m *UDPSessionManager) CreateFullConeMapping(internalAddr *net.UDPAddr) (*FullConeMapping, error) {
	m.fullConeMutex.Lock()
	defer m.fullConeMutex.Unlock()

	// 检查是否已存在映射
	if mapping, exists := m.fullConeMap[internalAddr.String()]; exists {
		mapping.LastActivity = time.Now()
		return mapping, nil
	}

	// 根据内部地址类型选择监听地址
	var listenAddr string
	if internalAddr.IP.To4() != nil {
		// IPv4: 监听所有IPv4接口
		listenAddr = "0.0.0.0:0"
	} else {
		// IPv6: 监听所有IPv6接口
		listenAddr = "[::]:0"
	}

	// 创建外部监听端口
	externalAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve external address: %v", err)
	}

	externalConn, err := net.ListenUDP("udp", externalAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on external port: %v", err)
	}

	// 获取实际分配的外部端口
	extPort := externalConn.LocalAddr().(*net.UDPAddr).Port

	mapping := &FullConeMapping{
		InternalAddr:    internalAddr,
		ExternalConn:    externalConn,
		ExternalPort:    extPort,
		CreatedAt:       time.Now(),
		LastActivity:    time.Now(),
		TargetEndpoints: make(map[string]bool),
	}

	m.fullConeMap[internalAddr.String()] = mapping
	m.logger.Info("Full Cone mapping created: %s -> external port %d", internalAddr, extPort)

	// 启动监听协程
	// handleFullConeTraffic 现在禁用 - 响应在 forwardUDPPacketWithFullCone 中处理
	// go m.handleFullConeTraffic(mapping)

	return mapping, nil
}

// GetFullConeMapping 获取Full Cone NAT映射
func (m *UDPSessionManager) GetFullConeMapping(internalAddr *net.UDPAddr) (*FullConeMapping, bool) {
	m.fullConeMutex.RLock()
	defer m.fullConeMutex.RUnlock()

	mapping, exists := m.fullConeMap[internalAddr.String()]
	if exists {
		mapping.LastActivity = time.Now()
	}
	return mapping, exists
}

// handleFullConeTraffic - 已移除
// 原函数存在bug：错误地尝试直接连接到客户端UDP端口
// UDP响应处理现在在forwardUDPPacketWithFullCone中完成
// func (m *UDPSessionManager) handleFullConeTraffic(mapping *FullConeMapping) {
// 	DEAD CODE: 此函数已被移除
// }

// buildFullConeResponsePacket 构建Full Cone NAT响应包
func (m *UDPSessionManager) buildFullConeResponsePacket(senderAddr *net.UDPAddr, data []byte) ([]byte, error) {
	var packet []byte

	// SOCKS5 UDP 头部
	packet = append(packet, 0x00, 0x00, 0x00) // RSV + FRAG

	// 添加源地址（外部发送方地址）
	if ip4 := senderAddr.IP.To4(); ip4 != nil {
		packet = append(packet, ATYPE_IPV4)
		packet = append(packet, ip4...)
	} else if ip6 := senderAddr.IP.To16(); ip6 != nil {
		packet = append(packet, ATYPE_IPV6)
		packet = append(packet, ip6...)
	} else {
		return nil, fmt.Errorf("invalid IP address")
	}

	// 添加源端口
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(senderAddr.Port))
	packet = append(packet, portBytes...)

	// 添加数据
	packet = append(packet, data...)

	return packet, nil
}

// SendViaFullCone 通过Full Cone NAT发送数据
func (m *UDPSessionManager) SendViaFullCone(internalAddr *net.UDPAddr, targetAddr *net.UDPAddr, data []byte) error {
	// 获取或创建映射
	mapping, exists := m.GetFullConeMapping(internalAddr)
	if !exists {
		var err error
		mapping, err = m.CreateFullConeMapping(internalAddr)
		if err != nil {
			return err
		}
	}

	// 更新活动时间和目标端点
	mapping.LastActivity = time.Now()
	mapping.TargetEndpoints[targetAddr.String()] = true

	// 通过外部连接发送数据
	_, err := mapping.ExternalConn.WriteToUDP(data, targetAddr)
	if err != nil {
		return fmt.Errorf("failed to send via Full Cone: %v", err)
	}

	m.logger.Debug("Full Cone send: %s -> %s (%d bytes)", internalAddr, targetAddr, len(data))
	return nil
}

// SOCKS5Server SOCKS5 服务器
type SOCKS5Server struct {
	listener            net.Listener
	tcpListener         *net.TCPListener // TCP监听器，用于SetDeadline
	udpListener         *net.UDPConn
	wg                  sync.WaitGroup
	logger              *logger.SlogLogger
	router              *Router
	detector            *TrafficDetector
	configPath          string
	rateLimiter         *RateLimiter
	authManager         *AuthManager
	blockedItems        *BlockedItemsManager // Enhanced blocked items tracking
	probingPorts        []int
	smartProxyEnabled   bool
	smartProxyTimeoutMs int
	udpSessions         *UDPSessionManager
	natTraversal        *NATTraversal // NAT穿透支持
}

type Connection struct {
	clientConn   net.Conn
	targetConn   net.Conn
	logger       *logger.SlogLogger
	server       *SOCKS5Server
	sessionID    string // 会话ID，用于追踪连接
	connID       string // 连接ID，用于流量统计
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
	// 创建 logger
	logger := logger.WithPrefix("[SOCKS5]")

	// 读取配置以获取IPv6设置
	ipv6Enabled := true
	if configData, err := ioutil.ReadFile(configPath); err == nil {
		var config struct {
			Listener struct {
				IPv6Enabled bool `json:"ipv6_enabled"`
			} `json:"listener"`
		}
		if json.Unmarshal(configData, &config) == nil {
			ipv6Enabled = config.Listener.IPv6Enabled
		}
	}

	var listener net.Listener
	var tcpListener *net.TCPListener
	var err error

	// 根据配置选择监听方式
	if ipv6Enabled {
		// 首先尝试IPv6（dual stack）
		tcpListener, err = net.ListenTCP("tcp6", &net.TCPAddr{Port: port})
		if err != nil {
			// IPv6失败，回退到IPv4
			logger.Warn("IPv6 listen failed, trying IPv4 only: %v", err)
			tcpListener, err = net.ListenTCP("tcp", &net.TCPAddr{Port: port})
			if err != nil {
				return nil, fmt.Errorf("failed to listen on port %d: %v", port, err)
			}
			logger.Info("SOCKS5 server listening on IPv4 only")
		} else {
			logger.Info("SOCKS5 server listening on IPv6 (dual-stack)")
		}
		listener = tcpListener
	} else {
		// 仅IPv4
		tcpListener, err = net.ListenTCP("tcp4", &net.TCPAddr{Port: port})
		if err != nil {
			return nil, fmt.Errorf("failed to listen on IPv4 port %d: %v", port, err)
		}
		listener = tcpListener
		logger.Info("SOCKS5 server listening on IPv4 only")
	}

	// -- Begin: Load smart_proxy config and initialize blocked items --
	var blockedItems *BlockedItemsManager
	var smartProxyProbingPorts []int
	var smartProxyEnabled bool
	var smartProxyTimeoutMs int
	var blockedItemsExpiryMinutes int = 360 // Default value

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
		logger.Warn("Could not read config file at %s for smart_proxy settings: %v", configPath, err)
	} else {
		var spc smartProxyConfig
		if err := json.Unmarshal(configData, &spc); err != nil {
			logger.Warn("Could not parse smart_proxy settings from config: %v", err)
		} else {
			if spc.SmartProxy.Enabled {
				logger.Info("SmartProxy is enabled.")
				smartProxyEnabled = true
				smartProxyTimeoutMs = spc.SmartProxy.TimeoutMs
				blockedItemsExpiryMinutes = spc.SmartProxy.BlacklistExpiryMinutes
				blockedItems = NewBlockedItemsManager(blockedItemsExpiryMinutes, logger)

				// 解析探测端口配置
				smartProxyProbingPorts = spc.SmartProxy.ProbingPorts

				// Overwrite probingPorts from parameter with the one from config if smart proxy is enabled
				if len(smartProxyProbingPorts) > 0 {
					probingPorts = smartProxyProbingPorts
				}
			} else {
				logger.Info("SmartProxy is disabled.")
			}
		}
	}
	// -- End: Load smart_proxy config and initialize blocked items --

	// 初始化路由器
	router, err := NewRouter(configPath)
	if err != nil {
		logger.Error("Failed to initialize router: %v", err)
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

	// 初始化 NAT 穿透管理器
	natTraversal := NewNATTraversal(configPath, logger)

	// User and rate limit configuration is now loaded and applied from main.go
	server := &SOCKS5Server{
		listener:            listener,
		tcpListener:         tcpListener,
		logger:              logger,
		router:              router,
		detector:            detector,
		configPath:          configPath,
		rateLimiter:         rateLimiter,
		authManager:         authManager,
		blockedItems:        blockedItems,
		probingPorts:        probingPorts,
		smartProxyEnabled:   smartProxyEnabled,
		smartProxyTimeoutMs: smartProxyTimeoutMs,
		udpSessions:         udpSessions,
		natTraversal:        natTraversal,
	}

	// 打印系统统计信息
	if router != nil {
		stats := router.GetStats()
		logger.Info("Router loaded: %d rules, %d IP rules, %d China rules (IPv4: %d nodes, IPv6: %d nodes)",
			stats["total_rules"], stats["ip_rules"], stats["china_rules"], stats["ipv4_nodes"], stats["ipv6_nodes"])
		logger.Info("IPv4/IPv6 support: ✓, Actions - Direct: %d, Proxy: %d, Block: %d",
			stats["allow"], stats["deny"], stats["block"])
	}
	logger.Info("Traffic detector: ✓ (HTTP/HTTPS/SNI detection)")

	// 设置内存监控器的回调
	if monitor := GetGlobalMemoryMonitor(); monitor != nil {
		// 设置UDP会话数更新回调
		monitor.SetUDPSessionsUpdater(func() int64 {
			if server.udpSessions != nil {
				return int64(server.udpSessions.GetSessionCount())
			}
			return 0
		})
	}

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
	s.logger.Info("SOCKS5 server started on %s", s.listener.Addr())

	// 使用select循环来处理连接，避免永久阻塞
	for {
		var clientConn net.Conn
		var err error

		// 如果有TCPListener，使用SetDeadline
		if s.tcpListener != nil {
			// 设置accept超时，减少为100ms以加快关闭速度
			s.tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond))
			clientConn, err = s.tcpListener.Accept()

			// 检查是否是超时
			if netErr, ok := err.(net.Error); ok && ok && netErr.Timeout() {
				continue // 继续下一次accept
			}
		} else {
			// 普通的Listener，没有deadline支持
			clientConn, err = s.listener.Accept()
		}

		if err != nil {
			// 检查是否是关闭信号导致的错误
			if opErr, ok := err.(*net.OpError); ok && opErr.Op == "accept" {
				if isClosedConnectionError(opErr.Err) || strings.Contains(err.Error(), "use of closed network connection") {
					s.logger.Info("Server shutting down...")
					return nil
				}
			}
			s.logger.Error("Failed to accept connection: %v", err)
			// 避免CPU占用过高
			time.Sleep(100 * time.Millisecond)
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
	// Stop the BlockedItemsManager cleanup routine
	if s.blockedItems != nil {
		s.blockedItems.Stop()
	}

	// Stop UDP session manager
	if s.udpSessions != nil {
		s.udpSessions.Stop()
	}

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
	conn.sessionID = generateSessionID() // 生成会话ID

	// 确保连接对象在函数结束时被重置并放回池中
	defer func() {
		conn.clientConn = nil
		conn.targetConn = nil
		conn.sessionID = ""
		conn.username = ""
		conn.targetAddr = ""
		conn.targetHost = ""
		conn.detectedHost = ""
		conn.protocol = ""
		connectionPool.Put(conn)
	}()

	s.logger.Info("New connection from %s", clientConn.RemoteAddr())

	// 更新活跃连接数
	if monitor := GetGlobalMemoryMonitor(); monitor != nil {
		monitor.IncrementActiveConnections()
		defer monitor.DecrementActiveConnections()
	}

	// 添加到流量监控
	connID := clientConn.RemoteAddr().String()
	if trafficMonitor := GetGlobalTrafficMonitor(); trafficMonitor != nil {
		trafficMonitor.AddConnection(connID)
		defer trafficMonitor.RemoveConnection(connID)
	}

	// 保存connID供后续使用
	conn.connID = connID

	// 认证协商
	if err := conn.handleAuthentication(); err != nil {
		s.logger.WithField("session_id", conn.sessionID).Warn("Authentication failed: %v", err)
		return
	}

	// 检查连接限制（仅对已认证用户）
	if conn.username != "" {
		clientIP, _, err := net.SplitHostPort(conn.clientConn.RemoteAddr().String())
		if err != nil {
			clientIP = conn.clientConn.RemoteAddr().String()
		}

		if err := s.authManager.CheckConnectionLimit(conn.username, clientIP); err != nil {
			s.logger.Warn("Connection limit check failed for %s: %v", conn.username, err)
			return
		}
	}

	// 处理连接请求
	if err := conn.handleRequest(); err != nil {
		s.logger.Error("Request failed: %v", err)
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
		// 根据客户端连接类型返回适当的错误地址
		clientAddr := c.clientConn.RemoteAddr().(*net.TCPAddr)
		if clientAddr.IP.To4() != nil {
			return c.sendReply(REP_COMMAND_NOT_SUPPORTED, "127.0.0.1", 1080)
		} else {
			return c.sendReply(REP_COMMAND_NOT_SUPPORTED, "::1", 1080)
		}
	case CMD_UDP_ASSOC:
		return c.handleUDPAssociateRequest(atype)
	default:
		// 根据客户端连接类型返回适当的错误地址
		clientAddr := c.clientConn.RemoteAddr().(*net.TCPAddr)
		if clientAddr.IP.To4() != nil {
			return c.sendReply(REP_COMMAND_NOT_SUPPORTED, "127.0.0.1", 1080)
		} else {
			return c.sendReply(REP_COMMAND_NOT_SUPPORTED, "::1", 1080)
		}
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
	c.logInfo("Connection request: %s -> %s (%s)", c.getClientInfo(), c.targetAddr, c.targetHost)

	// 3. 核心逻辑：检测SNI并根据路由规则建立连接
	finalTargetConn, err := c.detectAndConnect(targetAddr, targetPort)
	if err != nil {
		c.logError("Failed to establish connection for %s: %v", c.getClientInfo(), err)
		// Since a fake success reply was already sent, we can't send a SOCKS error.
		// We just close the connection by returning.
		return nil
	}
	defer finalTargetConn.Close()
	c.targetConn = finalTargetConn

	// 4. 开始双向转发数据
	c.logInfo("CONNECTED: %s -> %s", c.getAccessInfo(), c.targetAddr)

	// 使用传统的 io.Copy 进行数据转发
	return c.relay()
}

// handleUDPAssociateRequest 处理UDP ASSOCIATE请求
func (c *Connection) handleUDPAssociateRequest(atype byte) error {
	targetAddr, _, err := c.parseAddress(atype)
	if err != nil {
		return err // an error reply has already been sent by parseAddress
	}

	// 记录客户端请求的目标地址（仅用于日志）
	if targetAddr != "" {
		c.logInfo("UDP ASSOCIATE request for target: %s (address ignored per RFC 1928)", targetAddr)
	}

	// 创建 UDP 监听地址 - 根据客户端连接类型选择
	clientAddr := c.clientConn.RemoteAddr().(*net.TCPAddr)
	var udpAddr *net.UDPAddr

	if clientAddr.IP.To4() != nil {
		// IPv4客户端
		udpAddr, err = net.ResolveUDPAddr("udp", "0.0.0.0:0")
	} else {
		// IPv6客户端
		udpAddr, err = net.ResolveUDPAddr("udp", "[::]:0")
	}

	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %v", err)
	}

	// 启动 UDP 转发协程（使用Full Cone NAT）
	go c.handleUDPRelayWithFullCone(udpConn)

	// 发送成功响应
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	return c.sendUDPReply(localAddr.IP, uint16(localAddr.Port))
}

// handleUDPRelayWithFullCone 处理Full Cone NAT UDP数据转发
func (c *Connection) handleUDPRelayWithFullCone(udpConn *net.UDPConn) {
	c.logInfo("Full Cone UDP relay started (idle timeout: %v)", UDP_IDLE_TIMEOUT)

	defer udpConn.Close()

	buffer := make([]byte, UDP_BUFFER_SIZE)

	// 初始化空闲超时管理
	idleCount := 0
	idleTimer := time.NewTimer(UDP_IDLE_TIMEOUT)
	defer idleTimer.Stop()

	for {
		// 设置读取超时
		udpConn.SetReadDeadline(time.Now().Add(UDP_IDLE_TIMEOUT))

		select {
		case <-idleTimer.C:
			// 空闲超时
			idleCount++
			if idleCount >= UDP_MAX_IDLE_COUNT {
				c.logInfo("UDP association: idle timeout reached (%d times), closing", idleCount)
				return
			}
			c.logInfo("UDP association: idle warning (%d/%d), waiting for activity", idleCount, UDP_MAX_IDLE_COUNT)
			idleTimer.Reset(UDP_IDLE_TIMEOUT)
			continue

		default:
			// 尝试读取数据
			n, clientAddr, err := udpConn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// 超时，继续检查空闲定时器
					continue
				}
				c.logError("UDP read error: %v", err)
				continue
			}

			// 有数据活动，重置空闲计数和计时器
			idleCount = 0
			idleTimer.Reset(UDP_IDLE_TIMEOUT)

			// 解析 SOCKS5 UDP 数据包
			packet, err := c.parseUDPPacket(buffer[:n])
			if err != nil {
				c.logError("Failed to parse UDP packet: %v", err)
				continue
			}

			// 使用Full Cone NAT转发数据
			go c.forwardUDPPacketWithFullCone(udpConn, packet, clientAddr)
		}
	}
}

// forwardUDPPacketWithFullCone 使用Full Cone NAT转发UDP数据包
func (c *Connection) forwardUDPPacketWithFullCone(udpConn *net.UDPConn, packet *UDPPacket, clientAddr *net.UDPAddr) {
	var targetHost string
	var targetPort int

	// 从UDP包中解析目标地址
	switch packet.ATYPE {
	case ATYPE_IPV4:
		if len(packet.DSTADDR) != 4 {
			c.logError("UDP: Invalid IPv4 address length")
			return
		}
		targetHost = net.IP(packet.DSTADDR).String()
	case ATYPE_IPV6:
		if len(packet.DSTADDR) != 16 {
			c.logError("UDP: Invalid IPv6 address length")
			return
		}
		targetHost = net.IP(packet.DSTADDR).String()
	case ATYPE_DOMAIN:
		targetHost = string(packet.DSTADDR)
	default:
		c.logError("UDP: Unsupported address type in packet: %d", packet.ATYPE)
		return
	}
	targetPort = int(packet.DSTPORT)

	// 构建目标地址
	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	if err != nil {
		c.logError("Failed to resolve target UDP address: %v", err)
		return
	}

	// 路由决策
	var result MatchResult
	if c.server.router != nil {
		result = c.server.router.MatchRule(targetHost, "", targetPort)
	} else {
		result = MatchResult{Action: ActionDeny, Match: false}
	}

	// 根据路由结果执行操作
	switch result.Action {
	case ActionBlock:
		c.logWarn("UDP: Blocked packet to %s:%d by rule", targetHost, packet.DSTPORT)
		return

	case ActionAllow:
		c.logInfo("UDP: Allowed packet to %s:%d by rule (direct connection)", targetHost, packet.DSTPORT)
		// 使用Full Cone NAT发送
		err := c.server.udpSessions.SendViaFullCone(clientAddr, targetAddr, packet.DATA)
		if err != nil {
			c.logError("UDP: Full Cone forward failed: %v", err)
			return
		}

		// 等待响应并发送回客户端
		go func() {
			// 获取映射
			mapping, exists := c.server.udpSessions.GetFullConeMapping(clientAddr)
			if !exists || mapping == nil {
				return
			}

			// 设置读取超时
			mapping.ExternalConn.SetReadDeadline(time.Now().Add(5 * time.Second))

			// 从缓冲区池获取缓冲区
			var bufferSize int
			if targetPort == 53 { // DNS 端口
				bufferSize = DNS_BUFFER_SIZE
			} else {
				bufferSize = 2048 // 大多数UDP包不会超过2KB
			}
			buf := bufferPool.Get(bufferSize)
			defer bufferPool.Put(buf)

			n, senderAddr, err := mapping.ExternalConn.ReadFromUDP(buf)
			if err != nil {
				// 超时或错误，直接返回
				return
			}

			// 打印响应日志
			c.logDebug("UDP: Received %d bytes response from %s:%d", n, senderAddr.IP.String(), senderAddr.Port)

			// 构建SOCKS5响应包
			responsePacket, err := c.server.udpSessions.buildFullConeResponsePacket(senderAddr, buf[:n])
			if err != nil {
				return
			}

			// 通过客户端的UDP连接发回响应
			_, err = udpConn.WriteToUDP(responsePacket, clientAddr)
			if err != nil {
				c.logError("UDP: Failed to send response to client: %v", err)
				return
			}

			c.logDebug("UDP: Response sent to client (%d bytes)", len(responsePacket))
		}()

	case ActionProxy:
		proxyNode := c.server.router.GetProxyNode(result.ProxyNode)
		if proxyNode == nil {
			c.logWarn("UDP: Proxy node '%s' not found for %s:%d. Dropping packet.", result.ProxyNode, targetHost, packet.DSTPORT)
			return
		}
		c.logInfo("UDP: Proxying packet to %s:%d via %s", targetHost, packet.DSTPORT, proxyNode.Name)
		if err := c.forwardUDPPacketViaProxy(udpConn, packet, clientAddr, proxyNode); err != nil {
			c.logError("UDP: Failed to forward packet via proxy %s: %v", proxyNode.Name, err)
		}

	default: // ActionDeny 或无匹配规则
		defaultProxy := c.server.router.GetDefaultProxy()
		if defaultProxy == nil {
			c.logWarn("UDP: No rule matched for %s:%d and no default proxy configured. Dropping packet.", targetHost, packet.DSTPORT)
			return
		}
		c.logInfo("UDP: No rule matched for %s:%d, using default proxy %s", targetHost, packet.DSTPORT, defaultProxy.Name)
		if err := c.forwardUDPPacketViaProxy(udpConn, packet, clientAddr, defaultProxy); err != nil {
			c.logError("UDP: Failed to forward packet via default proxy %s: %v", defaultProxy.Name, err)
		}
	}
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
		// 根据客户端连接类型返回适当的错误地址
		clientAddr := c.clientConn.RemoteAddr().(*net.TCPAddr)
		if clientAddr.IP.To4() != nil {
			err = c.sendReply(REP_ADDRESS_TYPE_NOT_SUPPORTED, "127.0.0.1", 1080)
		} else {
			err = c.sendReply(REP_ADDRESS_TYPE_NOT_SUPPORTED, "::1", 1080)
		}
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
		c.logInfo("PROXY by %s: %s -> %s via %s", logContext, accessInfo, c.targetAddr, proxy.Name)
		return c.connectThroughProxy(proxy, targetAddr, targetPort)

	case ActionAllow:
		c.logInfo("ALLOW by %s: %s -> %s", logContext, accessInfo, c.targetAddr)

		// 纯粹直连
		target := formatNetworkAddress(targetAddr, targetPort)
		conn, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("direct connection failed: %v", err)
		}

		return conn, nil

	default:
		if c.server.smartProxyEnabled && c.server.isProbingPort(int(targetPort)) {
			// 检查是否在屏蔽列表中
			if c.server.blockedItems != nil {
				// 优先使用detectedHost（域名），如果没有则使用targetHost，最后才使用targetAddr（IP）
				key := c.detectedHost
				if key == "" {
					key = c.targetHost
				}
				if key == "" {
					key = targetAddr
				}
				if c.server.blockedItems.IsBlocked(key) {
					c.logInfo("🚫 %s is in blocked items, using proxy directly", key)
				} else {
					c.logInfo("✅ %s not in blocked items, trying direct connection", key)
					// 尝试直连
					target := formatNetworkAddress(targetAddr, targetPort)
					conn, err := net.DialTimeout("tcp", target, time.Duration(c.server.smartProxyTimeoutMs)*time.Millisecond)
					if err != nil {
								// For other errors, check if it's a timeout
								if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
									c.AddToBlockedItems(c.targetHost, targetAddr, targetPort, FailureReasonTimeout)
								} else {
									c.AddToBlockedItems(c.targetHost, targetAddr, targetPort, FailureReasonConnectionRefused)
								}
						return nil, fmt.Errorf("direct connection failed: %v", err)
					}
					return conn, nil
				}
			}
		}
		defaultProxy := c.server.router.GetDefaultProxy()
		if defaultProxy == nil {
			return nil, fmt.Errorf("no default proxy available")
		}
		c.logInfo("Using default proxy: %s -> %s via %s", accessInfo, c.targetAddr, defaultProxy.Name)
		return c.connectThroughProxy(defaultProxy, targetAddr, targetPort)

	}
}

// detectAndConnect 执行 "提前响应-检测-路由-连接" 的核心逻辑
func (c *Connection) detectAndConnect(targetAddr string, targetPort uint16) (net.Conn, error) {
	// 1. 包装客户端连接以支持数据"回放"
	prependingClientConn := &PrependingConn{Conn: c.clientConn}
	c.clientConn = prependingClientConn

	// 2. 发送"虚假"成功响应以解锁客户端
	var fakeAddr string
	// 检查客户端地址类型
	if clientAddr, ok := c.clientConn.RemoteAddr().(*net.TCPAddr); ok {
		if clientAddr.IP.To4() == nil {
			fakeAddr = "::1" // IPv6客户端使用IPv6地址
		} else {
			fakeAddr = "0.0.0.0" // IPv4客户端使用IPv4地址
		}
	} else {
		fakeAddr = "0.0.0.0" // 默认使用IPv4地址
	}
	if err := c.sendReply(REP_SUCCESS, fakeAddr, 0); err != nil {
		return nil, fmt.Errorf("failed to send temporary success reply: %v", err)
	}

	// 3. 检测 SNI/Host（针对探测端口）
	var detectedHost string
	shouldProbe := c.server.smartProxyEnabled && c.server.isProbingPort(int(targetPort))

	if shouldProbe {
		// 读取初始数据包进行SNI/Host检测
		// 使用2KB缓冲区足够检测HTTP Host头或HTTPS SNI
		buf := bufferPool.Get(2048)
		defer bufferPool.Put(buf)

		c.clientConn.SetReadDeadline(time.Now().Add(1300 * time.Millisecond))
		n, err := prependingClientConn.Conn.Read(buf)
		c.clientConn.SetReadDeadline(time.Time{})

		// ⭐ 缓存初始数据（关键修改）
		if n > 0 {
			c.initialData = make([]byte, n)
			copy(c.initialData, buf[:n])
			c.initialDataCached = true
			c.logInfo("Cached %d bytes of initial data for potential retry", n)

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
					c.logInfo("SNI/Host detected for port %d: %s", targetPort, hostname)
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

// parseUDPPacket 解析SOCKS5 UDP数据包
func (c *Connection) parseUDPPacket(data []byte) (*UDPPacket, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("packet too short")
	}

	packet := &UDPPacket{
		RESERVED: binary.BigEndian.Uint16(data[0:2]),
		FRAG:     data[2],
		ATYPE:    data[3],
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

// sendReply 发送SOCKS5回复
func (c *Connection) sendReply(rep byte, bindAddr string, bindPort int) error {
	// 检查客户端连接类型以决定返回的地址格式
	clientAddr := c.clientConn.RemoteAddr().(*net.TCPAddr)
	var response []byte
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(bindPort))

	// 获取服务器的实际监听端口（如果需要）
	if listenAddr, ok := c.server.listener.Addr().(*net.TCPAddr); ok && bindPort == 0 {
		binary.BigEndian.PutUint16(portBytes, uint16(listenAddr.Port))
	}

	if clientAddr.IP.To4() != nil {
		// IPv4客户端 - 返回IPv4格式响应（10字节）
		ip := net.ParseIP(bindAddr)
		if ip == nil {
			ip = net.IPv4(0, 0, 0, 0)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			ip4 = net.IPv4(0, 0, 0, 0)
		}

		response = make([]byte, 10)
		response[0] = SOCKS5_VERSION
		response[1] = rep
		response[2] = 0x00 // RSV
		response[3] = ATYPE_IPV4
		response[4], response[5], response[6], response[7] = ip4[0], ip4[1], ip4[2], ip4[3]
		response[8], response[9] = portBytes[0], portBytes[1]
	} else {
		// IPv6客户端 - 返回IPv6格式响应（22字节）
		ip := net.ParseIP(bindAddr)
		if ip == nil {
			ip = net.IPv6unspecified
		}
		ip6 := ip.To16()
		if ip6 == nil {
			ip6 = net.IPv6unspecified
		}

		response = make([]byte, 22)
		response[0] = SOCKS5_VERSION
		response[1] = rep
		response[2] = 0x00 // RSV
		response[3] = ATYPE_IPV6
		copy(response[4:20], ip6)
		response[20], response[21] = portBytes[0], portBytes[1]
	}

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
		// 使用带超时的等待来处理限速
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := w.rateLimiter.WaitForDownload(ctx, w.key, int64(n))
		cancel()
		if err != nil {
			return 0, err
		}
	}
	return w.conn.Write(p)
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
		err := c.relayClientToTargetOptimized(ctx, targetWriter, rateLimitKey)
		if err != nil {
			copyErr = err
			cancel()
		}
	}()

	// 目标到客户端 - 需要处理 RST 检测和代理切换
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.relayTargetToClient(ctx, clientWriter, rateLimitKey, &copyErr)
	}()

	// 等待所有 goroutine 完成
	wg.Wait()

	if copyErr != nil {
		c.logInfo("Relay finished with error: %v", copyErr)
	} else {
		c.logInfo("Connection closed successfully")
	}

	return copyErr
}

// relayTargetToClient 目标到客户端数据流处理
func (c *Connection) relayTargetToClient(ctx context.Context, writer io.Writer, rateLimitKey string, copyErr *error) {
	// 使用 bufio.Reader/Writer 减少系统调用
	buf := bufferPool.GetOptimized(BufferUsageLarge) // 32KB
	defer bufferPool.Put(buf)
	reader := bufio.NewReaderSize(c.targetConn, len(buf))

	// 使用 bufio.Writer 优化写入（减少系统调用）
	var bufferedWriter *bufio.Writer
	if _, ok := writer.(*bufio.Writer); !ok {
		bufferedWriter = bufio.NewWriterSize(writer, len(buf))
		defer bufferedWriter.Flush()
		writer = bufferedWriter
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := reader.Read(buf)
		if err != nil {
			// 优化：先检查最常见的错误
			if err == io.EOF {
				return // 正常结束
			}

			// 处理连接重置的特殊情况
			if strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "errno 104") {
				if c.targetHost != "" {
					c.logInfo("⚠️  Direct connection to %s reset by peer, switching to proxy", c.targetHost)
					c.handleErrorAndAddToBlocked(err, c.targetHost, c.targetAddr)

					// 尝试切换到代理连接
					if proxyConn, proxyErr := c.switchToProxyAndReplay(); proxyErr == nil {
						// 成功切换到代理，更新目标连接并继续读取
						oldConn := c.targetConn
						c.targetConn = proxyConn
						c.logInfo("✅ Successfully switched to proxy for %s", c.targetHost)
						oldConn.Close()

						// 从新代理连接继续读取数据，使用相同的优化逻辑
						// 更新reader以使用新的连接
						reader.Reset(c.targetConn)
						continue // 继续主循环
					} else {
						c.logInfo("❌ Failed to switch to proxy: %v", proxyErr)
					}
				}
			} else {
				// 其他错误类型的通用处理
				if c.targetHost != "" {
					c.handleErrorAndAddToBlocked(err, c.targetHost, c.targetAddr)
				}
			}
			*copyErr = err
			return
		}

		// 记录下载流量（从目标到客户端）
		if n > 0 && c.connID != "" {
			if trafficMonitor := GetGlobalTrafficMonitor(); trafficMonitor != nil {
				trafficMonitor.RecordDownload(c.connID, int64(n))
			}
		}

		// 使用高效的写入方式
		if c.server.rateLimiter != nil {
			// 应用下载限速，使用带超时的等待
			waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.server.rateLimiter.WaitForDownload(waitCtx, rateLimitKey, int64(n))
			cancel()
			if err != nil {
				// 限速等待失败或超时
				if err == context.DeadlineExceeded {
					c.logInfo("Rate limit wait timeout for %s", rateLimitKey)
				}
				*copyErr = err
				return
			}
		}

		// 转发数据到客户端
		if _, err := writer.Write(buf[:n]); err != nil {
			*copyErr = err
			return
		}

		// 如果使用了bufio.Writer，立即刷新以确保数据及时发送
		if bufferedWriter != nil {
			if err := bufferedWriter.Flush(); err != nil {
				*copyErr = err
				return
			}
		}
	}
}

// relayClientToTargetOptimized 优化版的客户端到目标数据流处理
func (c *Connection) relayClientToTargetOptimized(ctx context.Context, writer io.Writer, rateLimitKey string) error {
	// 使用 bufio.Reader/Writer 减少系统调用
	buf := bufferPool.GetOptimized(BufferUsageLarge) // 32KB
	defer bufferPool.Put(buf)
	reader := bufio.NewReaderSize(c.clientConn, len(buf))

	// 使用 bufio.Writer 优化写入（减少系统调用）
	var bufferedWriter *bufio.Writer
	if _, ok := writer.(*bufio.Writer); !ok {
		bufferedWriter = bufio.NewWriterSize(writer, len(buf))
		defer bufferedWriter.Flush()
		writer = bufferedWriter
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := reader.Read(buf)
		if err != nil {
			// 优化：先检查最常见的错误
			if err == io.EOF {
				return nil // 正常结束
			}
			return err
		}

		// 记录上传流量（从客户端到目标）
		if n > 0 && c.connID != "" {
			if trafficMonitor := GetGlobalTrafficMonitor(); trafficMonitor != nil {
				trafficMonitor.RecordUpload(c.connID, int64(n))
			}
		}

		// 应用上传限速，使用带超时的等待
		if c.server.rateLimiter != nil {
			waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.server.rateLimiter.WaitForUpload(waitCtx, rateLimitKey, int64(n))
			cancel()
			if err != nil {
				// 限速等待失败或超时
				if err == context.DeadlineExceeded {
					c.logInfo("Rate limit wait timeout for %s", rateLimitKey)
				}
				return err
			}
		}

		// 转发数据到目标
		if _, err := writer.Write(buf[:n]); err != nil {
			return err
		}

		// 如果使用了bufio.Writer，立即刷新以确保数据及时发送
		if bufferedWriter != nil {
			if err := bufferedWriter.Flush(); err != nil {
				return err
			}
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
		c.logDebug("🔄 Replaying %d bytes of cached data to proxy connection", len(c.initialData))
		if _, writeErr := proxyConn.Write(c.initialData); writeErr != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("failed to replay data to proxy: %v", writeErr)
		}
	}

	return proxyConn, nil
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

// handleAuthentication 处理SOCKS5认证
func (c *Connection) handleAuthentication() error {
	username, err := c.server.authManager.HandleAuthentication(c.clientConn)
	if err != nil {
		return err
	}

	// 设置认证的用户名
	c.setUsername(username)

	if username != "" {
		c.logInfo("User authenticated: %s (%s)", username, c.getClientInfo())
	} else {
		c.logInfo("Anonymous connection (%s)", c.getClientInfo())
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
		s.logger.Info("Rate limits configured: upload=%d bps, download=%d bps", uploadBps, downloadBps)
	}
}

// AddRateLimitRule 添加限速规则
func (s *SOCKS5Server) AddRateLimitRule(rule *RateLimitRule) error {
	if s.rateLimiter == nil {
		return fmt.Errorf("rate limiter not initialized")
	}

	err := s.rateLimiter.AddRule(rule)
	if err != nil {
		s.logger.Info("Failed to add rate limit rule: %v", err)
		return err
	}

	s.logger.Info("Added rate limit rule: %s", rule.ID)
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
			s.logger.Info("User authentication enabled")
		} else {
			s.logger.Info("User authentication disabled")
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

// GetBlockedItemsManager 获取增强版黑名单管理器实例
func (s *SOCKS5Server) GetBlockedItemsManager() *BlockedItemsManager {
	return s.blockedItems
}

// AddToBlockedItems 添加域名或IP到BlockedItemsManager
func (c *Connection) AddToBlockedItems(targetHost, targetAddr string, port uint16, failureReason FailureReason) {
	if c.server.blockedItems == nil || targetHost == "" {
		return
	}

	// 确定目标IP地址
	targetIP := targetHost
	// 如果targetHost是域名且targetAddr包含IP，使用targetAddr中的IP
	if net.ParseIP(targetHost) == nil { // targetHost不是IP
		if ip := net.ParseIP(targetAddr); ip != nil {
			targetIP = targetAddr
		}
	}

	// 添加到BlockedItemsManager
	c.server.blockedItems.AddBlockedDomain(targetHost, fmt.Sprintf("%d", port), targetIP, failureReason)
}

// handleErrorAndAddToBlocked 统一的错误处理和添加到黑名单的逻辑
func (c *Connection) handleErrorAndAddToBlocked(err error, targetHost, targetAddr string) {
	// 获取端口号
	port := uint16(80)
	if _, portStr, perr := net.SplitHostPort(c.targetAddr); perr == nil {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = uint16(p)
		}
	}

	// 优先使用检测到的域名
	hostToAdd := c.detectedHost
	if hostToAdd == "" {
		hostToAdd = targetHost
	}

	// 根据错误类型分类
	if err == io.EOF {
		// 正常关闭，不需要添加到黑名单
		return
	}

	if err == context.Canceled {
		// 上下文取消，不需要添加到黑名单
		return
	}

	if strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "errno 104") {
		c.AddToBlockedItems(hostToAdd, targetAddr, port, FailureReasonRST)
		return
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		c.AddToBlockedItems(hostToAdd, targetAddr, port, FailureReasonTimeout)
		return
	}

	if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
		c.AddToBlockedItems(hostToAdd, targetAddr, port, FailureReasonTimeout)
		return
	}

	// 其他错误
	c.AddToBlockedItems(hostToAdd, targetAddr, port, FailureReasonConnectionRefused)
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

	c.logInfo("DEBUG: Connecting via proxy: %s (%s)", proxy.Name, proxy.Address)

	// 1. 连接到代理服务器
	proxyConn, err := net.DialTimeout("tcp", proxy.Address, 5*time.Second)
	if err != nil {
		c.logInfo("DEBUG: Failed to connect to proxy '%s' at %s: %v", proxy.Name, proxy.Address, err)

		// 检测连接超时
		if strings.Contains(err.Error(), "dial tcp") && strings.Contains(err.Error(), "i/o timeout") {
			return nil, fmt.Errorf("proxy '%s' connection timeout - %s unreachable", proxy.Name, proxy.Address)
		}

		return nil, fmt.Errorf("failed to connect to proxy '%s' at %s: %v", proxy.Name, proxy.Address, err)
	}
	c.logInfo("DEBUG: Successfully connected to proxy: %s (%s)", proxy.Name, proxy.Address)

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
		c.logInfo("DEBUG: Proxy handshake reply read failed: %v", err)
		proxyConn.Close()
		return nil, fmt.Errorf("failed to read handshake reply from proxy: %v", err)
	}
	c.logInfo("DEBUG: Proxy handshake reply: version=%d, method=%d", resp[0], resp[1])
	if resp[0] != SOCKS5_VERSION || resp[1] != authMethod {
		c.logInfo("DEBUG: Proxy handshake failed: expected version=%d method=%d, got version=%d method=%d", SOCKS5_VERSION, authMethod, resp[0], resp[1])
		proxyConn.Close()
		return nil, fmt.Errorf("proxy handshake failed, unsupported auth method")
	}
	c.logInfo("DEBUG: Proxy handshake successful")

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
		c.logInfo("DEBUG: Failed to send connect request to proxy: %v", err)
		proxyConn.Close()
		return nil, fmt.Errorf("failed to send connect request to proxy: %v", err)
	}
	c.logInfo("DEBUG: Sent connect request to proxy, reading reply...")

	// 5. 读取代理的最终回复
	finalResp := make([]byte, 4) // VER, REP, RSV, ATYP
	if _, err := io.ReadFull(proxyConn, finalResp); err != nil {
		c.logInfo("DEBUG: Failed to read final reply from proxy: %v", err)
		proxyConn.Close()
		return nil, fmt.Errorf("failed to read final reply from proxy: %v", err)
	}
	c.logInfo("DEBUG: Proxy final reply: version=%d, response=%d, rsv=%d, atyp=%d", finalResp[0], finalResp[1], finalResp[2], finalResp[3])
	if finalResp[0] != SOCKS5_VERSION || finalResp[1] != REP_SUCCESS {
		c.logInfo("DEBUG: Proxy connect command failed: expected version=%d response=%d, got version=%d response=%d", SOCKS5_VERSION, REP_SUCCESS, finalResp[0], finalResp[1])
		proxyConn.Close()
		return nil, fmt.Errorf("proxy connect command failed with code %d", finalResp[1])
	}
	c.logInfo("DEBUG: Proxy connect command successful")
	// 忽略剩余的 BND.ADDR 和 BND.PORT
	// 这部分需要根据 ATYP 读取并丢弃
	if err := drainReply(proxyConn, finalResp[3]); err != nil {
		c.logInfo("DEBUG: Failed to drain final reply from proxy: %v", err)
		proxyConn.Close()
		return nil, fmt.Errorf("failed to drain final reply from proxy: %v", err)
	}
	c.logInfo("DEBUG: Proxy connection established successfully")

	return proxyConn, nil
}

// forwardUDPPacketViaProxy 通过另一个SOCKS5代理转发UDP数据包
func (c *Connection) forwardUDPPacketViaProxy(parentUdpConn *net.UDPConn, originalPacket *UDPPacket, originalClientAddr *net.UDPAddr, proxy *ProxyNode) error {
	c.logInfo("UDP-PROXY: Attempting to forward packet for %s via %s", originalClientAddr, proxy.Address)

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
	c.logInfo("UDP-PROXY: SOCKS5 handshake successful")

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
		c.logInfo("UDP-PROXY: Username/password authentication successful")
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

	c.logInfo("UDP-PROXY: UDP association established with proxy at %s", proxyUDPAddr)

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
			c.logInfo("UDP-PROXY: No response from proxy (timeout)")
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
		c.logInfo("UDP-PROXY: No data in response from proxy")
		return nil
	}

	// 打印代理响应日志
	c.logDebug("UDP-PROXY: Received %d bytes response from proxy %s:%d",
		len(responseData), proxyUDPAddr.IP.String(), proxyUDPAddr.Port)

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

	c.logDebug("UDP-PROXY: Response sent to client (%d bytes)", len(clientReply))
	c.logInfo("UDP-PROXY: Successfully forwarded UDP packet via proxy %s", proxy.Name)
	return nil
}

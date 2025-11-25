package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
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
	REP_SUCCESS              = 0x00
	REP_GENERAL_FAILURE      = 0x01
	REP_CONNECTION_FORBIDDEN = 0x02
	REP_NETWORK_UNREACHABLE  = 0x03
	REP_HOST_UNREACHABLE     = 0x04
	REP_CONNECTION_REFUSED   = 0x05
	REP_TTL_EXPIRED          = 0x06
	REP_COMMAND_NOT_SUPPORTED = 0x07
	REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08
)

// Logger 日志接口
type Logger interface {
	Printf(format string, v ...interface{})
	Print(v ...interface{})
}

// SOCKS5Server SOCKS5 服务器
type SOCKS5Server struct {
	listener    net.Listener
	wg          sync.WaitGroup
	logger      *log.Logger
	router      *Router
	detector    *TrafficDetector
	configPath  string
	rateLimiter *RateLimiter
	authManager *AuthManager
}

type Connection struct {
	clientConn net.Conn
	targetConn net.Conn
	logger     *log.Logger
	server     *SOCKS5Server
	username   string    // 认证用户名，空表示未认证
	targetAddr  string    // 目标地址 (host:port)
	targetHost  string    // 目标主机名
	detectedHost string   // 检测到的主机名 (HTTP Host或HTTPS SNI)
	protocol    string    // 协议类型 (HTTP/HTTPS/Unknown)
}

func NewSOCKS5Server(port int) (*SOCKS5Server, error) {
	return NewSOCKS5ServerWithConfig(port, "conf/config.json")
}

func NewSOCKS5ServerWithConfig(port int, configPath string) (*SOCKS5Server, error) {
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on port %d: %v", port, err)
	}

	// 创建 logger
	logger := log.New(os.Stdout, "[SOCKS5] ", log.LstdFlags)

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

	server := &SOCKS5Server{
		listener:    listener,
		logger:      logger,
		router:      router,
		detector:    detector,
		configPath:  configPath,
		rateLimiter: rateLimiter,
		authManager: authManager,
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

func (s *SOCKS5Server) Start() error {
	s.logger.Printf("SOCKS5 server started on %s", s.listener.Addr())

	for {
		clientConn, err := s.listener.Accept()
		if err != nil {
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

	conn := &Connection{
		clientConn: clientConn,
		logger:     s.logger,
		server:     s,
	}

	s.logger.Printf("New connection from %s", clientConn.RemoteAddr())

	// 认证协商
	if err := conn.handleAuthentication(); err != nil {
		s.logger.Printf("Authentication failed: %v", err)
		return
	}

	// 处理连接请求
	if err := conn.handleRequest(); err != nil {
		s.logger.Printf("Request failed: %v", err)
		return
	}
}


func (c *Connection) handleRequest() error {
	// 读取请求头
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

	// 解析目标地址
	var targetAddr string
	var targetPort uint16

	switch atype {
	case ATYPE_IPV4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c.clientConn, addr); err != nil {
			return fmt.Errorf("failed to read IPv4 address: %v", err)
		}
		targetAddr = net.IP(addr).String()

	case ATYPE_IPV6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(c.clientConn, addr); err != nil {
			return fmt.Errorf("failed to read IPv6 address: %v", err)
		}
		targetAddr = net.IP(addr).String()

	case ATYPE_DOMAIN:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(c.clientConn, lenByte); err != nil {
			return fmt.Errorf("failed to read domain length: %v", err)
		}

		domainLen := int(lenByte[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(c.clientConn, domain); err != nil {
			return fmt.Errorf("failed to read domain: %v", err)
		}
		targetAddr = string(domain)

	default:
		return c.sendReply(REP_ADDRESS_TYPE_NOT_SUPPORTED, "127.0.0.1", 1080)
	}

	// 读取端口
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(c.clientConn, portBytes); err != nil {
		return fmt.Errorf("failed to read port: %v", err)
	}
	targetPort = binary.BigEndian.Uint16(portBytes)

	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

	// 设置连接的目标信息
	c.targetAddr = target

	// 从目标地址中提取主机名
	if host, _, err := net.SplitHostPort(targetAddr); err == nil {
		c.targetHost = host
	} else {
		c.targetHost = targetAddr
	}

	// 记录连接请求（包含用户信息）
	clientInfo := c.getClientInfo()
	c.logger.Printf("Connection request: %s -> %s (%s)", clientInfo, target, c.targetHost)

	// 尝试检测流量特征（如果连接建立了，在这里我们可以读取一些初始数据）
	// 注意：这里我们暂时不进行实际的流量检测，因为我们还没有建立到目标的连接
	// 实际的流量检测将在数据转发阶段进行

	// 路由检查和访问控制
	if c.server.router != nil {
		// 检查是否被屏蔽
		if c.server.router.ShouldBlock(targetAddr, int(targetPort)) {
			accessInfo := c.getAccessInfo()
			c.logger.Printf("BLOCKED by ACL: %s -> %s (%s)", accessInfo, target, c.targetHost)
			return c.sendReply(REP_CONNECTION_FORBIDDEN, "127.0.0.1", 1080)
		}

		// 记录路由决策
		accessInfo := c.getAccessInfo()
		if c.server.router.ShouldDirect(targetAddr, int(targetPort)) {
			c.logger.Printf("DIRECT (China/local): %s -> %s (%s)", accessInfo, target, c.targetHost)
		} else {
			c.logger.Printf("PROXY (Foreign): %s -> %s (%s)", accessInfo, target, c.targetHost)
		}
	}

	// 连接目标服务器
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		accessInfo := c.getAccessInfo()
		c.logger.Printf("FAILED to connect: %s -> %s (%s): %v", accessInfo, target, c.targetHost, err)
		return c.sendReply(REP_HOST_UNREACHABLE, "127.0.0.1", 1080)
	}
	defer targetConn.Close()

	c.targetConn = targetConn

	// 发送成功回复
	if err := c.sendReply(REP_SUCCESS, "0.0.0.0", 0); err != nil {
		accessInfo := c.getAccessInfo()
		c.logger.Printf("Failed to send success reply for %s: %v", accessInfo, err)
		return fmt.Errorf("failed to send success reply: %v", err)
	}

	accessInfo := c.getAccessInfo()
	c.logger.Printf("CONNECTED: %s -> %s (%s)", accessInfo, target, c.targetHost)

	// 开始数据转发
	return c.relay()
}

func (c *Connection) sendReply(rep byte, bindAddr string, bindPort int) error {
	response := []byte{SOCKS5_VERSION, rep, 0x00, ATYPE_IPV4}

	// 添加绑定地址 (IPv4)
	ip := net.ParseIP(bindAddr)
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0)
	}
	response = append(response, ip.To4()...)

	// 添加绑定端口
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(bindPort))
	response = append(response, portBytes...)

	_, err := c.clientConn.Write(response)
	return err
}

func (c *Connection) relay() error {
	done := make(chan error, 2)

	// 流量检测相关变量
	detectionDone := make(chan *DetectionResult, 1)

	// 客户端到目标（带流量检测）
	go func() {
		err := c.relayWithDetection()
		done <- err
	}()

	// 目标到客户端（带下载限速）
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := c.targetConn.Read(buf)
			if err != nil {
				done <- err
				return
			}

			// 应用下载限速
			if c.server.rateLimiter != nil {
				// 优先使用用户名限速，回退到IP地址限速
				rateLimitKey := c.getRateLimitKey()
				if !c.server.rateLimiter.CheckDownloadLimit(rateLimitKey, int64(n)) {
					// 超过限速，丢弃数据包
					c.logger.Printf("Download rate limit exceeded for %s, dropping %d bytes", rateLimitKey, n)
					continue
				}
			}

			// 转发数据到客户端
			if _, err := c.clientConn.Write(buf[:n]); err != nil {
				done <- err
				return
			}
		}
	}()

	// 处理流量检测结果（异步）
	go func() {
		if result := <-detectionDone; result != nil {
			c.logger.Printf("Traffic detected: Type=%s, Host=%s, Method=%s, SNI=%s",
				result.Type.String(), result.Hostname, result.Method, result.SNI)

			// 如果检测到了主机名，可以基于此更新路由决策
			if result.Hostname != "" && c.server.router != nil {
				c.updateRoutingBasedOnDetection(result)
			}
		}
	}()

	// 等待任一方向的连接结束
	err := <-done
	c.logger.Printf("Connection closed: %v", err)

	return nil
}

// relayWithDetection 带流量检测的中继
func (c *Connection) relayWithDetection() error {
	buf := make([]byte, 4096)
	detectionPerformed := false

	for {
		n, err := c.clientConn.Read(buf)
		if err != nil {
			return err
		}

		// 只对前几个数据包进行检测
		if !detectionPerformed && c.server.detector != nil {
			result := c.server.detector.DetectTraffic(buf[:n])
			if result != nil && result.Type != TrafficTypeUnknown {
				// 异步发送检测结果
				go func(r *DetectionResult) {
					// 增强日志：包含用户信息和目标信息
					clientInfo := c.getClientInfo()
					c.logger.Printf("Traffic detected: %s %s -> %s | User: %s | Target: %s (%s) | Method: %s",
						r.Type.String(), r.Hostname, c.targetHost,
						clientInfo, c.targetAddr, c.detectedHost, r.Method)
				}(result)
				detectionPerformed = true
			}
		}

		// 应用上传限速
		if c.server.rateLimiter != nil {
			// 优先使用用户名限速，回退到IP地址限速
			rateLimitKey := c.getRateLimitKey()
			if !c.server.rateLimiter.CheckUploadLimit(rateLimitKey, int64(n)) {
				// 超过限速，丢弃数据包
				c.logger.Printf("Upload rate limit exceeded for %s, dropping %d bytes", rateLimitKey, n)
				continue
			}
		}

		// 转发数据到目标
		if _, err := c.targetConn.Write(buf[:n]); err != nil {
			return err
		}
	}
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
		c.logger.Printf("User authenticated: %s (%s)", username, c.getClientInfo())
	} else {
		c.logger.Printf("Anonymous connection (%s)", c.getClientInfo())
	}

	return nil
}

// updateRoutingBasedOnDetection 基于检测结果更新路由
func (c *Connection) updateRoutingBasedOnDetection(result *DetectionResult) {
	// 这里可以根据检测结果动态调整路由策略
	// 例如，如果检测到特定的Host，可以调整QoS或监控策略

	if result.Type == TrafficTypeHTTP {
		// HTTP 流量的特殊处理
		clientInfo := c.getClientInfo()
		c.logger.Printf("HTTP traffic detected for host: %s | User: %s | Target: %s (%s)",
			result.Hostname, clientInfo, c.targetAddr, c.targetHost)
	} else if result.Type == TrafficTypeHTTPS && result.SNI != "" {
		// HTTPS 流量的 SNI 处理
		clientInfo := c.getClientInfo()
		c.logger.Printf("HTTPS SNI detected: %s | User: %s | Target: %s (%s)",
			result.SNI, clientInfo, c.targetAddr, c.targetHost)
	}
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


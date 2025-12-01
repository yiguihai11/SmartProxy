package socks5

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
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
	probingPorts []int
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
}

func NewSOCKS5Server(port int) (*SOCKS5Server, error) {
	return NewSOCKS5ServerWithConfig(port, "conf/config.json", nil)
}

func NewSOCKS5ServerWithConfig(port int, configPath string, probingPorts []int) (*SOCKS5Server, error) {
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
		probingPorts: probingPorts,
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

	// 根据端口决定使用哪种路由逻辑
	if c.server.isProbingPort(int(targetPort)) {
		// 对指定端口执行新的、复杂的路由和回退逻辑
		c.logger.Printf("Port %d is a probing port, using advanced routing.", targetPort)
		return c.executeAdvancedRouting(targetAddr, targetPort)
	} else {
		// 对其他端口执行旧的、简单的路由逻辑
		return c.simpleConnectAndRelay(targetAddr, targetPort)
	}
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
		// 📡 在转发时也检测SNI/Host，解决代理转发盲区问题
		if result := c.server.detector.DetectTraffic(buf[:n]); result != nil && result.Type != TrafficTypeUnknown {
			// 🔄 检测到真实主机名，更新路由策略
			if result.Hostname != "" && result.Hostname != c.targetHost {
				c.logger.Printf("Enhanced detection in relay: real host=%s, switching route", result.Hostname)
	
				c.detectedHost = result.Hostname
			}
		}

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

// simpleConnectAndRelay 执行简化的连接和转发逻辑
func (c *Connection) simpleConnectAndRelay(targetAddr string, targetPort uint16) error {
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

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

// executeAdvancedRouting 执行包含嗅探和回退的复杂路由逻辑
func (c *Connection) executeAdvancedRouting(targetAddr string, targetPort uint16) error {
	var finalTargetConn net.Conn
	var err error

	// 1. 执行“检测前”路由匹配
	result := c.server.router.matchRulePreDetection(targetAddr, int(targetPort))

	switch result.Action {
	case ActionBlock:
		// 规则要求阻止
		accessInfo := c.getAccessInfo()
		c.logger.Printf("BLOCKED by pre-detection rule: %s -> %s:%d", accessInfo, targetAddr, targetPort)
		return c.sendReply(REP_CONNECTION_FORBIDDEN, "127.0.0.1", 1080)

	case ActionProxy:
		// 规则要求走代理
		accessInfo := c.getAccessInfo()
		proxy := c.server.router.GetProxyNode(result.ProxyNode)
		if proxy == nil {
			c.logger.Printf("Proxy node '%s' not found, falling back to default proxy", result.ProxyNode)
			proxy = c.server.router.GetDefaultProxy()
		}
		c.logger.Printf("PROXY by pre-detection rule: %s -> %s:%d via %s", accessInfo, targetAddr, targetPort, proxy.Name)
		finalTargetConn, err = c.connectThroughProxy(proxy, targetAddr, targetPort)

	case ActionAllow:
		// 规则要求直连
		fallthrough // 执行与默认行为相同的逻辑
	default:
		// 默认行为：尝试直连，并根据嗅探结果决定是否回退
		accessInfo := c.getAccessInfo()
		c.logger.Printf("ALLOW by pre-detection rule (or default): %s -> %s:%d", accessInfo, targetAddr, targetPort)
		finalTargetConn, err = c.attemptDirectAndSniff(targetAddr, targetPort)
	}

	// 3. 处理连接结果
	if err != nil {
		// 所有连接尝试都失败了
		accessInfo := c.getAccessInfo()
		c.logger.Printf("ALL attempts FAILED for %s -> %s:%d: %v", accessInfo, targetAddr, targetPort, err)
		// 根据错误类型发送更具体的回应
		// (为了简化，这里统一发送 Host Unreachable)
		return c.sendReply(REP_HOST_UNREACHABLE, "127.0.0.1", 1080)
	}
	defer finalTargetConn.Close()

	c.targetConn = finalTargetConn

	// 4. 发送成功回复并开始转发
	if err := c.sendReply(REP_SUCCESS, "0.0.0.0", 0); err != nil {
		return fmt.Errorf("failed to send success reply: %v", err)
	}

	c.logger.Printf("CONNECTED: %s -> %s:%d", c.getAccessInfo(), targetAddr, targetPort)
	return c.relay()
}

// connectThroughProxy 通过指定的代理节点建立连接
func (c *Connection) connectThroughProxy(proxy *ProxyNode, targetAddr string, targetPort uint16) (net.Conn, error) {
	if proxy == nil {
		return nil, fmt.Errorf("proxy node is nil")
	}

	// 1. 连接到代理服务器
	proxyConn, err := net.DialTimeout("tcp", proxy.Address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy '%s' at %s: %v", proxy.Name, proxy.Address, err)
	}

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
		proxyConn.Close()
		return nil, fmt.Errorf("failed to read handshake reply from proxy: %v", err)
	}
	if resp[0] != SOCKS5_VERSION || resp[1] != authMethod {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy handshake failed, unsupported auth method")
	}

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
		proxyConn.Close()
		return nil, fmt.Errorf("failed to send connect request to proxy: %v", err)
	}

	// 5. 读取代理的最终回复
	finalResp := make([]byte, 4) // VER, REP, RSV, ATYP
	if _, err := io.ReadFull(proxyConn, finalResp); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("failed to read final reply from proxy: %v", err)
	}
	if finalResp[0] != SOCKS5_VERSION || finalResp[1] != REP_SUCCESS {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy connect command failed with code %d", finalResp[1])
	}
	// 忽略剩余的 BND.ADDR 和 BND.PORT
	// 这部分需要根据 ATYP 读取并丢弃
	if err := drainReply(proxyConn, finalResp[3]); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("failed to drain final reply from proxy: %v", err)
	}

	return proxyConn, nil
}

// attemptDirectAndSniff 尝试直接连接、嗅探，并在需要时执行回退
func (c *Connection) attemptDirectAndSniff(targetAddr string, targetPort uint16) (net.Conn, error) {
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

	// 1. 尝试直接连接
	c.logger.Printf("Attempting direct connection to %s", target)
	directConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		// 直连失败，触发回退
		c.logger.Printf("Direct connection to %s failed (%v), falling back to default proxy.", target, err)
		defaultProxy := c.server.router.GetDefaultProxy()
		if defaultProxy == nil {
			return nil, fmt.Errorf("direct connection failed and no default proxy available for fallback")
		}
		return c.connectThroughProxy(defaultProxy, targetAddr, targetPort)
	}

	// 2. 嗅探 SNI/Host
	// 使用 bufio.Reader 来 'Peek' 数据而不是直接读取，这样不会消耗掉客户端连接中的数据
	br := bufio.NewReader(c.clientConn)
	// 假设 TLS Client Hello 不会超过 4k
	peekedData, err := br.Peek(4096)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		// Peek 失败，无法嗅探。关闭直连并回退
		directConn.Close()
		c.logger.Printf("Failed to peek initial data for SNI sniffing (%v), falling back to default proxy.", err)
		defaultProxy := c.server.router.GetDefaultProxy()
		if defaultProxy == nil {
			return nil, fmt.Errorf("SNI sniffing failed and no default proxy available for fallback")
		}
		return c.connectThroughProxy(defaultProxy, targetAddr, targetPort)
	}

	result := c.server.detector.DetectTraffic(peekedData)
	detectedHost := result.Hostname
	if result.Type == TrafficTypeHTTPS && result.SNI != "" {
		detectedHost = result.SNI
	}

	// 3. 根据嗅探结果再路由
	if detectedHost == "" {
		// 无法从流量中识别主机名，保持直连
		c.logger.Printf("SNI/Host not detected in initial packet, keeping direct connection to %s", target)
		return directConn, nil
	}

	c.detectedHost = detectedHost
	c.logger.Printf("SNI/Host '%s' detected for connection to %s", detectedHost, target)
	postResult := c.server.router.matchRulePostDetection(detectedHost)

	if !postResult.Match {
		// 没有匹配到任何“检测后”规则，保持直连
		c.logger.Printf("No post-detection rule matched for '%s', keeping direct connection.", detectedHost)
		return directConn, nil
	}

	switch postResult.Action {
	case ActionAllow:
		// 规则仍然是直连，路由一致
		c.logger.Printf("Post-detection rule for '%s' is ALLOW, keeping direct connection.", detectedHost)
		return directConn, nil
	case ActionBlock:
		// 规则要求阻止，关闭直连并返回错误
		c.logger.Printf("Post-detection rule for '%s' is BLOCK, closing connection.", detectedHost)
		directConn.Close()
		return nil, fmt.Errorf("blocked by post-detection rule for host '%s'", detectedHost)
	case ActionProxy:
		// 规则要求走代理，关闭直连并回退到指定代理
		c.logger.Printf("Post-detection rule for '%s' is PROXY, closing direct connection and falling back to proxy.", detectedHost)
		directConn.Close()
		proxy := c.server.router.GetProxyNode(postResult.ProxyNode)
		if proxy == nil {
			c.logger.Printf("Proxy node '%s' for post-detection rule not found, falling back to default proxy", postResult.ProxyNode)
			proxy = c.server.router.GetDefaultProxy()
		}
		if proxy == nil {
			return nil, fmt.Errorf("post-detection rule requires proxy, but none is available")
		}
		return c.connectThroughProxy(proxy, targetAddr, targetPort)
	}

	return directConn, nil // 默认应不会到达这里
}

func getAddrSpec(addr string) (addrType byte, addrBody []byte, err error) {
	if ip := net.ParseIP(addr); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ATYPE_IPV4, ipv4, nil
		}
		return ATYPE_IPV6, ip, nil
	}
	if len(addr) > 255 {
		return 0, nil, fmt.Errorf("domain name too long: %s", addr)
	}
	return ATYPE_DOMAIN, append([]byte{byte(len(addr))}, []byte(addr)...), nil
}

func drainReply(r io.Reader, atyp byte) error {
	var readLen int
	switch atyp {
	case ATYPE_IPV4:
		readLen = net.IPv4len + 2 // 4 bytes for IP, 2 for port
	case ATYPE_IPV6:
		readLen = net.IPv6len + 2 // 16 bytes for IP, 2 for port
	case ATYPE_DOMAIN:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(r, lenByte); err != nil {
			return err
		}
		readLen = int(lenByte[0]) + 2 // domain length + 2 bytes for port
	default:
		return fmt.Errorf("unsupported address type: %d", atyp)
	}

	if _, err := io.CopyN(ioutil.Discard, r, int64(readLen)); err != nil {
		return err
	}
	return nil
}



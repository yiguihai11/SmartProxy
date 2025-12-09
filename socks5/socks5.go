package socks5

import (
	"bufio"
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

// BufferedConn is a net.Conn that allows peeking and then reading the peeked data.
type BufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// NewBufferedConn creates a new BufferedConn.
func NewBufferedConn(conn net.Conn) *BufferedConn {
	return &BufferedConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

// Read reads data from the connection. It will first read from the buffer if data has been peeked.
func (b *BufferedConn) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

// Peek peeks at the connection's data.
func (b *BufferedConn) Peek(n int) ([]byte, error) {
	return b.reader.Peek(n)
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

	target := formatNetworkAddress(targetAddr, targetPort)

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

	// 统一使用高级路由逻辑，实现全面的连接失败回退功能
	return c.executeAdvancedRouting(targetAddr, targetPort)
}

func (c *Connection) sendReply(rep byte, bindAddr string, bindPort int) error {
	// 1. 获取服务器的实际监听地址
	listenAddr, ok := c.server.listener.Addr().(*net.TCPAddr)
	if !ok {
		// 如果不是TCPAddr，或有其他问题，使用一个安全的回退值
		// 理论上在我们的场景中这不应该发生
		c.logger.Printf("Could not assert listener address to TCPAddr")
		fallbackIP := net.IPv4(0, 0, 0, 0)
		response := []byte{SOCKS5_VERSION, rep, 0x00, ATYPE_IPV4}
		response = append(response, fallbackIP.To4()...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(0))
		response = append(response, portBytes...)
		_, err := c.clientConn.Write(response)
		return err
	}

	// 2. 准备地址和端口
	var addrType byte
	var addrBody []byte
	addrIP := listenAddr.IP

	if ipv4 := addrIP.To4(); ipv4 != nil {
		addrType = ATYPE_IPV4
		addrBody = ipv4
	} else if ipv6 := addrIP.To16(); ipv6 != nil {
		addrType = ATYPE_IPV6
		addrBody = ipv6
	} else {
		// 如果地址既不是IPv4也不是IPv6（例如，未指定），则回退
		addrType = ATYPE_IPV4
		addrBody = net.IPv4(0, 0, 0, 0).To4()
	}

	// 3. 构建回复
	// [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
	response := []byte{SOCKS5_VERSION, rep, 0x00, addrType}
	response = append(response, addrBody...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(listenAddr.Port))
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

// relayClientToTarget 处理客户端到目标的数据流，支持动态代理切换
func (c *Connection) relayClientToTarget(ctx context.Context, done chan error) {
	buf := bufferPool.Get()
	defer bufferPool.Put(buf)
	detectionDone := false
	pendingData := []byte{}
	lastDataTransferTime := time.Now()

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

		// 记录数据传输时间
		lastDataTransferTime = time.Now()

		// 只对前几个数据包进行SNI/Host检测
		if !detectionDone {
			if detectedHost := c.detectHostnameFromData(buf[:n]); detectedHost != "" {
				c.detectedHost = detectedHost
				detectionDone = true

				// 检查PostDetection规则
				if newProxy, err := c.checkProxySwitch(detectedHost); err != nil {
					// Block规则或其他错误情况，终止连接
					c.logger.Printf("Connection blocked by post-detection rule: %v", err)
					done <- err
					return
				} else if newProxy != nil {
					// 需要切换到代理
					if newConn, switchErr := c.switchToProxy(newProxy, pendingData, buf[:n]); switchErr == nil {
						c.targetConn.Close()
						c.targetConn = newConn
						c.logger.Printf("Switched to proxy %s based on host %s", newProxy.Name, detectedHost)
						pendingData = []byte{}
					} else {
						c.logger.Printf("Failed to switch proxy: %v", switchErr)
						done <- switchErr
						return
					}
				}
				// ActionAllow或未匹配规则：继续当前连接方式
			}
		}

		// 应用上传限速
		if !c.applyUploadRateLimit(int64(n)) {
			continue // 超过限速，丢弃数据
		}

		// 转发数据到目标，并检测可能的GFW干扰
		if _, err := c.targetConn.Write(buf[:n]); err != nil {
			// 检测是否是GFW重置
			if c.isGFWDetected(err) {
				c.logger.Printf("GFW reset detected during data transfer, switching to proxy")
				// 触发动态代理切换
				defaultProxy := c.server.router.GetDefaultProxy()
				if defaultProxy != nil {
					newConn, switchErr := c.switchToProxy(defaultProxy, pendingData, buf[:n])
					if switchErr == nil {
						c.targetConn.Close()
						c.targetConn = newConn
						c.logger.Printf("Switched to default proxy due to GFW reset")
						pendingData = []byte{}
					} else {
						c.logger.Printf("Failed to switch to proxy due to GFW reset: %v", switchErr)
						done <- switchErr
						return
					}
				} else {
					c.logger.Printf("No default proxy available for GFW reset fallback")
					done <- err
					return
				}
			} else {
				done <- err
				return
			}
		}

		// 检测数据传输响应（检测无响应的超时情况）
		if err := c.checkDataTransferTimeout(lastDataTransferTime); err != nil {
			c.logger.Printf("Data transfer timeout detected, switching to proxy")
			defaultProxy := c.server.router.GetDefaultProxy()
			if defaultProxy != nil {
				newConn, switchErr := c.switchToProxy(defaultProxy, pendingData, buf[:n])
				if switchErr == nil {
					c.targetConn.Close()
					c.targetConn = newConn
					c.logger.Printf("Switched to default proxy due to transfer timeout")
					pendingData = []byte{}
				} else {
					c.logger.Printf("Failed to switch to proxy due to timeout: %v", switchErr)
					done <- switchErr
					return
				}
			} else {
				c.logger.Printf("No default proxy available for timeout fallback")
				done <- err
				return
			}
		}

		// 保存未决数据用于可能的代理切换
		if !detectionDone {
			pendingData = append(pendingData, buf[:n]...)
			// 限制pending data大小
			if len(pendingData) > 8192 {
				pendingData = pendingData[len(pendingData)-4096:]
			}
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
			done <- err
			return
		}

		// DEBUG: 记录收到的数据
		if n > 0 {
			c.logger.Printf("DEBUG: Received %d bytes from target: %x", n, buf[:min(n, 32)])
			// 如果数据很短，尝试转换为字符串
			if n <= 16 {
				c.logger.Printf("DEBUG: Data as string: %q", string(buf[:n]))
			}
		}

		// 应用下载限速
		if !c.applyDownloadRateLimit(int64(n)) {
			continue // 超过限速，丢弃数据
		}

		// 转发数据到客户端
		if _, err := c.clientConn.Write(buf[:n]); err != nil {
			done <- err
			return
		}
	}
}

// detectHostnameFromData 从数据中检测主机名
func (c *Connection) detectHostnameFromData(data []byte) string {
	if c.server.detector == nil {
		return ""
	}

	result := c.server.detector.DetectTraffic(data)
	if result == nil {
		return ""
	}

	// 优先使用SNI，其次使用HTTP Host
	if result.Type == TrafficTypeHTTPS && result.SNI != "" {
		return result.SNI
	}

	if result.Type == TrafficTypeHTTP && result.Hostname != "" {
		return result.Hostname
	}

	return ""
}

// checkProxySwitch 检查PostDetection规则并返回处理结果
func (c *Connection) checkProxySwitch(hostname string) (*ProxyNode, error) {
	if c.server.router == nil {
		return nil, nil
	}

	postResult := c.server.router.matchRulePostDetection(hostname)
	if !postResult.Match {
		return nil, nil
	}

	accessInfo := c.getAccessInfo()

	switch postResult.Action {
	case ActionBlock:
		// 规则要求阻止连接
		c.logger.Printf("BLOCKED by post-detection rule: %s (detected: %s)", accessInfo, hostname)
		return nil, fmt.Errorf("connection blocked by rule for host %s", hostname)

	case ActionProxy:
		// 规则要求走指定代理节点
		if postResult.ProxyNodeSpecified {
			proxy := c.server.router.GetProxyNode(postResult.ProxyNode)
			if proxy != nil {
				c.logger.Printf("PROXY by post-detection rule: %s (detected: %s) via %s", accessInfo, hostname, proxy.Name)
				return proxy, nil
			} else {
				c.logger.Printf("Proxy node '%s' not found for host %s, falling back to default proxy", postResult.ProxyNode, hostname)
			}
		}
		// 如果没有指定代理节点或指定的节点不存在，使用默认代理
		defaultProxy := c.server.router.GetDefaultProxy()
		if defaultProxy != nil {
			c.logger.Printf("PROXY by post-detection rule: %s (detected: %s) via default proxy %s", accessInfo, hostname, defaultProxy.Name)
			return defaultProxy, nil
		}
		c.logger.Printf("PROXY rule matched but no proxy available for host %s", hostname)
		return nil, fmt.Errorf("no proxy available for host %s", hostname)

	case ActionDeny:
		// 规则要求走代理 (deny在配置中表示走代理)
		defaultProxy := c.server.router.GetDefaultProxy()
		if defaultProxy != nil {
			c.logger.Printf("DENY by post-detection rule, using proxy: %s (detected: %s) via %s", accessInfo, hostname, defaultProxy.Name)
			return defaultProxy, nil
		}
		c.logger.Printf("DENY rule matched but no default proxy available for host %s", hostname)
		return nil, fmt.Errorf("no default proxy available for host %s", hostname)

	case ActionAllow:
		// 规则要求直连，不需要切换代理
		c.logger.Printf("ALLOW by post-detection rule: %s (detected: %s) - direct connection", accessInfo, hostname)
		return nil, nil
	}

	return nil, nil
}

// switchToProxy 切换到指定的代理
func (c *Connection) switchToProxy(proxy *ProxyNode, pendingData, currentData []byte) (net.Conn, error) {
	// 解析目标地址和端口
	targetHost, targetPort, err := net.SplitHostPort(c.targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target address: %v", err)
	}

	port, err := strconv.Atoi(targetPort)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target port: %v", err)
	}

	// 合并待发送的数据
	allData := append(pendingData, currentData...)

	// 通过代理建立连接
	return c.connectThroughProxyWithData(proxy, targetHost, uint16(port), allData)
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
		// 规则要求走指定代理节点
		accessInfo := c.getAccessInfo()
		proxy := c.server.router.GetProxyNode(result.ProxyNode)
		if proxy == nil {
			c.logger.Printf("Proxy node '%s' not found, falling back to default proxy", result.ProxyNode)
			proxy = c.server.router.GetDefaultProxy()
		}
		c.logger.Printf("PROXY by specific rule: %s -> %s:%d via %s", accessInfo, targetAddr, targetPort, proxy.Name)
		finalTargetConn, err = c.connectThroughProxy(proxy, targetAddr, targetPort)

	case ActionDeny:
		// 规则要求走代理 (deny在配置中表示走代理)
		accessInfo := c.getAccessInfo()
		defaultProxy := c.server.router.GetDefaultProxy()
		if defaultProxy == nil {
			c.logger.Printf("DENY rule matched but no default proxy available for %s -> %s:%d", accessInfo, targetAddr, targetPort)
			return c.sendReply(REP_GENERAL_FAILURE, "127.0.0.1", 1080)
		}
		c.logger.Printf("DENY by pre-detection rule, using proxy: %s -> %s:%d via %s", accessInfo, targetAddr, targetPort, defaultProxy.Name)
		finalTargetConn, err = c.connectThroughProxy(defaultProxy, targetAddr, targetPort)

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
	return c.connectThroughProxyWithData(proxy, targetAddr, targetPort, nil)
}

// connectThroughProxyWithData 通过指定的代理节点建立连接，并转发已读取的客户端数据
func (c *Connection) connectThroughProxyWithData(proxy *ProxyNode, targetAddr string, targetPort uint16, clientData []byte) (net.Conn, error) {
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

	// 如果有客户端数据需要转发，立即写入代理连接
	if len(clientData) > 0 {
		if _, err := proxyConn.Write(clientData); err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("failed to write client data to proxy: %v", err)
		}
		c.logger.Printf("DEBUG: Forwarded %d bytes of client data to proxy", len(clientData))
	}

	return proxyConn, nil
}

// attemptDirectAndSniff 智能连接：并行尝试直连和代理，选择最优路径
func (c *Connection) attemptDirectAndSniff(targetAddr string, targetPort uint16) (net.Conn, error) {
	// 使用智能连接选择最优路径
	conn, connType, proxyNode, err := c.selectOptimalConnection(targetAddr, targetPort)
	if err != nil {
		return nil, err
	}

	// 记录连接类型
	c.logConnectionChoice(connType, proxyNode, targetAddr, targetPort)

	return conn, nil
}

// selectOptimalConnection 选择最优连接路径
func (c *Connection) selectOptimalConnection(targetAddr string, targetPort uint16) (net.Conn, string, *ProxyNode, error) {
	target := formatNetworkAddress(targetAddr, targetPort)

	// 首先检查预检测路由规则，如果明确要求直连，则直接直连
	if c.server.router != nil {
		result := c.server.router.matchRulePreDetection(targetAddr, int(targetPort))
		if result.Match && result.Action == ActionAllow {
			// 规则明确要求直连，不进行智能探测
			conn, err := net.DialTimeout("tcp", target, 5*time.Second)
			return conn, "direct", nil, err
		}
	}

	// 如果未启用智能代理，使用简单直连
	if !c.server.smartProxyEnabled || !c.server.isProbingPort(int(targetPort)) {
		conn, err := net.DialTimeout("tcp", target, 5*time.Second)
		return conn, "direct", nil, err
	}

	// 并行尝试直连和代理
	return c.tryParallelConnections(targetAddr, targetPort)
}

// tryParallelConnections 并行尝试直连和代理连接
func (c *Connection) tryParallelConnections(targetAddr string, targetPort uint16) (net.Conn, string, *ProxyNode, error) {
	directResult := make(chan *connectionAttempt, 1)
	proxyResult := make(chan *connectionAttempt, 1)

	// 并行启动连接尝试
	go c.tryDirectConnection(targetAddr, targetPort, directResult)
	go c.tryProxyConnection(targetAddr, targetPort, proxyResult)

	// 等待第一个成功的连接
	timeout := time.After(2 * time.Second)

	for {
		select {
		case result := <-directResult:
			if result.success {
				return result.conn, "direct", nil, nil
			}
		case result := <-proxyResult:
			if result.success {
				return result.conn, "proxy", result.proxy, nil
			}
		case <-timeout:
			// 检查是否有部分结果
			select {
			case result := <-proxyResult:
				if result.success {
					return result.conn, "proxy", result.proxy, nil
				}
			default:
				return nil, "", nil, fmt.Errorf("all connection attempts failed")
			}
		}
	}
}

// connectionAttempt 连接尝试结果
type connectionAttempt struct {
	conn    net.Conn
	proxy   *ProxyNode
	success bool
	err     error
}

// tryDirectConnection 尝试直连
func (c *Connection) tryDirectConnection(targetAddr string, targetPort uint16, resultChan chan *connectionAttempt) {
	target := formatNetworkAddress(targetAddr, targetPort)
	timeout := time.Duration(c.server.smartProxyTimeoutMs) * time.Millisecond

	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		c.logger.Printf("Direct connection to %s failed: %v", target, err)
		if c.server.blacklist != nil {
			c.server.blacklist.Add(targetAddr)
		}
		resultChan <- &connectionAttempt{success: false, err: err}
		return
	}

	c.logger.Printf("Direct connection to %s established", target)
	resultChan <- &connectionAttempt{success: true, conn: conn}
}

// tryProxyConnection 尝试代理连接
func (c *Connection) tryProxyConnection(targetAddr string, targetPort uint16, resultChan chan *connectionAttempt) {
	proxy := c.server.router.GetDefaultProxy()
	if proxy == nil {
		resultChan <- &connectionAttempt{success: false, err: fmt.Errorf("no proxy available")}
		return
	}

	conn, err := c.connectThroughProxy(proxy, targetAddr, targetPort)
	if err != nil {
		c.logger.Printf("Proxy connection through %s failed: %v", proxy.Name, err)
		resultChan <- &connectionAttempt{success: false, err: err}
		return
	}

	c.logger.Printf("Proxy connection through %s established", proxy.Name)
	resultChan <- &connectionAttempt{success: true, conn: conn, proxy: proxy}
}

// isGFWDetected 传输层系统错误码检测 + 应用层字符串检测
func (c *Connection) isGFWDetected(err error) bool {
	if err == nil {
		return false
	}

	// 优先使用传输层系统错误码检测（更准确）
	if opErr, ok := err.(*net.OpError); ok {
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
			if errno, ok := sysErr.Err.(syscall.Errno); ok {
				// 系统错误码 104 = ECONNRESET = GFW重置
				if errno == syscall.ECONNRESET {
					c.logger.Printf("GFW reset detected by system error code: ECONNRESET(104)")
					return true
				}
				// 系统错误码 32 = EPIPE = 也是GFW重置的常见模式
				if errno == syscall.EPIPE {
					c.logger.Printf("GFW reset detected by system error code: EPIPE(32)")
					return true
				}
			}
		}
	}

	// 作为fallback，使用应用层字符串匹配
	if strings.Contains(err.Error(), "connection reset by peer") {
		c.logger.Printf("GFW reset detected by string matching")
		return true
	}

	return false
}

// checkDataTransferTimeout 检测数据传输超时
func (c *Connection) checkDataTransferTimeout(lastTransfer time.Time) error {
	timeoutDuration := time.Duration(c.server.smartProxyTimeoutMs) * time.Millisecond
	if time.Since(lastTransfer) > timeoutDuration {
		return fmt.Errorf("data transfer timeout after %v", timeoutDuration)
	}
	return nil
}

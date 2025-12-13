package socks5

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"smartproxy/logger"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProxyType 代理类型
type ProxyType string

const (
	ProxyTypeSOCKS5 ProxyType = "socks5"
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeHTTPS  ProxyType = "https"
	ProxyTypeSOCKS4 ProxyType = "socks4"
)

// ProxyNode 代理节点配置
type ProxyNode struct {
	Name        string    `json:"name"`
	Type        ProxyType `json:"type"`
	Address     string    `json:"address"`
	Enabled     bool      `json:"enabled"`
	Username    *string   `json:"username"`    // 使用指针区分空字符串和null
	Password    *string   `json:"password"`    // 使用指针区分空字符串和null
	AuthMethod  string    `json:"auth_method"` // "none", "userpass"
	Description string    `json:"description"`
}

// ProxyNodeHealth 代理节点健康状态
type ProxyNodeHealth struct {
	NodeName              string    // 节点名称
	ConsecutiveFailures   int       // 连续失败次数
	LastFailureTime       time.Time // 最后一次失败时间
	IsBlacklisted         bool      // 是否被拉黑
	BlacklistUntil        time.Time // 拉黑到期时间
	TotalConnections      int64     // 总连接次数
	SuccessfulConnections int64     // 成功连接次数
	LastSuccessTime       time.Time // 最后一次成功时间
	mu                    sync.RWMutex
}

// 常量配置
const (
	MaxConsecutiveFailures = 3               // 最大连续失败次数
	BlacklistDuration      = 5 * time.Minute // 拉黑持续时间
)

// ProxyNodes 代理节点管理器
type ProxyNodes struct {
	nodes          []ProxyNode
	mu             sync.RWMutex
	logger         *logger.SlogLogger
	healthMap      map[string]*ProxyNodeHealth // 节点健康状态映射
	healthMapMu    sync.RWMutex                // 健康状态映射锁
	cleanupTicker  *time.Ticker                // 定期清理过期的拉黑状态
	cleanupStopped chan struct{}               // 停止清理协程的信号
}

// NewProxyNodes 创建代理节点管理器
func NewProxyNodes(log *logger.SlogLogger) *ProxyNodes {
	if log == nil {
		log = logger.NewLogger().WithField("prefix", "[ProxyNodes]")
	}

	pn := &ProxyNodes{
		nodes:          make([]ProxyNode, 0),
		logger:         log,
		healthMap:      make(map[string]*ProxyNodeHealth),
		cleanupStopped: make(chan struct{}),
	}

	// 启动定期清理过期拉黑状态的协程
	pn.startCleanupRoutine()

	return pn
}

// LoadFromJSON 从JSON加载代理节点配置
func (pn *ProxyNodes) LoadFromJSON(jsonData []byte) error {
	pn.mu.Lock()
	defer pn.mu.Unlock()

	var nodes []ProxyNode
	if err := json.Unmarshal(jsonData, &nodes); err != nil {
		return fmt.Errorf("failed to parse proxy nodes JSON: %v", err)
	}

	// 验证配置
	for i, node := range nodes {
		if node.Name == "" {
			return fmt.Errorf("proxy node %d: name cannot be empty", i)
		}
		if node.Address == "" {
			return fmt.Errorf("proxy node %s: address cannot be empty", node.Name)
		}
		if !isValidProxyType(string(node.Type)) {
			return fmt.Errorf("proxy node %s: invalid type '%s'", node.Name, node.Type)
		}
	}

	pn.nodes = nodes
	pn.logger.Info("Loaded %d proxy nodes", len(nodes))

	return nil
}

// LoadNodes 直接加载代理节点切片
func (pn *ProxyNodes) LoadNodes(nodes []ProxyNode) error {
	pn.mu.Lock()
	defer pn.mu.Unlock()

	// 验证配置
	for i, node := range nodes {
		if node.Name == "" {
			return fmt.Errorf("proxy node %d: name cannot be empty", i)
		}
		if node.Address == "" {
			return fmt.Errorf("proxy node %s: address cannot be empty", node.Name)
		}
		if !isValidProxyType(string(node.Type)) {
			return fmt.Errorf("proxy node %s: invalid type '%s'", node.Name, node.Type)
		}
	}

	pn.nodes = nodes
	pn.logger.Info("Loaded %d proxy nodes", len(nodes))

	return nil
}

// GetDefaultProxy 获取默认代理节点
// 返回第一个启用且未被拉黑的代理节点，如果没有可用的则返回nil
func (pn *ProxyNodes) GetDefaultProxy() *ProxyNode {
	pn.mu.RLock()
	defer pn.mu.RUnlock()

	for _, node := range pn.nodes {
		if node.Enabled && pn.isNodeAvailable(node.Name) {
			return &node
		}
	}

	return nil
}

// GetProxyByName 根据名称获取代理节点
func (pn *ProxyNodes) GetProxyByName(name string) *ProxyNode {
	pn.mu.RLock()
	defer pn.mu.RUnlock()

	// 如果指定为空字符串，返回默认代理
	if name == "" {
		return pn.GetDefaultProxy()
	}

	for _, node := range pn.nodes {
		if node.Name == name && node.Enabled && pn.isNodeAvailable(node.Name) {
			return &node
		}
	}

	return nil
}

// GetEnabledProxies 获取所有启用的代理节点
func (pn *ProxyNodes) GetEnabledProxies() []ProxyNode {
	pn.mu.RLock()
	defer pn.mu.RUnlock()

	var enabled []ProxyNode
	for _, node := range pn.nodes {
		if node.Enabled {
			enabled = append(enabled, node)
		}
	}

	return enabled
}

// GetAvailableProxies 获取所有可用（启用且未被拉黑）的代理节点
func (pn *ProxyNodes) GetAvailableProxies() []ProxyNode {
	pn.mu.RLock()
	defer pn.mu.RUnlock()

	var available []ProxyNode
	for _, node := range pn.nodes {
		if node.Enabled && pn.isNodeAvailable(node.Name) {
			available = append(available, node)
		}
	}

	return available
}

// GetStats 获取代理节点统计信息
func (pn *ProxyNodes) GetStats() map[string]interface{} {
	pn.mu.RLock()
	defer pn.mu.RUnlock()

	stats := map[string]interface{}{
		"total":   len(pn.nodes),
		"enabled": 0,
		"nodes":   make([]map[string]interface{}, 0),
	}

	enabledCount := 0
	for _, node := range pn.nodes {
		// 获取节点健康状态
		healthStatus := pn.GetHealthStatus(node.Name)

		nodeInfo := map[string]interface{}{
			"name":                 node.Name,
			"type":                 node.Type,
			"address":              node.Address,
			"enabled":              node.Enabled,
			"auth_method":          node.AuthMethod,
			"consecutive_failures": healthStatus["consecutive_failures"],
			"is_blacklisted":       healthStatus["is_blacklisted"],
			"success_rate":         healthStatus["success_rate"],
			"total_connections":    healthStatus["total_connections"],
		}
		stats["nodes"] = append(stats["nodes"].([]map[string]interface{}), nodeInfo)

		if node.Enabled {
			enabledCount++
		}
	}

	stats["enabled"] = enabledCount

	// 添加整体健康状态统计
	pn.healthMapMu.RLock()
	healthyNodes := 0
	blacklistedNodes := 0
	totalConnections := int64(0)
	totalSuccessful := int64(0)

	for _, health := range pn.healthMap {
		health.mu.RLock()
		if !health.IsBlacklisted || time.Now().After(health.BlacklistUntil) {
			healthyNodes++
		}
		if health.IsBlacklisted {
			blacklistedNodes++
		}
		totalConnections += health.TotalConnections
		totalSuccessful += health.SuccessfulConnections
		health.mu.RUnlock()
	}
	pn.healthMapMu.RUnlock()

	stats["health"] = map[string]interface{}{
		"healthy_nodes":     healthyNodes,
		"blacklisted_nodes": blacklistedNodes,
		"total_connections": totalConnections,
		"total_successful":  totalSuccessful,
	}

	return stats
}

// isValidProxyType 检查代理类型是否有效
func isValidProxyType(proxyType string) bool {
	validTypes := []string{
		string(ProxyTypeSOCKS5),
		string(ProxyTypeHTTP),
		string(ProxyTypeHTTPS),
		string(ProxyTypeSOCKS4),
	}
	for _, validType := range validTypes {
		if proxyType == validType {
			return true
		}
	}
	return false
}

// ConnectToProxy 连接到代理服务器
func (pn *ProxyNodes) ConnectToProxy(proxyName, targetAddr string) (net.Conn, error) {
	proxy := pn.GetProxyByName(proxyName)
	if proxy == nil {
		return nil, fmt.Errorf("proxy node '%s' not found or disabled", proxyName)
	}

	// 检查节点是否被拉黑
	if !pn.isNodeAvailable(proxy.Name) {
		// 获取健康状态以提供更详细的错误信息
		healthStatus := pn.GetHealthStatus(proxy.Name)
		blacklistUntil := healthStatus["blacklist_until"].(string)
		return nil, fmt.Errorf("proxy node '%s' is blacklisted until %s due to connection failures",
			proxy.Name, blacklistUntil)
	}

	var conn net.Conn
	var err error

	// 根据代理类型进行连接
	switch proxy.Type {
	case ProxyTypeSOCKS5:
		conn, err = pn.connectSOCKS5(proxy, targetAddr)
	case ProxyTypeHTTP:
		conn, err = pn.connectHTTP(proxy, targetAddr)
	case ProxyTypeHTTPS:
		conn, err = pn.connectHTTPS(proxy, targetAddr)
	case ProxyTypeSOCKS4:
		conn, err = pn.connectSOCKS4(proxy, targetAddr)
	default:
		err = fmt.Errorf("unsupported proxy type: %s", proxy.Type)
	}

	// 记录连接结果
	if err != nil {
		pn.recordConnectionFailure(proxy.Name)
		return nil, err
	}

	pn.recordConnectionSuccess(proxy.Name)
	return conn, nil
}

// connectSOCKS5 连接SOCKS5代理
func (pn *ProxyNodes) connectSOCKS5(proxy *ProxyNode, targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxy.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy %s: %v", proxy.Address, err)
	}

	// SOCKS5握手
	if err := pn.performSOCKS5Handshake(conn, proxy); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed: %v", err)
	}

	// 建立连接
	if err := pn.performSOCKS5Connect(conn, targetAddr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed: %v", err)
	}

	return conn, nil
}

// performSOCKS5Handshake 执行SOCKS5握手
func (pn *ProxyNodes) performSOCKS5Handshake(conn net.Conn, proxy *ProxyNode) error {
	// 发送版本和认证方法
	authMethods := []byte{0x05} // SOCKS5版本
	if proxy.AuthMethod == "userpass" && proxy.Username != nil && proxy.Password != nil {
		authMethods = append(authMethods, 0x02) // 用户名密码认证
	} else {
		authMethods = append(authMethods, 0x00) // 无认证
	}

	handshake := []byte{0x05, byte(len(authMethods) - 1)}
	handshake = append(handshake, authMethods[1:]...)

	if _, err := conn.Write(handshake); err != nil {
		return err
	}

	// 读取响应
	response := make([]byte, 2)
	if _, err := conn.Read(response); err != nil {
		return err
	}

	if response[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS5 version: %d", response[0])
	}

	if response[1] == 0xFF {
		return fmt.Errorf("no acceptable authentication method")
	}

	// 如果需要用户名密码认证
	if response[1] == 0x02 && proxy.AuthMethod == "userpass" {
		return pn.performSOCKS5Auth(conn, proxy)
	}

	return nil
}

// performSOCKS5Auth 执行SOCKS5用户名密码认证
func (pn *ProxyNodes) performSOCKS5Auth(conn net.Conn, proxy *ProxyNode) error {
	username := *proxy.Username
	password := *proxy.Password

	// 构建认证请求
	authReq := []byte{0x01}
	authReq = append(authReq, byte(len(username)))
	authReq = append(authReq, []byte(username)...)
	authReq = append(authReq, byte(len(password)))
	authReq = append(authReq, []byte(password)...)

	if _, err := conn.Write(authReq); err != nil {
		return err
	}

	// 读取认证响应
	authResp := make([]byte, 2)
	if _, err := conn.Read(authResp); err != nil {
		return err
	}

	if authResp[0] != 0x01 {
		return fmt.Errorf("invalid auth response version: %d", authResp[0])
	}

	if authResp[1] != 0x00 {
		return fmt.Errorf("authentication failed: %d", authResp[1])
	}

	return nil
}

// performSOCKS5Connect 执行SOCKS5连接请求
func (pn *ProxyNodes) performSOCKS5Connect(conn net.Conn, targetAddr string) error {
	// 解析目标地址
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address: %v", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %v", err)
	}

	// 构建连接请求 - 智能选择地址类型
	ip := net.ParseIP(host)
	var connectReq []byte

	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4地址
			connectReq = []byte{0x05, 0x01, 0x00, 0x01} // ATYP=IPv4
			connectReq = append(connectReq, ip4...)
		} else {
			// IPv6地址
			connectReq = []byte{0x05, 0x01, 0x00, 0x04} // ATYP=IPv6
			connectReq = append(connectReq, ip.To16()...)
		}
	} else {
		// 域名
		connectReq = []byte{0x05, 0x01, 0x00, 0x03} // ATYP=domain
		connectReq = append(connectReq, byte(len(host)))
		connectReq = append(connectReq, []byte(host)...)
	}

	// 添加端口
	connectReq = append(connectReq, byte(port>>8), byte(port))

	if _, err := conn.Write(connectReq); err != nil {
		return err
	}

	// 读取连接响应头部（前4字节）
	connectResp := make([]byte, 4)
	if _, err := conn.Read(connectResp); err != nil {
		return err
	}

	if connectResp[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS5 version in response: %d", connectResp[0])
	}

	if connectResp[1] != 0x00 {
		return fmt.Errorf("connection failed with code: %d", connectResp[1])
	}

	// 根据地址类型读取剩余部分
	remainingBytes := 0
	switch connectResp[3] {
	case 0x01: // IPv4
		remainingBytes = 6 // 4字节IP + 2字节端口
	case 0x03: // 域名
		if _, err := conn.Read(connectResp[:1]); err != nil { // 读取域名长度
			return err
		}
		domainLen := int(connectResp[0])
		remainingBytes = domainLen + 2 // 域名 + 2字节端口
	case 0x04: // IPv6
		remainingBytes = 18 // 16字节IP + 2字节端口
	default:
		return fmt.Errorf("unsupported address type in response: %d", connectResp[3])
	}

	// 读取并丢弃剩余字节
	if remainingBytes > 0 {
		remaining := make([]byte, remainingBytes)
		if _, err := conn.Read(remaining); err != nil {
			return err
		}
	}

	return nil
}

// connectHTTP 连接HTTP代理
func (pn *ProxyNodes) connectHTTP(proxy *ProxyNode, targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxy.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to HTTP proxy %s: %v", proxy.Address, err)
	}

	// HTTP CONNECT方法
	if err := pn.performHTTPConnect(conn, targetAddr, proxy); err != nil {
		conn.Close()
		return nil, fmt.Errorf("HTTP CONNECT failed: %v", err)
	}

	return conn, nil
}

// performHTTPConnect 执行HTTP CONNECT请求
func (pn *ProxyNodes) performHTTPConnect(conn net.Conn, targetAddr string, proxy *ProxyNode) error {
	// 构建CONNECT请求
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", targetAddr)

	// 添加Host头
	if host, _, err := net.SplitHostPort(proxy.Address); err == nil {
		connectReq += fmt.Sprintf("Host: %s\r\n", host)
	} else {
		connectReq += fmt.Sprintf("Host: %s\r\n", proxy.Address)
	}

	// 添加代理认证头（如果需要）
	if proxy.AuthMethod == "userpass" && proxy.Username != nil && proxy.Password != nil {
		auth := *proxy.Username + ":" + *proxy.Password
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n",
			base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		return err
	}

	// 读取响应
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	// 检查响应状态
	if !strings.Contains(response, "200") {
		return fmt.Errorf("HTTP CONNECT failed: %s", strings.TrimSpace(response))
	}

	// 读取剩余的响应头
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	return nil
}

// connectHTTPS 连接HTTPS代理
func (pn *ProxyNodes) connectHTTPS(proxy *ProxyNode, targetAddr string) (net.Conn, error) {
	// HTTPS代理实际上是通过HTTP CONNECT方法实现的
	// 与HTTP代理相同，但通常用于加密流量的代理
	return pn.connectHTTP(proxy, targetAddr)
}

// connectSOCKS4 连接SOCKS4代理
func (pn *ProxyNodes) connectSOCKS4(proxy *ProxyNode, targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxy.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS4 proxy %s: %v", proxy.Address, err)
	}

	// SOCKS4握手
	if err := pn.performSOCKS4Handshake(conn, targetAddr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 handshake failed: %v", err)
	}

	return conn, nil
}

// performSOCKS4Handshake 执行SOCKS4握手
func (pn *ProxyNodes) performSOCKS4Handshake(conn net.Conn, targetAddr string) error {
	// 解析目标地址
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address: %v", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %v", err)
	}

	// SOCKS4代理用户ID (通常为0x00)
	userId := byte(0x00)

	// 构建SOCKS4请求
	request := []byte{
		0x04,                        // SOCKS4版本
		0x01,                        // CONNECT命令
		byte(port >> 8), byte(port), // 端口号（大端序）
	}

	// 添加IP地址或主机名
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		// IPv4地址
		request = append(request, ip.To4()...)
	} else {
		// 主机名格式
		request = append(request, 0x00, 0x00, 0x00, 0x01) // 0.0.0.1表示主机名
		request = append(request, byte(len(host)))
		request = append(request, []byte(host)...)
	}

	// 添加用户ID (SOCKS4协议要求)
	request = append(request, userId)

	// 发送请求
	if _, err := conn.Write(request); err != nil {
		return err
	}

	// 读取响应
	response := make([]byte, 8)
	if _, err := conn.Read(response); err != nil {
		return err
	}

	// 检查响应
	if response[0] != 0x00 {
		return fmt.Errorf("SOCKS4 failed with code: %d", response[0])
	}

	// SOCKS4a支持
	if response[1] == 0x90 {
		// 读取附加数据
		additionalData := make([]byte, 6)
		if _, err := conn.Read(additionalData); err != nil {
			return err
		}
	}

	return nil
}

// GetProxyNodeForRoute 根据路由匹配结果获取代理节点
// 这是Router调用的主要接口
func (pn *ProxyNodes) GetProxyNodeForRoute(proxyNodeName string) *ProxyNode {
	if proxyNodeName == "" {
		return pn.GetDefaultProxy()
	}
	return pn.GetProxyByName(proxyNodeName)
}

// startCleanupRoutine 启动定期清理过期拉黑状态的协程
func (pn *ProxyNodes) startCleanupRoutine() {
	pn.cleanupTicker = time.NewTicker(1 * time.Minute) // 每分钟检查一次

	go func() {
		defer pn.cleanupTicker.Stop()

		for {
			select {
			case <-pn.cleanupTicker.C:
				pn.cleanupExpiredBlacklists()
			case <-pn.cleanupStopped:
				return
			}
		}
	}()
}

// cleanupExpiredBlacklists 清理过期的拉黑状态
func (pn *ProxyNodes) cleanupExpiredBlacklists() {
	pn.healthMapMu.Lock()
	defer pn.healthMapMu.Unlock()

	now := time.Now()
	for nodeName, health := range pn.healthMap {
		health.mu.Lock()
		if health.IsBlacklisted && now.After(health.BlacklistUntil) {
			// 解除拉黑
			health.IsBlacklisted = false
			health.ConsecutiveFailures = 0
			pn.logger.Info("Node %s blacklist expired, node is now available", nodeName)
		}
		health.mu.Unlock()
	}
}

// getOrCreateHealth 获取或创建节点的健康状态
func (pn *ProxyNodes) getOrCreateHealth(nodeName string) *ProxyNodeHealth {
	pn.healthMapMu.Lock()
	defer pn.healthMapMu.Unlock()

	health, exists := pn.healthMap[nodeName]
	if !exists {
		health = &ProxyNodeHealth{
			NodeName: nodeName,
		}
		pn.healthMap[nodeName] = health
	}

	return health
}

// recordConnectionSuccess 记录连接成功
func (pn *ProxyNodes) recordConnectionSuccess(nodeName string) {
	health := pn.getOrCreateHealth(nodeName)
	health.mu.Lock()
	defer health.mu.Unlock()

	health.TotalConnections++
	health.SuccessfulConnections++
	health.LastSuccessTime = time.Now()
	health.ConsecutiveFailures = 0 // 重置连续失败次数

	// 如果之前被拉黑，现在解除
	if health.IsBlacklisted {
		health.IsBlacklisted = false
		health.BlacklistUntil = time.Time{}
		pn.logger.Info("Node %s recovered after successful connection", nodeName)
	}
}

// recordConnectionFailure 记录连接失败
func (pn *ProxyNodes) recordConnectionFailure(nodeName string) {
	health := pn.getOrCreateHealth(nodeName)
	health.mu.Lock()
	defer health.mu.Unlock()

	health.TotalConnections++
	health.ConsecutiveFailures++
	health.LastFailureTime = time.Now()

	// 检查是否需要拉黑
	if health.ConsecutiveFailures >= MaxConsecutiveFailures && !health.IsBlacklisted {
		health.IsBlacklisted = true
		health.BlacklistUntil = time.Now().Add(BlacklistDuration)
		pn.logger.Info("Node %s blacklisted due to %d consecutive failures, will be available at %v",
			nodeName, health.ConsecutiveFailures, health.BlacklistUntil.Format("15:04:05"))
	}
}

// isNodeAvailable 检查节点是否可用（未被拉黑）
func (pn *ProxyNodes) isNodeAvailable(nodeName string) bool {
	pn.healthMapMu.RLock()
	health, exists := pn.healthMap[nodeName]
	pn.healthMapMu.RUnlock()

	if !exists {
		return true // 新节点默认可用
	}

	health.mu.RLock()
	defer health.mu.RUnlock()

	// 如果被拉黑但已过期，则可用
	if health.IsBlacklisted && time.Now().After(health.BlacklistUntil) {
		return true
	}

	return !health.IsBlacklisted
}

// GetHealthStatus 获取节点的健康状态
func (pn *ProxyNodes) GetHealthStatus(nodeName string) map[string]interface{} {
	pn.healthMapMu.RLock()
	health, exists := pn.healthMap[nodeName]
	pn.healthMapMu.RUnlock()

	if !exists {
		return map[string]interface{}{
			"node_name":              nodeName,
			"consecutive_failures":   0,
			"is_blacklisted":         false,
			"total_connections":      0,
			"successful_connections": 0,
			"success_rate":           0.0,
		}
	}

	health.mu.RLock()
	defer health.mu.RUnlock()

	successRate := 0.0
	if health.TotalConnections > 0 {
		successRate = float64(health.SuccessfulConnections) / float64(health.TotalConnections) * 100
	}

	return map[string]interface{}{
		"node_name":              health.NodeName,
		"consecutive_failures":   health.ConsecutiveFailures,
		"last_failure_time":      health.LastFailureTime.Format("2006-01-02 15:04:05"),
		"is_blacklisted":         health.IsBlacklisted,
		"blacklist_until":        health.BlacklistUntil.Format("2006-01-02 15:04:05"),
		"total_connections":      health.TotalConnections,
		"successful_connections": health.SuccessfulConnections,
		"last_success_time":      health.LastSuccessTime.Format("2006-01-02 15:04:05"),
		"success_rate":           successRate,
	}
}

// GetAllHealthStatus 获取所有节点的健康状态
func (pn *ProxyNodes) GetAllHealthStatus() map[string]interface{} {
	pn.healthMapMu.RLock()
	defer pn.healthMapMu.RUnlock()

	status := make(map[string]interface{})
	status["nodes"] = make([]map[string]interface{}, 0)

	for nodeName := range pn.healthMap {
		nodeStatus := pn.GetHealthStatus(nodeName)
		status["nodes"] = append(status["nodes"].([]map[string]interface{}), nodeStatus)
	}

	status["total_nodes"] = len(pn.healthMap)

	return status
}

// Close 关闭代理节点管理器，清理资源
func (pn *ProxyNodes) Close() {
	if pn.cleanupTicker != nil {
		pn.cleanupTicker.Stop()
		close(pn.cleanupStopped)
	}
}

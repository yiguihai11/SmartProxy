package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"smartproxy/socks5"
)

// CacheEntry 缓存条目
type CacheEntry struct {
	Msg    *dns.Msg
	Expiry time.Time
	Access time.Time
}

// DNSCache DNS缓存系统
type DNSCache struct {
	cache       map[string]*CacheEntry
	maxSize     int
	cleanupMu   sync.RWMutex
	cleanupDone chan struct{}
	logger      *log.Logger
}

// NewDNSCache 创建新的DNS缓存
func NewDNSCache(maxSize int, cleanupInterval time.Duration, logger *log.Logger) *DNSCache {
	dc := &DNSCache{
		cache:       make(map[string]*CacheEntry),
		maxSize:     maxSize,
		cleanupDone: make(chan struct{}),
		logger:      logger,
	}

	// 启动清理任务
	if cleanupInterval > 0 {
		go dc.cleanupLoop(cleanupInterval)
	}

	return dc
}

// Get 从缓存获取DNS响应
func (dc *DNSCache) Get(key string) *dns.Msg {
	dc.cleanupMu.RLock()
	defer dc.cleanupMu.RUnlock()

	entry, exists := dc.cache[key]
	if !exists {
		dc.logger.Printf("Cache miss for %s", key)
		return nil
	}

	// 检查是否过期
	if time.Now().After(entry.Expiry) {
		delete(dc.cache, key)
		dc.logger.Printf("Cache expired for %s", key)
		return nil
	}

	// 更新访问时间
	entry.Access = time.Now()
	dc.logger.Printf("Cache hit for %s", key)

	// 返回消息的副本
	msg := entry.Msg.Copy()
	return msg
}

// Put 将DNS响应存入缓存
func (dc *DNSCache) Put(key string, msg *dns.Msg) {
	dc.cleanupMu.Lock()
	defer dc.cleanupMu.Unlock()

	// 如果缓存已满，删除最旧的条目
	if len(dc.cache) >= dc.maxSize {
		dc.evictOldest()
	}

	// 计算TTL
	minTTL := 300 // 默认5分钟
	if len(msg.Answer) > 0 {
		minTTL = int(msg.Answer[0].Header().Ttl)
		for _, rr := range msg.Answer {
			if int(rr.Header().Ttl) < minTTL {
				minTTL = int(rr.Header().Ttl)
			}
		}
	}

	if minTTL <= 0 {
		minTTL = 300
	}

	entry := &CacheEntry{
		Msg:    msg.Copy(),
		Expiry: time.Now().Add(time.Duration(minTTL) * time.Second),
		Access: time.Now(),
	}

	dc.cache[key] = entry
	dc.logger.Printf("Cached %s with TTL %ds", key, minTTL)
}

// evictOldest 驱逐最旧的缓存条目
func (dc *DNSCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range dc.cache {
		if oldestKey == "" || entry.Access.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Access
		}
	}

	if oldestKey != "" {
		delete(dc.cache, oldestKey)
	}
}

// cleanupLoop 定期清理过期缓存
func (dc *DNSCache) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dc.cleanup()
		case <-dc.cleanupDone:
			return
		}
	}
}

// cleanup 清理过期缓存
func (dc *DNSCache) cleanup() {
	dc.cleanupMu.Lock()
	defer dc.cleanupMu.Unlock()

	now := time.Now()
	for key, entry := range dc.cache {
		if now.After(entry.Expiry) {
			delete(dc.cache, key)
		}
	}
}

// Stop 停止缓存系统
func (dc *DNSCache) Stop() {
	close(dc.cleanupDone)
}

// HijackRule DNS劫持规则
type HijackRule struct {
	Pattern string
	Target  string
}

// Config DNS配置
type Config struct {
	CNServers       []string
	ForeignServers  []string
	HijackRules     []HijackRule
	CacheSize       int
	CleanupInterval time.Duration
	ProxyNodes      []ProxyNode // SOCKS5代理节点
}

// ProxyNode SOCKS5代理节点配置
type ProxyNode struct {
	Name     string
	Address  string
	Username string
	Password string
	Enabled  bool
}

// Resolver DNS解析器
type Resolver struct {
	config *Config
	cache  *DNSCache
	client *dns.Client
	logger *log.Logger
	router *socks5.Router
}

// NewResolver 创建新的DNS解析器
func NewResolver(config *Config, logger *log.Logger, router *socks5.Router) *Resolver {
	cache := NewDNSCache(config.CacheSize, config.CleanupInterval, logger)

	// 直接打印到标准输出，确保能看到
	if router == nil {
		fmt.Printf("CRITICAL: NewResolver called with nil router!\n")
	} else {
		fmt.Printf("SUCCESS: NewResolver called with valid router\n")
	}

	// 也记录到logger
	if router == nil {
		logger.Printf("DEBUG: NewResolver called with nil router")
	} else {
		logger.Printf("DEBUG: NewResolver called with valid router")
	}

	return &Resolver{
		config: config,
		cache:  cache,
		client: &dns.Client{
			Timeout: 5 * time.Second, // 增加超时时间以减少超时失败
		},
		logger: logger,
		router: router,
	}
}

// matchPattern 匹配域名模式
func (r *Resolver) matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(value, pattern[1:])
	}
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-2])
	}
	return pattern == value
}

// extractIPs 从DNS响应中提取IP地址
func (r *Resolver) extractIPs(msg *dns.Msg) []string {
	var ips []string
	for _, rr := range msg.Answer {
		switch t := rr.(type) {
		case *dns.A:
			ips = append(ips, t.A.String())
		case *dns.AAAA:
			ips = append(ips, t.AAAA.String())
		}
	}
	return ips
}

// isChinaIP 检查IP是否为中国IP (使用Router的chnroutes结果)
func (r *Resolver) isChinaIP(ipStr string) bool {
	r.logger.Printf("DNS DEBUG: Checking IP %s, router is nil: %v", ipStr, r.router == nil)
	if r.router == nil {
		r.logger.Printf("DNS ERROR: Router not initialized, falling back to default IP check for %s", ipStr)
		return false
	}

	r.logger.Printf("DNS DEBUG: Checking if IP %s is in China routes", ipStr)
	// 使用 Router 的 IsChinaIP 方法来检查中国IP基数树
	isChina := r.router.IsChinaIP(ipStr)

	r.logger.Printf("DNS DEBUG: IP %s isChinaIP check returned: %v", ipStr, isChina)
	return isChina
}

// querySingleServer 查询单个DNS服务器
func (r *Resolver) querySingleServer(msg *dns.Msg, server string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // 增加超时时间
	defer cancel()

	resp, _, err := r.client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// queryConcurrent 并发查询多个服务器
func (r *Resolver) queryConcurrent(msg *dns.Msg, servers []string) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers available")
	}

	// 随机打乱服务器顺序
	shuffled := make([]string, len(servers))
	copy(shuffled, servers)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	type result struct {
		msg *dns.Msg
		err error
	}

	results := make(chan result, len(shuffled))
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second) // 增加并发查询超时
	defer cancel()

	// 并发查询
	for _, server := range shuffled {
		go func(s string) {
			msg := msg.Copy()
			resp, err := r.querySingleServer(msg, s)
			select {
			case results <- result{resp, err}:
			case <-ctx.Done():
			}
		}(server)
	}

	// 等待第一个成功的结果
	for i := 0; i < len(shuffled); i++ {
		select {
		case res := <-results:
			if res.err == nil {
				return res.msg, nil
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("all DNS queries timed out")
		}
	}

	return nil, fmt.Errorf("all DNS queries failed")
}

// queryThroughProxyNodes 通过SOCKS5代理节点查询DNS
func (r *Resolver) queryThroughProxyNodes(msg *dns.Msg, servers []string) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers available")
	}

	// 获取可用的代理节点
	var enabledNodes []ProxyNode
	for _, node := range r.config.ProxyNodes {
		if node.Enabled {
			enabledNodes = append(enabledNodes, node)
		}
	}

	if len(enabledNodes) == 0 {
		r.logger.Printf("No enabled proxy nodes available, falling back to direct query")
		return r.queryConcurrent(msg, servers)
	}

	r.logger.Printf("Using %d proxy nodes for DNS query", len(enabledNodes))

	type result struct {
		msg  *dns.Msg
		err  error
		node ProxyNode
	}

	results := make(chan result, len(enabledNodes))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second) // 增加超时时间
	defer cancel()

	// 通过每个代理节点并发查询
	for _, node := range enabledNodes {
		go func(n ProxyNode) {
			resp, err := r.queryThroughSingleProxy(msg, n)
			select {
			case results <- result{resp, err, n}:
			case <-ctx.Done():
			}
		}(node)
	}

	// 等待第一个成功的结果
	for i := 0; i < len(enabledNodes); i++ {
		select {
		case res := <-results:
			if res.err == nil {
				r.logger.Printf("Successfully queried through proxy node: %s", res.node.Name)
				return res.msg, nil
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("all proxy queries timed out")
		}
	}

	return nil, fmt.Errorf("all proxy queries failed")
}

// queryThroughSingleProxy 通过单个SOCKS5代理查询DNS
func (r *Resolver) queryThroughSingleProxy(msg *dns.Msg, proxyNode ProxyNode) (*dns.Msg, error) {
	r.logger.Printf("Querying through proxy node %s (%s)", proxyNode.Name, proxyNode.Address)

	// 创建SOCKS5代理连接
	proxyConn, err := net.Dial("tcp", proxyNode.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy node %s: %v", proxyNode.Name, err)
	}
	defer proxyConn.Close()

	// SOCKS5握手
	proxyAuth := ""
	if proxyNode.Username != "" && proxyNode.Password != "" {
		proxyAuth = fmt.Sprintf("\x05%s%s",
			string([]byte{byte(len(proxyNode.Username))}),
			proxyNode.Username,
			proxyNode.Password)
	}

	// SOCKS5认证
	if _, err := proxyConn.Write([]byte("\x05" + proxyAuth)); err != nil {
		return nil, fmt.Errorf("SOCKS5 auth failed: %v", err)
	}

	// 读取响应
	response := make([]byte, 2)
	if _, err := proxyConn.Read(response); err != nil {
		return nil, fmt.Errorf("failed to read SOCKS5 auth response: %v", err)
	}

	if response[0] != 0x05 || response[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 auth failed: %v", response)
	}

	// 为每个DNS服务器创建连接和查询
	type proxyResult struct {
		msg    *dns.Msg
		err    error
		server string
	}

	// 通过代理并发查询所有DNS服务器
	foreignServers := r.config.ForeignServers
	proxyResults := make(chan proxyResult, len(foreignServers))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, server := range foreignServers {
		go func(s string) {
			resp, err := r.querySingleServerThroughProxy(msg, s, proxyConn)
			select {
			case proxyResults <- proxyResult{resp, err, s}:
			case <-ctx.Done():
			}
		}(server)
	}

	// 等待第一个成功的结果
	for i := 0; i < len(foreignServers); i++ {
		select {
		case res := <-proxyResults:
			if res.err == nil {
				r.logger.Printf("Successfully queried through proxy: %s -> %s", proxyNode.Name, res.server)
				return res.msg, nil
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("proxy queries timed out")
		}
	}

	return nil, fmt.Errorf("all proxy queries failed")
}

// querySingleServerThroughProxy 通过SOCKS5代理查询单个DNS服务器
func (r *Resolver) querySingleServerThroughProxy(msg *dns.Msg, server string, proxyConn net.Conn) (*dns.Msg, error) {
	// 解析服务器地址
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		host = server
		portStr = "53"
	}

	// 将端口字符串转换为整数
	port := 53
	if p, err := net.LookupPort("tcp", portStr); err == nil {
		port = p
	}

	// SOCKS5 CONNECT请求
	connectReq := []byte{0x05, 0x01, 0x00, 0x03}               // VER=5, CMD=CONNECT, RSV=0, ATYP=domain
	connectReq = append(connectReq, byte(len(host)))           // 域名长度
	connectReq = append(connectReq, []byte(host)...)           // 域名
	connectReq = append(connectReq, byte(port>>8), byte(port)) // 端口

	if _, err := proxyConn.Write(connectReq); err != nil {
		return nil, fmt.Errorf("failed to send SOCKS5 CONNECT request: %v", err)
	}

	// 读取CONNECT响应
	connectResp := make([]byte, 10)
	if _, err := proxyConn.Read(connectResp); err != nil {
		return nil, fmt.Errorf("failed to read SOCKS5 CONNECT response: %v", err)
	}

	if connectResp[0] != 0x05 || connectResp[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 CONNECT failed: %v", connectResp)
	}

	// 现在通过代理发送DNS查询
	return r.querySingleServerWithConn(msg, server, proxyConn)
}

// querySingleServerWithConn 使用现有连接查询单个DNS服务器
func (r *Resolver) querySingleServerWithConn(msg *dns.Msg, server string, conn net.Conn) (*dns.Msg, error) {
	// 使用miekg/dns的UDP客户端通过代理发送查询
	// 由于SOCKS5代理建立的是TCP连接，我们需要特殊处理
	// 这里我们发送原始UDP DNS查询包

	// 构建UDP代理请求
	udpMsg := msg.Copy()
	data, err := udpMsg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	// SOCKS5 UDP关联
	udpAssociate := []byte{0x05, 0x03, 0x00, 0x03, 0x01, 0x08, 0x00, 0x00, 0x00, 0x01} // ATYP=IPv4
	if _, err := conn.Write(udpAssociate); err != nil {
		return nil, fmt.Errorf("failed to send UDP associate request: %v", err)
	}

	// 读取UDP关联响应
	udpResp := make([]byte, 10)
	if _, err := conn.Read(udpResp); err != nil {
		return nil, fmt.Errorf("failed to read UDP associate response: %v", err)
	}

	if udpResp[0] != 0x05 || udpResp[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 UDP associate failed: %v", udpResp)
	}

	// 发送DNS查询数据
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("failed to send DNS query through proxy: %v", err)
	}

	// 读取DNS响应
	response := make([]byte, 2048) // 足过足够的缓冲区
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response from proxy: %v", err)
	}

	// 解析DNS响应
	resp := new(dns.Msg)
	if err := resp.Unpack(response[:n]); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %v", err)
	}

	return resp, nil
}

// hijackQuery 处理DNS劫持
func (r *Resolver) hijackQuery(msg *dns.Msg, domain string) (*dns.Msg, bool) {
	domain = strings.TrimSuffix(domain, ".")

	for _, rule := range r.config.HijackRules {
		if r.matchPattern(rule.Pattern, domain) {
			r.logger.Printf("DNS query for '%s' hijacked by rule '%s' -> '%s'",
				domain, rule.Pattern, rule.Target)

			reply := msg.Copy()
			reply.Response = true
			reply.Authoritative = true

			// 检查目标是否为纯IP地址（直接返回该IP）
			if ip := net.ParseIP(rule.Target); ip != nil {
				r.logger.Printf("Hijacking '%s' to IP address: %s", domain, rule.Target)

				// 根据查询类型创建相应的DNS记录
				question := msg.Question[0]
				switch question.Qtype {
				case dns.TypeA:
					if ip4 := ip.To4(); ip4 != nil {
						rr := new(dns.A)
						rr.Hdr = dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    60,
						}
						rr.A = ip4
						reply.Answer = append(reply.Answer, rr)
					}
				case dns.TypeAAAA:
					if ip.To4() == nil { // IPv6 address
						rr := new(dns.AAAA)
						rr.Hdr = dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    60,
						}
						rr.AAAA = ip
						reply.Answer = append(reply.Answer, rr)
					}
				}
				return reply, true
			}

			// 检查目标是否为IP:Port格式（转发到指定DNS服务器）
			if host, _, err := net.SplitHostPort(rule.Target); err == nil {
				if net.ParseIP(host) != nil {
					dnsServer := rule.Target // 直接使用完整的 host:port
					r.logger.Printf("Forwarding hijacked query for '%s' to DNS server: %s", domain, dnsServer)

					resp, err := r.querySingleServer(msg, dnsServer)
					if err != nil {
						r.logger.Printf("Failed to forward hijacked query to %s: %v", dnsServer, err)
						return nil, false
					}
					return resp, true
				}
			}

			// 如果是域名格式，尝试添加默认DNS端口53
			if net.ParseIP(rule.Target) == nil {
				dnsServer := rule.Target + ":53"
				r.logger.Printf("Forwarding hijacked query for '%s' to DNS server: %s", domain, dnsServer)

				resp, err := r.querySingleServer(msg, dnsServer)
				if err != nil {
					r.logger.Printf("Failed to forward hijacked query to %s: %v", dnsServer, err)
					return nil, false
				}
				return resp, true
			}

			// 如果目标格式无法识别，记录错误
			r.logger.Printf("Invalid hijack target format for rule '%s': %s", rule.Pattern, rule.Target)
			return nil, false
		}
	}

	return nil, false
}

// Resolve 解析DNS查询
func (r *Resolver) Resolve(msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("no question in DNS query")
	}

	question := msg.Question[0]
	domain := question.Name
	qtype := question.Qtype

	// 生成缓存键
	cacheKey := fmt.Sprintf("%s:%d", strings.TrimSuffix(domain, "."), qtype)

	// 检查缓存
	if cached := r.cache.Get(cacheKey); cached != nil {
		cached.Id = msg.Id
		r.logger.Printf("Serving cached response for %s", domain)
		return cached, nil
	}

	// 检查劫持规则
	if hijacked, isHijacked := r.hijackQuery(msg, domain); isHijacked {
		r.cache.Put(cacheKey, hijacked)
		hijacked.Id = msg.Id
		return hijacked, nil
	}

	// 首先查询中国DNS服务器
	var resp *dns.Msg
	var err error

	if len(r.config.CNServers) > 0 {
		r.logger.Printf("Querying CN DNS servers for %s", domain)
		resp, err = r.queryConcurrent(msg, r.config.CNServers)
		if err != nil {
			r.logger.Printf("CN DNS query failed for %s: %v", domain, err)
		}
	}

	// 检查污染
	if resp != nil {
		ips := r.extractIPs(resp)
		isPolluted := false

		for _, ip := range ips {
			if !r.isChinaIP(ip) && qtype == dns.TypeA {
				isPolluted = true
				break
			}
		}

		if isPolluted {
			r.logger.Printf("CN response for %s appears polluted, trying foreign servers", domain)
			resp = nil
		}
	}

	// 如果中国服务器失败或被污染，通过SOCKS5代理查询外国服务器
	if resp == nil && len(r.config.ForeignServers) > 0 {
		r.logger.Printf("Querying Foreign DNS servers for %s through SOCKS5 proxy", domain)
		resp, err = r.queryThroughProxyNodes(msg, r.config.ForeignServers)
		if err != nil {
			r.logger.Printf("Foreign DNS query through proxy failed for %s: %v", domain, err)
			// 如果代理查询也失败，尝试直连外国服务器
			r.logger.Printf("Attempting direct foreign DNS query for %s", domain)
			resp, err = r.queryConcurrent(msg, r.config.ForeignServers)
			if err != nil {
				r.logger.Printf("Direct foreign DNS query failed for %s: %v", domain, err)
				return nil, err
			}
		}
	}

	if resp == nil {
		return nil, fmt.Errorf("failed to resolve %s", domain)
	}

	// 缓存结果
	r.cache.Put(cacheKey, resp)
	resp.Id = msg.Id

	r.logger.Printf("Successfully resolved %s", domain)
	return resp, nil
}

// Stop 停止解析器
func (r *Resolver) Stop() {
	r.cache.Stop()
}

// SmartDNSServer 智能DNS服务器
type SmartDNSServer struct {
	config   *Config
	resolver *Resolver
	server   *dns.Server
	logger   *log.Logger
}

// NewSmartDNSServer 创建新的智能DNS服务器
func NewSmartDNSServer(config *Config, port int, logger *log.Logger, router *socks5.Router) *SmartDNSServer {
	resolver := NewResolver(config, logger, router)

	// 检查是否启用IPv6
	listenAddr := fmt.Sprintf(":%d", port)
	if isIPv6EnabledDNS() {
		listenAddr = fmt.Sprintf("[::]:%d", port)
	}

	server := &SmartDNSServer{
		config:   config,
		resolver: resolver,
		logger:   logger,
		server: &dns.Server{
			Addr: listenAddr,
			Net:  "udp",
		},
	}
	server.server.Handler = dns.HandlerFunc(server.handleDNSRequest)
	return server
}

// handleDNSRequest 处理DNS请求
func (s *SmartDNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	s.logger.Printf("Received DNS query for %s from %s",
		r.Question[0].Name, w.RemoteAddr())

	resp, err := s.resolver.Resolve(r)
	if err != nil {
		s.logger.Printf("Failed to resolve query for %s: %v",
			r.Question[0].Name, err)

		// 返回SERVFAIL
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	w.WriteMsg(resp)
}

// Start 启动DNS服务器
func (s *SmartDNSServer) Start() error {
	s.logger.Printf("Starting Smart DNS server on %s", s.server.Addr)

	// 添加Router状态检查
	if s.resolver != nil {
		s.logger.Printf("DNS DEBUG: Resolver is not nil, checking router...")
		// 这里我们不能直接访问resolver的router，因为它没有公开
		// 但是可以调用一个简单的方法来验证
		s.logger.Printf("DNS DEBUG: DNS Server configuration loaded successfully")
	} else {
		s.logger.Printf("DNS ERROR: Resolver is nil!")
	}

	return s.server.ListenAndServe()
}

// Stop 停止DNS服务器
func (s *SmartDNSServer) Stop() error {
	s.logger.Printf("Stopping Smart DNS server")
	s.resolver.Stop()
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}

// isIPv6EnabledDNS 检查是否应该为DNS服务器启用IPv6监听
func isIPv6EnabledDNS() bool {
	// 读取配置文件检查ipv6_enabled设置
	configPath := "conf/config.json"
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return false // 无法读取配置，默认使用IPv4
	}

	var config struct {
		Listener struct {
			IPv6Enabled bool `json:"ipv6_enabled"`
		} `json:"listener"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return false // 无法解析配置，默认使用IPv4
	}

	return config.Listener.IPv6Enabled
}

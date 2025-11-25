package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry 缓存条目
type CacheEntry struct {
	Msg     *dns.Msg
	Expiry  time.Time
	Access  time.Time
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
		Msg:     msg.Copy(),
		Expiry:  time.Now().Add(time.Duration(minTTL) * time.Second),
		Access:  time.Now(),
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
	CNServers    []string
	ForeignServers []string
	HijackRules  []HijackRule
	CacheSize    int
	CleanupInterval time.Duration
}

// Resolver DNS解析器
type Resolver struct {
	config     *Config
	cache      *DNSCache
	client     *dns.Client
	logger     *log.Logger
}

// NewResolver 创建新的DNS解析器
func NewResolver(config *Config, logger *log.Logger) *Resolver {
	cache := NewDNSCache(config.CacheSize, config.CleanupInterval, logger)

	return &Resolver{
		config: config,
		cache:  cache,
		client: &dns.Client{
			Timeout: 2 * time.Second,
		},
		logger: logger,
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

// isValidHostname 验证主机名格式
func (r *Resolver) isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 255 {
		return false
	}

	// 基本格式检查
	if !regexp.MustCompile(`^[a-zA-Z0-9.-]+$`).MatchString(hostname) {
		return false
	}

	// 不能以 . 或 - 开始或结束
	if strings.HasPrefix(hostname, ".") || strings.HasPrefix(hostname, "-") ||
		strings.HasSuffix(hostname, ".") || strings.HasSuffix(hostname, "-") {
		return false
	}

	return true
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

// isChinaIP 检查IP是否为中国IP (简化版本)
func (r *Resolver) isChinaIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// 这里应该集成中国路由管理器
	// 为了演示，使用简单的IP段检查
	if ip4 := ip.To4(); ip4 != nil {
		// 一些常见的中国IP段
		chinaRanges := []string{
			"1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "1.0.32.0/19",
			"1.0.128.0/17", "1.1.0.0/8", "1.2.0.0/15", "1.4.0.0/12",
		}

		for _, cidr := range chinaRanges {
			_, network, _ := net.ParseCIDR(cidr)
			if network.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// querySingleServer 查询单个DNS服务器
func (r *Resolver) querySingleServer(msg *dns.Msg, server string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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

			// 检查目标是否为IP地址
			if ip := net.ParseIP(rule.Target); ip != nil {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				}
				rr.A = ip
				reply.Answer = append(reply.Answer, rr)
				return reply, true
			}

			// 如果是域名，转发到指定服务器
			resp, err := r.querySingleServer(msg, rule.Target)
			if err != nil {
				r.logger.Printf("Failed to forward hijacked query to %s: %v", rule.Target, err)
				return nil, false
			}

			return resp, true
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

	// 如果中国服务器失败或被污染，查询外国服务器
	if resp == nil && len(r.config.ForeignServers) > 0 {
		r.logger.Printf("Querying Foreign DNS servers for %s", domain)
		resp, err = r.queryConcurrent(msg, r.config.ForeignServers)
		if err != nil {
			r.logger.Printf("Foreign DNS query failed for %s: %v", domain, err)
			return nil, err
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
func NewSmartDNSServer(config *Config, port int, logger *log.Logger) *SmartDNSServer {
	resolver := NewResolver(config, logger)

	return &SmartDNSServer{
		config:   config,
		resolver: resolver,
		logger:   logger,
		server: &dns.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Net:     "udp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
		},
	}
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
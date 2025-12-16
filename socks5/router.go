package socks5

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
)

type Action string

const (
	ActionAllow Action = "allow" // 直连
	ActionDeny  Action = "deny"  // 走代理
	ActionProxy Action = "proxy" // 通过指定代理节点
	ActionBlock Action = "block" // 屏蔽
)

type Rule struct {
	Action      Action   `json:"action"`
	Patterns    []string `json:"patterns"`   // 域名/IP/端口模式列表
	ProxyNode   string   `json:"proxy_node"` // 指定代理节点名称
	Description string   `json:"description"`
}

// FullConfig 完整配置文件结构体，用于解析嵌套的router配置
type FullConfig struct {
	Listener struct {
		SOCKS5Port  int  `json:"socks5_port"`
		WebPort     int  `json:"web_port"`
		DNSPort     int  `json:"dns_port"`
		IPv6Enabled bool `json:"ipv6_enabled"`
	} `json:"listener"`
	Router struct {
		Chnroutes struct {
			Enable bool   `json:"enable"`
			Path   string `json:"path"`
		} `json:"chnroutes"`
		Rules      []Rule      `json:"rules"`
		ProxyNodes []ProxyNode `json:"proxy_nodes,omitempty"`
	} `json:"router"`
}

type Router struct {
	rules []Rule
	// 域名规则哈希表 - 高速查找
	exactDomains    map[string]*Rule // 精确域名匹配: "example.com" -> Rule
	wildcardDomains map[string]*Rule // 通配符域名匹配: "*.google.com" -> Rule
	suffixDomains   map[string]*Rule // 后缀域名匹配: ".cn" -> Rule
	// IP规则基数树 - IP网段匹配仍然有用
	ipTrie       *RadixTrie // IP基数树
	chinaTrie    *RadixTrie // 中国IP基数树
	configPath   string
	SupportsIPv4 bool
	SupportsIPv6 bool
	proxyNodes   *ProxyNodes // 代理节点管理器
}

type MatchResult struct {
	Action             Action
	Match              bool
	Rule               *Rule
	ProxyNode          string // 匹配到的代理节点名称
	ProxyNodeSpecified bool   // 规则是否明确指定了proxy_node
}

func NewRouter(configPath string) (*Router, error) {
	r := &Router{
		rules:           make([]Rule, 0),
		exactDomains:    make(map[string]*Rule),
		wildcardDomains: make(map[string]*Rule),
		suffixDomains:   make(map[string]*Rule),
		ipTrie:          NewRadixTrie(),
		chinaTrie:       NewRadixTrie(),
		configPath:      configPath,
		SupportsIPv4:    true,
		SupportsIPv6:    true,
		proxyNodes:      NewProxyNodes(nil),
	}

	if err := r.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	return r, nil
}

func (r *Router) loadConfig() error {
	// 读取配置文件
	data, err := ioutil.ReadFile(r.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	// 解析配置结构（嵌套的router配置）
	var fullConfig FullConfig
	if err := json.Unmarshal(data, &fullConfig); err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	// 根据配置文件设置IPv6支持
	r.SupportsIPv6 = fullConfig.Listener.IPv6Enabled

	// 加载路由规则
	r.rules = fullConfig.Router.Rules

	// 加载代理节点
	if len(fullConfig.Router.ProxyNodes) > 0 {
		if err := r.proxyNodes.LoadNodes(fullConfig.Router.ProxyNodes); err != nil {
			return fmt.Errorf("failed to load proxy nodes: %v", err)
		}
	}

	// 加载中国 IP 段
	if fullConfig.Router.Chnroutes.Enable && fullConfig.Router.Chnroutes.Path != "" {
		if err := r.loadChinaRoutes(fullConfig.Router.Chnroutes.Path); err != nil {
			// 如果文件读取失败，退出程序
			fmt.Fprintf(os.Stderr, "Failed to load china routes from %s: %v\n", fullConfig.Router.Chnroutes.Path, err)
			os.Exit(1)
		}
	}

	// 预编译规则
	r.precompileRules()

	return nil
}

func (r *Router) loadChinaRoutes(filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 直接将IP网段添加到中国IP基数树中，标记为allow
		if err := r.chinaTrie.Insert(line, ActionAllow, &Rule{
			Action:      ActionAllow,
			Patterns:    []string{line},
			Description: "中国IP段直连",
		}); err != nil {
			// 如果解析失败，跳过这一行
			continue
		}
	}

	return nil
}

func (r *Router) precompileRules() {
	for i := range r.rules {
		rule := &r.rules[i]

		for _, pattern := range rule.Patterns {
			if pattern == "" {
				continue
			}

			// IP规则 - 使用基数树（网段匹配仍然需要）
			if strings.Contains(pattern, "/") || net.ParseIP(pattern) != nil {
				r.ipTrie.Insert(pattern, rule.Action, rule)
				continue
			}

			// 端口规则 - 跳过（在matchRule中处理）
			if _, err := strconv.Atoi(pattern); err == nil {
				continue
			}

			// 域名规则 - 使用哈希表分类
			r.classifyDomainRule(pattern, rule)
		}
	}
}

// classifyDomainRule 将域名规则分类到不同的哈希表中
func (r *Router) classifyDomainRule(pattern string, rule *Rule) {
	lowerPattern := strings.ToLower(pattern)

	// 通配符域名: *.example.com
	if strings.HasPrefix(lowerPattern, "*.") {
		domain := lowerPattern[2:] // 移除 "*."
		r.wildcardDomains[domain] = rule
		return
	}

	// 后缀域名: .cn, .com.cn
	if strings.HasPrefix(lowerPattern, ".") {
		r.suffixDomains[lowerPattern] = rule
		return
	}

	// 精确域名: example.com
	if strings.Contains(lowerPattern, ".") {
		r.exactDomains[lowerPattern] = rule
		return
	}
}

// matchPortRule 检查端口规则
func (r *Router) matchPortRule(rule *Rule, portStr string) bool {
	for _, pattern := range rule.Patterns {
		if pattern == portStr {
			return true
		}
	}
	return false
}

// matchDomainRule 使用哈希表进行高速域名匹配
func (r *Router) matchDomainRule(host string) *Rule {
	if host == "" {
		return nil
	}

	lowerHost := strings.ToLower(host)

	// 1. 精确匹配 - O(1)
	if rule, exists := r.exactDomains[lowerHost]; exists {
		return rule
	}

	// 2. 通配符匹配 - O(n) 其中n是域名层级数
	hostParts := strings.Split(lowerHost, ".")
	for i := 1; i < len(hostParts); i++ {
		domain := strings.Join(hostParts[i:], ".")
		if rule, exists := r.wildcardDomains[domain]; exists {
			return rule
		}
	}

	// 3. 后缀匹配 - O(m) 其中m是后缀规则数
	for suffix, rule := range r.suffixDomains {
		if strings.HasSuffix(lowerHost, suffix) {
			return rule
		}
	}

	return nil
}

// GetProxyNode 根据名称获取代理节点
func (r *Router) GetProxyNode(name string) *ProxyNode {
	return r.proxyNodes.GetProxyNodeForRoute(name)
}

// GetDefaultProxy 获取默认代理节点
func (r *Router) GetDefaultProxy() *ProxyNode {
	return r.proxyNodes.GetDefaultProxy()
}

// IsChinaIP 检查IP是否在中国IP基数树中
func (r *Router) IsChinaIP(ip string) bool {
	// 检查是否在中国 IP 基数树中
	if _, found, _ := r.chinaTrie.Lookup(ip); found {
		return true
	}
	return false
}

// MatchRule 统一的路由匹配函数，支持预检测和后检测
// 优先级: 域名规则 -> IP/CIDR规则 -> 中国IP -> 端口规则 -> 默认
//
// 参数：
// - host: 目标地址（IP或域名）
// - detectedHost: 从流量中检测到的域名（可能为空，如果为空则使用host）
// - port: 目标端口
//
// 返回：匹配结果
func (r *Router) MatchRule(host, detectedHost string, port int) MatchResult {
	// 1. 域名匹配（最高优先级，优先使用检测到的域名）
	hostnameToMatch := detectedHost
	if hostnameToMatch == "" {
		hostnameToMatch = host
	}

	// 尝试域名匹配（只对非IP地址进行域名匹配）
	if hostnameToMatch != "" && net.ParseIP(hostnameToMatch) == nil {
		if rule := r.matchDomainRule(hostnameToMatch); rule != nil {
			return MatchResult{
				Action:             rule.Action,
				Match:              true,
				Rule:               rule,
				ProxyNode:          rule.ProxyNode,
				ProxyNodeSpecified: rule.ProxyNode != "",
			}
		}
	}

	// 2. IP地址匹配 - 使用基数树（host必须是IP地址）
	if ip := net.ParseIP(host); ip != nil {
		// 检查IPv6支持
		if ip.To4() == nil && !r.SupportsIPv6 {
			// IPv6地址但不支持IPv6，跳过IP匹配
		} else {
			// 2a. 自定义IP规则
			if action, found, rule := r.ipTrie.Lookup(host); found {
				return MatchResult{
					Action:             action,
					Match:              true,
					Rule:               rule,
					ProxyNode:          rule.ProxyNode,
					ProxyNodeSpecified: rule.ProxyNode != "",
				}
			}

			// 2b. 中国IP检查
			if action, found, rule := r.chinaTrie.Lookup(host); found {
				return MatchResult{
					Action:             action,
					Match:              true,
					Rule:               rule,
					ProxyNode:          rule.ProxyNode,
					ProxyNodeSpecified: rule.ProxyNode != "",
				}
			}
		}
	}

	// 3. 端口规则匹配
	portStr := strconv.Itoa(port)
	for i := range r.rules {
		rule := &r.rules[i]
		if r.matchPortRule(rule, portStr) {
			return MatchResult{
				Action:             rule.Action,
				Match:              true,
				Rule:               rule,
				ProxyNode:          rule.ProxyNode,
				ProxyNodeSpecified: rule.ProxyNode != "",
			}
		}
	}

	// 4. 默认行为
	return MatchResult{
		Action: ActionDeny, // 默认走代理
		Match:  false,
	}
}

func (r *Router) GetStats() map[string]int {
	stats := make(map[string]int)

	// 统计规则数量
	for _, rule := range r.rules {
		stats[string(rule.Action)]++
	}

	// 获取基数树统计信息（IP规则仍然使用基数树）
	ipv4Nodes, ipv6Nodes, ipRules := r.ipTrie.GetStats()
	chinaIPv4Nodes, chinaIPv6Nodes, chinaRules := r.chinaTrie.GetStats()

	stats["total_rules"] = len(r.rules)
	stats["ipv4_nodes"] = ipv4Nodes
	stats["ipv6_nodes"] = ipv6Nodes
	stats["ip_rules"] = ipRules
	stats["china_ipv4_nodes"] = chinaIPv4Nodes
	stats["china_ipv6_nodes"] = chinaIPv6Nodes
	stats["china_rules"] = chinaRules

	// 哈希表统计 - 新的域名匹配系统
	stats["exact_domains"] = len(r.exactDomains)
	stats["wildcard_domains"] = len(r.wildcardDomains)
	stats["suffix_domains"] = len(r.suffixDomains)
	stats["supports_ipv4"] = 1
	stats["supports_ipv6"] = 1

	return stats
}

func (r *Router) Reload() error {
	return r.loadConfig()
}

package socks5

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Action string

const (
	ActionAllow Action = "allow"  // 直连
	ActionDeny  Action = "deny"   // 走代理
	ActionBlock Action = "block"  // 屏蔽
)

type Rule struct {
	Action      Action `json:"action"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

type RouterConfig struct {
	ACLRules       []Rule `json:"acl_rules"`
	ChinaRoutes    bool   `json:"china_routes_enable"`
	ChinaRoutesPath string `json:"china_routes_path"`
}

type Router struct {
	rules         []Rule
	domains       map[string]bool
	domainTrie    *RadixTrie        // 域名基数树（将域名转换为IP后存储）
	ipTrie        *RadixTrie        // IP基数树
	chinaTrie     *RadixTrie        // 中国IP基数树
	configPath    string
	supportsIPv4  bool
	supportsIPv6  bool
}

type MatchResult struct {
	Action Action
	Match  bool
	Rule   *Rule
}

func NewRouter(configPath string) (*Router, error) {
	r := &Router{
		rules:        make([]Rule, 0),
		domains:      make(map[string]bool),
		domainTrie:   NewRadixTrie(),
		ipTrie:       NewRadixTrie(),
		chinaTrie:    NewRadixTrie(),
		configPath:   configPath,
		supportsIPv4: true,
		supportsIPv6: true,
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

	var config RouterConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	// 加载 ACL 规则
	r.rules = config.ACLRules

	// 加载中国 IP 段
	if config.ChinaRoutes && config.ChinaRoutesPath != "" {
		if err := r.loadChinaRoutes(config.ChinaRoutesPath); err != nil {
			// 如果文件不存在，创建默认的中国 IP 段
			r.createDefaultChinaRoutes(config.ChinaRoutesPath)
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
			Pattern:     line,
			Description: "中国IP段直连",
		}); err != nil {
			// 如果解析失败，跳过这一行
			continue
		}
	}

	return nil
}

func (r *Router) createDefaultChinaRoutes(filePath string) {
	// 创建一些常见的中国 IP 段（包括IPv4和IPv6）
	defaultChinaRoutes := `# 中国大陆 IP 段文件
# IPv4 DNS
114.114.114.114/32
223.5.5.5/32
223.6.6.6/32
119.29.29.29/32
180.76.76.76/32
123.125.81.6/32

# IPv6 DNS
2400:da00::6666/128
2001:4860:4860::8888/128
2001:4860:4860::8844/128

# 常见中国网段（示例）
58.240.0.0/16
202.96.0.0/12
211.136.0.0/16
218.0.0.0/8
`

	// 确保目录存在
	dir := filepath.Dir(filePath)
	os.MkdirAll(dir, 0755)

	ioutil.WriteFile(filePath, []byte(defaultChinaRoutes), 0644)
	r.loadChinaRoutes(filePath)
}

func (r *Router) precompileRules() {
	for i := range r.rules {
		rule := &r.rules[i]

		// 判断是否为域名
		if strings.Contains(rule.Pattern, "*") || strings.Contains(rule.Pattern, ".") {
			if !strings.Contains(rule.Pattern, "/") && net.ParseIP(rule.Pattern) == nil {
				r.domains[rule.Pattern] = true
			}
		}

		// 将IP规则添加到基数树中
		if strings.Contains(rule.Pattern, "/") || net.ParseIP(rule.Pattern) != nil {
			r.ipTrie.Insert(rule.Pattern, rule.Action, rule)
		}
	}
}

func (r *Router) ShouldBlock(host string, port int) bool {
	result := r.matchRule(host, port)
	return result.Action == ActionBlock
}

func (r *Router) ShouldDirect(host string, port int) bool {
	result := r.matchRule(host, port)
	return result.Action == ActionAllow || (result.Action == "" && r.isChinaIP(host))
}

func (r *Router) ShouldProxy(host string, port int) bool {
	result := r.matchRule(host, port)
	return result.Action == ActionDeny
}

func (r *Router) matchRule(host string, port int) MatchResult {
	// 1. 首先检查IP基数树（最高优先级）
	if ip := net.ParseIP(host); ip != nil {
		if action, found, rule := r.ipTrie.Lookup(host); found {
			return MatchResult{
				Action: action,
				Match:  true,
				Rule:   rule,
			}
		}
	}

	// 2. 检查中国IP基数树
	if ip := net.ParseIP(host); ip != nil {
		if action, found, rule := r.chinaTrie.Lookup(host); found {
			return MatchResult{
				Action: action,
				Match:  true,
				Rule:   rule,
			}
		}
	}

	// 3. 检查域名规则
	portStr := strconv.Itoa(port)
	for i := range r.rules {
		rule := &r.rules[i]

		if r.matchPattern(rule.Pattern, host, portStr) {
			return MatchResult{
				Action: rule.Action,
				Match:  true,
				Rule:   rule,
			}
		}
	}

	// 4. 默认行为：如果没有匹配规则，检查是否为中国域名
	if r.isChinaDomain(host) {
		return MatchResult{
			Action: ActionAllow,
			Match:  true,
		}
	}

	return MatchResult{
		Action: ActionDeny,
		Match:  false,
	}
}

func (r *Router) matchPattern(pattern, host, port string) bool {
	// 端口匹配
	if pattern == port {
		return true
	}

	// CIDR 网段匹配
	if strings.Contains(pattern, "/") {
		if _, ipNet, err := net.ParseCIDR(pattern); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				return ipNet.Contains(ip)
			}
		}
	}

	// 精确 IP 匹配
	if ip := net.ParseIP(pattern); ip != nil {
		return pattern == host
	}

	// 域名匹配
	if strings.Contains(pattern, "*") {
		// 通配符匹配
		regex := strings.ReplaceAll(pattern, ".", "\\.")
		regex = strings.ReplaceAll(regex, "*", ".*")
		matched, _ := regexp.MatchString("^"+regex+"$", host)
		return matched
	} else if strings.Contains(pattern, ".") {
		// 后缀匹配
		return strings.HasSuffix(host, pattern) || host == pattern
	}

	return false
}

func (r *Router) isChinaIP(host string) bool {
	// 检查是否在中国 IP 基数树中
	if _, found, _ := r.chinaTrie.Lookup(host); found {
		return true
	}

	return false
}

func (r *Router) isChinaDomain(host string) bool {
	// 检查域名后缀
	chinaTLDs := []string{".cn", ".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".ac.cn", ".ah.cn", ".bj.cn", ".cq.cn", ".fj.cn", ".gd.cn", ".gs.cn", ".gz.cn", ".gx.cn", ".ha.cn", ".hb.cn", ".he.cn", ".hi.cn", ".hl.cn", ".hn.cn", ".jl.cn", ".js.cn", ".jx.cn", ".ln.cn", ".nm.cn", ".nx.cn", ".qh.cn", ".sc.cn", ".sd.cn", ".sh.cn", ".sn.cn", ".sx.cn", ".tj.cn", ".tw.cn", ".xj.cn", ".xz.cn", ".yn.cn", ".zj.cn", ".hk.cn", ".mo.cn"}

	for _, tld := range chinaTLDs {
		if strings.HasSuffix(strings.ToLower(host), tld) {
			return true
		}
	}

	// 检查知名中国域名
	chinaDomains := []string{"baidu.com", "qq.com", "taobao.com", "tmall.com", "jd.com", "163.com", "sina.com.cn", "sohu.com", "weibo.com", "alipay.com", "360.cn", "pinduoduo.com"}

	for _, domain := range chinaDomains {
		if strings.HasSuffix(strings.ToLower(host), domain) {
			return true
		}
	}

	return false
}

func (r *Router) GetStats() map[string]int {
	stats := make(map[string]int)

	// 统计规则数量
	for _, rule := range r.rules {
		stats[string(rule.Action)]++
	}

	// 获取基数树统计信息
	ipv4Nodes, ipv6Nodes, ipRules := r.ipTrie.GetStats()
	chinaIPv4Nodes, chinaIPv6Nodes, chinaRules := r.chinaTrie.GetStats()

	stats["total_rules"] = len(r.rules)
	stats["ipv4_nodes"] = ipv4Nodes
	stats["ipv6_nodes"] = ipv6Nodes
	stats["ip_rules"] = ipRules
	stats["china_ipv4_nodes"] = chinaIPv4Nodes
	stats["china_ipv6_nodes"] = chinaIPv6Nodes
	stats["china_rules"] = chinaRules
	stats["supports_ipv4"] = 1
	stats["supports_ipv6"] = 1

	return stats
}

func (r *Router) Reload() error {
	return r.loadConfig()
}
package rules

import (
	"bufio"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"smartproxy/internal/chnroute"
)

type ProxyRule struct {
	Type         string
	Value        string
	Alias        string
	parsedPrefix *netip.Prefix
}

type proxyTarget struct {
	alias string
	index int
}

// ruleSet is an immutable snapshot of the effective ACL data. Readers load the
// current snapshot through Engine.rules and never mutate it; writers build a
// fresh snapshot and atomically swap the pointer, so hot paths take no locks.
type ruleSet struct {
	allowedPorts    map[int]bool
	allowedIPs      map[string]bool
	allowedCIDR     *chnroute.Trie
	allowedDomains  map[string]bool
	allowedSuffixes *suffixTrie

	blockedPorts    map[int]bool
	blockedIPs      map[string]bool
	blockedCIDR     *chnroute.Trie
	blockedDomains  map[string]bool
	blockedSuffixes *suffixTrie

	proxyPorts    map[int]proxyTarget
	proxyIPs      map[string]proxyTarget
	proxyCIDRTrie *proxyCidrTrie
	proxyDomains  map[string]proxyTarget
	proxySuffixes *proxySuffixTrie

	proxyRules []ProxyRule
}

// Engine holds the currently effective ACL rules as an immutable snapshot.
type Engine struct {
	rules atomic.Pointer[ruleSet]
}

func New(filePath string) (*Engine, error) {
	e := &Engine{}
	if err := e.Load(filePath); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) Load(path string) error {
	rs := newRuleSet()
	if err := rs.load(path); err != nil {
		return err
	}
	e.rules.Store(rs)
	return nil
}

func (e *Engine) Reload(path string) error {
	return e.Load(path)
}

// Pull atomically replaces the effective rule snapshot with other's snapshot,
// eliminating duplicate disk parsing and TOCTOU races during engine reloads.
func (e *Engine) Pull(other *Engine) {
	if other != nil {
		e.rules.Store(other.rules.Load())
	}
}

func newRuleSet() *ruleSet {
	rs := &ruleSet{}
	rs.reset()
	return rs
}

func (rs *ruleSet) reset() {
	rs.allowedPorts = make(map[int]bool)
	rs.allowedIPs = make(map[string]bool)
	rs.allowedCIDR = chnroute.New()
	rs.allowedDomains = make(map[string]bool)
	rs.allowedSuffixes = newSuffixTrie()

	rs.blockedPorts = make(map[int]bool)
	rs.blockedIPs = make(map[string]bool)
	rs.blockedCIDR = chnroute.New()
	rs.blockedDomains = make(map[string]bool)
	rs.blockedSuffixes = newSuffixTrie()

	rs.proxyPorts = make(map[int]proxyTarget)
	rs.proxyIPs = make(map[string]proxyTarget)
	rs.proxyCIDRTrie = newProxyCidrTrie()
	rs.proxyDomains = make(map[string]proxyTarget)
	rs.proxySuffixes = newProxySuffixTrie()
	rs.proxyRules = nil
}

func (rs *ruleSet) load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(strings.ToLower(line))
		if len(parts) < 2 {
			continue
		}
		action := parts[0]
		objType := parts[1]

		switch action {
		case "allow":
			rs.parseAllowBlock(objType, parts, true)
		case "block":
			rs.parseAllowBlock(objType, parts, false)
		case "proxy":
			if len(parts) >= 4 {
				rule := ProxyRule{Type: parts[1], Value: parts[2], Alias: parts[3]}
				ruleIndex := len(rs.proxyRules)
				target := proxyTarget{alias: rule.Alias, index: ruleIndex}
				switch rule.Type {
				case "port":
					port, err := strconv.Atoi(rule.Value)
					if err != nil {
						slog.Warn("invalid port in proxy rule", "value", rule.Value)
						continue
					}
					if _, exists := rs.proxyPorts[port]; !exists {
						rs.proxyPorts[port] = target
					}
				case "ip":
					if strings.Contains(rule.Value, "/") {
						prefix, err := netip.ParsePrefix(rule.Value)
						if err != nil {
							addr, err2 := netip.ParseAddr(rule.Value)
							if err2 != nil {
								slog.Warn("invalid CIDR in proxy rule", "value", rule.Value)
								continue
							}
							prefix = netip.PrefixFrom(addr, addr.BitLen())
						}
						rule.parsedPrefix = &prefix
						rs.proxyCIDRTrie.insert(prefix, target)
					} else {
						if _, exists := rs.proxyIPs[rule.Value]; !exists {
							rs.proxyIPs[rule.Value] = target
						}
					}
				case "cidr":
					prefix, err := netip.ParsePrefix(rule.Value)
					if err != nil {
						addr, err2 := netip.ParseAddr(rule.Value)
						if err2 != nil {
							slog.Warn("invalid CIDR in proxy rule", "value", rule.Value)
							continue
						}
						prefix = netip.PrefixFrom(addr, addr.BitLen())
					}
					rule.parsedPrefix = &prefix
					rs.proxyCIDRTrie.insert(prefix, target)
				case "domain":
					d := normalizeDomain(rule.Value)
					if strings.HasPrefix(d, "*.") {
						rs.proxySuffixes.insert(d[1:], target)
					} else {
						if _, exists := rs.proxyDomains[d]; !exists {
							rs.proxyDomains[d] = target
						}
					}
				}
				rs.proxyRules = append(rs.proxyRules, rule)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	slog.Info("rules loaded",
		"allowPorts", len(rs.allowedPorts),
		"blockPorts", len(rs.blockedPorts),
		"proxyPorts", len(rs.proxyPorts),
		"proxyIPs", len(rs.proxyIPs),
		"proxyCIDRs", rs.proxyCIDRTrie.size(),
		"proxyDomains", len(rs.proxyDomains),
		"totalProxyRules", len(rs.proxyRules))
	return nil
}

func (rs *ruleSet) parseAllowBlock(objType string, parts []string, isAllow bool) {
	if len(parts) < 3 {
		return
	}
	value := parts[2]

	switch objType {
	case "port":
		port, err := strconv.Atoi(value)
		if err != nil {
			return
		}
		if isAllow {
			rs.allowedPorts[port] = true
		} else {
			rs.blockedPorts[port] = true
		}
	case "ip":
		if strings.Contains(value, "/") {
			rs.parseCIDRInto(value, isAllow)
		} else {
			if isAllow {
				rs.allowedIPs[value] = true
			} else {
				rs.blockedIPs[value] = true
			}
		}
	case "cidr":
		rs.parseCIDRInto(value, isAllow)
	case "domain":
		if strings.HasPrefix(value, "*.") {
			suffix := value[1:]
			if isAllow {
				rs.allowedSuffixes.insert(suffix)
			} else {
				rs.blockedSuffixes.insert(suffix)
			}
		} else {
			if isAllow {
				rs.allowedDomains[value] = true
			} else {
				rs.blockedDomains[value] = true
			}
		}
	}
}

func (rs *ruleSet) parseCIDRInto(value string, isAllow bool) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		addr, err2 := netip.ParseAddr(value)
		if err2 != nil {
			return
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if isAllow {
		rs.allowedCIDR.Insert(prefix)
	} else {
		rs.blockedCIDR.Insert(prefix)
	}
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(domain), ".")
}

// ProxyRules returns the currently effective proxy rules. The returned slice
// belongs to an immutable snapshot and must not be modified.
func (e *Engine) ProxyRules() []ProxyRule {
	rs := e.rules.Load()
	if rs == nil {
		return nil
	}
	return rs.proxyRules
}

func (e *Engine) IsPortBlocked(port int) bool {
	rs := e.rules.Load()
	if rs == nil {
		return false
	}
	if rs.allowedPorts[port] {
		return false
	}
	return rs.blockedPorts[port]
}

func (e *Engine) IsIPBlocked(ip string) bool {
	rs := e.rules.Load()
	if rs == nil {
		return false
	}
	return rs.isIPBlocked(ip)
}

func (rs *ruleSet) isIPBlocked(ip string) bool {
	if rs.allowedIPs[ip] {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if rs.allowedCIDR.Contains(parsed) {
		return false
	}
	if rs.blockedIPs[ip] {
		return true
	}
	return rs.blockedCIDR.Contains(parsed)
}

func (e *Engine) IsDomainBlocked(domain string) bool {
	rs := e.rules.Load()
	if rs == nil {
		return false
	}
	domain = normalizeDomain(domain)
	return rs.isDomainBlocked(domain)
}

func (rs *ruleSet) isDomainBlocked(domain string) bool {
	if rs.allowedDomains[domain] {
		return false
	}
	if rs.allowedSuffixes.match(domain) {
		return false
	}
	if rs.blockedDomains[domain] {
		return true
	}
	return rs.blockedSuffixes.match(domain)
}

func (e *Engine) MatchProxyRule(targetIP string, targetPort int, domain string) (alias string, matched bool) {
	rs := e.rules.Load()
	if rs == nil {
		return "", false
	}

	if rs.allowedPorts[targetPort] {
		return "", false
	}
	if rs.allowedIPs[targetIP] {
		return "", false
	}
	if parsed := net.ParseIP(targetIP); parsed != nil && rs.allowedCIDR.Contains(parsed) {
		return "", false
	}
	if domain != "" {
		d := normalizeDomain(domain)
		if rs.allowedDomains[d] || rs.allowedSuffixes.match(d) {
			return "", false
		}
	}

	bestIndex := -1
	bestAlias := ""

	if t, ok := rs.proxyPorts[targetPort]; ok {
		if bestIndex == -1 || t.index < bestIndex {
			bestIndex = t.index
			bestAlias = t.alias
		}
	}
	if t, ok := rs.proxyIPs[targetIP]; ok {
		if bestIndex == -1 || t.index < bestIndex {
			bestIndex = t.index
			bestAlias = t.alias
		}
	}
	if domain != "" {
		d := normalizeDomain(domain)
		if t, ok := rs.proxyDomains[d]; ok {
			if bestIndex == -1 || t.index < bestIndex {
				bestIndex = t.index
				bestAlias = t.alias
			}
		}
		if t, ok := rs.proxySuffixes.match(d); ok {
			if bestIndex == -1 || t.index < bestIndex {
				bestIndex = t.index
				bestAlias = t.alias
			}
		}
	}
	if t, ok := rs.proxyCIDRTrie.lookup(targetIP); ok {
		if bestIndex == -1 || t.index < bestIndex {
			bestIndex = t.index
			bestAlias = t.alias
		}
	}

	if bestIndex != -1 {
		return bestAlias, true
	}
	return "", false
}

type proxySuffixTrie struct {
	root map[string]*proxySuffixNode
}

type proxySuffixNode struct {
	target    proxyTarget
	hasTarget bool
	children  map[string]*proxySuffixNode
}

func newProxySuffixTrie() *proxySuffixTrie {
	return &proxySuffixTrie{root: make(map[string]*proxySuffixNode)}
}

func (t *proxySuffixTrie) insert(suffix string, target proxyTarget) {
	labels := strings.Split(strings.TrimPrefix(suffix, "."), ".")
	if len(labels) == 0 {
		return
	}
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	current := t.root
	for i, label := range labels {
		node, ok := current[label]
		if !ok {
			node = &proxySuffixNode{children: make(map[string]*proxySuffixNode)}
			current[label] = node
		}
		if i == len(labels)-1 && !node.hasTarget {
			node.target = target
			node.hasTarget = true
		}
		current = node.children
	}
}

func (t *proxySuffixTrie) match(domain string) (proxyTarget, bool) {
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return proxyTarget{}, false
	}
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	current := t.root
	var bestTarget proxyTarget
	var matched bool
	for i, label := range labels {
		node, ok := current[label]
		if !ok {
			break
		}
		if node.hasTarget && i < len(labels)-1 {
			bestTarget = node.target
			matched = true
		}
		current = node.children
	}
	return bestTarget, matched
}

type proxyCidrTrie struct {
	root  *proxyCidrNode
	count int
}

type proxyCidrNode struct {
	children  [2]*proxyCidrNode
	target    proxyTarget
	hasTarget bool
}

func newProxyCidrTrie() *proxyCidrTrie {
	return &proxyCidrTrie{root: &proxyCidrNode{}}
}

func (t *proxyCidrTrie) size() int { return t.count }

func (t *proxyCidrTrie) insert(prefix netip.Prefix, target proxyTarget) {
	bits := prefix.Bits()
	addr := prefix.Addr()
	raw := addr.As16()
	bitOffset := 0
	if addr.Is4() {
		bitOffset = 96
	}
	node := t.root
	for i := bitOffset; i < bitOffset+bits; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (raw[byteIdx] >> bitIdx) & 1
		if node.children[bit] == nil {
			node.children[bit] = &proxyCidrNode{}
		}
		node = node.children[bit]
	}
	if !node.hasTarget {
		node.target = target
		node.hasTarget = true
		t.count++
	}
}

func (t *proxyCidrTrie) lookup(ipStr string) (proxyTarget, bool) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return proxyTarget{}, false
	}
	raw := addr.As16()
	bitOffset := 0
	if addr.Is4() {
		bitOffset = 96
	}
	node := t.root
	bestIndex := -1
	var bestTarget proxyTarget
	for i := bitOffset; i < 128; i++ {
		if node.hasTarget {
			if bestIndex == -1 || node.target.index < bestIndex {
				bestIndex = node.target.index
				bestTarget = node.target
			}
		}
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (raw[byteIdx] >> bitIdx) & 1
		if node.children[bit] == nil {
			break
		}
		node = node.children[bit]
	}
	if node != nil && node.hasTarget {
		if bestIndex == -1 || node.target.index < bestIndex {
			bestIndex = node.target.index
			bestTarget = node.target
		}
	}
	if bestIndex != -1 {
		return bestTarget, true
	}
	return proxyTarget{}, false
}

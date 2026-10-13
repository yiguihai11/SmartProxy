package rules

import (
	"bufio"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
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

type proxyGlobRule struct {
	pattern string
	target  proxyTarget
}

// globBucket 是 glob 规则的下标分桶:把「逐条 path.Match 全量线性扫描」压成
// 「只扫可能命中的那几条」。生产 ACL 里 14 条中缀 glob(*ads*-*.zijieapi.com 之类)
// 全靠它从每次域名匹配里消掉。
//
// 依据:path.Match 要求整个名字与整个模式匹配,所以模式里最后一个 '*' 之后的部分
// 必须逐字出现在名字的末尾 ——「名字以该字面后缀结尾」是命中的必要条件。
// 分桶只做排除,候选仍然要跑真正的 path.Match,所以不会凭空多出命中。
//
// 后缀不以 '.' 开头(没法按标签边界查表)、含模式元字符(* ? [ \)或最后一个 '*'
// 之后没有字面后缀的规则,一律进 always 逐条扫描:兜底方向是宁可多扫,绝不漏命中。
type globBucket struct {
	bySuffix map[string][]int // 字面后缀(含前导 '.')→ 规则下标
	always   []int
}

// bucketSuffix 取出 pattern 里能当桶键的字面后缀。ok=false 表示这条规则只能兜底扫描。
func bucketSuffix(pattern string) (string, bool) {
	star := strings.LastIndexByte(pattern, '*')
	if star < 0 {
		// 没有 '*' 的 glob(? 或 [):模式尾部不是确定字面量,分不了桶。
		return "", false
	}
	tail := pattern[star+1:]
	if len(tail) < 1 || tail[0] != '.' {
		// 不以 '.' 开头就无法用「按标签边界查 map」定位,空尾部则等于没有约束。
		return "", false
	}
	if strings.ContainsAny(tail, `*?[\`) {
		return "", false
	}
	return tail, true
}

// newGlobBucket 为 patterns 建索引(patterns[i] 是第 i 条规则的模式)。
func newGlobBucket(patterns []string) globBucket {
	var gb globBucket
	for i, p := range patterns {
		key, ok := bucketSuffix(p)
		if !ok {
			gb.always = append(gb.always, i)
			continue
		}
		if gb.bySuffix == nil {
			gb.bySuffix = make(map[string][]int)
		}
		gb.bySuffix[key] = append(gb.bySuffix[key], i)
	}
	return gb
}

// matchAny 判断 domain 是否命中 patterns 里的任意一条。
func (gb *globBucket) matchAny(patterns []string, domain string) bool {
	for _, i := range gb.always {
		if ok, _ := path.Match(patterns[i], domain); ok {
			return true
		}
	}
	// 桶键以 '.' 开头,所以在 domain 的每个标签边界上各查一次 map 就能覆盖全部
	// 可能的后缀:查找次数是域名标签数(常数级),与规则条数无关。
	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] != '.' {
			continue
		}
		for _, j := range gb.bySuffix[domain[i:]] {
			if ok, _ := path.Match(patterns[j], domain); ok {
				return true
			}
		}
	}
	return false
}

// bestMatchingGlob 返回命中 domain 的规则里 target.index 最小的那条;ok=false 表示没命中。
// ACL 的语义是「靠前的规则优先」,所以必须比较全部命中项,不能命中一条就返回:
// 分桶只是把不可能命中的规则排除掉,会命中哪些仍然由 path.Match 决定。
//
// 这里把扫描体写了两遍而不是抽成回调:回调闭包捕获 best 后每次调用都可能让
// best 逃逸到堆(1 alloc/op),而这条路径每次流建立都会走。
func (gb *globBucket) bestMatchingGlob(globs []proxyGlobRule, domain string) (proxyGlobRule, bool) {
	var best proxyGlobRule
	found := false
	for _, i := range gb.always {
		pg := globs[i]
		if ok, _ := path.Match(pg.pattern, domain); ok && (!found || pg.target.index < best.target.index) {
			best, found = pg, true
		}
	}
	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] != '.' {
			continue
		}
		for _, j := range gb.bySuffix[domain[i:]] {
			pg := globs[j]
			if ok, _ := path.Match(pg.pattern, domain); ok && (!found || pg.target.index < best.target.index) {
				best, found = pg, true
			}
		}
	}
	return best, found
}

// ruleSet is an immutable snapshot of the effective ACL data. Readers load the
// current snapshot through Engine.rules and never mutate it; writers build a
// fresh snapshot and atomically swap the pointer, so hot paths take no locks.
type ruleSet struct {
	// CIDR prefixes are accumulated while loading and inserted in one batch,
	// avoiding a full trie clone for every ACL line.
	pendingAllowedCIDR []netip.Prefix
	pendingBlockedCIDR []netip.Prefix

	allowedPorts    map[int]bool
	allowedIPs      map[string]bool
	allowedCIDR     *chnroute.Trie
	allowedDomains  map[string]bool
	allowedSuffixes *suffixTrie
	allowedGlobs    []string
	allowedGlobIdx  globBucket

	blockedPorts    map[int]bool
	blockedIPs      map[string]bool
	blockedCIDR     *chnroute.Trie
	blockedDomains  map[string]bool
	blockedSuffixes *suffixTrie
	blockedGlobs    []string
	blockedGlobIdx  globBucket

	proxyPorts    map[int]proxyTarget
	proxyIPs      map[string]proxyTarget
	proxyCIDRTrie *proxyCidrTrie
	proxyDomains  map[string]proxyTarget
	proxySuffixes *proxySuffixTrie
	proxyGlobs    []proxyGlobRule
	proxyGlobIdx  globBucket

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
	rs.allowedGlobs = nil
	rs.allowedGlobIdx = globBucket{}

	rs.blockedPorts = make(map[int]bool)
	rs.blockedIPs = make(map[string]bool)
	rs.blockedCIDR = chnroute.New()
	rs.blockedDomains = make(map[string]bool)
	rs.blockedSuffixes = newSuffixTrie()
	rs.blockedGlobs = nil
	rs.blockedGlobIdx = globBucket{}

	rs.proxyPorts = make(map[int]proxyTarget)
	rs.proxyIPs = make(map[string]proxyTarget)
	rs.proxyCIDRTrie = newProxyCidrTrie()
	rs.proxyDomains = make(map[string]proxyTarget)
	rs.proxySuffixes = newProxySuffixTrie()
	rs.proxyGlobs = nil
	rs.proxyGlobIdx = globBucket{}
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
		rawLine := scanner.Text()
		action, objType, value, alias, ok := parseRuleTokens(rawLine)
		if !ok {
			continue
		}

		switch action {
		case "allow":
			rs.parseAllowBlockValue(objType, value, true)
		case "block":
			rs.parseAllowBlockValue(objType, value, false)
		case "proxy":
			rule := ProxyRule{Type: objType, Value: value, Alias: alias}
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
				if isPureSuffixPattern(d) {
					rs.proxySuffixes.insert(d[1:], target)
				} else if isGlobPattern(d) {
					rs.proxyGlobs = append(rs.proxyGlobs, proxyGlobRule{pattern: d, target: target})
				} else {
					if _, exists := rs.proxyDomains[d]; !exists {
						rs.proxyDomains[d] = target
					}
				}
			}
			rs.proxyRules = append(rs.proxyRules, rule)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	// Build each CIDR trie once after parsing the file. InsertBatch clones the
	// current roots once, unlike Insert which clones the entire trie per prefix.
	rs.allowedCIDR.InsertBatch(rs.pendingAllowedCIDR)
	rs.blockedCIDR.InsertBatch(rs.pendingBlockedCIDR)
	rs.pendingAllowedCIDR = nil
	rs.pendingBlockedCIDR = nil

	// glob 分桶也在解析完成后建一次:桶只依赖模式本身,建完之后整份 ruleSet 就是
	// 只读快照,热路径上不再有任何索引维护。
	rs.allowedGlobIdx = newGlobBucket(rs.allowedGlobs)
	rs.blockedGlobIdx = newGlobBucket(rs.blockedGlobs)
	proxyGlobPatterns := make([]string, len(rs.proxyGlobs))
	for i, pg := range rs.proxyGlobs {
		proxyGlobPatterns[i] = pg.pattern
	}
	rs.proxyGlobIdx = newGlobBucket(proxyGlobPatterns)

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

// parseRuleTokens parses an ACL line into action, objType, value, and alias.
// It supports:
//   - Comments (# ...)
//   - Spaces, unicode, emojis, and quotes in aliases:
//       proxy domain google.com "Hong Kong 01"
//       proxy domain google.com 'Hong Kong 01'
//       proxy domain google.com Hong Kong 01
//       proxy domain google.com [v2rayfree] 未知 SS-01 | free-nodes # remark
//   - Preserves original case for alias, while action, objType, and domain value are lowercased.
func parseRuleTokens(line string) (action, objType, value, alias string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", "", "", false
	}

	// 1. Action
	sp1 := strings.IndexAny(line, " \t")
	if sp1 == -1 {
		return "", "", "", "", false
	}
	action = strings.ToLower(line[:sp1])
	rest := strings.TrimSpace(line[sp1:])

	// 2. Object Type (port, ip, cidr, domain)
	sp2 := strings.IndexAny(rest, " \t")
	if sp2 == -1 {
		return "", "", "", "", false
	}
	objType = strings.ToLower(rest[:sp2])
	rest = strings.TrimSpace(rest[sp2:])

	// 3. Value
	sp3 := strings.IndexAny(rest, " \t")
	if sp3 == -1 {
		value = rest
		rest = ""
	} else {
		value = rest[:sp3]
		rest = strings.TrimSpace(rest[sp3:])
	}

	// Clean any inline comments from value if there was no rest
	if hashIdx := strings.IndexByte(value, '#'); hashIdx != -1 {
		value = strings.TrimSpace(value[:hashIdx])
		rest = ""
	}

	if objType == "domain" {
		value = strings.ToLower(value)
	}

	if action != "proxy" {
		return action, objType, value, "", value != ""
	}

	// 4. Alias for proxy action
	if rest == "" {
		return "", "", "", "", false
	}

	// Check if quoted with " or '
	if rest[0] == '"' || rest[0] == '\'' {
		q := rest[0]
		endQuote := strings.IndexByte(rest[1:], q)
		if endQuote != -1 {
			alias = rest[1 : 1+endQuote]
		} else {
			// Unclosed quote: take remainder up to comment
			alias = rest[1:]
			if hashIdx := strings.IndexByte(alias, '#'); hashIdx != -1 {
				alias = alias[:hashIdx]
			}
			alias = strings.TrimSpace(alias)
		}
	} else {
		// Unquoted alias: everything up to '#' is the alias
		if hashIdx := strings.IndexByte(rest, '#'); hashIdx != -1 {
			rest = rest[:hashIdx]
		}
		alias = strings.TrimSpace(rest)
	}

	if alias == "" {
		return "", "", "", "", false
	}
	return action, objType, value, alias, true
}

func (rs *ruleSet) parseAllowBlockValue(objType, value string, isAllow bool) {
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
		d := normalizeDomain(value)
		if isPureSuffixPattern(d) {
			suffix := d[1:]
			if isAllow {
				rs.allowedSuffixes.insert(suffix)
			} else {
				rs.blockedSuffixes.insert(suffix)
			}
		} else if isGlobPattern(d) {
			if isAllow {
				rs.allowedGlobs = append(rs.allowedGlobs, d)
			} else {
				rs.blockedGlobs = append(rs.blockedGlobs, d)
			}
		} else {
			if isAllow {
				rs.allowedDomains[d] = true
			} else {
				rs.blockedDomains[d] = true
			}
		}
	}
}

func isPureSuffixPattern(domain string) bool {
	return strings.HasPrefix(domain, "*.") && !strings.ContainsAny(domain[2:], "*?[")
}

func isGlobPattern(domain string) bool {
	return strings.ContainsAny(domain, "*?[")
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
		rs.pendingAllowedCIDR = append(rs.pendingAllowedCIDR, prefix)
	} else {
		rs.pendingBlockedCIDR = append(rs.pendingBlockedCIDR, prefix)
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
	if rs.allowedGlobIdx.matchAny(rs.allowedGlobs, domain) {
		return false
	}
	if rs.blockedDomains[domain] {
		return true
	}
	if rs.blockedSuffixes.match(domain) {
		return true
	}
	if rs.blockedGlobIdx.matchAny(rs.blockedGlobs, domain) {
		return true
	}
	return false
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
		if rs.allowedGlobIdx.matchAny(rs.allowedGlobs, d) {
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
		// 命中多条时取 index 最小(ACL 靠前优先),所以按 index 而不是按别名比较。
		if pg, ok := rs.proxyGlobIdx.bestMatchingGlob(rs.proxyGlobs, d); ok {
			if bestIndex == -1 || pg.target.index < bestIndex {
				bestIndex = pg.target.index
				bestAlias = pg.target.alias
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
	// Walk labels from right to left without strings.Split or a temporary
	// reversed slice. Two rules differ from suffixTrie.match: a deeper target
	// overrides a shallower one, so the walk must not stop at the first hit,
	// and a missing label ends the walk while keeping whatever matched above
	// it. Like suffixTrie, a "*.a.com" rule covers a.com itself.
	current := t.root
	remaining := domain
	var bestTarget proxyTarget
	var matched bool
	for remaining != "" {
		label := remaining
		if i := strings.LastIndexByte(remaining, '.'); i >= 0 {
			label, remaining = remaining[i+1:], remaining[:i]
		} else {
			remaining = ""
		}
		node, ok := current[label]
		if !ok {
			break
		}
		if node.hasTarget {
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

var aclFileMu sync.Mutex

// AppendProxyRule appends a `proxy domain <domain> <alias>` or `proxy ip <host> <alias>`
// rule to the ACL file at aclPath if not already present. It safely trims and canonicalizes
// the target before deduplication. It is thread-safe across concurrent callers.
func AppendProxyRule(aclPath, host, domain, alias string) error {
	if aclPath == "" {
		return nil
	}
	aclFileMu.Lock()
	defer aclFileMu.Unlock()

	if alias == "" {
		alias = "default"
	}
	var line string
	if domain != "" {
		d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		line = "proxy domain " + d + " " + alias
	} else if host != "" {
		h := strings.Trim(strings.TrimSpace(host), "[]")
		line = "proxy ip " + h + " " + alias
	} else {
		return nil
	}

	exist, err := aclLineExists(aclPath, line)
	if err != nil {
		return err
	}
	if exist {
		slog.Debug("ACL proxy rule already exists in file", "line", line)
		return nil
	}

	f, err := os.OpenFile(aclPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString("\n" + line + "\n"); err != nil {
		return err
	}
	slog.Info("persisted proxy rule to ACL file", "path", aclPath, "line", line)
	return nil
}

func aclLineExists(path, want string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == want {
			return true, nil
		}
	}
	return false, sc.Err()
}


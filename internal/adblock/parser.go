package adblock

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
)

// maxLinesPerList 是单条清单行数上限: 防止坏清单占用过多内存。
const maxLinesPerList = 500000

// maxTotalRules 是生效条目总数上限。
const maxTotalRules = 500000

// ParseStats 记录单条清单的解析统计。
type ParseStats struct {
	Lines    int            `json:"lines"`
	Kept     int            `json:"kept"`
	Skipped  int            `json:"skipped"`
	Reasons  map[string]int `json:"reasons,omitempty"`
}

func newParseStats() ParseStats {
	return ParseStats{
		Reasons: make(map[string]int),
	}
}

func (s *ParseStats) addSkip(reason string) {
	s.Skipped++
	if s.Reasons == nil {
		s.Reasons = make(map[string]int)
	}
	s.Reasons[reason]++
}

// isNoisyHost 判定 hosts 清单中的系统本地噪音域名。
func isNoisyHost(d string) bool {
	switch d {
	case "localhost", "localhost.localdomain", "local", "broadcasthost",
		"ip6-localhost", "ip6-loopback", "ip6-allnodes", "ip6-allrouters":
		return true
	}
	if strings.HasSuffix(d, ".local") || strings.HasSuffix(d, ".localhost") {
		return true
	}
	return net.ParseIP(d) != nil
}

// isAdblockBlackholeIP 判定 hosts 行的 IP 是否为广告拦截假地址。
func isAdblockBlackholeIP(ipStr string) bool {
	switch ipStr {
	case "0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0":
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsUnspecified() || ip.IsLoopback()
}

// ParseList 流式解析单个清单数据流。
func ParseList(r io.Reader) (suffixes, allow, badfilters []string, stats ParseStats, err error) {
	stats = newParseStats()
	scanner := bufio.NewScanner(r)
	// 放大缓冲到 1 MB
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		stats.Lines++
		if stats.Lines > maxLinesPerList {
			stats.addSkip("line_limit_exceeded")
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 顺序陷阱: 元素隐藏判定必须在注释判定之前, 因为 ##.ad 以 # 开头
		if isCosmeticRule(line) {
			stats.addSkip("cosmetic")
			continue
		}

		// 注释与头部判定
		if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}

		// 检查 $badfilter
		if bf, ok := extractBadfilter(line); ok {
			badfilters = append(badfilters, bf)
			stats.addSkip("badfilter")
			continue
		}

		// 检查 URL 路径规则或正则规则
		if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") && len(line) > 2 {
			stats.addSkip("regex")
			continue
		}

		// hosts 格式检查
		if fields := strings.Fields(line); len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
			if !isAdblockBlackholeIP(fields[0]) {
				// 真实 IP 映射而非屏蔽覆盖, 跳过
				stats.addSkip("real_ip_host")
				continue
			}
			matchedAny := false
			for _, alias := range fields[1:] {
				if strings.HasPrefix(alias, "#") {
					break // 行内注释
				}
				alias = strings.ToLower(strings.TrimSpace(alias))
				if isNoisyHost(alias) {
					stats.addSkip("noise_hosts")
					continue
				}
				norm, _, ok := normalizeRuleDomain(alias)
				if !ok {
					stats.addSkip("invalid_domain")
					continue
				}
				suffixes = append(suffixes, norm)
				stats.Kept++
				matchedAny = true
			}
			if !matchedAny && len(fields) > 1 && !strings.HasPrefix(fields[1], "#") {
				// 未保留任何条目
			}
			continue
		}

		// ABP 语法: @@|| 开头 (例外/白名单)
		if strings.HasPrefix(line, "@@||") {
			domainPart := line[4:]
			d, reason, ok := extractABPDomain(domainPart)
			if !ok {
				stats.addSkip(reason)
				continue
			}
			norm, _, valid := normalizeRuleDomain(d)
			if !valid {
				stats.addSkip("invalid_domain")
				continue
			}
			allow = append(allow, norm)
			stats.Kept++
			continue
		}

		// ABP 语法: || 开头 (屏蔽规则)
		if strings.HasPrefix(line, "||") {
			domainPart := line[2:]
			d, reason, ok := extractABPDomain(domainPart)
			if !ok {
				stats.addSkip(reason)
				continue
			}
			norm, _, valid := normalizeRuleDomain(d)
			if !valid {
				stats.addSkip("invalid_domain")
				continue
			}
			suffixes = append(suffixes, norm)
			stats.Kept++
			continue
		}

		// 含通配符 *
		if strings.Contains(line, "*") {
			stats.addSkip("wildcard")
			continue
		}

		// 含 / 的路径规则
		if strings.Contains(line, "/") {
			stats.addSkip("url_path")
			continue
		}

		// 裸域名清单 (纯域名一行)
		norm, _, ok := normalizeRuleDomain(line)
		if ok && !isNoisyHost(norm) {
			suffixes = append(suffixes, norm)
			stats.Kept++
			continue
		}

		stats.addSkip("unsupported_syntax")
	}

	if err := scanner.Err(); err != nil {
		return suffixes, allow, badfilters, stats, fmt.Errorf("scan list: %w", err)
	}

	return suffixes, allow, badfilters, stats, nil
}

// isCosmeticRule 检测元素隐藏规则。
func isCosmeticRule(line string) bool {
	return strings.HasPrefix(line, "##") ||
		strings.HasPrefix(line, "#?#") ||
		strings.HasPrefix(line, "#@#") ||
		strings.HasPrefix(line, "#%#") ||
		strings.Contains(line, "##") ||
		strings.Contains(line, "#?#") ||
		strings.Contains(line, "#@#") ||
		strings.Contains(line, "#%#")
}

// extractABPDomain 从 ABP ||... 规则体中提取域名并处理选项。
func extractABPDomain(body string) (domain, skipReason string, ok bool) {
	if strings.Contains(body, "/") {
		return "", "url_path", false
	}
	if strings.Contains(body, "*") {
		return "", "wildcard", false
	}

	// 检查选项 $
	if idx := strings.Index(body, "$"); idx >= 0 {
		options := strings.Split(strings.ToLower(body[idx+1:]), ",")
		body = body[:idx]
		// 仅允许 important 选项; 其他非 DNS 选项跳过
		for _, opt := range options {
			opt = strings.TrimSpace(opt)
			if opt == "important" {
				continue
			}
			return "", "option", false
		}
	}

	body = strings.TrimSuffix(body, "^")
	if isNoisyHost(body) {
		return "", "noise_hosts", false
	}
	return body, "", true
}

// extractBadfilter 解析 $badfilter 规则。
// 返回规范化的 key (例如 "domain.com" 或 "@@domain.com")。
func extractBadfilter(line string) (string, bool) {
	lower := strings.ToLower(line)
	idx := strings.Index(lower, "$")
	if idx < 0 {
		return "", false
	}
	options := strings.Split(lower[idx+1:], ",")
	isBadfilter := false
	for _, opt := range options {
		if strings.TrimSpace(opt) == "badfilter" {
			isBadfilter = true
			break
		}
	}
	if !isBadfilter {
		return "", false
	}

	rulePart := strings.TrimSpace(line[:idx])
	allow := strings.HasPrefix(rulePart, "@@")
	if allow {
		rulePart = rulePart[2:]
	}
	if !strings.HasPrefix(rulePart, "||") {
		return "", false
	}
	domainPart := strings.TrimPrefix(rulePart, "||")
	domainPart = strings.TrimSuffix(domainPart, "^")
	norm, _, ok := normalizeRuleDomain(domainPart)
	if !ok {
		return "", false
	}
	if allow {
		return "@@" + norm, true
	}
	return norm, true
}

// ParseLists 归并多条清单并去重 (含 $badfilter 后置处理)。
// 返回的 suffixes/allow 已归一化、去重; 压缩在 NewSet 里做。
func ParseLists(readers map[string]io.Reader) (suffixes, allow []string, stats map[string]ParseStats, err error) {
	stats = make(map[string]ParseStats, len(readers))
	disabledSet := make(map[string]struct{})

	type listResult struct {
		name       string
		suffixes   []string
		allow      []string
		badfilters []string
		stat       ParseStats
	}

	results := make([]listResult, 0, len(readers))

	for name, r := range readers {
		sList, aList, badfilters, st, parseErr := ParseList(r)
		if parseErr != nil {
			return nil, nil, nil, fmt.Errorf("parse list %s: %w", name, parseErr)
		}
		for _, bf := range badfilters {
			disabledSet[bf] = struct{}{}
		}
		stats[name] = st
		results = append(results, listResult{
			name:       name,
			suffixes:   sList,
			allow:      aList,
			badfilters: badfilters,
			stat:       st,
		})
	}

	seenSuffix := make(map[string]struct{})
	seenAllow := make(map[string]struct{})

	for _, res := range results {
		for _, d := range res.suffixes {
			if _, off := disabledSet[d]; off {
				continue
			}
			if _, exists := seenSuffix[d]; !exists {
				if len(seenSuffix) >= maxTotalRules {
					break
				}
				seenSuffix[d] = struct{}{}
				suffixes = append(suffixes, d)
			}
		}

		for _, d := range res.allow {
			key := "@@" + d
			if _, off := disabledSet[key]; off {
				continue
			}
			if _, exists := seenAllow[d]; !exists {
				seenAllow[d] = struct{}{}
				allow = append(allow, d)
			}
		}
	}

	return suffixes, allow, stats, nil
}

package adblock

import "strings"

// maxLabels 是存储侧与查询侧共用的标签数上限:真实清单不存在更深的条目,
// 同时把「构造 127 标签超长域名刷 CPU」的放大路径堵死。
const maxLabels = 8

// minLabelsDefault 是有效域名（非单标签）最少标签数默认值。
const minLabelsDefault = 2

// Set 是不可变快照:构建完成后只读,由 atomic.Pointer 发布。
type Set struct {
	suffixes  map[string]struct{} // 已压缩;键一律小写、无尾点、2..8 标签的 ASCII 域名
	allow     map[string]struct{} // @@|| 例外 + 面板白名单(同格式,含自身)
	minLabels int                 // suffixes 中最少标签数,查询侧早退用
	stats     *Stats              // 由 Manager 持有,跨刷新存活,榜单不清零
}

// Blocked 入参约定:已小写、已去尾点(dns/handler.go:200 已做规范化)。
// 热路径:零分配、零锁、最多 maxLabels 次 map 查找。命中即计数。
func (s *Set) Blocked(q string) bool {
	if s == nil || len(s.suffixes) == 0 {
		return false
	}
	if len(s.allow) != 0 && s.has(s.allow, q) {
		return false // 例外/白名单优先
	}
	if s.has(s.suffixes, q) {
		s.stats.hit(q)
		return true
	}
	return false
}

func (s *Set) has(m map[string]struct{}, q string) bool {
	if _, ok := m[q]; ok {
		return true // 全名命中:hosts 型清单最常见,一次查找即中
	}
	labels := 0
	for i := len(q) - 1; i >= 0; i-- {
		if q[i] != '.' {
			continue
		}
		// labels 自增后恰好等于候选后缀 q[i+1:] 的标签数,无需重复计数。
		if labels++; labels > maxLabels {
			return false // 更深的标签不可能是条目
		}
		if labels >= s.minLabels {
			if _, ok := m[q[i+1:]]; ok {
				return true
			}
		}
	}
	return false
}

// Len 返回生效的屏蔽规则数量。
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.suffixes)
}

// AllowLen 返回白名单/例外数量。
func (s *Set) AllowLen() int {
	if s == nil {
		return 0
	}
	return len(s.allow)
}

// normalizeRuleDomain 规范化规则域名:
// 规则: 小写、去空白、去尾点、去前导 "*."、必须是 2..maxLabels 个标签的合法 ASCII 域名。
func normalizeRuleDomain(raw string) (string, int, bool) {
	d := strings.TrimSpace(strings.ToLower(raw))
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, ".")
	d = strings.TrimSuffix(d, ".")
	if len(d) == 0 || len(d) > 253 {
		return "", 0, false
	}

	labels := 0
	start := 0
	for i := 0; i <= len(d); i++ {
		if i == len(d) || d[i] == '.' {
			part := d[start:i]
			if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
				return "", 0, false
			}
			for j := 0; j < len(part); j++ {
				c := part[j]
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
					return "", 0, false
				}
			}
			labels++
			start = i + 1
		}
	}

	if labels < minLabelsDefault || labels > maxLabels {
		return "", 0, false
	}
	return d, labels, true
}

// NewSet 由 Manager 在后台 goroutine 调用,绝不在查询路径上调用。
// suffixes/allow 是原始条目;构建过程负责归一化、去重与后缀压缩。
func NewSet(suffixes, allow []string, stats *Stats) *Set {
	s := &Set{
		suffixes:  make(map[string]struct{}, len(suffixes)),
		allow:     make(map[string]struct{}, len(allow)),
		minLabels: maxLabels,
		stats:     stats,
	}

	for _, raw := range allow {
		if d, _, ok := normalizeRuleDomain(raw); ok {
			s.allow[d] = struct{}{}
		}
	}

	for _, raw := range suffixes {
		if d, labels, ok := normalizeRuleDomain(raw); ok {
			s.suffixes[d] = struct{}{}
			if labels < s.minLabels {
				s.minLabels = labels
			}
		}
	}

	if len(s.suffixes) == 0 {
		s.minLabels = minLabelsDefault
		return s
	}

	// 后缀压缩: 若某条目的父后缀已在集合中,则该条目冗余,删除。
	// 例如: sub.a.com 在 a.com 存在时删除。
	for d := range s.suffixes {
		for i := 0; i < len(d); i++ {
			if d[i] == '.' {
				parent := d[i+1:]
				if _, exists := s.suffixes[parent]; exists {
					delete(s.suffixes, d)
					break
				}
			}
		}
	}

	// 压缩后重算 minLabels
	newMin := maxLabels
	for d := range s.suffixes {
		labels := 1
		for i := 0; i < len(d); i++ {
			if d[i] == '.' {
				labels++
			}
		}
		if labels < newMin {
			newMin = labels
		}
	}
	if newMin > maxLabels {
		newMin = minLabelsDefault
	}
	s.minLabels = newMin

	return s
}

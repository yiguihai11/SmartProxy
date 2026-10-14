package adblock

import "strings"

type Set struct {
	blocked map[string]string
	allowed map[string]struct{}
}

func NewSet(rules []Rule) *Set {
	s := &Set{blocked: make(map[string]string, len(rules)), allowed: make(map[string]struct{})}
	for _, r := range rules {
		d := strings.TrimSuffix(strings.ToLower(r.Domain), ".")
		if d == "" { continue }
		if r.Allow { s.allowed[d] = struct{}{} } else if _, exists := s.blocked[d]; !exists { s.blocked[d] = r.SourceURL }
	}
	return s
}

func (s *Set) Blocked(qname string) bool {
	blocked, _ := s.BlockedBy(qname)
	return blocked
}

func (s *Set) BlockedBy(qname string) (bool, string) {
	if s == nil { return false, "" }
	qname = strings.TrimSuffix(strings.ToLower(qname), ".")
	for d := qname; d != ""; {
		if _, ok := s.allowed[d]; ok { return false, "" }
		if source, ok := s.blocked[d]; ok { return true, source }
		i := strings.IndexByte(d, '.')
		if i < 0 { break }
		d = d[i+1:]
	}
	return false, ""
}

func (s *Set) Len() int {
	if s == nil { return 0 }
	return len(s.blocked)
}

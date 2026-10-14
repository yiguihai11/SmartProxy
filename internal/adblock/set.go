package adblock

import "strings"

// Set is an immutable domain rule snapshot. Construct a new Set and atomically swap
// the pointer when subscriptions refresh; DNS queries never observe a partial rebuild.
type Set struct {
	blocked map[string]struct{}
	allowed map[string]struct{}
}

func NewSet(rules []Rule) *Set {
	s := &Set{blocked: make(map[string]struct{}, len(rules)), allowed: make(map[string]struct{})}
	for _, r := range rules {
		d := strings.TrimSuffix(strings.ToLower(r.Domain), ".")
		if d == "" { continue }
		if r.Allow { s.allowed[d] = struct{}{} } else { s.blocked[d] = struct{}{} }
	}
	return s
}

// Blocked returns true for the apex and all subdomains of a blocked domain.
// A matching exception overrides a matching block rule.
func (s *Set) Blocked(qname string) bool {
	if s == nil { return false }
	qname = strings.TrimSuffix(strings.ToLower(qname), ".")
	for d := qname; d != ""; {
		if _, ok := s.allowed[d]; ok { return false }
		if _, ok := s.blocked[d]; ok { return true }
		i := strings.IndexByte(d, '.')
		if i < 0 { break }
		d = d[i+1:]
	}
	return false
}

func (s *Set) Len() int {
	if s == nil { return 0 }
	return len(s.blocked)
}

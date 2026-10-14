// Package adblock parses common DNS-relevant AdGuard/ABP and hosts rules.
package adblock

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

type Rule struct {
	Domain string
	Allow  bool
}

type ParseStats struct {
	Accepted   int            `json:"accepted"`
	Ignored    int            `json:"ignored"`
	Exceptions int            `json:"exceptions"`
	Reasons    map[string]int `json:"reasons"`
}

// Parse accepts domain-wide AdGuard/ABP rules and hosts files. Unsupported rules are
// skipped explicitly; callers can show the reason counts in the admin UI.
func Parse(input string) ([]Rule, ParseStats, error) {
	stats := ParseStats{Reasons: make(map[string]int)}
	rules := make([]Rule, 0)
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		rule, reason, ok := parseLine(line)
		if !ok {
			if reason != "" {
				stats.Ignored++
				stats.Reasons[reason]++
			}
			continue
		}
		key := rule.Domain
		if rule.Allow { key = "@@" + key }
		if _, exists := seen[key]; exists { continue }
		seen[key] = struct{}{}
		rules = append(rules, rule)
		stats.Accepted++
		if rule.Allow { stats.Exceptions++ }
	}
	if err := scanner.Err(); err != nil { return nil, stats, fmt.Errorf("read rules: %w", err) }
	if stats.Accepted == 0 {
		return nil, stats, fmt.Errorf("no supported rules found")
	}
	return rules, stats, nil
}

func parseLine(line string) (Rule, string, bool) {
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "@@") {
		domain, ok := parseDomainRule(strings.TrimPrefix(line[2:], "||"))
		if !ok { return Rule{}, "unsupported_exception", false }
		return Rule{Domain: domain, Allow: true}, "", true
	}
	if strings.Contains(lower, "$badfilter") {
		return Rule{}, "badfilter", false
	}
	if strings.HasPrefix(lower, "||") {
		body := strings.TrimPrefix(line, "||")
		if i := strings.IndexAny(body, "^/$"); i >= 0 {
			if body[i] != '^' || i != len(body)-1 {
				return Rule{}, "path_or_option", false
			}
			body = body[:i]
		}
		domain, ok := normalizeDomain(body)
		if !ok { return Rule{}, "invalid_domain", false }
		return Rule{Domain: domain}, "", true
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
		// A hosts row may contain several aliases; this parser emits the first alias.
		domain, ok := normalizeDomain(fields[1])
		if !ok { return Rule{}, "invalid_hosts_domain", false }
		if isNoisyLocal(domain) { return Rule{}, "local_domain", false }
		return Rule{Domain: domain}, "", true
	}
	if strings.Contains(line, "$") || strings.Contains(line, "/") || strings.Contains(line, "*") {
		return Rule{}, "unsupported_syntax", false
	}
	return Rule{}, "unsupported_syntax", false
}

func parseDomainRule(s string) (string, bool) {
	s = strings.TrimSuffix(s, "^")
	if strings.ContainsAny(s, "/$*") { return "", false }
	return normalizeDomain(s)
}

func normalizeDomain(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " /\\:\t") { return "", false }
	if net.ParseIP(s) != nil { return "", false }
	labels := strings.Split(s, ".")
	if len(labels) > 8 { return "", false }
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' { return "", false }
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') { return "", false }
		}
	}
	if isNoisyLocal(s) { return "", false }
	return s, true
}

func isNoisyLocal(domain string) bool {
	return domain == "localhost" || strings.HasSuffix(domain, ".localhost") ||
		domain == "local" || strings.HasSuffix(domain, ".local") ||
		domain == "broadcasthost" || domain == "ip6-localhost"
}

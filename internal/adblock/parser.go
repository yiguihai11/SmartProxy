// Package adblock parses common DNS-relevant AdGuard/ABP and hosts rules.
package adblock

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

const maxRuleLines = 500000

type Rule struct {
	Domain string
	Allow bool
	SourceURL string
}

type ParseStats struct {
	Accepted   int            `json:"accepted"`
	Ignored    int            `json:"ignored"`
	Exceptions int            `json:"exceptions"`
	Reasons    map[string]int `json:"reasons"`
}

// Parse accepts domain-wide AdGuard/ABP rules and hosts files. Unsupported rules are
// skipped explicitly; callers can show the reason counts in the admin UI. Badfilter
// directives are applied after scanning so they work regardless of list ordering.
func Parse(input string) ([]Rule, ParseStats, error) {
	stats := ParseStats{Reasons: make(map[string]int)}
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Buffer(make([]byte, 4096), 1024*1024)

	lines := make([]string, 0)
	disabled := make(map[string]struct{})
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > maxRuleLines {
			return nil, stats, fmt.Errorf("subscription exceeds %d lines limit", maxRuleLines)
		}
		line := strings.TrimSpace(scanner.Text())
		lines = append(lines, line)
		if key, ok := parseBadfilter(line); ok {
			disabled[key] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, stats, fmt.Errorf("read rules: %w", err)
	}

	rules := make([]Rule, 0)
	seen := make(map[string]struct{})
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		if _, ok := parseBadfilter(line); ok {
			stats.Ignored++
			stats.Reasons["badfilter"]++
			continue
		}

		if hosts, matched := parseHostsLine(line); matched {
			if len(hosts) == 0 {
				stats.Ignored++
				stats.Reasons["invalid_hosts_domain"]++
				continue
			}
			for _, rule := range hosts {
				addRule(rule, disabled, seen, &rules, &stats)
			}
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
		addRule(rule, disabled, seen, &rules, &stats)
	}
	if stats.Accepted == 0 {
		return nil, stats, fmt.Errorf("no supported rules found")
	}
	return rules, stats, nil
}

func addRule(rule Rule, disabled, seen map[string]struct{}, rules *[]Rule, stats *ParseStats) {
	key := rule.Domain
	if rule.Allow {
		key = "@@" + key
	}
	if _, off := disabled[key]; off {
		stats.Ignored++
		stats.Reasons["badfilter_disabled"]++
		return
	}
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*rules = append(*rules, rule)
	stats.Accepted++
	if rule.Allow {
		stats.Exceptions++
	}
}

// parseBadfilter returns the canonical key of a domain rule disabled by $badfilter.
func parseBadfilter(line string) (string, bool) {
	lower := strings.ToLower(line)
	i := strings.Index(lower, "$")
	if i < 0 {
		return "", false
	}
	options := strings.Split(lower[i+1:], ",")
	found := false
	for _, option := range options {
		if strings.TrimSpace(option) == "badfilter" {
			found = true
			break
		}
	}
	if !found {
		return "", false
	}
	ruleText := strings.TrimSpace(line[:i])
	allow := strings.HasPrefix(strings.ToLower(ruleText), "@@")
	if allow {
		ruleText = ruleText[2:]
	}
	if !strings.HasPrefix(ruleText, "||") {
		return "", false
	}
	domain, ok := parseDomainRule(strings.TrimPrefix(ruleText, "||"))
	if !ok {
		return "", false
	}
	if allow {
		return "@@" + domain, true
	}
	return domain, true
}

func parseHostsLine(line string) ([]Rule, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
		return nil, false
	}
	rules := make([]Rule, 0, len(fields)-1)
	for _, alias := range fields[1:] {
		// Hosts files allow trailing inline comments.
		if strings.HasPrefix(alias, "#") {
			break
		}
		domain, ok := normalizeDomain(alias)
		if !ok {
			continue
		}
		rules = append(rules, Rule{Domain: domain})
	}
	return rules, true
}

func parseLine(line string) (Rule, string, bool) {
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "@@") {
		domain, ok := parseDomainRule(strings.TrimPrefix(line[2:], "||"))
		if !ok {
			return Rule{}, "unsupported_exception", false
		}
		return Rule{Domain: domain, Allow: true}, "", true
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
		if !ok {
			return Rule{}, "invalid_domain", false
		}
		return Rule{Domain: domain}, "", true
	}
	return Rule{}, "unsupported_syntax", false
}

func parseDomainRule(s string) (string, bool) {
	s = strings.TrimSuffix(s, "^")
	if strings.ContainsAny(s, "/$*") {
		return "", false
	}
	return normalizeDomain(s)
}

func normalizeDomain(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " /\\:\t") {
		return "", false
	}
	if net.ParseIP(s) != nil {
		return "", false
	}
	labels := strings.Split(s, ".")
	if len(labels) > 8 {
		return "", false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	if isNoisyLocal(s) {
		return "", false
	}
	return s, true
}

func isNoisyLocal(domain string) bool {
	return domain == "localhost" || strings.HasSuffix(domain, ".localhost") ||
		domain == "local" || strings.HasSuffix(domain, ".local") ||
		domain == "broadcasthost" || domain == "ip6-localhost"
}

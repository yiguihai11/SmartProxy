package portal

import (
	"net/url"
	"strings"
)

// IsCaptivePortalProbe checks whether a raw URL corresponds to known OS/browser captive portal detection probes
// (such as Android generate_204, Windows msftconnecttest/ncsi, Apple hotspot-detect/captive.apple.com).
func IsCaptivePortalProbe(rawURL string) bool {
	if rawURL == "" {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		lower := strings.ToLower(rawURL)
		return strings.Contains(lower, "generate_204") || strings.Contains(lower, "gen_204")
	}
	h := strings.ToLower(u.Hostname())
	p := strings.ToLower(u.Path)

	if strings.Contains(p, "generate_204") || strings.Contains(p, "gen_204") ||
		strings.Contains(p, "hotspot-detect") || strings.Contains(p, "connecttest") ||
		strings.Contains(p, "success.txt") || strings.Contains(p, "ncsi.txt") {
		return true
	}
	if strings.Contains(h, "connectivitycheck") || strings.Contains(h, "msftconnecttest") ||
		strings.Contains(h, "msftncsi") || h == "captive.apple.com" ||
		strings.Contains(h, "detectportal") {
		return true
	}
	return false
}

// IsPortalPath checks whether a URL path points to the captive portal service or its APIs,
// preventing self-referential redirect loops.
func IsPortalPath(path string) bool {
	clean := strings.ToLower(strings.TrimSpace(path))
	return clean == "/portal" || clean == "/portal/" ||
		strings.HasPrefix(clean, "/portal?") ||
		clean == "/api/portal/status" ||
		clean == "/api/portal/login" ||
		clean == "/api/portal/logout" ||
		clean == "/api/capport" ||
		clean == "/.well-known/capport" ||
		clean == "/.well-known/captive-portal"
}

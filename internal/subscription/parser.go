package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"smartproxy/internal/upstream"
)

// UserInfo represents subscription metadata (quota usage and expiration).
type UserInfo struct {
	Upload   int64 `json:"upload,omitempty"`
	Download int64 `json:"download,omitempty"`
	Total    int64 `json:"total,omitempty"`
	Expire   int64 `json:"expire,omitempty"` // Unix timestamp seconds
}

// ParseSubscriptionUserInfo parses standard "Subscription-Userinfo" HTTP header values:
// e.g. "upload=1000; download=2000; total=100000; expire=1700000000".
func ParseSubscriptionUserInfo(headerVal string) *UserInfo {
	if headerVal == "" {
		return nil
	}
	info := &UserInfo{}
	found := false
	parts := strings.Split(headerVal, ";")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "upload":
			info.Upload = v
			found = true
		case "download":
			info.Download = v
			found = true
		case "total":
			info.Total = v
			found = true
		case "expire":
			info.Expire = v
			found = true
		}
	}
	if !found {
		return nil
	}
	return info
}

// ParseContent parses raw subscription payload into proxy entries and optional userinfo.
// It auto-detects or follows subType: "auto", "sip008", "base64", "clash", "sing-box".
func ParseContent(subType string, headers http.Header, body []byte) ([]upstream.ProxyEntry, *UserInfo, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil, errors.New("empty subscription content")
	}

	var userinfo *UserInfo
	if headers != nil {
		if uinfo := headers.Get("Subscription-Userinfo"); uinfo != "" {
			userinfo = ParseSubscriptionUserInfo(uinfo)
		}
	}

	subType = strings.ToLower(strings.TrimSpace(subType))
	if subType == "" {
		subType = "auto"
	}

	switch subType {
	case "sip008":
		entries, u, err := parseSIP008(trimmed)
		if err == nil && len(entries) > 0 {
			if userinfo == nil {
				userinfo = u
			}
			return entries, userinfo, nil
		}
		return nil, userinfo, err

	case "sing-box":
		entries, err := parseSingBox(trimmed)
		if err == nil && len(entries) > 0 {
			return entries, userinfo, nil
		}
		return nil, userinfo, err

	case "clash":
		entries, err := parseClashYAML(trimmed)
		if err == nil && len(entries) > 0 {
			return entries, userinfo, nil
		}
		return nil, userinfo, err

	case "base64", "lines":
		entries, err := parseBase64OrLines(trimmed)
		if err == nil && len(entries) > 0 {
			return entries, userinfo, nil
		}
		return nil, userinfo, err

	default: // "auto"
		// 1. If starts with '{', try JSON: SIP008 first, then sing-box outbounds
		if trimmed[0] == '{' {
			if entries, u, err := parseSIP008(trimmed); err == nil && len(entries) > 0 {
				if userinfo == nil {
					userinfo = u
				}
				return entries, userinfo, nil
			}
			if entries, err := parseSingBox(trimmed); err == nil && len(entries) > 0 {
				return entries, userinfo, nil
			}
		}

		// 2. If starts with '[': could be sing-box outbounds array or JSON array
		if trimmed[0] == '[' {
			if entries, err := parseSingBoxArray(trimmed); err == nil && len(entries) > 0 {
				return entries, userinfo, nil
			}
		}

		// 3. Check for Clash YAML
		if bytes.Contains(trimmed, []byte("proxies:")) {
			if entries, err := parseClashYAML(trimmed); err == nil && len(entries) > 0 {
				return entries, userinfo, nil
			}
		}

		// 4. Try Base64 or plain lines (most universal airport subscription format)
		if entries, err := parseBase64OrLines(trimmed); err == nil && len(entries) > 0 {
			return entries, userinfo, nil
		}

		return nil, userinfo, errors.New("unrecognized subscription format or no valid proxy nodes found")
	}
}

// ---- SIP008 Parser ----

type sip008Doc struct {
	Version        int            `json:"version"`
	Servers        []sip008Server `json:"servers"`
	BytesUsed      int64          `json:"bytes_used,omitempty"`
	BytesRemaining int64          `json:"bytes_remaining,omitempty"`
}

type sip008Server struct {
	ID         string `json:"id"`
	Remarks    string `json:"remarks"`
	Server     string `json:"server"`
	ServerPort any    `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Plugin     string `json:"plugin,omitempty"`
	PluginOpts string `json:"plugin_opts,omitempty"`
}

func parseSIP008(data []byte) ([]upstream.ProxyEntry, *UserInfo, error) {
	var doc sip008Doc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	if len(doc.Servers) == 0 {
		return nil, nil, errors.New("no servers found in SIP008 document")
	}

	var uinfo *UserInfo
	if doc.BytesUsed > 0 || doc.BytesRemaining > 0 {
		uinfo = &UserInfo{
			Download: doc.BytesUsed,
			Total:    doc.BytesUsed + doc.BytesRemaining,
		}
	}

	var entries []upstream.ProxyEntry
	for i, s := range doc.Servers {
		if s.Server == "" || s.Method == "" {
			continue
		}
		port := parsePortAny(s.ServerPort)
		if port <= 0 || port > 65535 {
			port = 8388
		}

		remarks := strings.TrimSpace(s.Remarks)
		if remarks == "" {
			remarks = strings.TrimSpace(s.ID)
		}
		if remarks == "" {
			remarks = fmt.Sprintf("ss-%d", i+1)
		}

		// Encode method:password into standard SIP002 base64
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(s.Method + ":" + s.Password))
		ssURL := fmt.Sprintf("ss://%s@%s:%d", userinfo, s.Server, port)

		if s.Plugin != "" {
			pluginArg := s.Plugin
			if s.PluginOpts != "" {
				pluginArg += ";" + s.PluginOpts
			}
			ssURL += "/?plugin=" + url.QueryEscape(pluginArg)
		}
		ssURL += "#" + url.QueryEscape(remarks)

		entries = append(entries, upstream.ProxyEntry{
			Alias: remarks,
			URL:   ssURL,
		})
	}

	if len(entries) == 0 {
		return nil, uinfo, errors.New("all servers in SIP008 document had invalid format")
	}
	return entries, uinfo, nil
}

// ---- sing-box Outbounds Parser ----

func parseSingBox(data []byte) ([]upstream.ProxyEntry, error) {
	var doc struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Outbounds) == 0 {
		return nil, errors.New("no outbounds found in sing-box config")
	}
	return parseRawOutbounds(doc.Outbounds)
}

func parseSingBoxArray(data []byte) ([]upstream.ProxyEntry, error) {
	var outbounds []json.RawMessage
	if err := json.Unmarshal(data, &outbounds); err != nil {
		return nil, err
	}
	return parseRawOutbounds(outbounds)
}

func parseRawOutbounds(rawList []json.RawMessage) ([]upstream.ProxyEntry, error) {
	var entries []upstream.ProxyEntry
	for i, raw := range rawList {
		var meta struct {
			Type   string `json:"type"`
			Tag    string `json:"tag"`
			Server string `json:"server"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		typ := strings.ToLower(meta.Type)
		// Filter out non-proxy types
		switch typ {
		case "direct", "block", "dns", "selector", "urltest", "route":
			continue
		}
		if meta.Server == "" && typ != "socks" && typ != "shadowsocks" {
			continue
		}

		alias := strings.TrimSpace(meta.Tag)
		if alias == "" {
			alias = fmt.Sprintf("singbox-%s-%d", typ, i+1)
		}

		entries = append(entries, upstream.ProxyEntry{
			Alias: alias,
			URL:   string(raw),
		})
	}
	if len(entries) == 0 {
		return nil, errors.New("no proxy outbounds found in sing-box list")
	}
	return entries, nil
}

// ---- Clash YAML Parser ----

func parseClashYAML(data []byte) ([]upstream.ProxyEntry, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Proxies) == 0 {
		return nil, errors.New("no proxies found in clash yaml")
	}

	var entries []upstream.ProxyEntry
	for i, p := range doc.Proxies {
		typ, _ := p["type"].(string)
		typ = strings.ToLower(typ)
		name, _ := p["name"].(string)
		if name == "" {
			name = fmt.Sprintf("proxy-%d", i+1)
		}
		server, _ := p["server"].(string)
		port := parsePortAny(p["port"])
		if server == "" || port <= 0 {
			continue
		}

		var proxyURL string
		switch typ {
		case "ss", "shadowsocks":
			cipher, _ := p["cipher"].(string)
			password, _ := p["password"].(string)
			if cipher == "" {
				continue
			}
			userinfo := base64.RawURLEncoding.EncodeToString([]byte(cipher + ":" + password))
			proxyURL = fmt.Sprintf("ss://%s@%s:%d", userinfo, server, port)
			plugin, _ := p["plugin"].(string)
			if plugin != "" {
				pluginOpts, _ := p["plugin-opts"].(map[string]any)
				var optPairs []string
				for k, v := range pluginOpts {
					optPairs = append(optPairs, fmt.Sprintf("%s=%v", k, v))
				}
				pArg := plugin
				if len(optPairs) > 0 {
					pArg += ";" + strings.Join(optPairs, ";")
				}
				proxyURL += "/?plugin=" + url.QueryEscape(pArg)
			}
			proxyURL += "#" + url.QueryEscape(name)

		case "vless":
			uuid, _ := p["uuid"].(string)
			if uuid == "" {
				continue
			}
			tls, _ := p["tls"].(bool)
			sni, _ := p["servername"].(string)
			flow, _ := p["flow"].(string)
			netType, _ := p["network"].(string)
			u := url.URL{
				Scheme: "vless",
				User:   url.User(uuid),
				Host:   fmt.Sprintf("%s:%d", server, port),
			}
			q := u.Query()
			if tls {
				q.Set("security", "tls")
				if sni != "" {
					q.Set("sni", sni)
				}
			} else {
				q.Set("security", "none")
			}
			if flow != "" {
				q.Set("flow", flow)
			}
			if netType != "" {
				q.Set("type", netType)
			}
			u.RawQuery = q.Encode()
			u.Fragment = name
			proxyURL = u.String()

		case "trojan":
			password, _ := p["password"].(string)
			sni, _ := p["sni"].(string)
			u := url.URL{
				Scheme: "trojan",
				User:   url.User(password),
				Host:   fmt.Sprintf("%s:%d", server, port),
			}
			q := u.Query()
			if sni != "" {
				q.Set("sni", sni)
			}
			u.RawQuery = q.Encode()
			u.Fragment = name
			proxyURL = u.String()

		case "hysteria2":
			password, _ := p["password"].(string)
			sni, _ := p["sni"].(string)
			u := url.URL{
				Scheme: "hysteria2",
				User:   url.User(password),
				Host:   fmt.Sprintf("%s:%d", server, port),
			}
			q := u.Query()
			if sni != "" {
				q.Set("sni", sni)
			}
			u.RawQuery = q.Encode()
			u.Fragment = name
			proxyURL = u.String()

		case "socks5":
			user, _ := p["username"].(string)
			pass, _ := p["password"].(string)
			if user != "" || pass != "" {
				proxyURL = fmt.Sprintf("socks5://%s:%s@%s:%d#%s", url.QueryEscape(user), url.QueryEscape(pass), server, port, url.QueryEscape(name))
			} else {
				proxyURL = fmt.Sprintf("socks5://%s:%d#%s", server, port, url.QueryEscape(name))
			}

		case "http":
			user, _ := p["username"].(string)
			pass, _ := p["password"].(string)
			if user != "" || pass != "" {
				proxyURL = fmt.Sprintf("http://%s:%s@%s:%d#%s", url.QueryEscape(user), url.QueryEscape(pass), server, port, url.QueryEscape(name))
			} else {
				proxyURL = fmt.Sprintf("http://%s:%d#%s", server, port, url.QueryEscape(name))
			}
		}

		if proxyURL != "" {
			entries = append(entries, upstream.ProxyEntry{
				Alias: name,
				URL:   proxyURL,
			})
		}
	}

	if len(entries) == 0 {
		return nil, errors.New("no supported proxies found in clash yaml")
	}
	return entries, nil
}

// ---- Base64 / Plaintext Lines Parser ----

func parseBase64OrLines(data []byte) ([]upstream.ProxyEntry, error) {
	// Try base64 decoding first
	rawText := string(data)
	compact := strings.TrimSpace(rawText)

	// Remove common base64 newlines / spaces if present
	compactNoSpace := strings.ReplaceAll(strings.ReplaceAll(compact, "\n", ""), "\r", "")
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(compactNoSpace); err == nil && len(decoded) > 0 {
			s := string(decoded)
			if isProxyList(s) {
				rawText = s
				break
			}
		}
	}

	lines := strings.Split(rawText, "\n")
	var entries []upstream.ProxyEntry
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		alias, valid := extractLineAliasAndValidate(line, i+1)
		if valid {
			entries = append(entries, upstream.ProxyEntry{
				Alias: alias,
				URL:   line,
			})
		}
	}

	if len(entries) == 0 {
		return nil, errors.New("no valid proxy links found in lines")
	}
	return entries, nil
}

func isProxyList(s string) bool {
	for _, scheme := range knownSchemes {
		if strings.Contains(s, scheme) {
			return true
		}
	}
	return false
}

var knownSchemes = []string{
	"ss://", "vmess://", "vless://", "trojan://", "hysteria2://", "hy2://", "tuic://", "socks5://", "socks5h://", "http://", "https://",
}

func extractLineAliasAndValidate(line string, index int) (string, bool) {
	lower := strings.ToLower(line)
	matched := false
	for _, s := range knownSchemes {
		if strings.HasPrefix(lower, s) {
			matched = true
			break
		}
	}
	if !matched {
		return "", false
	}

	// Try extracting #fragment
	if idx := strings.IndexByte(line, '#'); idx != -1 {
		rawFragment := line[idx+1:]
		if unescaped, err := url.QueryUnescape(rawFragment); err == nil && unescaped != "" {
			return unescaped, true
		}
		if rawFragment != "" {
			return rawFragment, true
		}
	}
	return fmt.Sprintf("node-%d", index), true
}

func parsePortAny(v any) int {
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	case string:
		p, _ := strconv.Atoi(val)
		return p
	default:
		return 0
	}
}

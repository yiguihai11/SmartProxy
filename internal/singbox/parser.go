package singbox

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParsedOutbound contains the sing-box outbound configuration and metadata.
type ParsedOutbound struct {
	Tag      string
	Type     string
	Server   string
	Port     int
	RawJSON  []byte
}

// ParseLink parses a proxy sharing link (vless, hysteria2/hy2, trojan, tuic, vmess)
// or raw sing-box JSON into a ParsedOutbound ready for sing-box.
func ParseLink(link string) (*ParsedOutbound, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil, errors.New("empty link")
	}

	// 1. Raw JSON outbound
	if strings.HasPrefix(link, "{") {
		return parseRawJSON([]byte(link))
	}

	// 2. VMess Base64 link
	if strings.HasPrefix(link, "vmess://") {
		return parseVMess(link)
	}

	// 3. Standard URL schemes (vless, hysteria2, hy2, trojan, tuic)
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "vless":
		return parseVLESS(u)
	case "hysteria2", "hy2":
		return parseHysteria2(u)
	case "trojan":
		return parseTrojan(u)
	case "tuic":
		return parseTUIC(u)
	default:
		return nil, fmt.Errorf("unsupported singbox scheme %q", scheme)
	}
}

// SetTag updates the outbound tag and synchronizes the tag inside RawJSON.
func (p *ParsedOutbound) SetTag(newTag string) error {
	p.Tag = newTag
	var m map[string]any
	if err := json.Unmarshal(p.RawJSON, &m); err != nil {
		return err
	}
	m["tag"] = newTag
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	p.RawJSON = data
	return nil
}

func parseRawJSON(data []byte) (*ParsedOutbound, error) {
	var meta struct {
		Tag        string `json:"tag"`
		Type       string `json:"type"`
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
		Port       int    `json:"port"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("invalid sing-box json: %w", err)
	}
	if meta.Type == "" {
		return nil, errors.New("sing-box json missing 'type' field")
	}
	if meta.ServerPort == 0 && meta.Port != 0 {
		meta.ServerPort = meta.Port
	}
	if meta.Tag == "" {
		meta.Tag = fmt.Sprintf("%s-%s-%d", meta.Type, meta.Server, meta.ServerPort)
	}

	return &ParsedOutbound{
		Tag:     meta.Tag,
		Type:    meta.Type,
		Server:  meta.Server,
		Port:    meta.ServerPort,
		RawJSON: data,
	}, nil
}

func parseVLESS(u *url.URL) (*ParsedOutbound, error) {
	uuid := u.User.Username()
	if uuid == "" {
		return nil, errors.New("vless missing uuid")
	}
	host := u.Hostname()
	port := parsePort(u.Port(), 443)
	tag := cleanTag(u.Fragment, fmt.Sprintf("vless-%s-%d", host, port))

	q := u.Query()
	outbound := map[string]any{
		"type":        "vless",
		"tag":         tag,
		"server":      host,
		"server_port": port,
		"uuid":        uuid,
	}

	if flow := q.Get("flow"); flow != "" {
		outbound["flow"] = flow
	}

	security := strings.ToLower(q.Get("security"))
	tlsConfig := map[string]any{
		"enabled": security == "tls" || security == "reality",
	}

	sni := q.Get("sni")
	if sni != "" {
		tlsConfig["server_name"] = sni
	}

	fp := q.Get("fp")
	if fp != "" {
		tlsConfig["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": fp,
		}
	}

	if security == "reality" {
		if fp == "" {
			fp = "chrome"
		}
		tlsConfig["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": fp,
		}
		realityConfig := map[string]any{
			"enabled":    true,
			"public_key": q.Get("pbk"),
			"short_id":   q.Get("sid"),
		}
		if spx := q.Get("spx"); spx != "" {
			realityConfig["spider_x"] = spx
		}
		tlsConfig["reality"] = realityConfig
	}

	if tlsConfig["enabled"].(bool) {
		outbound["tls"] = tlsConfig
	}

	transportType := strings.ToLower(q.Get("type"))
	if transportType == "ws" {
		wsConfig := map[string]any{
			"type": "ws",
			"path": q.Get("path"),
		}
		if h := q.Get("host"); h != "" {
			wsConfig["headers"] = map[string]string{"Host": h}
		}
		outbound["transport"] = wsConfig
	} else if transportType == "grpc" {
		outbound["transport"] = map[string]any{
			"type":         "grpc",
			"service_name": q.Get("serviceName"),
		}
	}

	raw, err := json.Marshal(outbound)
	if err != nil {
		return nil, err
	}
	return &ParsedOutbound{
		Tag:     tag,
		Type:    "vless",
		Server:  host,
		Port:    port,
		RawJSON: raw,
	}, nil
}

func parseHysteria2(u *url.URL) (*ParsedOutbound, error) {
	password := u.User.Username()
	if password == "" {
		if p, ok := u.User.Password(); ok {
			password = p
		}
	}
	host := u.Hostname()
	port := parsePort(u.Port(), 443)
	tag := cleanTag(u.Fragment, fmt.Sprintf("hy2-%s-%d", host, port))

	q := u.Query()
	outbound := map[string]any{
		"type":        "hysteria2",
		"tag":         tag,
		"server":      host,
		"server_port": port,
		"password":    password,
	}

	tlsConfig := map[string]any{
		"enabled": true,
	}
	if sni := q.Get("sni"); sni != "" {
		tlsConfig["server_name"] = sni
	}
	if q.Get("insecure") == "1" || strings.ToLower(q.Get("insecure")) == "true" {
		tlsConfig["insecure"] = true
	}
	outbound["tls"] = tlsConfig

	if mport := q.Get("mport"); mport != "" {
		outbound["server_ports"] = mport
	}

	raw, err := json.Marshal(outbound)
	if err != nil {
		return nil, err
	}
	return &ParsedOutbound{
		Tag:     tag,
		Type:    "hysteria2",
		Server:  host,
		Port:    port,
		RawJSON: raw,
	}, nil
}

func parseTrojan(u *url.URL) (*ParsedOutbound, error) {
	password := u.User.Username()
	host := u.Hostname()
	port := parsePort(u.Port(), 443)
	tag := cleanTag(u.Fragment, fmt.Sprintf("trojan-%s-%d", host, port))

	q := u.Query()
	outbound := map[string]any{
		"type":        "trojan",
		"tag":         tag,
		"server":      host,
		"server_port": port,
		"password":    password,
	}

	tlsConfig := map[string]any{
		"enabled": true,
	}
	if sni := q.Get("sni"); sni != "" {
		tlsConfig["server_name"] = sni
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tlsConfig["alpn"] = strings.Split(alpn, ",")
	}
	if q.Get("insecure") == "1" || strings.ToLower(q.Get("insecure")) == "true" {
		tlsConfig["insecure"] = true
	}
	outbound["tls"] = tlsConfig

	transportType := strings.ToLower(q.Get("type"))
	if transportType == "ws" {
		wsConfig := map[string]any{
			"type": "ws",
			"path": q.Get("path"),
		}
		if h := q.Get("host"); h != "" {
			wsConfig["headers"] = map[string]string{"Host": h}
		}
		outbound["transport"] = wsConfig
	} else if transportType == "grpc" {
		outbound["transport"] = map[string]any{
			"type":         "grpc",
			"service_name": q.Get("serviceName"),
		}
	}

	raw, err := json.Marshal(outbound)
	if err != nil {
		return nil, err
	}
	return &ParsedOutbound{
		Tag:     tag,
		Type:    "trojan",
		Server:  host,
		Port:    port,
		RawJSON: raw,
	}, nil
}

func parseTUIC(u *url.URL) (*ParsedOutbound, error) {
	uuid := u.User.Username()
	password, _ := u.User.Password()
	host := u.Hostname()
	port := parsePort(u.Port(), 443)
	tag := cleanTag(u.Fragment, fmt.Sprintf("tuic-%s-%d", host, port))

	q := u.Query()
	outbound := map[string]any{
		"type":        "tuic",
		"tag":         tag,
		"server":      host,
		"server_port": port,
		"uuid":        uuid,
		"password":    password,
	}

	if cc := q.Get("congestion_control"); cc != "" {
		outbound["congestion_control"] = cc
	}

	tlsConfig := map[string]any{
		"enabled": true,
	}
	if sni := q.Get("sni"); sni != "" {
		tlsConfig["server_name"] = sni
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tlsConfig["alpn"] = strings.Split(alpn, ",")
	}
	if q.Get("insecure") == "1" || strings.ToLower(q.Get("insecure")) == "true" {
		tlsConfig["insecure"] = true
	}
	outbound["tls"] = tlsConfig

	raw, err := json.Marshal(outbound)
	if err != nil {
		return nil, err
	}
	return &ParsedOutbound{
		Tag:     tag,
		Type:    "tuic",
		Server:  host,
		Port:    port,
		RawJSON: raw,
	}, nil
}

func parseVMess(link string) (*ParsedOutbound, error) {
	b64 := strings.TrimPrefix(link, "vmess://")
	// Some links have a fragment attached after base64
	var fragment string
	if idx := strings.Index(b64, "#"); idx != -1 {
		fragment = b64[idx+1:]
		b64 = b64[:idx]
	}

	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// try URL encoding
		data, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			// try unpadded
			data, err = base64.RawStdEncoding.DecodeString(b64)
			if err != nil {
				return nil, fmt.Errorf("failed to decode vmess base64: %w", err)
			}
		}
	}

	var v struct {
		V    any    `json:"v"`
		PS   string `json:"ps"`
		Add  string `json:"add"`
		Port any    `json:"port"`
		ID   string `json:"id"`
		Aid  any    `json:"aid"`
		Net  string `json:"net"`
		Type string `json:"type"`
		Host string `json:"host"`
		Path string `json:"path"`
		TLS  string `json:"tls"`
		SNI  string `json:"sni"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vmess json: %w", err)
	}

	port := 443
	switch p := v.Port.(type) {
	case float64:
		port = int(p)
	case string:
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}

	alterId := 0
	switch a := v.Aid.(type) {
	case float64:
		alterId = int(a)
	case string:
		if n, err := strconv.Atoi(a); err == nil {
			alterId = n
		}
	}

	tag := v.PS
	if tag == "" && fragment != "" {
		tag = fragment
	}
	tag = cleanTag(tag, fmt.Sprintf("vmess-%s-%d", v.Add, port))

	outbound := map[string]any{
		"type":        "vmess",
		"tag":         tag,
		"server":      v.Add,
		"server_port": port,
		"uuid":        v.ID,
		"alter_id":    alterId,
		"security":    "auto",
	}

	if strings.ToLower(v.TLS) == "tls" {
		tlsConfig := map[string]any{
			"enabled": true,
		}
		if v.SNI != "" {
			tlsConfig["server_name"] = v.SNI
		} else if v.Host != "" {
			tlsConfig["server_name"] = v.Host
		}
		outbound["tls"] = tlsConfig
	}

	if v.Net == "ws" {
		wsConfig := map[string]any{
			"type": "ws",
			"path": v.Path,
		}
		if v.Host != "" {
			wsConfig["headers"] = map[string]string{"Host": v.Host}
		}
		outbound["transport"] = wsConfig
	} else if v.Net == "grpc" {
		outbound["transport"] = map[string]any{
			"type":         "grpc",
			"service_name": v.Path,
		}
	}

	raw, err := json.Marshal(outbound)
	if err != nil {
		return nil, err
	}
	return &ParsedOutbound{
		Tag:     tag,
		Type:    "vmess",
		Server:  v.Add,
		Port:    port,
		RawJSON: raw,
	}, nil
}

func parsePort(portStr string, defaultPort int) int {
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
		return p
	}
	return defaultPort
}

func cleanTag(tag, defaultTag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return defaultTag
	}
	// Decode percent-encoding if needed
	if decoded, err := url.QueryUnescape(tag); err == nil {
		tag = decoded
	}
	return tag
}

// SplitHostPort handles IPv6 brackets properly.
func SplitHostPort(addr string) (string, int, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, port, nil
}

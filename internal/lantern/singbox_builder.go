package lantern

import (
	"encoding/json"
	"fmt"
)

// SingBoxInboundConfig represents an inbound endpoint.
type SingBoxInboundConfig struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
}

// SingBoxCompleteConfig represents a full sing-box JSON configuration.
type SingBoxCompleteConfig struct {
	Log struct {
		Level     string `json:"level"`
		Timestamp bool   `json:"timestamp"`
	} `json:"log"`
	Inbounds  []SingBoxInboundConfig `json:"inbounds"`
	Outbounds []json.RawMessage      `json:"outbounds"`
	Route     struct {
		Rules []struct {
			Inbound  []string `json:"inbound,omitempty"`
			Outbound string   `json:"outbound"`
		} `json:"rules"`
		Final string `json:"final"`
	} `json:"route"`
}

// BuildCompleteSingBoxConfig builds a standard sing-box config containing:
// 1. A local SOCKS5 inbound at 127.0.0.1:socksPort.
// 2. An urltest outbound group automatically selecting the lowest latency working node.
// 3. A manual selector group.
// 4. Direct and DNS-out fallback outbounds.
func BuildCompleteSingBoxConfig(nodes []json.RawMessage, socksPort int) ([]byte, error) {
	if socksPort <= 0 {
		socksPort = 1080
	}

	var tags []string
	for i, raw := range nodes {
		var meta struct {
			Tag string `json:"tag"`
		}
		_ = json.Unmarshal(raw, &meta)
		tag := meta.Tag
		if tag == "" {
			tag = fmt.Sprintf("node-%d", i)
		}
		tags = append(tags, tag)
	}

	var outbounds []json.RawMessage

	// 1. urltest auto selector
	autoOutbound := map[string]any{
		"type":      "urltest",
		"tag":       "auto",
		"outbounds": tags,
		"url":       "http://cp.cloudflare.com/generate_204",
		"interval":  "3m",
		"tolerance": 50,
	}
	autoBytes, _ := json.Marshal(autoOutbound)
	outbounds = append(outbounds, autoBytes)

	// 2. manual selector
	selectorTags := append([]string{"auto"}, tags...)
	selectorOutbound := map[string]any{
		"type":      "selector",
		"tag":       "proxy",
		"outbounds": selectorTags,
		"default":   "auto",
	}
	selBytes, _ := json.Marshal(selectorOutbound)
	outbounds = append(outbounds, selBytes)

	// 3. direct
	directOutbound := map[string]any{
		"type": "direct",
		"tag":  "direct",
	}
	dirBytes, _ := json.Marshal(directOutbound)
	outbounds = append(outbounds, dirBytes)

	// 4. append all real proxy nodes
	outbounds = append(outbounds, nodes...)

	var cfg SingBoxCompleteConfig
	cfg.Log.Level = "warn"
	cfg.Log.Timestamp = true

	cfg.Inbounds = []SingBoxInboundConfig{
		{
			Type:       "socks",
			Tag:        "socks-in",
			Listen:     "127.0.0.1",
			ListenPort: socksPort,
		},
	}
	cfg.Outbounds = outbounds
	cfg.Route.Final = "proxy"

	return json.MarshalIndent(cfg, "", "  ")
}

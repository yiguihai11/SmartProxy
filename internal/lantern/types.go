package lantern

import (
	"encoding/json"
	"time"
)

// Standard protocols recognized and supported by standard sing-box.
var StandardProtocols = []string{
	"shadowsocks", "vmess", "vless", "trojan",
	"hysteria2", "tuic", "wireguard",
}

// Private / non-standard protocols from Lantern that standard sing-box cannot parse.
var PrivateProtocols = map[string]bool{
	"meek":      true,
	"water":     true,
	"reflex":    true,
	"unbounded": true,
	"algeneva":  true,
	"samizdat":  true,
	"outline":   true,
	"amnezia":   true,
}

// Infrastructure outbounds from Lantern that are not proxy nodes.
var InfraProtocols = map[string]bool{
	"direct":   true,
	"block":    true,
	"dns":      true,
	"selector": true,
	"urltest":  true,
	"fallback": true,
	"mux":      true,
}

// Account represents a single Lantern account and its traffic state.
type Account struct {
	DeviceID       string `json:"device_id"`
	UserID         int64  `json:"user_id"`
	ProToken       string `json:"pro_token"`
	Allot          int64  `json:"allot"`
	Used           int64  `json:"used"`
	Remain         int64  `json:"remain"`
	QuotaOK        bool   `json:"quota_ok"`
	ExhaustedUntil int64  `json:"exhausted_until,omitempty"` // Unix timestamp when quota resets
	LastCheck      int64  `json:"last_check"`
}

// UnmarshalJSON handles both integer and float (e.g. from Python time.time()) timestamp fields.
func (a *Account) UnmarshalJSON(data []byte) error {
	type rawAccount struct {
		DeviceID       string          `json:"device_id"`
		UserID         int64           `json:"user_id"`
		ProToken       string          `json:"pro_token"`
		Allot          int64           `json:"allot"`
		Used           int64           `json:"used"`
		Remain         int64           `json:"remain"`
		QuotaOK        bool            `json:"quota_ok"`
		ExhaustedUntil json.RawMessage `json:"exhausted_until,omitempty"`
		LastCheck      json.RawMessage `json:"last_check,omitempty"`
	}

	var raw rawAccount
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	a.DeviceID = raw.DeviceID
	a.UserID = raw.UserID
	a.ProToken = raw.ProToken
	a.Allot = raw.Allot
	a.Used = raw.Used
	a.Remain = raw.Remain
	a.QuotaOK = raw.QuotaOK

	parseTimestamp := func(rm json.RawMessage) int64 {
		if len(rm) == 0 || string(rm) == "null" {
			return 0
		}
		var f float64
		if err := json.Unmarshal(rm, &f); err == nil {
			return int64(f)
		}
		var s string
		if err := json.Unmarshal(rm, &s); err == nil {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t.Unix()
			}
		}
		return 0
	}

	a.ExhaustedUntil = parseTimestamp(raw.ExhaustedUntil)
	a.LastCheck = parseTimestamp(raw.LastCheck)

	return nil
}

// Config specifies the runtime configuration for the Lantern client.
type Config struct {
	DataDir         string        // Working directory for persistence (accounts.json, lantern_nodes.json)
	AccountsFile    string        // Accounts file name or relative path (default: accounts.json)
	NodesFile       string        // Nodes file name or relative path (default: lantern_nodes.json)
	MaxAccounts     int           // Maximum registered accounts allowed (default: 5)
	MinRemainBytes  int64         // Threshold below which an account is considered exhausted (default: 1MB)
	HTTPTimeout     time.Duration // Timeout for HTTP API calls (default: 30s)
	EnableSSE       bool          // Whether to enable background SSE listener (default: false, battery-saving)
	SingBoxPath     string        // Deprecated: sing-box is now embedded in-process as a Go library
	TestURL         string        // Probe URL to verify node connectivity (default: http://cp.cloudflare.com/generate_204)
	TestTimeout     time.Duration // Timeout per node connectivity test (default: 5s)
	FilterDeadNodes bool          // Whether to automatically test and prune unreachable nodes (default: true)
}

// NodeInfo contains parsed metadata for a standard outbound node.
type NodeInfo struct {
	Tag        string `json:"tag"`
	Type       string `json:"type"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Raw        json.RawMessage
}

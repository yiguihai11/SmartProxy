package engine

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"smartproxy/internal/dns"
	"smartproxy/internal/route"
	"smartproxy/internal/upstream"
)

const WarmStateFileName = "warm_state.json"

// WarmState holds transient operational state snapshots (dynamic blacklist, DNS cache,
// upstream node health/latency/circuit breakers) across core relaunches or to warm-start tethering core.
type WarmState struct {
	Version         int                      `json:"version"`
	Timestamp       int64                    `json:"timestamp"`
	IPBlacklist     []route.BlacklistEntry   `json:"ip_blacklist"`
	DomainBlacklist []route.BlacklistEntry   `json:"domain_blacklist"`
	DNSCache        []dns.SavedDNSEntry      `json:"dns_cache"`
	NodeStates      []upstream.NodeWarmState `json:"node_states"`
}

// ExportWarmState creates a WarmState snapshot of current runtime state.
func (e *Engine) ExportWarmState() *WarmState {
	if e == nil {
		return nil
	}
	var ipBL, domainBL []route.BlacklistEntry
	if e.Router != nil {
		ipBL, domainBL = e.Router.BlacklistSnapshot()
	}
	var dnsEntries []dns.SavedDNSEntry
	if e.DNSHandler != nil {
		dnsEntries = e.DNSHandler.DumpCache()
	}
	var nodeStates []upstream.NodeWarmState
	if e.UpstreamMgr != nil {
		nodeStates = e.UpstreamMgr.ExportNodeStates()
	}

	return &WarmState{
		Version:         1,
		Timestamp:       time.Now().Unix(),
		IPBlacklist:     ipBL,
		DomainBlacklist: domainBL,
		DNSCache:        dnsEntries,
		NodeStates:      nodeStates,
	}
}

// ExportWarmStateJSON returns the serialized JSON representation of ExportWarmState.
func (e *Engine) ExportWarmStateJSON() ([]byte, error) {
	ws := e.ExportWarmState()
	if ws == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(ws)
}

// ImportWarmState restores runtime state from a WarmState snapshot.
func (e *Engine) ImportWarmState(ws *WarmState) error {
	if e == nil || ws == nil {
		return nil
	}
	if e.Router != nil && (len(ws.IPBlacklist) > 0 || len(ws.DomainBlacklist) > 0) {
		e.Router.ImportBlacklist(ws.IPBlacklist, ws.DomainBlacklist)
	}
	if e.DNSHandler != nil && len(ws.DNSCache) > 0 {
		e.DNSHandler.ImportCache(ws.DNSCache)
	}
	if e.UpstreamMgr != nil && len(ws.NodeStates) > 0 {
		e.UpstreamMgr.ImportNodeStates(ws.NodeStates)
	}
	slog.Info("warm state imported successfully",
		"nodes", len(ws.NodeStates),
		"dns", len(ws.DNSCache),
		"ip_bl", len(ws.IPBlacklist),
		"domain_bl", len(ws.DomainBlacklist),
	)
	return nil
}

// ImportWarmStateJSON deserializes and imports warm state from JSON bytes.
func (e *Engine) ImportWarmStateJSON(data []byte) error {
	if len(data) == 0 || string(data) == "{}" {
		return nil
	}
	var ws WarmState
	if err := json.Unmarshal(data, &ws); err != nil {
		return fmt.Errorf("failed to unmarshal warm state: %w", err)
	}
	return e.ImportWarmState(&ws)
}

// loadWarmStateFromDir checks if warm_state.json exists in dir and imports it if present.
func (e *Engine) loadWarmStateFromDir(dir string) {
	if dir == "" {
		return
	}
	path := filepath.Join(dir, WarmStateFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return // not present, normal cold start
	}
	if err := e.ImportWarmStateJSON(data); err != nil {
		slog.Warn("failed to import warm state from disk", "path", path, "error", err)
	} else {
		slog.Info("loaded warm state from disk", "path", path)
	}
}

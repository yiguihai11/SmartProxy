package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"smartproxy/internal/adblock"
	"smartproxy/internal/config"
)

func (s *Server) handleAdBlockStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	if s.configSrc == nil { http.Error(w, "config not available", http.StatusServiceUnavailable); return }
	cfg := s.configSrc()
	var states interface{} = []adblock.SourceState{}
	if s.adblockMgr != nil { states = s.adblockMgr.Status() }
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": cfg.DNS.AdBlock.Enabled,
		"subscriptions": cfg.DNS.AdBlock.Subscriptions,
		"sources": states,
	})
}

func (s *Server) handleAdBlockRefresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	if s.adblockMgr == nil { http.Error(w, "adblock manager unavailable", http.StatusServiceUnavailable); return }
	var req struct { Name string `json:"name"` }
	if r.Body != nil { _ = json.NewDecoder(r.Body).Decode(&req) }
	if strings.TrimSpace(req.Name) == "" {
		s.adblockMgr.RefreshAll()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "refreshing": "all"})
		return
	}
	if err := s.adblockMgr.Refresh(r.Context(), strings.TrimSpace(req.Name)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest); return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func (s *Server) handleAdBlockSubscriptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.configSrc == nil { http.Error(w, "config not available", http.StatusServiceUnavailable); return }
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(s.configSrc().DNS.AdBlock.Subscriptions)
		return
	}
	if s.configPath == "" || s.reloadConfig == nil {
		http.Error(w, "config write not available", http.StatusServiceUnavailable); return
	}
	current := s.configSrc()
	if current == nil { http.Error(w, "config not available", http.StatusServiceUnavailable); return }
	next := *current
	next.DNS = current.DNS
	next.DNS.AdBlock = current.DNS.AdBlock
	next.DNS.AdBlock.Subscriptions = append([]config.AdBlockSubscription(nil), current.DNS.AdBlock.Subscriptions...)

	switch r.Method {
	case http.MethodPost:
		var req config.AdBlockSubscription
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest); return }
		req.Name = strings.TrimSpace(req.Name)
		req.URL = strings.TrimSpace(req.URL)
		if req.Name == "" { http.Error(w, "name is required", http.StatusBadRequest); return }
		u, err := url.ParseRequestURI(req.URL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			http.Error(w, "URL must be http(s)", http.StatusBadRequest); return
		}
		replaced := false
		for i, old := range next.DNS.AdBlock.Subscriptions {
			if old.Name == req.Name || old.URL == req.URL {
				next.DNS.AdBlock.Subscriptions[i] = req
				replaced = true
				break
			}
		}
		if !replaced { next.DNS.AdBlock.Subscriptions = append(next.DNS.AdBlock.Subscriptions, req) }
	case http.MethodDelete:
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" { http.Error(w, "name is required", http.StatusBadRequest); return }
		filtered := next.DNS.AdBlock.Subscriptions[:0]
		found := false
		for _, sub := range next.DNS.AdBlock.Subscriptions {
			if sub.Name == name || sub.URL == name { found = true; continue }
			filtered = append(filtered, sub)
		}
		if !found { http.Error(w, "subscription not found", http.StatusNotFound); return }
		next.DNS.AdBlock.Subscriptions = filtered
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := json.MarshalIndent(&next, "", "  ")
	if err != nil { http.Error(w, fmt.Sprintf("encode config: %v", err), http.StatusInternalServerError); return }
	if err := atomicWriteFile(s.configPath, data, 0600); err != nil {
		http.Error(w, "save config: "+err.Error(), http.StatusInternalServerError); return
	}
	s.reloadConfig()
	if s.adblockMgr != nil {
		subs := make([]adblock.Subscription, 0, len(next.DNS.AdBlock.Subscriptions))
		for _, sub := range next.DNS.AdBlock.Subscriptions {
			subs = append(subs, adblock.Subscription{Name: sub.Name, URL: sub.URL, Enabled: sub.Enabled})
		}
		s.adblockMgr.Configure(subs)
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "subscriptions": next.DNS.AdBlock.Subscriptions})
}

func (s *Server) handleAdBlockToggle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	if s.configSrc == nil || s.configPath == "" || s.reloadConfig == nil {
		http.Error(w, "config write not available", http.StatusServiceUnavailable); return
	}
	var req struct { Enabled *bool `json:"enabled"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Enabled == nil {
		http.Error(w, "enabled boolean is required", http.StatusBadRequest); return
	}
	current := s.configSrc()
	if current == nil { http.Error(w, "config not available", http.StatusServiceUnavailable); return }
	next := *current
	next.DNS = current.DNS
	next.DNS.AdBlock = current.DNS.AdBlock
	next.DNS.AdBlock.Subscriptions = append([]config.AdBlockSubscription(nil), current.DNS.AdBlock.Subscriptions...)
	next.DNS.AdBlock.Enabled = *req.Enabled
	data, err := json.MarshalIndent(&next, "", "  ")
	if err != nil { http.Error(w, "encode config: "+err.Error(), http.StatusInternalServerError); return }
	if err := atomicWriteFile(s.configPath, data, 0600); err != nil {
		http.Error(w, "save config: "+err.Error(), http.StatusInternalServerError); return
	}
	s.reloadConfig()
	if s.adblockMgr != nil {
		s.adblockMgr.SetEnabled(*req.Enabled)
		if *req.Enabled { s.adblockMgr.Start() }
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "enabled": *req.Enabled})
}

package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"smartproxy/internal/config"
)

func (s *Server) handleAdblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if s.adblockMgr == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":     false,
			"items":       []interface{}{},
			"total_hits":  0,
			"since":       0,
			"top_domains": []interface{}{},
			"cache_count": 0,
			"cache_mtime": 0,
			"whitelist":   []string{},
		})
		return
	}

	st := s.adblockMgr.Status()
	wl := s.adblockMgr.Whitelist()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":     st.Enabled,
		"items":       st.Items,
		"total_hits":  st.TotalHits,
		"since":       st.Since,
		"top_domains": st.TopDomains,
		"cache_count": st.CacheCount,
		"cache_mtime": st.CacheMtime,
		"whitelist":   wl,
	})
}

func (s *Server) handleAdblockRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.adblockMgr == nil {
		http.Error(w, "adblock manager unavailable", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	target := strings.TrimSpace(req.Name)
	kept, err := s.adblockMgr.Refresh(r.Context(), target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"kept":   kept,
	})
}

func (s *Server) handleAdblockSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req config.AdblockListConf
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.URL = strings.TrimSpace(req.URL)
	if req.Name == "" || req.URL == "" {
		http.Error(w, "name and url must not be empty", http.StatusBadRequest)
		return
	}
	u, err := url.ParseRequestURI(req.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		http.Error(w, "url must be a valid http(s) URL", http.StatusBadRequest)
		return
	}
	if req.UpdateInterval == "" {
		req.UpdateInterval = "24h"
	}

	_, valErr, writeErr := s.saveConfig(func(c *config.Config) {
		found := false
		for i, l := range c.DNS.Adblock.Lists {
			if l.Name == req.Name {
				c.DNS.Adblock.Lists[i] = req
				found = true
				break
			}
		}
		if !found {
			c.DNS.Adblock.Lists = append(c.DNS.Adblock.Lists, req)
		}
	})
	if valErr != nil {
		http.Error(w, "validation failed: "+valErr.Error(), http.StatusBadRequest)
		return
	}
	if writeErr != nil {
		http.Error(w, "write failed: "+writeErr.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("admin: adblock subscription saved", "name", req.Name, "url", req.URL)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
}

func (s *Server) handleAdblockDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		var req struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		name = strings.TrimSpace(req.Name)
	}
	if name == "" {
		http.Error(w, "name must not be empty", http.StatusBadRequest)
		return
	}

	_, valErr, writeErr := s.saveConfig(func(c *config.Config) {
		var filtered []config.AdblockListConf
		for _, l := range c.DNS.Adblock.Lists {
			if l.Name != name && l.URL != name {
				filtered = append(filtered, l)
			}
		}
		c.DNS.Adblock.Lists = filtered
	})
	if valErr != nil {
		http.Error(w, "validation failed: "+valErr.Error(), http.StatusBadRequest)
		return
	}
	if writeErr != nil {
		http.Error(w, "write failed: "+writeErr.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("admin: adblock subscription deleted", "name", name)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
}

func (s *Server) handleAdblockToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name    string `json:"name,omitempty"`
		Enabled *bool  `json:"enabled,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSpace(r.URL.Query().Get("name"))
	}

	enable := true
	if req.Enabled != nil {
		enable = *req.Enabled
	} else if enableStr := r.URL.Query().Get("enable"); enableStr != "" {
		enable = enableStr == "true" || enableStr == "1"
	}

	_, valErr, writeErr := s.saveConfig(func(c *config.Config) {
		if name != "" {
			for i, l := range c.DNS.Adblock.Lists {
				if l.Name == name || l.URL == name {
					c.DNS.Adblock.Lists[i].Enabled = enable
					break
				}
			}
		} else {
			c.DNS.Adblock.Enabled = enable
		}
	})
	if valErr != nil {
		http.Error(w, "validation failed: "+valErr.Error(), http.StatusBadRequest)
		return
	}
	if writeErr != nil {
		http.Error(w, "write failed: "+writeErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "enabled": enable})
}

func (s *Server) handleAdblockWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action string `json:"action"` // "add" or "remove"
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	domain := strings.TrimSpace(strings.ToLower(req.Domain))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, ".")
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		http.Error(w, "domain must not be empty", http.StatusBadRequest)
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != "add" && action != "remove" {
		http.Error(w, "action must be 'add' or 'remove'", http.StatusBadRequest)
		return
	}

	_, valErr, writeErr := s.saveConfig(func(c *config.Config) {
		if action == "add" {
			for _, d := range c.DNS.Adblock.Whitelist {
				if d == domain {
					return
				}
			}
			if len(c.DNS.Adblock.Whitelist) >= 5000 {
				return
			}
			c.DNS.Adblock.Whitelist = append(c.DNS.Adblock.Whitelist, domain)
		} else {
			var filtered []string
			for _, d := range c.DNS.Adblock.Whitelist {
				if d != domain {
					filtered = append(filtered, d)
				}
			}
			c.DNS.Adblock.Whitelist = filtered
		}
	})
	if valErr != nil {
		http.Error(w, "validation failed: "+valErr.Error(), http.StatusBadRequest)
		return
	}
	if writeErr != nil {
		http.Error(w, "write failed: "+writeErr.Error(), http.StatusInternalServerError)
		return
	}

	wl := []string{}
	if s.adblockMgr != nil {
		wl = s.adblockMgr.Whitelist()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "whitelist": wl})
}

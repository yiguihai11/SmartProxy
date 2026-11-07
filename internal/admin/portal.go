package admin

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"smartproxy/internal/portal"
)

//go:embed portal.html
var portalHTML string

var portalTmpl = template.Must(template.New("portal").Parse(portalHTML))

type portalPageData struct {
	Title       string
	ClientIP    string
	CSRFToken   string
	RedirectURL string
}

// SetPortalManager attaches the captive portal manager to the admin server.
func (s *Server) SetPortalManager(mgr *portal.Manager) {
	s.portalMgr = mgr
	if mgr != nil {
		var cacheMu sync.RWMutex
		var lastFetch time.Time
		var cachedTable map[string]string

		mgr.SetMACResolver(func(ip string) string {
			cacheMu.RLock()
			if time.Since(lastFetch) < 3*time.Second && cachedTable != nil {
				mac := cachedTable[ip]
				cacheMu.RUnlock()
				return mac
			}
			cacheMu.RUnlock()

			cacheMu.Lock()
			defer cacheMu.Unlock()
			// Double check under write lock
			if time.Since(lastFetch) < 3*time.Second && cachedTable != nil {
				return cachedTable[ip]
			}

			newTable := make(map[string]string)

			// 1. Read from system ARP table
			for k, v := range readSystemARP() {
				newTable[k] = strings.ToLower(v)
			}

			// 2. Read from hardware tethering bridge if available
			if s.tetheringBridge != nil {
				raw := s.tetheringBridge.GetTetheredClients()
				if raw != "" {
					var clients []struct {
						MAC         string   `json:"mac"`
						IP          string   `json:"ip"`
						AssignedIPs []string `json:"assigned_ips"`
						ExtraIPs    []string `json:"extra_ips"`
					}
					if err := json.Unmarshal([]byte(raw), &clients); err == nil {
						for _, c := range clients {
							mac := strings.ToLower(c.MAC)
							if c.IP != "" {
								newTable[c.IP] = mac
							}
							for _, aip := range c.AssignedIPs {
								if aip != "" {
									newTable[aip] = mac
								}
							}
							for _, eip := range c.ExtraIPs {
								if eip != "" {
									newTable[eip] = mac
								}
							}
						}
						// If exactly 1 physical client is connected to the tethering hotspot,
						// map the virtual TUN NAT IP addresses to that client's physical MAC.
						if len(clients) == 1 && clients[0].MAC != "" {
							singleMAC := strings.ToLower(clients[0].MAC)
							newTable["192.0.2.2"] = singleMAC
							newTable["2001:db8:9877::2"] = singleMAC
						}
					}
				}
			}

			cachedTable = newTable
			lastFetch = time.Now()
			return cachedTable[ip]
		})
	}
}

// handlePortal serves the captive portal authentication page.
func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	if s.portalMgr == nil || !s.portalMgr.IsEnabled() {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	clientIP := extractClientIP(r)

	// Check if already authenticated by cookie token
	if cookie, err := r.Cookie("smartproxy_portal_token"); err == nil && cookie.Value != "" {
		if _, err := s.portalMgr.AuthenticateByToken(clientIP, "", cookie.Value, r.UserAgent()); err == nil {
			// Seamless auto-redirect if target URL specified
			target := r.URL.Query().Get("url")
			if target == "" {
				target = r.URL.Query().Get("redirect-url")
			}
			if target != "" && (strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")) {
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
		}
	}

	target := r.URL.Query().Get("url")
	if target == "" {
		target = r.URL.Query().Get("redirect-url")
	}

	csrf := s.portalMgr.GenerateCSRFToken(clientIP)

	title := "SmartProxy Hotspot"
	if cfg := s.configSrc(); cfg != nil && cfg.Listen.Portal != nil && cfg.Listen.Portal.PortalTitle() != "" {
		title = cfg.Listen.Portal.PortalTitle()
	}

	data := portalPageData{
		Title:       title,
		ClientIP:    clientIP,
		CSRFToken:   csrf,
		RedirectURL: target,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	_ = portalTmpl.Execute(w, data)
}

// handlePortalLogin processes authentication login requests.
func (s *Server) handlePortalLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.portalMgr == nil || !s.portalMgr.IsEnabled() {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "Captive Portal is not enabled",
		})
		return
	}

	clientIP := extractClientIP(r)

	// Validate CSRF token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		csrfToken = r.FormValue("csrf_token")
	}

	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		CSRFToken string `json:"csrf_token"`
	}

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "Invalid request JSON"})
			return
		}
	} else {
		req.Username = r.FormValue("username")
		req.Password = r.FormValue("password")
		if req.CSRFToken != "" {
			csrfToken = req.CSRFToken
		}
	}

	if csrfToken == "" && req.CSRFToken != "" {
		csrfToken = req.CSRFToken
	}

	if !s.portalMgr.ValidateCSRFToken(clientIP, csrfToken) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "Invalid or expired CSRF token. Please refresh the page.",
		})
		return
	}

	// Authenticate client
	sess, token, err := s.portalMgr.Authenticate(clientIP, "", req.Username, req.Password, r.UserAgent())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	// Set persistent HttpOnly session cookie
	maxAge := int(time.Until(sess.ExpiresAt).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "smartproxy_portal_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
		MaxAge:   maxAge,
	})

	resp := map[string]interface{}{
		"ok":          true,
		"user":        sess.Username,
		"mac":         sess.MAC,
		"login_at":    sess.LoginAt.Unix(),
		"expires_at":  sess.ExpiresAt.Unix(),
		"allow_proxy": s.portalMgr.IsUserProxyAllowed(sess.Username),
	}
	traffic := s.portalMgr.GetUserTrafficInfo(sess.Username)
	if traffic != nil {
		resp["traffic_limit_bytes"] = traffic.LimitBytes
		resp["traffic_used_bytes"] = traffic.UsedBytes
		resp["traffic_reset_cycle"] = traffic.ResetCycle
		if !traffic.NextReset.IsZero() {
			resp["traffic_next_reset"] = traffic.NextReset.Unix()
		}
		resp["quota_exceeded"] = traffic.IsExceeded
		resp["traffic_reset_desc"] = traffic.ResetDescription
	}
	activeDevs, maxDevs := s.portalMgr.UserSessionStats(sess.Username)
	resp["active_devices"] = activeDevs
	resp["max_devices"] = maxDevs

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handlePortalLogout ends the client's authenticated portal session.
func (s *Server) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clientIP := extractClientIP(r)

	token := ""
	if cookie, err := r.Cookie("smartproxy_portal_token"); err == nil {
		token = cookie.Value
	}

	if s.portalMgr != nil {
		s.portalMgr.Logout(clientIP, "", token)
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "smartproxy_portal_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// handlePortalStatus returns authentication status for the requesting client.
func (s *Server) handlePortalStatus(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r)

	if s.portalMgr == nil || !s.portalMgr.IsEnabled() {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":       false,
			"authenticated": true,
			"ip":            clientIP,
		})
		return
	}

	sess := s.portalMgr.GetSession(clientIP, "")
	if sess == nil {
		// Also try resolving cookie
		if cookie, err := r.Cookie("smartproxy_portal_token"); err == nil && cookie.Value != "" {
			if roamed, err := s.portalMgr.AuthenticateByToken(clientIP, "", cookie.Value, r.UserAgent()); err == nil {
				sess = roamed
			}
		}
	}

	resp := map[string]interface{}{
		"enabled":       true,
		"ip":            clientIP,
		"authenticated": sess != nil,
	}

	if sess != nil {
		resp["user"] = sess.Username
		resp["mac"] = sess.MAC
		resp["login_at"] = sess.LoginAt.Unix()
		resp["expires_at"] = sess.ExpiresAt.Unix()
		resp["allow_proxy"] = s.portalMgr.IsUserProxyAllowed(sess.Username)

		traffic := s.portalMgr.GetUserTrafficInfo(sess.Username)
		if traffic != nil {
			resp["traffic_limit_bytes"] = traffic.LimitBytes
			resp["traffic_used_bytes"] = traffic.UsedBytes
			resp["traffic_reset_cycle"] = traffic.ResetCycle
			if !traffic.NextReset.IsZero() {
				resp["traffic_next_reset"] = traffic.NextReset.Unix()
			}
			resp["quota_exceeded"] = traffic.IsExceeded
			resp["traffic_reset_desc"] = traffic.ResetDescription
		}
		activeDevs, maxDevs := s.portalMgr.UserSessionStats(sess.Username)
		resp["active_devices"] = activeDevs
		resp["max_devices"] = maxDevs
	} else if s.portalMgr.IsAuthorized(clientIP) {
		resp["authenticated"] = true
		resp["exempt"] = true
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handlePortalTraffic returns traffic consumption and quota stats for all users.
func (s *Server) handlePortalTraffic(w http.ResponseWriter, r *http.Request) {
	if s.portalMgr == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"users": []interface{}{}})
		return
	}

	records := s.portalMgr.AllUsersTraffic()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    true,
		"users": records,
	})
}

// handlePortalTrafficReset clears traffic quota counters for a user.
func (s *Server) handlePortalTrafficReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.portalMgr == nil {
		http.Error(w, "portal not initialized", http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Username = r.FormValue("username")
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	reset := s.portalMgr.ResetUserTraffic(req.Username)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       true,
		"reset":    reset,
		"username": req.Username,
	})
}

// handlePortalKick allows administrators to forcibly terminate a device's portal session.
func (s *Server) handlePortalKick(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := r.URL.Query().Get("target")
	ip := r.URL.Query().Get("ip")
	if target == "" {
		var body struct {
			Target string `json:"target"`
			IP     string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			target = body.Target
			if ip == "" {
				ip = body.IP
			}
		}
	}

	target = strings.TrimSpace(target)
	ip = strings.TrimSpace(ip)
	if target == "" && ip != "" {
		target = ip
	}
	if target == "" {
		http.Error(w, "target IP or MAC required", http.StatusBadRequest)
		return
	}

	revoked := false
	if s.portalMgr != nil {
		revoked = s.portalMgr.RevokeSession(target)
		if ip != "" && ip != target {
			if s.portalMgr.RevokeSession(ip) {
				revoked = true
			}
		}
	}

	if s.tetheringBridge != nil {
		if s.tetheringBridge.KickClient(target, ip) {
			revoked = true
		}
	}

	// Kill existing TCP connections for target, ip, and tethering NAT address
	if s.killClientConnections != nil {
		_ = s.killClientConnections(target)
		if ip != "" {
			_ = s.killClientConnections(ip)
		}
		_ = s.killClientConnections("192.0.2.2")
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"revoked": revoked,
		"target":  target,
	})
}

func isCapportPath(p string) bool {
	return p == "/.well-known/captive-portal" || p == "/.well-known/capport" ||
		p == "/api/capport" || p == "/api/captive-portal"
}

// handleCapport implements the RFC 8908 Captive Portal API endpoint.
// It returns application/captive+json conforming to RFC 8908 section 4.
func (s *Server) handleCapport(w http.ResponseWriter, r *http.Request) {
	// CORS support for modern captive portal web agents and preflight
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, X-Requested-With")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := extractClientIP(r)

	redirectHost := "smartproxy.lan"
	if h := r.Host; h != "" {
		if host, _, err := net.SplitHostPort(h); err == nil {
			redirectHost = host
		} else {
			redirectHost = h
		}
	}

	adminPort := s.tcpPort
	if adminPort <= 0 {
		adminPort = 9090
	}

	var status portal.CapportStatus
	if s.portalMgr != nil {
		status = s.portalMgr.GetCapportStatus(clientIP, redirectHost, adminPort)
	} else {
		status = portal.CapportStatus{
			Captive:       false,
			UserPortalURL: fmt.Sprintf("http://%s:%d/portal", redirectHost, adminPort),
		}
	}

	// RFC 8908 Section 4.1 specifies Content-Type: application/captive+json
	w.Header().Set("Content-Type", "application/captive+json")
	w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(status)
}

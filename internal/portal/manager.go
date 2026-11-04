package portal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"smartproxy/internal/config"
	"smartproxy/internal/safego"
)

// Session represents an authenticated portal user session.
type Session struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Username  string    `json:"username"`
	LoginAt   time.Time `json:"login_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UserAgent string    `json:"user_agent"`
	Token     string    `json:"token,omitempty"`
}

type failRecord struct {
	count      int
	lastFail   time.Time
	lockedTill time.Time
}

// Manager manages captive portal authentication, active sessions, and security limits.
type Manager struct {
	mu              sync.RWMutex
	config          atomic.Pointer[config.Config]
	sessionsByIP    map[string]*Session
	sessionsByMAC   map[string]*Session
	sessionsByToken map[string]*Session
	failedAttempts  map[string]*failRecord
	csrfSecret      []byte
	macResolver     func(ip string) string
	stopCh          chan struct{}
	stopOnce        sync.Once
}

// NewManager creates a new portal Manager.
func NewManager(cfg *config.Config) *Manager {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// Fallback to time-based entropy if crypto/rand fails
		h := sha256.Sum256([]byte(fmt.Sprintf("portal-secret-%d", time.Now().UnixNano())))
		copy(secret, h[:])
	}

	m := &Manager{
		sessionsByIP:    make(map[string]*Session),
		sessionsByMAC:   make(map[string]*Session),
		sessionsByToken: make(map[string]*Session),
		failedAttempts:  make(map[string]*failRecord),
		csrfSecret:      secret,
		stopCh:          make(chan struct{}),
	}
	m.config.Store(cfg)

	m.startCleaner()
	return m
}

func (m *Manager) startCleaner() {
	safego.Go("portal.cleaner", func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.purgeExpired()
			case <-m.stopCh:
				return
			}
		}
	})
}

// Close stops the periodic cleanup goroutine.
func (m *Manager) Close() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

// SetMACResolver registers an optional hook to query physical MAC for an IP.
func (m *Manager) SetMACResolver(fn func(ip string) string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.macResolver = fn
}

// UpdateConfig hot-reloads the portal configuration.
func (m *Manager) UpdateConfig(cfg *config.Config) {
	m.config.Store(cfg)
}

func (m *Manager) getPortalConf() *config.PortalConf {
	cfg := m.config.Load()
	if cfg == nil || cfg.Listen.Portal == nil {
		return nil
	}
	return cfg.Listen.Portal
}

func (m *Manager) getAuthConf() *config.AuthConf {
	cfg := m.config.Load()
	if cfg == nil {
		return nil
	}
	return cfg.Listen.Auth
}

// IsEnabled reports whether the Captive Portal is active.
func (m *Manager) IsEnabled() bool {
	p := m.getPortalConf()
	return p != nil && p.Enabled
}

// IsAuthorized checks whether the client IP has an active authenticated session or is exempt.
func (m *Manager) IsAuthorized(clientIP string) bool {
	if !m.IsEnabled() {
		return true
	}

	normIP := normalizeIP(clientIP)
	if normIP == "" {
		return false
	}

	p := m.getPortalConf()
	if p != nil {
		for _, ip := range p.ExemptIPs {
			if normalizeIP(ip) == normIP {
				return true
			}
		}
	}

	var currentMAC string
	m.mu.RLock()
	resolver := m.macResolver
	m.mu.RUnlock()

	if resolver != nil {
		currentMAC = strings.ToLower(resolver(normIP))
	}

	if p != nil && currentMAC != "" {
		for _, mac := range p.ExemptMACs {
			if strings.EqualFold(mac, currentMAC) {
				return true
			}
		}
	}

	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 1. Check IP session
	if sess, ok := m.sessionsByIP[normIP]; ok {
		if now.Before(sess.ExpiresAt) {
			// MAC integrity check: if neighbor table reports a different non-empty MAC,
			// prevent stale IP takeover from authorizing an imposter device.
			if currentMAC != "" && sess.MAC != "" && !strings.EqualFold(sess.MAC, currentMAC) {
				m.mu.RUnlock()
				m.mu.Lock()
				if cur, exists := m.sessionsByIP[normIP]; exists && cur.MAC == sess.MAC {
					delete(m.sessionsByIP, normIP)
				}
				m.mu.Unlock()
				m.mu.RLock()
				return false
			}
			return true
		}
	}

	// 2. Check MAC session for seamless IP roaming
	if currentMAC != "" {
		if sess, ok := m.sessionsByMAC[currentMAC]; ok {
			if now.Before(sess.ExpiresAt) {
				return true
			}
		}
	}

	return false
}

// Authenticate verifies credentials and establishes an authenticated session.
func (m *Manager) Authenticate(clientIP, mac, username, password, userAgent string) (*Session, string, error) {
	if !m.IsEnabled() {
		return nil, "", errors.New("captive portal is disabled")
	}

	normIP := normalizeIP(clientIP)
	if normIP == "" {
		return nil, "", errors.New("invalid client IP")
	}

	// Rate limiting / brute-force protection
	if err := m.checkRateLimit(normIP); err != nil {
		return nil, "", err
	}

	auth := m.getAuthConf()
	if auth == nil || !auth.HasCredentials() {
		return nil, "", errors.New("no authentication users configured on server")
	}

	if !auth.Match(username, password) {
		m.recordFailure(normIP)
		return nil, "", errors.New("invalid username or password")
	}

	// Successful credential match resets failure tracker
	m.recordSuccess(normIP)

	normMAC := strings.ToLower(strings.TrimSpace(mac))
	if normMAC == "" {
		m.mu.RLock()
		resolver := m.macResolver
		m.mu.RUnlock()
		if resolver != nil {
			normMAC = strings.ToLower(resolver(normIP))
		}
	}

	p := m.getPortalConf()
	leaseDuration := p.LeaseDuration()

	m.mu.Lock()
	defer m.mu.Unlock()

	maxDevices := auth.UserMaxDevices(username)
	now := time.Now()

	// Strategy B: Reject new login when active device count reaches max_devices.
	if maxDevices > 0 {
		var activeDevices []*Session
		isRenewing := false

		// Check all existing sessions for this username
		for _, s := range m.sessionsByIP {
			if s.Username == username && now.Before(s.ExpiresAt) {
				// Avoid counting the same device twice
				if s.IP == normIP || (normMAC != "" && strings.EqualFold(s.MAC, normMAC)) {
					isRenewing = true
				} else {
					// Check if already in activeDevices by MAC or IP
					found := false
					for _, d := range activeDevices {
						if d.IP == s.IP || (d.MAC != "" && strings.EqualFold(d.MAC, s.MAC)) {
							found = true
							break
						}
					}
					if !found {
						activeDevices = append(activeDevices, s)
					}
				}
			}
		}

		// Also check sessionsByMAC in case device has no IP session yet
		for _, s := range m.sessionsByMAC {
			if s.Username == username && now.Before(s.ExpiresAt) {
				if s.IP == normIP || (normMAC != "" && strings.EqualFold(s.MAC, normMAC)) {
					isRenewing = true
				} else {
					found := false
					for _, d := range activeDevices {
						if d.IP == s.IP || (d.MAC != "" && strings.EqualFold(d.MAC, s.MAC)) {
							found = true
							break
						}
					}
					if !found {
						activeDevices = append(activeDevices, s)
					}
				}
			}
		}

		if !isRenewing && len(activeDevices) >= maxDevices {
			var deviceDetails []string
			for _, d := range activeDevices {
				info := d.IP
				if d.MAC != "" {
					info += " (" + d.MAC + ")"
				}
				deviceDetails = append(deviceDetails, info)
			}
			return nil, "", fmt.Errorf("concurrent device limit (%d) reached for user %q. Active devices: [%s]. Please log out on another device first", maxDevices, username, strings.Join(deviceDetails, ", "))
		}
	}

	token := generateSecureToken()
	sess := &Session{
		IP:        normIP,
		MAC:       normMAC,
		Username:  username,
		LoginAt:   now,
		ExpiresAt: now.Add(leaseDuration),
		UserAgent: userAgent,
		Token:     token,
	}

	// Remove old session under this IP or MAC if any
	m.removeSessionLocked(normIP, normMAC, "")

	m.sessionsByIP[normIP] = sess
	if normMAC != "" {
		m.sessionsByMAC[normMAC] = sess
	}
	m.sessionsByToken[token] = sess

	return sess, token, nil
}

// AuthenticateByToken re-authenticates or roams an existing valid session using its cookie token.
func (m *Manager) AuthenticateByToken(clientIP, mac, token, userAgent string) (*Session, error) {
	if !m.IsEnabled() {
		return nil, errors.New("captive portal is disabled")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("empty token")
	}

	normIP := normalizeIP(clientIP)
	normMAC := strings.ToLower(strings.TrimSpace(mac))

	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessionsByToken[token]
	if !ok || time.Now().After(sess.ExpiresAt) {
		if ok {
			delete(m.sessionsByToken, token)
		}
		return nil, errors.New("session expired or token invalid")
	}

	// If resolved MAC is empty, try resolver
	if normMAC == "" && m.macResolver != nil && normIP != "" {
		normMAC = strings.ToLower(m.macResolver(normIP))
	}

	// Update roaming IP/MAC
	if normIP != "" && normIP != sess.IP {
		delete(m.sessionsByIP, sess.IP)
		sess.IP = normIP
		m.sessionsByIP[normIP] = sess
	}
	if normMAC != "" && normMAC != sess.MAC {
		if sess.MAC != "" {
			delete(m.sessionsByMAC, sess.MAC)
		}
		sess.MAC = normMAC
		m.sessionsByMAC[normMAC] = sess
	}
	if userAgent != "" {
		sess.UserAgent = userAgent
	}

	return sess, nil
}

// Logout ends an authenticated session for an IP, MAC, or token.
func (m *Manager) Logout(clientIP, mac, token string) {
	normIP := normalizeIP(clientIP)
	normMAC := strings.ToLower(strings.TrimSpace(mac))

	m.mu.Lock()
	defer m.mu.Unlock()

	m.removeSessionLocked(normIP, normMAC, token)
}

// RevokeSession revokes any session matching the given IP or MAC address (Admin Kick).
func (m *Manager) RevokeSession(ipOrMAC string) bool {
	target := strings.TrimSpace(ipOrMAC)
	if target == "" {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	normIP := normalizeIP(target)
	normMAC := strings.ToLower(target)

	found := false
	if sess, ok := m.sessionsByIP[normIP]; ok {
		m.removeSessionLocked(sess.IP, sess.MAC, sess.Token)
		found = true
	}
	if sess, ok := m.sessionsByMAC[normMAC]; ok {
		m.removeSessionLocked(sess.IP, sess.MAC, sess.Token)
		found = true
	}
	return found
}

func (m *Manager) removeSessionLocked(ip, mac, token string) {
	var tokensToRemove []string

	if ip != "" {
		if s, ok := m.sessionsByIP[ip]; ok {
			tokensToRemove = append(tokensToRemove, s.Token)
			delete(m.sessionsByIP, ip)
		}
	}
	if mac != "" {
		if s, ok := m.sessionsByMAC[mac]; ok {
			tokensToRemove = append(tokensToRemove, s.Token)
			delete(m.sessionsByMAC, mac)
		}
	}
	if token != "" {
		tokensToRemove = append(tokensToRemove, token)
	}

	for _, t := range tokensToRemove {
		if t != "" {
			if s, ok := m.sessionsByToken[t]; ok {
				delete(m.sessionsByIP, s.IP)
				if s.MAC != "" {
					delete(m.sessionsByMAC, s.MAC)
				}
				delete(m.sessionsByToken, t)
			}
		}
	}
}

// GetSession returns the active session for an IP or MAC, if any.
func (m *Manager) GetSession(clientIP, mac string) *Session {
	normIP := normalizeIP(clientIP)
	normMAC := strings.ToLower(strings.TrimSpace(mac))

	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()

	if normIP != "" {
		if s, ok := m.sessionsByIP[normIP]; ok && now.Before(s.ExpiresAt) {
			cp := *s
			return &cp
		}
	}
	if normMAC != "" {
		if s, ok := m.sessionsByMAC[normMAC]; ok && now.Before(s.ExpiresAt) {
			cp := *s
			return &cp
		}
	}
	return nil
}

// ActiveSessions returns a list of all currently active sessions.
func (m *Manager) ActiveSessions() []*Session {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()

	seen := make(map[string]bool)
	var result []*Session

	for _, s := range m.sessionsByToken {
		if now.Before(s.ExpiresAt) && !seen[s.Token] {
			seen[s.Token] = true
			cp := *s
			result = append(result, &cp)
		}
	}
	return result
}

// Rate limiting: 5 failed attempts within 5 minutes = 5 minute jail
func (m *Manager) checkRateLimit(ip string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.failedAttempts[ip]
	if !ok {
		return nil
	}
	now := time.Now()
	if now.Before(rec.lockedTill) {
		remaining := int(rec.lockedTill.Sub(now).Seconds())
		return fmt.Errorf("too many failed login attempts; please wait %d seconds before trying again", remaining)
	}
	return nil
}

func (m *Manager) recordFailure(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	rec, ok := m.failedAttempts[ip]
	if !ok || now.Sub(rec.lastFail) > 5*time.Minute {
		rec = &failRecord{count: 1, lastFail: now}
		m.failedAttempts[ip] = rec
		return
	}

	rec.count++
	rec.lastFail = now
	if rec.count >= 5 {
		rec.lockedTill = now.Add(5 * time.Minute)
	}
}

func (m *Manager) recordSuccess(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.failedAttempts, ip)
}

func (m *Manager) purgeExpired() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	for token, s := range m.sessionsByToken {
		if now.After(s.ExpiresAt) {
			delete(m.sessionsByToken, token)
			if curr, ok := m.sessionsByIP[s.IP]; ok && curr.Token == token {
				delete(m.sessionsByIP, s.IP)
			}
			if s.MAC != "" {
				if curr, ok := m.sessionsByMAC[s.MAC]; ok && curr.Token == token {
					delete(m.sessionsByMAC, s.MAC)
				}
			}
		}
	}

	for ip, rec := range m.failedAttempts {
		if now.After(rec.lockedTill) && now.Sub(rec.lastFail) > 10*time.Minute {
			delete(m.failedAttempts, ip)
		}
	}
}

// GenerateCSRFToken generates a signed CSRF token bound to client IP and timestamp window.
func (m *Manager) GenerateCSRFToken(clientIP string) string {
	normIP := normalizeIP(clientIP)
	window := time.Now().Unix() / 3600 // hourly window
	msg := fmt.Sprintf("%s:%d", normIP, window)

	mac := hmac.New(sha256.New, m.csrfSecret)
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%d.%s", window, sig)
}

// ValidateCSRFToken verifies that a CSRF token is valid and issued for the given client IP.
func (m *Manager) ValidateCSRFToken(clientIP, token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	window, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	currentWindow := time.Now().Unix() / 3600
	// Allow current hour or previous hour
	if window != currentWindow && window != currentWindow-1 {
		return false
	}

	normIP := normalizeIP(clientIP)
	msg := fmt.Sprintf("%s:%d", normIP, window)

	mac := hmac.New(sha256.New, m.csrfSecret)
	mac.Write([]byte(msg))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(parts[1]), []byte(expectedSig))
}

func normalizeIP(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return ""
	}
	// Fast path for plain IPv4: no brackets, no colons
	if strings.IndexByte(ipStr, ':') == -1 && strings.IndexByte(ipStr, '[') == -1 {
		return ipStr
	}
	// Strip IPv6 brackets [::1]
	ipStr = strings.Trim(ipStr, "[]")
	// If host:port, split host
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return ipStr
	}
	// If IPv4-mapped IPv6, normalize to IPv4
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

func generateSecureToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-token-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

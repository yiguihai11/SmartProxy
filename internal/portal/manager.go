package portal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// UserTraffic tracks bandwidth consumption and reset cycle for a user account.
type UserTraffic struct {
	Username      string    `json:"username"`
	UsedBytes     int64     `json:"used_bytes"`
	CycleStart    time.Time `json:"cycle_start"`
	LastUpdated   time.Time `json:"last_updated"`
	nextResetUnix int64     `json:"-"`
}

// UserTrafficInfo represents user traffic quota and usage statistics for export/APIs.
type UserTrafficInfo struct {
	Username         string    `json:"username"`
	UsedBytes        int64     `json:"used_bytes"`
	LimitBytes       int64     `json:"limit_bytes"`
	ResetCycle       string    `json:"reset_cycle"`
	CycleStart       time.Time `json:"cycle_start"`
	NextReset        time.Time `json:"next_reset"`
	IsExceeded       bool      `json:"is_exceeded"`
	ResetDescription string    `json:"reset_description"`
}

// TrafficStorageFile is the JSON schema persisted to portal_traffic.json.
type TrafficStorageFile struct {
	Version   int                     `json:"version"`
	UpdatedAt int64                   `json:"updated_at"`
	Users     map[string]*UserTraffic `json:"users"`
}

// SessionStorageFile is the JSON schema persisted to portal_sessions.json.
type SessionStorageFile struct {
	Version   int        `json:"version"`
	UpdatedAt int64      `json:"updated_at"`
	Sessions  []*Session `json:"sessions"`
}

type failRecord struct {
	count      int
	lastFail   time.Time
	lockedTill time.Time
}

// Manager manages captive portal authentication, active sessions, and security limits.
type Manager struct {
	mu                  sync.RWMutex
	config              atomic.Pointer[config.Config]
	sessionsByIP        map[string]*Session
	sessionsByMAC       map[string]*Session
	sessionsByToken     map[string]*Session
	failedAttempts      map[string]*failRecord
	userTraffic         map[string]*UserTraffic
	trafficFilePath     string
	trafficDirty        atomic.Bool
	trafficFileModTimes map[string]time.Time
	sessionFilePath     string
	sessionDirty        atomic.Bool
	sessionFileModTimes map[string]time.Time
	csrfSecret          []byte
	macResolver         func(ip string) string
	forcedDisabled      atomic.Bool
	stopCh              chan struct{}
	cleanerDone         chan struct{}
	stopOnce            sync.Once
}

// Android tethering runtime directory where Shizuku tethering core stores persistent assets.
const androidTetheringAssetsDir = "/data/local/tmp/smartproxy-tethering-assets"

// NewManager creates a new portal Manager.
func NewManager(cfg *config.Config) *Manager {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// Fallback to time-based entropy if crypto/rand fails
		h := sha256.Sum256([]byte(fmt.Sprintf("portal-secret-%d", time.Now().UnixNano())))
		copy(secret, h[:])
	}

	m := &Manager{
		sessionsByIP:        make(map[string]*Session),
		sessionsByMAC:       make(map[string]*Session),
		sessionsByToken:     make(map[string]*Session),
		failedAttempts:      make(map[string]*failRecord),
		userTraffic:         make(map[string]*UserTraffic),
		trafficFileModTimes: make(map[string]time.Time),
		sessionFileModTimes: make(map[string]time.Time),
		csrfSecret:          secret,
		stopCh:              make(chan struct{}),
		cleanerDone:         make(chan struct{}),
	}
	m.config.Store(cfg)

	m.startCleaner()
	return m
}

func (m *Manager) startCleaner() {
	safego.Go("portal.cleaner", func() {
		defer close(m.cleanerDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.purgeExpired()
				m.saveTrafficIfDirty()
				m.saveSessionsIfDirty()
			case <-m.stopCh:
				return
			}
		}
	})
}

// Close stops the periodic cleanup goroutine and flushes persistent state.
func (m *Manager) Close() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
		<-m.cleanerDone
		m.saveTrafficIfDirty()
		m.saveSessionsIfDirty()
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

// SetForcedDisabled forces IsEnabled() to return false without mutating the active Config struct.
// This is used by the host VPN engine to ignore portal authentication in memory while
// preserving the user's config file and web panel editor intact.
func (m *Manager) SetForcedDisabled(disabled bool) {
	m.forcedDisabled.Store(disabled)
}

// IsEnabled reports whether the Captive Portal is active.
func (m *Manager) IsEnabled() bool {
	if m.forcedDisabled.Load() {
		return false
	}
	p := m.getPortalConf()
	return p != nil && p.Enabled
}

// isGatewayIP checks if the normalized IP belongs to the local machine loopback (127.0.0.1, ::1),
// any local network interface on this device, or the configured TUN interface address.
// The gateway machine itself is always exempt from captive portal interception.
func (m *Manager) isGatewayIP(normIP string) bool {
	ip := net.ParseIP(normIP)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}

	// 1. Check all local network interface IPs on this device
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if ipNet, ok := a.(*net.IPNet); ok {
					if normalizeIP(ipNet.IP.String()) == normIP {
						return true
					}
				}
			}
		}
	}

	// 2. Check configured TUN addresses
	if cfg := m.config.Load(); cfg != nil {
		for _, addr := range cfg.TUN.Address {
			if tunIP, _, err := net.ParseCIDR(addr); err == nil {
				if normalizeIP(tunIP.String()) == normIP {
					return true
				}
			}
		}
	}

	return false
}

// isHostLoopbackOrTun reports whether a source address is the host machine's own loopback
// or configured VPN TUN address. Local network interfaces (e.g. Wi-Fi downstream or tethering TUN)
// must NOT be used to authorize a source IP, because guest traffic originates from or passes through them.
func (m *Manager) isHostLoopbackOrTun(normIP string) bool {
	ip := net.ParseIP(normIP)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	if cfg := m.config.Load(); cfg != nil {
		for _, addr := range cfg.TUN.Address {
			if tunIP, _, err := net.ParseCIDR(addr); err == nil {
				if normalizeIP(tunIP.String()) == normIP {
					return true
				}
			}
		}
	}
	return false
}

// IsGatewayIP reports whether the given IP string corresponds to a local gateway/interface IP.
func (m *Manager) IsGatewayIP(ipStr string) bool {
	return m.isGatewayIP(normalizeIP(ipStr))
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

	// Host's own loopback and VPN TUN IPs are strictly the host machine itself and never intercepted.
	if m.isHostLoopbackOrTun(normIP) {
		return true
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
			if m.isUserQuotaExceededLocked(sess.Username, now) {
				return false
			}
			return true
		}
	}

	// 2. Check MAC session for seamless IP roaming
	if currentMAC != "" {
		if sess, ok := m.sessionsByMAC[currentMAC]; ok {
			if now.Before(sess.ExpiresAt) {
				if m.isUserQuotaExceededLocked(sess.Username, now) {
					return false
				}
				return true
			}
		}
	}

	return false
}

// IsUserProxyAllowed returns true if the username is configured with proxy access allowed.
// If username is empty, portal is disabled, or user is not found, defaults to true.
func (m *Manager) IsUserProxyAllowed(username string) bool {
	if m == nil || username == "" {
		return true
	}
	auth := m.getAuthConf()
	if auth == nil || len(auth.Users) == 0 {
		return true
	}
	for _, u := range auth.Users {
		if strings.EqualFold(u.Username, username) {
			return u.IsProxyAllowed()
		}
	}
	return true
}

// IsIPProxyAllowed checks if the client IP is allowed to use proxy nodes.
// If captive portal is disabled, IP is loopback/TUN, or user is not found, defaults to true.
// Returns false only if the client IP is authenticated as a user whose AllowProxy is explicitly false.
func (m *Manager) IsIPProxyAllowed(clientIP string) bool {
	if m == nil || !m.IsEnabled() {
		return true
	}
	normIP := normalizeIP(clientIP)
	if normIP == "" || m.isHostLoopbackOrTun(normIP) {
		return true
	}

	var currentMAC string
	m.mu.RLock()
	resolver := m.macResolver
	m.mu.RUnlock()
	if resolver != nil {
		currentMAC = strings.ToLower(resolver(normIP))
	}

	sess := m.GetSession(normIP, currentMAC)
	if sess != nil && sess.Username != "" {
		return m.IsUserProxyAllowed(sess.Username)
	}
	return true
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

	now := time.Now()

	// Check if user traffic quota is exceeded
	if m.isUserQuotaExceededLocked(username, now) {
		info := m.getUserTrafficInfoLocked(username, now)
		return nil, "", fmt.Errorf("流量配额已用尽（已使用 %s / 限额 %s）%s",
			formatBytes(info.UsedBytes), formatBytes(info.LimitBytes), info.ResetDescription)
	}

	maxDevices := auth.UserMaxDevices(username)

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
	m.sessionDirty.Store(true)
	safego.Go("portal.saveSessions", func() { m.saveSessionsIfDirty() })

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

	if m.isUserQuotaExceededLocked(sess.Username, time.Now()) {
		return nil, errors.New("traffic quota exceeded")
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
	m.sessionDirty.Store(true)
	safego.Go("portal.saveSessions", func() { m.saveSessionsIfDirty() })

	return sess, nil
}

// Logout ends an authenticated session for an IP, MAC, or token.
func (m *Manager) Logout(clientIP, mac, token string) {
	normIP := normalizeIP(clientIP)
	normMAC := strings.ToLower(strings.TrimSpace(mac))

	m.mu.Lock()
	defer m.mu.Unlock()

	m.removeSessionLocked(normIP, normMAC, token)
	safego.Go("portal.saveSessions", func() { m.saveSessionsIfDirty() })
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
	if found {
		safego.Go("portal.saveSessions", func() { m.saveSessionsIfDirty() })
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
				m.sessionDirty.Store(true)
			}
		}
	}
}

func (m *Manager) lookupSessionLocked(normIP, normMAC string, now time.Time) *Session {
	if normIP != "" {
		if s, ok := m.sessionsByIP[normIP]; ok && now.Before(s.ExpiresAt) {
			return s
		}
	}
	if normMAC != "" {
		if s, ok := m.sessionsByMAC[normMAC]; ok && now.Before(s.ExpiresAt) {
			return s
		}
	}
	return nil
}

func (m *Manager) effectiveSessionFilePaths() []string {
	m.mu.RLock()
	primary := m.sessionFilePath
	m.mu.RUnlock()

	var paths []string
	if primary != "" {
		paths = append(paths, primary)
	}
	tetheringSessions := filepath.Join(androidTetheringAssetsDir, "portal_sessions.json")
	if tetheringSessions != primary {
		paths = append(paths, tetheringSessions)
	}
	return paths
}

func (m *Manager) effectiveTrafficFilePaths() []string {
	m.mu.RLock()
	primary := m.trafficFilePath
	m.mu.RUnlock()

	var paths []string
	if primary != "" {
		paths = append(paths, primary)
	}
	tetheringTraffic := filepath.Join(androidTetheringAssetsDir, "portal_traffic.json")
	if tetheringTraffic != primary {
		paths = append(paths, tetheringTraffic)
	}
	return paths
}

func (m *Manager) reloadSessionsIfUpdated() bool {
	paths := m.effectiveSessionFilePaths()
	updated := false
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		mod := fi.ModTime()
		m.mu.RLock()
		lastMod := m.sessionFileModTimes[p]
		m.mu.RUnlock()

		if mod.After(lastMod) {
			if err := m.LoadSessionsFile(p); err == nil {
				m.mu.Lock()
				if m.sessionFileModTimes == nil {
					m.sessionFileModTimes = make(map[string]time.Time)
				}
				m.sessionFileModTimes[p] = mod
				m.mu.Unlock()
				updated = true
			}
		}
	}
	return updated
}

func (m *Manager) reloadTrafficIfUpdated() bool {
	paths := m.effectiveTrafficFilePaths()
	updated := false
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		mod := fi.ModTime()
		m.mu.RLock()
		lastMod := m.trafficFileModTimes[p]
		m.mu.RUnlock()

		if mod.After(lastMod) {
			if err := m.LoadTrafficFile(p); err == nil {
				m.mu.Lock()
				if m.trafficFileModTimes == nil {
					m.trafficFileModTimes = make(map[string]time.Time)
				}
				m.trafficFileModTimes[p] = mod
				m.mu.Unlock()
				updated = true
			}
		}
	}
	return updated
}

// GetSession returns the active session for an IP or MAC, if any.
func (m *Manager) GetSession(clientIP, mac string) *Session {
	normIP := normalizeIP(clientIP)
	normMAC := strings.ToLower(strings.TrimSpace(mac))

	now := time.Now()
	m.mu.RLock()
	s := m.lookupSessionLocked(normIP, normMAC, now)
	m.mu.RUnlock()

	if s != nil {
		cp := *s
		return &cp
	}

	if m.reloadSessionsIfUpdated() {
		m.mu.RLock()
		s = m.lookupSessionLocked(normIP, normMAC, now)
		m.mu.RUnlock()
		if s != nil {
			cp := *s
			return &cp
		}
	}
	return nil
}

// ActiveSessions returns a list of all currently active sessions.
func (m *Manager) ActiveSessions() []*Session {
	_ = m.reloadSessionsIfUpdated()
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

// UserSessionStats returns the number of active devices currently online for the given username,
// and the configured max_devices limit (-1 = unlimited, >0 = limit, 0 = default 1).
func (m *Manager) UserSessionStats(username string) (activeCount int, maxDevices int) {
	if username == "" {
		return 0, 1
	}
	_ = m.reloadSessionsIfUpdated()
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()

	auth := m.getAuthConf()
	maxDevs := 1
	if auth != nil {
		maxDevs = auth.UserMaxDevices(username)
	}

	seen := make(map[string]bool)
	for _, s := range m.sessionsByToken {
		if s.Username == username && now.Before(s.ExpiresAt) {
			key := strings.ToLower(s.MAC)
			if key == "" {
				key = s.IP
			}
			if key != "" && !seen[key] {
				seen[key] = true
				activeCount++
			}
		}
	}
	return activeCount, maxDevs
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

	dirty := false
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
			dirty = true
		}
	}
	if dirty {
		m.sessionDirty.Store(true)
		safego.Go("portal.saveSessions", func() { m.saveSessionsIfDirty() })
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

// SetStoragePath sets the JSON file path for persistent user traffic quotas and sessions.
func (m *Manager) SetStoragePath(path string) {
	m.mu.Lock()
	m.trafficFilePath = path
	sessionPath := ""
	if path != "" {
		sessionPath = filepath.Join(filepath.Dir(path), "portal_sessions.json")
		m.sessionFilePath = sessionPath
	}
	m.mu.Unlock()

	if path != "" {
		_ = m.LoadTrafficFile(path)
		if sessionPath != "" {
			_ = m.LoadSessionsFile(sessionPath)
		}
	}

	// Also load from secondary paths if present (e.g. Android tethering assets directory)
	_ = m.reloadTrafficIfUpdated()
	_ = m.reloadSessionsIfUpdated()
}

// SetSessionStoragePath explicitly sets the JSON file path for active sessions.
func (m *Manager) SetSessionStoragePath(path string) {
	m.mu.Lock()
	m.sessionFilePath = path
	m.mu.Unlock()

	if path != "" {
		_ = m.LoadSessionsFile(path)
	}
	_ = m.reloadSessionsIfUpdated()
}

// LoadTrafficFile loads persisted user traffic states from disk.
func (m *Manager) LoadTrafficFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var sf TrafficStorageFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if fi, err := os.Stat(path); err == nil {
		if m.trafficFileModTimes == nil {
			m.trafficFileModTimes = make(map[string]time.Time)
		}
		m.trafficFileModTimes[path] = fi.ModTime()
	}

	now := time.Now()
	auth := m.getAuthConf()

	if sf.Users != nil {
		for k, v := range sf.Users {
			if v != nil {
				cycle := auth.UserResetCycle(k)
				m.checkResetCycleLocked(v, cycle, now)
				m.userTraffic[k] = v
			}
		}
	}
	return nil
}

// SaveTrafficFile saves all user traffic usage records to disk atomically.
func (m *Manager) SaveTrafficFile(path string) error {
	m.mu.RLock()
	sf := TrafficStorageFile{
		Version:   1,
		UpdatedAt: time.Now().Unix(),
		Users:     make(map[string]*UserTraffic, len(m.userTraffic)),
	}
	for k, v := range m.userTraffic {
		cp := *v
		sf.Users[k] = &cp
	}
	m.mu.RUnlock()

	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	m.trafficDirty.Store(false)
	return nil
}

func (m *Manager) saveTrafficIfDirty() {
	if !m.trafficDirty.Load() {
		return
	}
	m.mu.RLock()
	path := m.trafficFilePath
	m.mu.RUnlock()

	if path != "" {
		_ = m.SaveTrafficFile(path)
	}
}

// LoadSessionsFile restores valid active sessions from disk.
func (m *Manager) LoadSessionsFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var sf SessionStorageFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if fi, err := os.Stat(path); err == nil {
		if m.sessionFileModTimes == nil {
			m.sessionFileModTimes = make(map[string]time.Time)
		}
		m.sessionFileModTimes[path] = fi.ModTime()
	}

	now := time.Now()
	for _, s := range sf.Sessions {
		if s == nil || s.Token == "" {
			continue
		}
		if now.After(s.ExpiresAt) {
			continue
		}
		if m.isUserQuotaExceededLocked(s.Username, now) {
			continue
		}
		normIP := normalizeIP(s.IP)
		normMAC := strings.ToLower(strings.TrimSpace(s.MAC))
		s.IP = normIP
		s.MAC = normMAC

		m.sessionsByToken[s.Token] = s
		if normIP != "" {
			m.sessionsByIP[normIP] = s
		}
		if normMAC != "" {
			m.sessionsByMAC[normMAC] = s
		}
	}
	return nil
}

// SaveSessionsFile persists all active, unexpired sessions to disk atomically.
func (m *Manager) SaveSessionsFile(path string) error {
	now := time.Now()
	m.mu.RLock()
	sf := SessionStorageFile{
		Version:   1,
		UpdatedAt: now.Unix(),
		Sessions:  make([]*Session, 0, len(m.sessionsByToken)),
	}
	seen := make(map[string]bool)
	for _, s := range m.sessionsByToken {
		if s != nil && s.Token != "" && now.Before(s.ExpiresAt) && !seen[s.Token] {
			seen[s.Token] = true
			cp := *s
			sf.Sessions = append(sf.Sessions, &cp)
		}
	}
	m.mu.RUnlock()

	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	m.sessionDirty.Store(false)
	return nil
}

func (m *Manager) saveSessionsIfDirty() {
	if !m.sessionDirty.Load() {
		return
	}
	m.mu.RLock()
	path := m.sessionFilePath
	m.mu.RUnlock()

	if path != "" {
		_ = m.SaveSessionsFile(path)
	}
}

func daysInMonth(year int, month time.Month, loc *time.Location) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, loc).Day()
}

func effectiveDayInMonth(year int, month time.Month, targetDay int, loc *time.Location) int {
	maxDays := daysInMonth(year, month, loc)
	if targetDay > maxDays {
		return maxDays
	}
	if targetDay < 1 {
		return 1
	}
	return targetDay
}

func monthlyResetDate(year int, month time.Month, targetDay int, loc *time.Location) time.Time {
	effDay := effectiveDayInMonth(year, month, targetDay, loc)
	return time.Date(year, month, effDay, 0, 0, 0, 0, loc)
}

func getMonthlyCycleBoundaries(now time.Time, targetDay int) (cycleStart time.Time, nextReset time.Time) {
	loc := now.Location()
	thisMonthReset := monthlyResetDate(now.Year(), now.Month(), targetDay, loc)
	if now.Before(thisMonthReset) {
		cycleStart = monthlyResetDate(now.Year(), now.Month()-1, targetDay, loc)
		nextReset = thisMonthReset
	} else {
		cycleStart = thisMonthReset
		nextReset = monthlyResetDate(now.Year(), now.Month()+1, targetDay, loc)
	}
	return cycleStart, nextReset
}

func getWeeklyCycleBoundaries(now time.Time, targetDay int) (cycleStart time.Time, nextReset time.Time) {
	loc := now.Location()
	isoWeekday := int(now.Weekday())
	if isoWeekday == 0 {
		isoWeekday = 7
	}
	if targetDay < 1 || targetDay > 7 {
		targetDay = 1
	}
	daysSince := (isoWeekday - targetDay + 7) % 7
	thisWeekReset := time.Date(now.Year(), now.Month(), now.Day()-daysSince, 0, 0, 0, 0, loc)
	if now.Before(thisWeekReset) {
		cycleStart = thisWeekReset.AddDate(0, 0, -7)
		nextReset = thisWeekReset
	} else {
		cycleStart = thisWeekReset
		nextReset = thisWeekReset.AddDate(0, 0, 7)
	}
	return cycleStart, nextReset
}

// checkResetCycleLocked checks if the traffic cycle for this user has rolled over,
// and resets UsedBytes if due. Must be called with m.mu locked.
func (m *Manager) checkResetCycleLocked(ut *UserTraffic, resetCycle string, now time.Time) bool {
	if ut == nil {
		return false
	}
	kind, day := config.ParseResetCycle(resetCycle, 0)
	switch kind {
	case "daily":
		startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		nextReset := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		if ut.CycleStart.IsZero() {
			ut.CycleStart = startOfToday
			ut.nextResetUnix = nextReset.Unix()
			return false
		}
		if ut.CycleStart.Before(startOfToday) {
			ut.UsedBytes = 0
			ut.CycleStart = startOfToday
			ut.LastUpdated = now
			ut.nextResetUnix = nextReset.Unix()
			m.trafficDirty.Store(true)
			return true
		}
		if ut.nextResetUnix == 0 {
			ut.nextResetUnix = nextReset.Unix()
		}
	case "monthly":
		cycleStart, nextReset := getMonthlyCycleBoundaries(now, day)
		if ut.CycleStart.IsZero() {
			ut.CycleStart = cycleStart
			ut.nextResetUnix = nextReset.Unix()
			return false
		}
		if ut.CycleStart.Before(cycleStart) {
			ut.UsedBytes = 0
			ut.CycleStart = cycleStart
			ut.LastUpdated = now
			ut.nextResetUnix = nextReset.Unix()
			m.trafficDirty.Store(true)
			return true
		}
		if ut.nextResetUnix == 0 {
			ut.nextResetUnix = nextReset.Unix()
		}
	case "weekly":
		cycleStart, nextReset := getWeeklyCycleBoundaries(now, day)
		if ut.CycleStart.IsZero() {
			ut.CycleStart = cycleStart
			ut.nextResetUnix = nextReset.Unix()
			return false
		}
		if ut.CycleStart.Before(cycleStart) {
			ut.UsedBytes = 0
			ut.CycleStart = cycleStart
			ut.LastUpdated = now
			ut.nextResetUnix = nextReset.Unix()
			m.trafficDirty.Store(true)
			return true
		}
		if ut.nextResetUnix == 0 {
			ut.nextResetUnix = nextReset.Unix()
		}
	default:
		if ut.CycleStart.IsZero() {
			ut.CycleStart = now
		}
	}
	return false
}

// isUserQuotaExceededLocked checks if a user's traffic quota is exceeded.
func (m *Manager) isUserQuotaExceededLocked(username string, now time.Time) bool {
	auth := m.getAuthConf()
	if auth == nil {
		return false
	}
	limit := auth.UserTrafficLimit(username)
	if limit <= 0 {
		return false
	}

	ut, ok := m.userTraffic[username]
	if !ok {
		return false
	}

	cycle := auth.UserResetCycle(username)
	m.checkResetCycleLocked(ut, cycle, now)

	return ut.UsedBytes >= limit
}

func (m *Manager) getUserTrafficInfoLocked(username string, now time.Time) *UserTrafficInfo {
	auth := m.getAuthConf()
	limit := auth.UserTrafficLimit(username)
	cycle := auth.UserResetCycle(username)

	ut, ok := m.userTraffic[username]
	if !ok {
		ut = &UserTraffic{
			Username:    username,
			CycleStart:  now,
			LastUpdated: now,
		}
		m.userTraffic[username] = ut
	}
	m.checkResetCycleLocked(ut, cycle, now)

	nextReset := computeNextReset(cycle, now)
	isExceeded := limit > 0 && ut.UsedBytes >= limit

	return &UserTrafficInfo{
		Username:         username,
		UsedBytes:        ut.UsedBytes,
		LimitBytes:       limit,
		ResetCycle:       cycle,
		CycleStart:       ut.CycleStart,
		NextReset:        nextReset,
		IsExceeded:       isExceeded,
		ResetDescription: formatResetDescription(cycle, nextReset),
	}
}

// GetUserTrafficInfo returns the quota, usage, and reset status for a given user.
func (m *Manager) GetUserTrafficInfo(username string) *UserTrafficInfo {
	_ = m.reloadTrafficIfUpdated()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getUserTrafficInfoLocked(username, time.Now())
}

// IsQuotaExceeded checks if a user has exceeded their configured traffic quota.
func (m *Manager) IsQuotaExceeded(username string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isUserQuotaExceededLocked(username, time.Now())
}

// AddTrafficForUser records consumed bytes directly for an authenticated user (e.g. SOCKS5).
// Returns true if the user's traffic quota is now exceeded.
func (m *Manager) AddTrafficForUser(username string, bytes int64) bool {
	if bytes <= 0 || username == "" {
		return false
	}

	auth := m.getAuthConf()
	limit := auth.UserTrafficLimit(username)
	cycle := auth.UserResetCycle(username)

	m.mu.RLock()
	ut := m.userTraffic[username]
	now := time.Now()
	nowUnix := now.Unix()

	needsWriteLock := ut == nil || (ut.nextResetUnix > 0 && nowUnix >= ut.nextResetUnix)
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	ut = m.userTraffic[username]
	if ut == nil {
		ut = &UserTraffic{
			Username:    username,
			CycleStart:  now,
			LastUpdated: now,
		}
		m.userTraffic[username] = ut
	}

	if needsWriteLock {
		m.checkResetCycleLocked(ut, cycle, now)
	}

	ut.UsedBytes += bytes
	ut.LastUpdated = now
	m.trafficDirty.Store(true)

	return limit > 0 && ut.UsedBytes >= limit
}

// AddTraffic records consumed bytes for the authenticated user associated with clientIP.
// Returns true if the user's traffic quota is now exceeded.
func (m *Manager) AddTraffic(clientIP string, bytes int64) bool {
	if bytes <= 0 {
		return false
	}
	normIP := normalizeIP(clientIP)
	if normIP == "" {
		return false
	}

	m.mu.RLock()
	sess, ok := m.sessionsByIP[normIP]
	if !ok && m.macResolver != nil {
		mac := strings.ToLower(m.macResolver(normIP))
		if mac != "" {
			sess = m.sessionsByMAC[mac]
		}
	}
	if sess == nil {
		m.mu.RUnlock()
		return false
	}
	username := sess.Username
	m.mu.RUnlock()

	return m.AddTrafficForUser(username, bytes)
}

// ResetUserTraffic clears accumulated bandwidth usage for a user.
func (m *Manager) ResetUserTraffic(username string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	ut, ok := m.userTraffic[username]
	if !ok {
		return false
	}
	ut.UsedBytes = 0
	ut.CycleStart = time.Now()
	ut.LastUpdated = time.Now()
	m.trafficDirty.Store(true)
	return true
}

// AllUsersTraffic returns traffic records for all configured and tracked users.
func (m *Manager) AllUsersTraffic() []*UserTrafficInfo {
	_ = m.reloadTrafficIfUpdated()
	auth := m.getAuthConf()
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var result []*UserTrafficInfo
	seen := make(map[string]bool)

	if auth != nil {
		for _, u := range auth.Users {
			seen[u.Username] = true
			result = append(result, m.getUserTrafficInfoLocked(u.Username, now))
		}
	}

	for username := range m.userTraffic {
		if !seen[username] {
			result = append(result, m.getUserTrafficInfoLocked(username, now))
		}
	}

	return result
}

func computeNextReset(cycle string, now time.Time) time.Time {
	kind, day := config.ParseResetCycle(cycle, 0)
	switch kind {
	case "daily":
		return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	case "monthly":
		_, nextReset := getMonthlyCycleBoundaries(now, day)
		return nextReset
	case "weekly":
		_, nextReset := getWeeklyCycleBoundaries(now, day)
		return nextReset
	default:
		return time.Time{}
	}
}

func formatResetDescription(cycle string, nextReset time.Time) string {
	kind, day := config.ParseResetCycle(cycle, 0)
	switch kind {
	case "daily":
		return fmt.Sprintf("（将于每日 00:00 重置，下次重置: %s）", nextReset.Format("2006-01-02 15:04:05"))
	case "monthly":
		return fmt.Sprintf("（将于每月%d日 00:00 重置，下次重置: %s）", day, nextReset.Format("2006-01-02 15:04:05"))
	case "weekly":
		weekdayNames := []string{"", "周一", "周二", "周三", "周四", "周五", "周六", "周日"}
		name := "周一"
		if day >= 1 && day <= 7 {
			name = weekdayNames[day]
		}
		return fmt.Sprintf("（将于每%s 00:00 重置，下次重置: %s）", name, nextReset.Format("2006-01-02 15:04:05"))
	default:
		return "（不自动重置）"
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

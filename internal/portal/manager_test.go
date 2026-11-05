package portal

import (
	"strings"
	"testing"
	"time"

	"smartproxy/internal/config"
)

func makeTestConfig(maxDevices int) *config.Config {
	cfg := config.DefaultConfig()
	cfg.Listen.Auth = &config.AuthConf{
		Enabled: true,
		Users: []config.AuthUserConf{
			{Username: "alice", Password: "secret123", MaxDevices: maxDevices},
		},
	}
	cfg.Listen.Portal = &config.PortalConf{
		Enabled:            true,
		Title:              "Test Hotspot",
		LeaseHours:         24,
		AutoReauthByCookie: true,
		ExemptIPs:          []string{"192.168.43.99"},
		ExemptMACs:         []string{"00:11:22:33:44:55"},
	}
	return cfg
}

func TestPortal_Exemptions(t *testing.T) {
	cfg := makeTestConfig(2)
	mgr := NewManager(cfg)
	defer mgr.Close()

	// Exempt IP
	if !mgr.IsAuthorized("192.168.43.99") {
		t.Errorf("expected exempt IP 192.168.43.99 to be authorized")
	}

	// Non-exempt IP without session
	if mgr.IsAuthorized("192.168.43.10") {
		t.Errorf("expected unauthenticated IP 192.168.43.10 to NOT be authorized")
	}

	// Exempt MAC
	mgr.SetMACResolver(func(ip string) string {
		if ip == "192.168.43.10" {
			return "00:11:22:33:44:55"
		}
		return ""
	})

	if !mgr.IsAuthorized("192.168.43.10") {
		t.Errorf("expected IP with exempt MAC 00:11:22:33:44:55 to be authorized")
	}
}

func TestPortal_Authenticate_StrategyB(t *testing.T) {
	// Alice max_devices = 2
	cfg := makeTestConfig(2)
	mgr := NewManager(cfg)
	defer mgr.Close()

	// Device 1 login
	sess1, tok1, err := mgr.Authenticate("192.168.43.101", "aa:bb:cc:11:22:01", "alice", "secret123", "UA1")
	if err != nil {
		t.Fatalf("device 1 login failed: %v", err)
	}
	if tok1 == "" || sess1 == nil {
		t.Fatalf("expected valid token and session")
	}
	if !mgr.IsAuthorized("192.168.43.101") {
		t.Fatalf("device 1 should now be authorized")
	}

	// Device 1 renews login (should NOT count as a second device)
	_, _, err = mgr.Authenticate("192.168.43.101", "aa:bb:cc:11:22:01", "alice", "secret123", "UA1-new")
	if err != nil {
		t.Fatalf("device 1 renewal failed: %v", err)
	}

	// Device 2 login
	sess2, tok2, err := mgr.Authenticate("192.168.43.102", "aa:bb:cc:11:22:02", "alice", "secret123", "UA2")
	if err != nil {
		t.Fatalf("device 2 login failed: %v", err)
	}
	if tok2 == "" || sess2 == nil {
		t.Fatalf("expected valid token for device 2")
	}
	if !mgr.IsAuthorized("192.168.43.102") {
		t.Fatalf("device 2 should be authorized")
	}

	// Device 3 login -> MUST BE REJECTED by Strategy B!
	_, _, err = mgr.Authenticate("192.168.43.103", "aa:bb:cc:11:22:03", "alice", "secret123", "UA3")
	if err == nil {
		t.Fatalf("expected device 3 login to be rejected due to max_devices limit, but it succeeded")
	}
	if !strings.Contains(err.Error(), "concurrent device limit (2) reached") {
		t.Errorf("unexpected error message: %v", err)
	}
	if !strings.Contains(err.Error(), "192.168.43.101") || !strings.Contains(err.Error(), "192.168.43.102") {
		t.Errorf("error should list existing active devices: %v", err)
	}

	// Logout device 1
	mgr.Logout("192.168.43.101", "aa:bb:cc:11:22:01", tok1)
	if mgr.IsAuthorized("192.168.43.101") {
		t.Errorf("device 1 should not be authorized after logout")
	}

	// Now Device 3 login should succeed!
	_, _, err = mgr.Authenticate("192.168.43.103", "aa:bb:cc:11:22:03", "alice", "secret123", "UA3")
	if err != nil {
		t.Fatalf("device 3 login should succeed after device 1 logged out, but got: %v", err)
	}
	if !mgr.IsAuthorized("192.168.43.103") {
		t.Fatalf("device 3 should be authorized")
	}
}

func TestPortal_CookieTokenRoaming(t *testing.T) {
	cfg := makeTestConfig(1)
	mgr := NewManager(cfg)
	defer mgr.Close()

	// Initial login from 192.168.43.50 with MAC1
	_, token, err := mgr.Authenticate("192.168.43.50", "aa:11:22:33:44:55", "alice", "secret123", "PhoneBrowser")
	if err != nil {
		t.Fatalf("initial login failed: %v", err)
	}

	// Device roams: IP changes to 192.168.43.60, randomized MAC rotates to MAC2
	// Browser presents cookie token
	roamedSess, err := mgr.AuthenticateByToken("192.168.43.60", "bb:66:77:88:99:00", token, "PhoneBrowser")
	if err != nil {
		t.Fatalf("token roaming failed: %v", err)
	}
	if roamedSess.IP != "192.168.43.60" || roamedSess.MAC != "bb:66:77:88:99:00" {
		t.Errorf("expected session IP and MAC updated, got IP=%s, MAC=%s", roamedSess.IP, roamedSess.MAC)
	}

	// New IP is now authorized
	if !mgr.IsAuthorized("192.168.43.60") {
		t.Errorf("roamed IP should be authorized")
	}
	// Old IP is no longer authorized
	if mgr.IsAuthorized("192.168.43.50") {
		t.Errorf("old IP should no longer be authorized")
	}
}

func TestPortal_StaleIPTakeoverProtection(t *testing.T) {
	cfg := makeTestConfig(1)
	mgr := NewManager(cfg)
	defer mgr.Close()

	// Alice logs in with MAC A on 192.168.43.100
	_, _, err := mgr.Authenticate("192.168.43.100", "aa:aa:aa:aa:aa:aa", "alice", "secret123", "DeviceA")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Neighbor table resolver simulates MAC lookup:
	// A new device with MAC B has taken over IP 192.168.43.100
	mgr.SetMACResolver(func(ip string) string {
		if ip == "192.168.43.100" {
			return "bb:bb:bb:bb:bb:bb" // Different MAC!
		}
		return ""
	})

	// IsAuthorized should detect MAC mismatch and reject!
	if mgr.IsAuthorized("192.168.43.100") {
		t.Errorf("expected stale IP with mismatched MAC to NOT be authorized")
	}

	// Verify that the stale IP was immediately unlinked
	sess := mgr.GetSession("192.168.43.100", "")
	if sess != nil {
		t.Errorf("stale IP should have been unlinked from old session")
	}

	// Device B logs in on the reassigned IP with Device B's MAC
	_, _, err = mgr.Authenticate("192.168.43.100", "bb:bb:bb:bb:bb:bb", "alice", "secret123", "DeviceB")
	if err != nil {
		t.Fatalf("Device B login on reassigned IP failed: %v", err)
	}

	// Now Device B is legitimately authorized on 192.168.43.100!
	if !mgr.IsAuthorized("192.168.43.100") {
		t.Errorf("Device B should now be authorized after authenticating")
	}
}

func TestPortal_RateLimiting(t *testing.T) {
	cfg := makeTestConfig(1)
	mgr := NewManager(cfg)
	defer mgr.Close()

	clientIP := "192.168.43.200"

	// 4 failed attempts: should return invalid password
	for i := 1; i <= 4; i++ {
		_, _, err := mgr.Authenticate(clientIP, "", "alice", "wrong-password", "BadGuy")
		if err == nil || err.Error() != "invalid username or password" {
			t.Fatalf("attempt %d: expected 'invalid username or password', got: %v", i, err)
		}
	}

	// 5th failed attempt triggers jail
	_, _, err := mgr.Authenticate(clientIP, "", "alice", "wrong-password", "BadGuy")
	if err == nil {
		t.Fatalf("5th attempt should fail")
	}

	// 6th attempt: even with correct password, should be locked out!
	_, _, err = mgr.Authenticate(clientIP, "", "alice", "secret123", "BadGuy")
	if err == nil || !strings.Contains(err.Error(), "too many failed login attempts") {
		t.Fatalf("expected rate limit lockout error, got: %v", err)
	}
}

func TestPortal_CSRFToken(t *testing.T) {
	cfg := makeTestConfig(1)
	mgr := NewManager(cfg)
	defer mgr.Close()

	clientIP := "192.168.43.150"
	csrf := mgr.GenerateCSRFToken(clientIP)

	if !mgr.ValidateCSRFToken(clientIP, csrf) {
		t.Errorf("valid CSRF token validation failed")
	}

	// Different IP should fail validation
	if mgr.ValidateCSRFToken("192.168.43.151", csrf) {
		t.Errorf("CSRF token should be bound to client IP")
	}

	// Tampered token should fail
	if mgr.ValidateCSRFToken(clientIP, csrf+"tampered") {
		t.Errorf("tampered CSRF token should fail")
	}
}

func TestPortal_AdminRevoke(t *testing.T) {
	cfg := makeTestConfig(1)
	mgr := NewManager(cfg)
	defer mgr.Close()

	clientIP := "192.168.43.88"
	clientMAC := "cc:cc:cc:cc:cc:cc"

	_, _, err := mgr.Authenticate(clientIP, clientMAC, "alice", "secret123", "MyPhone")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if !mgr.IsAuthorized(clientIP) {
		t.Fatalf("should be authorized before revoke")
	}

	// Admin revokes by MAC
	if !mgr.RevokeSession(clientMAC) {
		t.Errorf("expected RevokeSession to return true")
	}

	if mgr.IsAuthorized(clientIP) {
		t.Errorf("should not be authorized after revoke")
	}
}

func TestPortal_TrafficLimitAndQuota(t *testing.T) {
	cfg := makeTestConfig(2)
	cfg.Listen.Auth.Users[0].TrafficLimitBytes = 1000 // 1000 bytes
	cfg.Listen.Auth.Users[0].ResetCycle = "daily"

	mgr := NewManager(cfg)
	defer mgr.Close()

	clientIP := "192.168.43.10"
	_, _, err := mgr.Authenticate(clientIP, "", "alice", "secret123", "UA")
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}

	if !mgr.IsAuthorized(clientIP) {
		t.Fatalf("expected authorized initially")
	}

	// Add 600 bytes
	exceeded := mgr.AddTraffic(clientIP, 600)
	if exceeded {
		t.Errorf("expected 600 bytes not to exceed 1000 limit")
	}
	if !mgr.IsAuthorized(clientIP) {
		t.Errorf("expected still authorized after 600 bytes")
	}

	info := mgr.GetUserTrafficInfo("alice")
	if info.UsedBytes != 600 {
		t.Errorf("expected 600 bytes used, got %d", info.UsedBytes)
	}
	if info.IsExceeded {
		t.Errorf("expected not exceeded")
	}

	// Add 450 bytes -> total 1050 bytes (exceeded!)
	exceeded = mgr.AddTraffic(clientIP, 450)
	if !exceeded {
		t.Errorf("expected 1050 bytes to exceed 1000 limit")
	}
	if mgr.IsAuthorized(clientIP) {
		t.Errorf("expected NOT authorized after quota exceeded")
	}

	// Re-login should be rejected due to exhausted quota
	_, _, err = mgr.Authenticate("192.168.43.11", "", "alice", "secret123", "UA2")
	if err == nil || !strings.Contains(err.Error(), "流量配额已用尽") {
		t.Errorf("expected quota exceeded error on re-login, got: %v", err)
	}

	// Admin resets traffic
	if !mgr.ResetUserTraffic("alice") {
		t.Fatalf("expected ResetUserTraffic to succeed")
	}

	// Now authorized again
	if !mgr.IsAuthorized(clientIP) {
		t.Errorf("expected authorized after traffic reset")
	}
}

func TestPortal_AddTrafficForUser(t *testing.T) {
	cfg := makeTestConfig(2)
	cfg.Listen.Auth.Users[0].TrafficLimitBytes = 500
	mgr := NewManager(cfg)
	defer mgr.Close()

	// Direct user traffic accumulation (e.g. from SOCKS5)
	exceeded := mgr.AddTrafficForUser("alice", 300)
	if exceeded {
		t.Errorf("expected 300 bytes not to exceed 500")
	}
	if mgr.IsQuotaExceeded("alice") {
		t.Errorf("expected quota not exceeded at 300 bytes")
	}

	exceeded = mgr.AddTrafficForUser("alice", 250)
	if !exceeded {
		t.Errorf("expected 550 bytes to exceed 500 limit")
	}
	if !mgr.IsQuotaExceeded("alice") {
		t.Errorf("expected quota exceeded at 550 bytes")
	}
}

func TestPortal_ResetCycle_DailyAndMonthly(t *testing.T) {
	cfg := makeTestConfig(1)
	mgr := NewManager(cfg)
	defer mgr.Close()

	now := time.Now()

	// 1. Daily cycle
	yesterday := now.AddDate(0, 0, -1)
	utDaily := &UserTraffic{
		Username:   "bob",
		UsedBytes:  5000,
		CycleStart: yesterday,
	}
	if !mgr.checkResetCycleLocked(utDaily, "daily", now) {
		t.Errorf("expected daily reset when cycle start was yesterday")
	}
	if utDaily.UsedBytes != 0 {
		t.Errorf("expected UsedBytes reset to 0, got %d", utDaily.UsedBytes)
	}

	// Check same day doesn't reset again
	if mgr.checkResetCycleLocked(utDaily, "daily", now) {
		t.Errorf("expected no second reset on the same day")
	}

	// 2. Monthly cycle
	lastMonth := now.AddDate(0, -1, 0)
	utMonthly := &UserTraffic{
		Username:   "bob",
		UsedBytes:  10000,
		CycleStart: lastMonth,
	}
	if !mgr.checkResetCycleLocked(utMonthly, "monthly", now) {
		t.Errorf("expected monthly reset when cycle start was last month")
	}
	if utMonthly.UsedBytes != 0 {
		t.Errorf("expected UsedBytes reset to 0, got %d", utMonthly.UsedBytes)
	}

	// 3. None cycle
	utNone := &UserTraffic{
		Username:   "bob",
		UsedBytes:  10000,
		CycleStart: lastMonth,
	}
	if mgr.checkResetCycleLocked(utNone, "none", now) {
		t.Errorf("expected no reset for 'none' cycle")
	}
	if utNone.UsedBytes != 10000 {
		t.Errorf("expected UsedBytes unchanged")
	}
}

func TestPortal_TrafficPersistence(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/portal_traffic.json"

	cfg := makeTestConfig(2)
	mgr := NewManager(cfg)
	mgr.SetStoragePath(filePath)

	clientIP := "192.168.43.10"
	_, _, err := mgr.Authenticate(clientIP, "", "alice", "secret123", "UA")
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}

	mgr.AddTraffic(clientIP, 123456)
	mgr.Close()

	// New manager loads from disk
	mgr2 := NewManager(cfg)
	defer mgr2.Close()
	mgr2.SetStoragePath(filePath)

	info := mgr2.GetUserTrafficInfo("alice")
	if info.UsedBytes != 123456 {
		t.Errorf("expected loaded used bytes 123456, got %d", info.UsedBytes)
	}
}

func BenchmarkIsAuthorized(b *testing.B) {
	cfg := makeTestConfig(10)
	mgr := NewManager(cfg)
	defer mgr.Close()

	mgr.SetMACResolver(func(ip string) string {
		return "aa:bb:cc:dd:ee:ff"
	})

	_, _, err := mgr.Authenticate("192.168.43.100", "aa:bb:cc:dd:ee:ff", "alice", "secret123", "UA")
	if err != nil {
		b.Fatalf("auth failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !mgr.IsAuthorized("192.168.43.100") {
			b.Fatal("not authorized")
		}
	}
}

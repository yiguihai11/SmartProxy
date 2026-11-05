package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"smartproxy/internal/config"
	"smartproxy/internal/portal"
)

func setupTestPortalAdmin(t *testing.T) (*Server, *portal.Manager) {
	cfg := config.DefaultConfig()
	cfg.Listen.Auth = &config.AuthConf{
		Users: []config.AuthUserConf{
			{Username: "alice", Password: "password123", MaxDevices: 2},
		},
	}
	cfg.Listen.Portal = &config.PortalConf{
		Enabled:            true,
		Title:              "Portal Test Unit",
		LeaseHours:         24,
		AutoReauthByCookie: true,
	}

	pm := portal.NewManager(cfg)
	t.Cleanup(func() { pm.Close() })

	srv := &Server{
		configSrc: func() *config.Config { return cfg },
	}
	srv.SetPortalManager(pm)

	return srv, pm
}

func TestPortal_HTTPFlow(t *testing.T) {
	srv, pm := setupTestPortalAdmin(t)

	clientIP := "192.168.43.55"

	// 1. GET /portal
	req := httptest.NewRequest(http.MethodGet, "/portal?url=http://example.com/test", nil)
	req.RemoteAddr = clientIP + ":45678"
	rec := httptest.NewRecorder()

	srv.handlePortal(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /portal, got %d", rec.Code)
	}
	html := rec.Body.String()
	if !strings.Contains(html, "Portal Test Unit") {
		t.Errorf("HTML should contain portal title")
	}
	if !strings.Contains(html, clientIP) {
		t.Errorf("HTML should contain client IP")
	}

	// 2. Obtain valid CSRF token
	csrf := pm.GenerateCSRFToken(clientIP)

	// 3. POST /api/portal/login with invalid CSRF token -> 403
	{
		body := `{"username":"alice","password":"password123"}`
		badReq := httptest.NewRequest(http.MethodPost, "/api/portal/login", strings.NewReader(body))
		badReq.RemoteAddr = clientIP + ":45678"
		badReq.Header.Set("Content-Type", "application/json")
		badReq.Header.Set("X-CSRF-Token", "invalid-csrf")
		badRec := httptest.NewRecorder()

		srv.handlePortalLogin(badRec, badReq)
		if badRec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for bad CSRF, got %d", badRec.Code)
		}
	}

	// 4. POST /api/portal/login with wrong password -> 400
	{
		body := `{"username":"alice","password":"wrongpassword"}`
		failReq := httptest.NewRequest(http.MethodPost, "/api/portal/login", strings.NewReader(body))
		failReq.RemoteAddr = clientIP + ":45678"
		failReq.Header.Set("Content-Type", "application/json")
		failReq.Header.Set("X-CSRF-Token", csrf)
		failRec := httptest.NewRecorder()

		srv.handlePortalLogin(failRec, failReq)
		if failRec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for wrong credentials, got %d", failRec.Code)
		}
	}

	// 5. POST /api/portal/login with correct credentials -> 200 & cookie set
	var cookieVal string
	{
		body := `{"username":"alice","password":"password123"}`
		loginReq := httptest.NewRequest(http.MethodPost, "/api/portal/login", strings.NewReader(body))
		loginReq.RemoteAddr = clientIP + ":45678"
		loginReq.Header.Set("Content-Type", "application/json")
		loginReq.Header.Set("X-CSRF-Token", csrf)
		loginRec := httptest.NewRecorder()

		srv.handlePortalLogin(loginRec, loginReq)
		if loginRec.Code != http.StatusOK {
			t.Fatalf("expected 200 for valid login, got %d: %s", loginRec.Code, loginRec.Body.String())
		}

		cookies := loginRec.Result().Cookies()
		foundCookie := false
		for _, c := range cookies {
			if c.Name == "smartproxy_portal_token" {
				foundCookie = true
				cookieVal = c.Value
				if !c.HttpOnly {
					t.Errorf("expected cookie to be HttpOnly")
				}
			}
		}
		if !foundCookie || cookieVal == "" {
			t.Fatalf("expected smartproxy_portal_token cookie in login response")
		}
	}

	// 6. GET /api/portal/status -> should now report authenticated: true
	{
		statusReq := httptest.NewRequest(http.MethodGet, "/api/portal/status", nil)
		statusReq.RemoteAddr = clientIP + ":45678"
		statusRec := httptest.NewRecorder()

		srv.handlePortalStatus(statusRec, statusReq)
		if statusRec.Code != http.StatusOK {
			t.Fatalf("expected 200 for status, got %d", statusRec.Code)
		}
		var st struct {
			Authenticated bool   `json:"authenticated"`
			User          string `json:"user"`
			IP            string `json:"ip"`
		}
		if err := json.Unmarshal(statusRec.Body.Bytes(), &st); err != nil {
			t.Fatalf("failed to decode status: %v", err)
		}
		if !st.Authenticated || st.User != "alice" || st.IP != clientIP {
			t.Errorf("status mismatch: %+v", st)
		}
	}

	// 7. GET /portal again with cookie -> auto-redirects to target url
	{
		portalReq := httptest.NewRequest(http.MethodGet, "/portal?url=http://example.com/dest", nil)
		portalReq.RemoteAddr = clientIP + ":45678"
		portalReq.AddCookie(&http.Cookie{Name: "smartproxy_portal_token", Value: cookieVal})
		portalRec := httptest.NewRecorder()

		srv.handlePortal(portalRec, portalReq)
		if portalRec.Code != http.StatusFound {
			t.Errorf("expected 302 Found redirect for authenticated client, got %d", portalRec.Code)
		}
		if portalRec.Header().Get("Location") != "http://example.com/dest" {
			t.Errorf("expected redirect to original URL, got %s", portalRec.Header().Get("Location"))
		}
	}

	// 8. POST /api/portal/logout -> clears cookie and session
	{
		logoutReq := httptest.NewRequest(http.MethodPost, "/api/portal/logout", nil)
		logoutReq.RemoteAddr = clientIP + ":45678"
		logoutReq.AddCookie(&http.Cookie{Name: "smartproxy_portal_token", Value: cookieVal})
		logoutRec := httptest.NewRecorder()

		srv.handlePortalLogout(logoutRec, logoutReq)
		if logoutRec.Code != http.StatusOK {
			t.Errorf("expected 200 for logout, got %d", logoutRec.Code)
		}
	}

	// 9. Status after logout -> authenticated: false
	{
		statusReq := httptest.NewRequest(http.MethodGet, "/api/portal/status", nil)
		statusReq.RemoteAddr = clientIP + ":45678"
		statusRec := httptest.NewRecorder()

		srv.handlePortalStatus(statusRec, statusReq)
		var st struct {
			Authenticated bool `json:"authenticated"`
		}
		_ = json.Unmarshal(statusRec.Body.Bytes(), &st)
		if st.Authenticated {
			t.Errorf("expected unauthenticated after logout")
		}
	}

	// 10. Admin Kick API /api/portal/kick
	{
		// Authenticate another device first
		_, _, _ = pm.Authenticate("192.168.43.99", "ee:ee:ee:ee:ee:ee", "alice", "password123", "UA")
		if !pm.IsAuthorized("192.168.43.99") {
			t.Fatalf("expected authorized before kick")
		}

		kickReq := httptest.NewRequest(http.MethodPost, "/api/portal/kick?target=192.168.43.99", nil)
		kickRec := httptest.NewRecorder()

		srv.handlePortalKick(kickRec, kickReq)
		if kickRec.Code != http.StatusOK {
			t.Errorf("expected 200 from kick, got %d", kickRec.Code)
		}
		if pm.IsAuthorized("192.168.43.99") {
			t.Errorf("expected device to be unauthenticated after kick")
		}
	}
}

func TestPortal_DevicesAuthUserIntegration(t *testing.T) {
	srv, pm := setupTestPortalAdmin(t)

	// Authenticate device
	devIP := "192.168.43.80"
	devMAC := "00:aa:bb:cc:dd:ee"
	_, _, err := pm.Authenticate(devIP, devMAC, "alice", "password123", "Phone")
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}

	// Query device session
	sess := pm.GetSession(devIP, devMAC)
	if sess == nil || sess.Username != "alice" {
		t.Fatalf("expected active session for alice")
	}

	// Mock ARP mapping
	srv.deviceMgr = newDeviceManager(t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	rec := httptest.NewRecorder()

	srv.handleDevices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/devices, got %d", rec.Code)
	}
}

func TestPortal_TrafficAPIs(t *testing.T) {
	srv, pm := setupTestPortalAdmin(t)

	// Set alice quota to 2000 bytes
	cfg := srv.configSrc()
	cfg.Listen.Auth.Users[0].TrafficLimitBytes = 2000
	cfg.Listen.Auth.Users[0].ResetCycle = "daily"
	pm.UpdateConfig(cfg)

	devIP := "192.168.43.101"
	_, _, err := pm.Authenticate(devIP, "", "alice", "password123", "Phone")
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}

	// Add 500 bytes traffic
	pm.AddTraffic(devIP, 500)

	// 1. GET /api/portal/status should include quota info
	{
		req := httptest.NewRequest(http.MethodGet, "/api/portal/status", nil)
		req.RemoteAddr = devIP + ":12345"
		rec := httptest.NewRecorder()
		srv.handlePortalStatus(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status failed: %d", rec.Code)
		}
		var st struct {
			Authenticated   bool   `json:"authenticated"`
			TrafficUsed     int64  `json:"traffic_used_bytes"`
			TrafficLimit    int64  `json:"traffic_limit_bytes"`
			ResetCycle      string `json:"traffic_reset_cycle"`
			QuotaExceeded   bool   `json:"quota_exceeded"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("decode status failed: %v", err)
		}
		if !st.Authenticated || st.TrafficUsed != 500 || st.TrafficLimit != 2000 || st.ResetCycle != "daily" || st.QuotaExceeded {
			t.Errorf("status traffic info mismatch: %+v", st)
		}
	}

	// 2. GET /api/portal/traffic
	{
		req := httptest.NewRequest(http.MethodGet, "/api/portal/traffic", nil)
		rec := httptest.NewRecorder()
		srv.handlePortalTraffic(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("traffic list failed: %d", rec.Code)
		}
		var res struct {
			Ok    bool `json:"ok"`
			Users []struct {
				Username  string `json:"username"`
				UsedBytes int64  `json:"used_bytes"`
			} `json:"users"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode traffic list failed: %v", err)
		}
		if !res.Ok || len(res.Users) == 0 {
			t.Fatalf("expected non-empty users list")
		}
		foundAlice := false
		for _, u := range res.Users {
			if u.Username == "alice" && u.UsedBytes == 500 {
				foundAlice = true
				break
			}
		}
		if !foundAlice {
			t.Errorf("alice traffic record not found in list: %+v", res.Users)
		}
	}

	// 3. POST /api/portal/traffic/reset
	{
		body := `{"username":"alice"}`
		req := httptest.NewRequest(http.MethodPost, "/api/portal/traffic/reset", strings.NewReader(body))
		rec := httptest.NewRecorder()
		srv.handlePortalTrafficReset(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("reset failed: %d", rec.Code)
		}

		info := pm.GetUserTrafficInfo("alice")
		if info.UsedBytes != 0 {
			t.Errorf("expected UsedBytes reset to 0, got %d", info.UsedBytes)
		}
	}
}

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
		Enabled: true,
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

	portal.SetAndroidTetheringAssetsDirForTest(t.TempDir())
	t.Cleanup(func() {
		portal.SetAndroidTetheringAssetsDirForTest("/data/local/tmp/smartproxy-tethering-assets")
	})

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

		var loginResp struct {
			Ok         bool `json:"ok"`
			AllowProxy bool `json:"allow_proxy"`
		}
		if err := json.Unmarshal(loginRec.Body.Bytes(), &loginResp); err != nil {
			t.Fatalf("failed to decode login resp: %v", err)
		}
		if !loginResp.Ok || !loginResp.AllowProxy {
			t.Errorf("expected loginResp.AllowProxy to be true for alice")
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
			AllowProxy    bool   `json:"allow_proxy"`
		}
		if err := json.Unmarshal(statusRec.Body.Bytes(), &st); err != nil {
			t.Fatalf("failed to decode status: %v", err)
		}
		if !st.Authenticated || st.User != "alice" || st.IP != clientIP || !st.AllowProxy {
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

func TestPortal_TetheringBridgeClient_NATResolution(t *testing.T) {
	srv, pm := setupTestPortalAdmin(t)

	bridgeJSON := `[{"ip":"10.140.12.152","mac":"12:34:56:78:9a:bc","hostname":"JER-AN20"}]`
	bridge := &mockTetheringBridge{clients: bridgeJSON}
	srv.SetTetheringBridge(bridge)

	// 1. Initial state: virtual TUN IP 192.0.2.2 must NOT be authorized or exempt by default
	if pm.IsAuthorized("192.0.2.2") {
		t.Fatalf("expected unauthenticated tethering client (192.0.2.2) to NOT be authorized initially")
	}

	// 2. Perform portal login from client NAT IP 192.0.2.2
	csrf := pm.GenerateCSRFToken("192.0.2.2")
	loginBody := `{"username":"alice","password":"password123","csrf_token":"` + csrf + `"}`
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/portal/login", strings.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.RemoteAddr = "192.0.2.2:54321"
	recLogin := httptest.NewRecorder()
	srv.handlePortalLogin(recLogin, reqLogin)

	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected login success 200, got %d: %s", recLogin.Code, recLogin.Body.String())
	}

	// 3. 192.0.2.2 is now authorized
	if !pm.IsAuthorized("192.0.2.2") {
		t.Fatalf("expected 192.0.2.2 to be authorized after login")
	}

	// 4. Session should be associated with the physical client's MAC
	sess := pm.GetSession("10.140.12.152", "12:34:56:78:9a:bc")
	if sess == nil || sess.Username != "alice" {
		t.Fatalf("expected active session for alice on physical MAC 12:34:56:78:9a:bc, got %+v", sess)
	}

	// 5. Query /api/devices and verify AuthUser
	reqDevs := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	recDevs := httptest.NewRecorder()
	srv.handleDevices(recDevs, reqDevs)
	if recDevs.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/devices, got %d", recDevs.Code)
	}

	var devResp struct {
		Devices []TetheredDevice `json:"devices"`
	}
	if err := json.Unmarshal(recDevs.Body.Bytes(), &devResp); err != nil {
		t.Fatalf("failed to decode /api/devices response: %v", err)
	}
	if len(devResp.Devices) != 1 {
		t.Fatalf("expected 1 connected device, got %d", len(devResp.Devices))
	}
	d := devResp.Devices[0]
	if d.IP != "10.140.12.152" || d.MAC != "12:34:56:78:9a:bc" || d.AuthUser != "alice" || d.AuthMaxDevices != 2 || d.AuthActiveDevices != 1 {
		t.Fatalf("expected device authenticated with alice, got: %+v", d)
	}

	// 6. Test handlePortalKick: kicking device by MAC/IP deauthorizes it immediately
	kickReq := httptest.NewRequest(http.MethodPost, "/api/portal/kick?target=12:34:56:78:9a:bc&ip=10.140.12.152", nil)
	kickRec := httptest.NewRecorder()
	srv.handlePortalKick(kickRec, kickReq)
	if kickRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from kick, got %d", kickRec.Code)
	}
	if pm.IsAuthorized("192.0.2.2") {
		t.Fatalf("expected 192.0.2.2 to be deauthorized after kick")
	}

	// 7. MAC Exemption: if the physical client's MAC is in ExemptMACs,
	// IsAuthorized("192.0.2.2") should be true even without an active session
	cfg := srv.configSrc()
	cfg.Listen.Portal.ExemptMACs = []string{"12:34:56:78:9a:bc"}
	if !pm.IsAuthorized("192.0.2.2") {
		t.Fatalf("expected 192.0.2.2 to be authorized via MAC exemption")
	}
}

func TestPortal_CapportRFC8908(t *testing.T) {
	srv, pm := setupTestPortalAdmin(t)

	paths := []string{
		"/.well-known/captive-portal",
		"/.well-known/capport",
		"/api/capport",
		"/api/captive-portal",
	}

	testIP := "192.168.43.160"

	// 1. Unauthenticated client on each path
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.RemoteAddr = testIP + ":54321"
		req.Header.Set("Accept", "application/captive+json")
		rec := httptest.NewRecorder()

		srv.handleCapport(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("[%s] expected 200, got %d", p, rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.Contains(ct, "application/captive+json") {
			t.Fatalf("[%s] expected application/captive+json, got %s", p, ct)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("[%s] expected Access-Control-Allow-Origin: *", p)
		}

		var st portal.CapportStatus
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("[%s] json unmarshal: %v", p, err)
		}
		if !st.Captive {
			t.Errorf("[%s] expected captive: true for unauthenticated", p)
		}
		if !strings.Contains(st.UserPortalURL, "ip=192.168.43.160") {
			t.Errorf("[%s] expected UserPortalURL to have client IP: %s", p, st.UserPortalURL)
		}
	}

	// 2. Preflight OPTIONS
	{
		req := httptest.NewRequest(http.MethodOptions, "/.well-known/captive-portal", nil)
		rec := httptest.NewRecorder()
		srv.handleCapport(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 from OPTIONS, got %d", rec.Code)
		}
	}

	// 3. Authenticate client
	_, _, err := pm.Authenticate(testIP, "11:22:33:44:55:66", "alice", "password123", "Browser")
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}

	// 4. Authenticated client on /api/capport
	{
		req := httptest.NewRequest(http.MethodGet, "/api/capport", nil)
		req.RemoteAddr = testIP + ":54321"
		rec := httptest.NewRecorder()

		srv.handleCapport(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		var st portal.CapportStatus
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}
		if st.Captive {
			t.Errorf("expected captive: false for authenticated client")
		}
		if st.SecondsRemaining == nil || *st.SecondsRemaining <= 0 {
			t.Errorf("expected positive seconds-remaining, got %v", st.SecondsRemaining)
		}
	}
}

func TestPortal_TetheringBridgeClient_MultiDeviceAuthResolution(t *testing.T) {
	srv, pm := setupTestPortalAdmin(t)

	// Simulate hotspot with 2 devices: one stale unauthenticated, one active authenticated
	bridgeJSON := `[
		{"ip":"10.209.84.152","mac":"d8:a4:91:21:a3:c7","hostname":"JER-AN20"},
		{"ip":"10.209.84.6","mac":"90:e8:68:d6:97:b9","hostname":"DESKTOP-VUF2AE9"}
	]`
	bridge := &mockTetheringBridge{clients: bridgeJSON}
	srv.SetTetheringBridge(bridge)

	// 1. Initial state: neither device authenticated -> 192.0.2.2 must NOT be authorized
	if pm.IsAuthorized("192.0.2.2") {
		t.Fatalf("expected 192.0.2.2 to NOT be authorized when no devices are logged in")
	}

	// 2. Client on 10.209.84.6 authenticates
	_, _, err := pm.Authenticate("10.209.84.6", "90:e8:68:d6:97:b9", "alice", "password123", "Windows")
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}

	// 3. Virtual TUN NAT address 192.0.2.2 must now be authorized for the authenticated client
	if !pm.IsAuthorized("192.0.2.2") {
		t.Fatalf("expected 192.0.2.2 to be authorized after DESKTOP-VUF2AE9 logged in")
	}

	// 4. Verify traffic attribution works for 192.0.2.2
	exceeded := pm.AddTraffic("192.0.2.2", 1024)
	if exceeded {
		t.Errorf("expected quota not exceeded")
	}
	info := pm.GetUserTrafficInfo("alice")
	if info == nil || info.UsedBytes != 1024 {
		t.Errorf("expected 1024 bytes attributed to alice, got %v", info)
	}
}

func TestPortal_ProbeAndLoopRedirectProtection(t *testing.T) {
	srv, pm := setupTestPortalAdmin(t)

	// Authenticate client and get token
	_, token, err := pm.Authenticate("10.209.84.6", "90:e8:68:d6:97:b9", "alice", "password123", "Windows")
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}

	cookie := &http.Cookie{
		Name:  "smartproxy_portal_token",
		Value: token,
	}

	// 1. Probe URL (e.g. msftconnecttest) must NOT be redirected; should render portal page 200 OK
	{
		req := httptest.NewRequest(http.MethodGet, "/portal?url=http://www.msftconnecttest.com/connecttest.txt", nil)
		req.RemoteAddr = "10.209.84.6:54321"
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		srv.handlePortal(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK without redirect loop for probe URL, got %d", rec.Code)
		}
	}

	// 2. Self-referential /portal URL must NOT be redirected; should render portal page 200 OK
	{
		req := httptest.NewRequest(http.MethodGet, "/portal?url=http://192.168.2.226:9090/portal", nil)
		req.RemoteAddr = "10.209.84.6:54321"
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		srv.handlePortal(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK without redirect loop for portal URL, got %d", rec.Code)
		}
	}

	// 3. Legitimate external web URL SHOULD be redirected 302 Found
	{
		req := httptest.NewRequest(http.MethodGet, "/portal?url=http://example.com/welcome", nil)
		req.RemoteAddr = "10.209.84.6:54321"
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		srv.handlePortal(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302 Found for legitimate external URL, got %d", rec.Code)
		}
		loc := rec.Header().Get("Location")
		if loc != "http://example.com/welcome" {
			t.Fatalf("expected Location http://example.com/welcome, got %s", loc)
		}
	}
}

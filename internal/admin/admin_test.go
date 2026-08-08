package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/config"
	"smartproxy/internal/dns"
	"smartproxy/internal/logbuf"
	"smartproxy/internal/route"
	"smartproxy/internal/upstream"
)

func tempSocket(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "admin.sock")
}
func newTestServer(t *testing.T) *Server {
	t.Helper()
	ct := chnroute.New()
	ct.InsertBatch([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	mgr := newTestManager(t)
	dh := dns.NewHandler(1000, 300, "1.1.1.1:53", "[2606:4700:4700::1111]:53",
		ct, mgr, 3, "0.0.0.0", "::", false, "", nil, true)
	rt := route.New(ct, mgr, false, 3*time.Second, []int{80, 443}, 300*time.Second)
	s := New(tempSocket(t), rt, mgr, dh, ct)
	return s
}
func newTestManager(t *testing.T) *upstream.Manager {
	t.Helper()
	cfg := upstream.UpstreamConfig{
		Default: "failover",
		Proxies: []upstream.ProxyEntry{
			{Alias: "ss-local", URL: "socks5://127.0.0.1:1081"},
		},
	}
	m, err := upstream.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	return m
}
func httpGet(sock, path string) (*http.Response, error) {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
		Timeout: 5 * time.Second,
	}
	return c.Get("http://unix" + path)
}
func httpPost(sock, path string) (*http.Response, error) {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
		Timeout: 5 * time.Second,
	}
	return c.Post("http://unix"+path, "application/json", nil)
}
func startServer(t *testing.T, s *Server) {
	t.Helper()
	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(s.Stop)
	// Wait for socket to appear
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(s.sockPath); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("socket did not appear")
}
func TestAdmin_Stats(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpGet(s.sockPath, "/stats")
	if err != nil {
		t.Fatalf("GET /stats failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var data StatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if data.TCP.ActiveConns != 0 {
		t.Error("expected 0 tcp connections")
	}
	if data.Process.Goroutines <= 0 {
		t.Error("expected goroutines > 0")
	}
	if data.Process.CPUPercent < 0 {
		t.Error("expected cpu_percent >= 0")
	}
	if data.Process.Uptime == "" {
		t.Error("expected non-empty uptime")
	}
}
func TestAdmin_Route(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpGet(s.sockPath, "/route")
	if err != nil {
		t.Fatalf("GET /route failed: %v", err)
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	if data["v4"].(float64) != 2 {
		t.Errorf("expected 2 v4 entries, got %v", data["v4"])
	}
	if data["v6"].(float64) != 1 {
		t.Errorf("expected 1 v6 entries, got %v", data["v6"])
	}
	if data["loaded"].(bool) != true {
		t.Error("expected loaded=true")
	}
}
func TestAdmin_Health(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpGet(s.sockPath, "/health")
	if err != nil {
		t.Fatalf("GET /health failed: %v", err)
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	proxies, ok := data["proxies"].([]interface{})
	if !ok || len(proxies) == 0 {
		t.Fatal("expected non-empty proxies array")
	}
	first := proxies[0].(map[string]interface{})
	if first["alias"] != "ss-local" {
		t.Errorf("expected alias ss-local, got %v", first["alias"])
	}
	if first["strategy"] != nil {
		t.Error("strategy should not be inside proxy")
	}
	strat, _ := data["strategy"].(string)
	if strat != "failover" {
		t.Errorf("expected strategy failover, got %s", strat)
	}
}
func TestAdmin_Blacklist(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpGet(s.sockPath, "/blacklist")
	if err != nil {
		t.Fatalf("GET /blacklist failed: %v", err)
	}
	defer resp.Body.Close()
	var entries []BlacklistEntry
	json.NewDecoder(resp.Body).Decode(&entries)
	if len(entries) != 0 {
		t.Errorf("expected empty blacklist, got %d items", len(entries))
	}
}
func TestAdmin_Cache(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpGet(s.sockPath, "/cache")
	if err != nil {
		t.Fatalf("GET /cache failed: %v", err)
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	if data["entries"].(float64) != 0 {
		t.Errorf("expected 0 cache entries, got %v", data["entries"])
	}
}
func TestAdmin_CacheFlush(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpPost(s.sockPath, "/cache/flush")
	if err != nil {
		t.Fatalf("POST /cache/flush failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
func TestAdmin_HealthProxyToggle(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	// Disable
	resp, err := httpPost(s.sockPath, "/health/proxy?alias=ss-local&action=disable")
	if err != nil {
		t.Fatalf("POST /health/proxy disable failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	// Verify disabled
	resp2, _ := httpGet(s.sockPath, "/health")
	var data map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&data)
	resp2.Body.Close()
	proxies := data["proxies"].([]interface{})
	first := proxies[0].(map[string]interface{})
	health := first["health"].(map[string]interface{})
	if health["available"].(bool) != false {
		t.Error("expected proxy to be unavailable after disable")
	}
	// Re-enable
	resp3, _ := httpPost(s.sockPath, "/health/proxy?alias=ss-local&action=enable")
	resp3.Body.Close()
}
func TestAdmin_HealthProxyBadAlias(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpPost(s.sockPath, "/health/proxy?alias=nonexistent&action=disable")
	if err != nil {
		t.Fatalf("POST /health/proxy failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for bad alias, got %d", resp.StatusCode)
	}
}
func TestAdmin_HealthProxyBadAction(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpPost(s.sockPath, "/health/proxy?alias=ss-local&action=bad")
	if err != nil {
		t.Fatalf("POST /health/proxy failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for bad action, got %d", resp.StatusCode)
	}
}
func TestAdmin_HealthProxyCircuitTCP(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpPost(s.sockPath, "/health/proxy?alias=ss-local&circuit=tcp&action=disable")
	if err != nil {
		t.Fatalf("POST disable tcp failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	resp2, _ := httpGet(s.sockPath, "/health")
	var data map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&data)
	resp2.Body.Close()
	first := data["proxies"].([]interface{})[0].(map[string]interface{})
	health := first["health"].(map[string]interface{})
	udpHealth := first["udp_health"].(map[string]interface{})
	if health["available"].(bool) != false {
		t.Error("expected tcp unavailable after circuit=tcp disable")
	}
	if !health["manual"].(bool) {
		t.Error("expected tcp marked manual")
	}
	if udpHealth["available"].(bool) != true {
		t.Error("expected udp still available after circuit=tcp disable")
	}
	if udpHealth["manual"].(bool) != false {
		t.Error("expected udp not marked manual")
	}
}
func TestAdmin_HealthProxyReleaseToAuto(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	httpPost(s.sockPath, "/health/proxy?alias=ss-local&circuit=both&action=disable")
	resp, err := httpPost(s.sockPath, "/health/proxy?alias=ss-local&circuit=both&action=auto")
	if err != nil {
		t.Fatalf("POST auto failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for action=auto, got %d", resp.StatusCode)
	}
	resp2, _ := httpGet(s.sockPath, "/health")
	var data map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&data)
	resp2.Body.Close()
	first := data["proxies"].([]interface{})[0].(map[string]interface{})
	health := first["health"].(map[string]interface{})
	if !health["available"].(bool) || health["manual"].(bool) {
		t.Error("expected tcp available and not manual after release to auto")
	}
}
func TestAdmin_HealthProxyBadCircuit(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpPost(s.sockPath, "/health/proxy?alias=ss-local&circuit=foo&action=disable")
	if err != nil {
		t.Fatalf("POST /health/proxy failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for bad circuit, got %d", resp.StatusCode)
	}
}
func TestAdmin_ConfigReloadAvailable(t *testing.T) {
	s := newTestServer(t)
	reloaded := false
	s.SetReloadConfig(func() { reloaded = true })
	startServer(t, s)
	resp, err := httpPost(s.sockPath, "/config/reload")
	if err != nil {
		t.Fatalf("POST /config/reload failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !reloaded {
		t.Error("reload function was not called")
	}
}
func TestAdmin_ConfigReloadUnavailable(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpPost(s.sockPath, "/config/reload")
	if err != nil {
		t.Fatalf("POST /config/reload failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}
func TestAdmin_StatsMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpPost(s.sockPath, "/stats")
	if err != nil {
		t.Fatalf("POST /stats failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}
func TestAdmin_RouteMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)
	resp, err := httpPost(s.sockPath, "/route")
	if err != nil {
		t.Fatalf("POST /route failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}
func TestAdmin_TCPPort(t *testing.T) {
	s := newTestServer(t)
	s.SetTCPPort(19999)
	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(s.Stop)

	// wait for TCP listener to be ready
	var dialOK bool
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:19999", 200*time.Millisecond)
		if err == nil {
			conn.Close()
			dialOK = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !dialOK {
		t.Fatal("TCP port 19999 not listening after 1.5s")
	}

	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:19999/stats")
	if err != nil {
		t.Fatalf("TCP GET /stats failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 via TCP, got %d", resp.StatusCode)
	}
}

func TestAdmin_TCPOnlyNoSocket(t *testing.T) {
	// Only admin_port is set and admin_socket is empty: only a TCP listener should be started, no unix socket is created
	ct := chnroute.New()
	ct.InsertBatch([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	mgr := newTestManager(t)
	dh := dns.NewHandler(1000, 300, "1.1.1.1:53", "[2606:4700:4700::1111]:53",
		ct, mgr, 3, "0.0.0.0", "::", false, "", nil, true)
	rt := route.New(ct, mgr, false, 3*time.Second, []int{80, 443}, 300*time.Second)
	s := New("", rt, mgr, dh, ct)
	s.SetTCPPort(19998)
	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(s.Stop)

	var dialOK bool
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:19998", 200*time.Millisecond)
		if err == nil {
			conn.Close()
			dialOK = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !dialOK {
		t.Fatal("TCP port 19998 not listening after 1.5s")
	}

	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:19998/dashboard")
	if err != nil {
		t.Fatalf("TCP GET /dashboard failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 via TCP, got %d", resp.StatusCode)
	}

	if s.sockPath != "" {
		if _, err := os.Stat(s.sockPath); err == nil {
			t.Errorf("unix socket should not be created, found %s", s.sockPath)
		}
	}
}

func TestAdmin_TCPPortDisabledByDefault(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)

	resp, err := httpGet(s.sockPath, "/stats")
	if err != nil {
		t.Fatalf("GET /stats failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAdmin_Logs(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)

	// Inject a log entry
	if s.logBuf != nil {
		s.logBuf.Add(logbuf.LogEntry{
			Level:   "INFO",
			Message: "test admin log entry",
		})
		s.logBuf.Add(logbuf.LogEntry{
			Level:   "ERROR",
			Message: "test admin error entry",
		})
	}

	resp, err := httpGet(s.sockPath, "/logs")
	if err != nil {
		t.Fatalf("GET /logs failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var logs []logbuf.LogEntry
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		t.Fatalf("decode logs failed: %v", err)
	}
	if len(logs) < 2 {
		t.Fatalf("expected at least 2 log entries, got %d", len(logs))
	}

	// Test level filtering
	respFiltered, err := httpGet(s.sockPath, "/logs?level=ERROR")
	if err != nil {
		t.Fatalf("GET /logs?level=ERROR failed: %v", err)
	}
	defer respFiltered.Body.Close()

	var filteredLogs []logbuf.LogEntry
	if err := json.NewDecoder(respFiltered.Body).Decode(&filteredLogs); err != nil {
		t.Fatalf("decode filtered logs failed: %v", err)
	}
	for _, l := range filteredLogs {
		if l.Level != "ERROR" {
			t.Errorf("expected level ERROR, got %s", l.Level)
		}
	}
}

func httpPutBody(sock, path, body string) (*http.Response, error) {
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest(http.MethodPut, "http://unix"+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// TestAdmin_ChnrouteUpload_ParseAndWrite verifies the "parse and write directly" semantics of PUT /chnroute:
// valid content → 200 and written to disk; no valid CIDR prefix → 400 and not written to disk.
func TestAdmin_ChnrouteUpload_ParseAndWrite(t *testing.T) {
	dir := t.TempDir()
	chnPath := filepath.Join(dir, "chnroute.txt")
	if err := os.WriteFile(chnPath, []byte("10.0.0.0/8\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Routing.ChnrouteFile = chnPath

	s := newTestServer(t)
	s.SetConfigSrc(func() *config.Config { return cfg })
	startServer(t, s)

	// Valid content → 200 + written to disk
	valid := "1.1.1.0/24\n8.8.4.4\n# comment\n"
	resp, err := httpPutBody(s.sockPath, "/chnroute", valid)
	if err != nil {
		t.Fatalf("PUT /chnroute failed: %v", err)
	}
	body1, _ := readAllAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for valid upload, got %d (body=%s)", resp.StatusCode, body1)
	}
	got, err := os.ReadFile(chnPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != valid {
		t.Errorf("file content = %q, want %q", got, valid)
	}

	// Invalid content (no valid CIDR) → 400 + not written to disk
	invalid := "not-a-cidr\n\n# only comments\n"
	resp2, err := httpPutBody(s.sockPath, "/chnroute", invalid)
	if err != nil {
		t.Fatalf("PUT /chnroute (invalid) failed: %v", err)
	}
	body2, _ := readAllAndClose(resp2)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid upload, got %d (body=%s)", resp2.StatusCode, body2)
	}
	got2, err := os.ReadFile(chnPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got2) != valid {
		t.Errorf("file must be unchanged after rejected upload, got %q", got2)
	}
}

func readAllAndClose(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	b, err := ioReadAll(resp.Body)
	return string(b), err
}

func ioReadAll(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r)
	return buf.Bytes(), err
}

func TestAdmin_FilesList(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}

	resp, err := httpGet(s.sockPath, "/files?path="+url.QueryEscape(dir))
	if err != nil {
		t.Fatalf("GET /files failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var fl FileListResponse
	if err := json.NewDecoder(resp.Body).Decode(&fl); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fl.Path != dir {
		t.Errorf("path: got %q want %q", fl.Path, dir)
	}
	if fl.Parent == "" {
		t.Error("expected non-empty parent for a temp dir")
	}
	foundFile, foundDir := false, false
	for _, e := range fl.Entries {
		if e.Name == "a.txt" && !e.IsDir {
			foundFile = true
		}
		if e.Name == "sub" && e.IsDir {
			foundDir = true
		}
	}
	if !foundFile || !foundDir {
		t.Errorf("missing entries, file=%v dir=%v, got %+v", foundFile, foundDir, fl.Entries)
	}
}

func TestAdmin_FilesListNoPath(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)

	// When path is empty, list from the working directory
	resp, err := httpGet(s.sockPath, "/files")
	if err != nil {
		t.Fatalf("GET /files failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var fl FileListResponse
	if err := json.NewDecoder(resp.Body).Decode(&fl); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fl.Path == "" {
		t.Error("expected cwd path")
	}
}

func TestAdmin_FilesNotFound(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)

	resp, err := httpGet(s.sockPath, "/files?path="+url.QueryEscape(filepath.Join(t.TempDir(), "nope")))
	if err != nil {
		t.Fatalf("GET /files failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAdmin_FilesValidate(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)

	dir := t.TempDir()
	validChn := filepath.Join(dir, "chn.txt")
	if err := os.WriteFile(validChn, []byte("1.0.0.0/8\n2.2.2.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	badChn := filepath.Join(dir, "badchn.txt")
	if err := os.WriteFile(badChn, []byte("this is not a cidr\nstill not\n"), 0644); err != nil {
		t.Fatal(err)
	}
	validACL := filepath.Join(dir, "acl.txt")
	if err := os.WriteFile(validACL, []byte("allow port 22\nproxy domain *.example.com direct\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		typ, path string
		wantOK    bool
	}{
		{"chnroute", validChn, true},
		{"chnroute", badChn, false}, // No valid CIDR → empty Trie → rejected
		{"chnroute", filepath.Join(dir, "missing.txt"), false},
		{"acl", validACL, true},
		{"acl", filepath.Join(dir, "missing.txt"), false},
	}
	for _, c := range cases {
		resp, err := httpGet(s.sockPath, "/files/validate?type="+c.typ+"&path="+url.QueryEscape(c.path))
		if err != nil {
			t.Fatalf("validate type=%s path=%s: %v", c.typ, c.path, err)
		}
		var out map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		got, _ := out["ok"].(bool)
		if got != c.wantOK {
			t.Errorf("validate type=%s path=%s: ok=%v want %v (err=%v)", c.typ, c.path, got, c.wantOK, out["error"])
		}
	}
}

package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

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
func TestAdmin_CachePinStaticRecord(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.DefaultConfig()
	// Seed a cache entry so the pin endpoint has something to supersede.
	m := new(mdns.Msg)
	m.SetQuestion("example.com.", mdns.TypeA)
	m.Answer = []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
		A:   net.ParseIP("1.2.3.4"),
	}}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	dh := dns.NewHandler(1000, 300, "1.1.1.1:53", "[2606:4700:4700::1111]:53",
		chnroute.New(), newTestManager(t), 3, "0.0.0.0", "::", false, "", nil, true)
	dh.CacheSet("example.com", mdns.TypeA, wire, time.Minute)
	rt := route.New(chnroute.New(), newTestManager(t), false, 3*time.Second, []int{80, 443}, 300*time.Second)
	s := New(tempSocket(t), rt, newTestManager(t), dh, chnroute.New())
	s.SetConfigSrc(func() *config.Config { return cfg })
	s.SetConfigPath(cfgPath)
	s.SetReloadConfig(func() {}) // availability check only; real reload is fsnotify-owned
	startServer(t, s)

	post := func(qname string, qtype uint16, ip interface{}) (*http.Response, error) {
		c := &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", s.sockPath)
		}}, Timeout: 5 * time.Second}
		body, _ := json.Marshal(map[string]interface{}{"qname": qname, "qtype": qtype, "ip": ip})
		return c.Post("http://unix/cache", "application/json", bytes.NewReader(body))
	}

	// Valid A pin → config written + cache entry removed.
	resp, err := post("example.com", mdns.TypeA, "5.6.7.8")
	if err != nil {
		t.Fatalf("POST /cache failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()
	if dh.CacheLen() != 0 {
		t.Errorf("expected cache entry removed, still %d entries", dh.CacheLen())
	}
	disk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	var got config.Config
	if err := json.Unmarshal(disk, &got); err != nil {
		t.Fatalf("written config invalid: %v", err)
	}
	if len(got.DNS.StaticRecords) != 1 || got.DNS.StaticRecords[0].Host != "example.com" ||
		len(got.DNS.StaticRecords[0].IP) != 1 || got.DNS.StaticRecords[0].IP[0] != "5.6.7.8" {
		t.Fatalf("static record not written correctly: %+v", got.DNS.StaticRecords)
	}

	// Family mismatch → 400, config untouched.
	if err := os.WriteFile(cfgPath, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	resp, err = post("example.com", mdns.TypeA, "::1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("A record with IPv6 should be 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Unsupported type → 400.
	resp, err = post("example.com", mdns.TypeTXT, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("TXT pin should be 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Multiple IPs → all written; response echoes the array.
	if err := os.WriteFile(cfgPath, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	resp, err = post("example.com", mdns.TypeA, []string{"9.9.9.9", "8.8.4.4"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200 for multi-IP pin, got %d: %s", resp.StatusCode, body)
	}
	var multiResp struct {
		Host string   `json:"host"`
		IP   []string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&multiResp); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if multiResp.Host != "example.com" || len(multiResp.IP) != 2 ||
		multiResp.IP[0] != "9.9.9.9" || multiResp.IP[1] != "8.8.4.4" {
		t.Errorf("response did not echo both IPs: %+v", multiResp)
	}
	disk, err = os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	var got2 config.Config
	if err := json.Unmarshal(disk, &got2); err != nil {
		t.Fatalf("written config invalid: %v", err)
	}
	if len(got2.DNS.StaticRecords) != 1 || len(got2.DNS.StaticRecords[0].IP) != 2 {
		t.Fatalf("multi-IP static record not written correctly: %+v", got2.DNS.StaticRecords)
	}
	// Mixed family in one A pin → 400, nothing written.
	resp, err = post("example.com", mdns.TypeA, []string{"1.2.3.4", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("A pin mixing IPv6 should be 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAdmin_DNSStatic(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.DefaultConfig()
	cfg.DNS.StaticRecords = []config.StaticRecord{{Host: "smartproxy.lan", IP: config.IPList{"192.168.1.1"}}}
	if err := os.WriteFile(cfgPath, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	dh := dns.NewHandler(1000, 300, "1.1.1.1:53", "[2606:4700:4700::1111]:53",
		chnroute.New(), newTestManager(t), 3, "0.0.0.0", "::", false, "", nil, true)
	rt := route.New(chnroute.New(), newTestManager(t), false, 3*time.Second, []int{80, 443}, 300*time.Second)
	s := New(tempSocket(t), rt, newTestManager(t), dh, chnroute.New())
	s.SetConfigSrc(func() *config.Config { return cfg })
	s.SetConfigPath(cfgPath)
	s.SetReloadConfig(func() {})
	// In production the config file watcher reloads configSrc after each write;
	// simulate that here so subsequent mutations build on the persisted state.
	reload := func() {
		b, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		var c config.Config
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		cfg = &c
	}
	startServer(t, s)

	do := func(method, path string, body []byte) (*http.Response, []byte) {
		t.Helper()
		c := &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", s.sockPath)
		}}, Timeout: 5 * time.Second}
		var req *http.Request
		var err error
		if body != nil {
			req, err = http.NewRequest(method, "http://unix"+path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req, err = http.NewRequest(method, "http://unix"+path, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	// GET returns the seed record.
	resp, b := do("GET", "/dns/static", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d: %s", resp.StatusCode, b)
	}
	var list []config.StaticRecord
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("GET: bad json: %v", err)
	}
	if len(list) != 1 || list[0].Host != "smartproxy.lan" || list[0].IP[0] != "192.168.1.1" {
		t.Fatalf("GET: unexpected list %+v", list)
	}

	// POST adds a second family to the same host.
	body := []byte(`{"host":"SmartProxy.LAN.","ip":["::1"]}`)
	resp, b = do("POST", "/dns/static", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST: expected 200, got %d: %s", resp.StatusCode, b)
	}
	var upd struct {
		Records []config.StaticRecord `json:"records"`
	}
	if err := json.Unmarshal(b, &upd); err != nil {
		t.Fatalf("POST: bad json: %v", err)
	}
	if len(upd.Records) != 1 || len(upd.Records[0].IP) != 2 {
		t.Fatalf("POST: expected merged v4+v6, got %+v", upd.Records)
	}
	disk, _ := os.ReadFile(cfgPath)
	var onDisk config.Config
	if err := json.Unmarshal(disk, &onDisk); err != nil {
		t.Fatalf("config on disk invalid: %v", err)
	}
	if len(onDisk.DNS.StaticRecords) != 1 || len(onDisk.DNS.StaticRecords[0].IP) != 2 {
		t.Fatalf("config not persisted: %+v", onDisk.DNS.StaticRecords)
	}
	reload()

	// DELETE a single IP → v6 left.
	resp, b = do("DELETE", "/dns/static?host=smartproxy.lan&ip=192.168.1.1", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE ip: expected 200, got %d: %s", resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, &upd); err != nil {
		t.Fatalf("DELETE ip: bad json: %v", err)
	}
	if len(upd.Records) != 1 || len(upd.Records[0].IP) != 1 || upd.Records[0].IP[0] != "::1" {
		t.Fatalf("DELETE ip: expected ::1 left, got %+v", upd.Records)
	}
	reload()

	// DELETE whole host → empty list.
	resp, b = do("DELETE", "/dns/static?host=smartproxy.lan", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE host: expected 200, got %d: %s", resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, &upd); err != nil {
		t.Fatalf("DELETE host: bad json: %v", err)
	}
	if len(upd.Records) != 0 {
		t.Fatalf("DELETE host: expected empty, got %+v", upd.Records)
	}

	// Bad IP → 400, empty host → 400.
	resp, _ = do("POST", "/dns/static", []byte(`{"host":"x.lan","ip":"not-an-ip"}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST bad ip: expected 400, got %d", resp.StatusCode)
	}
	resp, _ = do("POST", "/dns/static", []byte(`{"host":"  ","ip":"1.2.3.4"}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST empty host: expected 400, got %d", resp.StatusCode)
	}
}

func TestAdmin_DNSStaticEdit(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.DefaultConfig()
	cfg.DNS.StaticRecords = []config.StaticRecord{{Host: "smartproxy.lan", IP: config.IPList{"192.168.1.1", "::1"}}}
	dh := dns.NewHandler(1000, 300, "1.1.1.1:53", "[2606:4700:4700::1111]:53",
		chnroute.New(), newTestManager(t), 3, "0.0.0.0", "::", false, "", nil, true)
	rt := route.New(chnroute.New(), newTestManager(t), false, 3*time.Second, []int{80, 443}, 300*time.Second)
	s := New(tempSocket(t), rt, newTestManager(t), dh, chnroute.New())
	s.SetConfigSrc(func() *config.Config { return cfg })
	s.SetConfigPath(cfgPath)
	s.SetReloadConfig(func() {})
	reload := func() {
		b, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		var c config.Config
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		cfg = &c
	}
	startServer(t, s)
	do := func(method, path string, body []byte) (*http.Response, []byte) {
		t.Helper()
		c := &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", s.sockPath)
		}}, Timeout: 5 * time.Second}
		req, err := http.NewRequest(method, "http://unix"+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	// Edit: replace the address list wholesale (drops ::1, sets new v4).
	resp, b := do("PUT", "/dns/static", []byte(`{"old_host":"smartproxy.lan","host":"smartproxy.lan","ip":["5.6.7.8"]}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT: expected 200, got %d: %s", resp.StatusCode, b)
	}
	var upd struct {
		Records []config.StaticRecord `json:"records"`
	}
	if err := json.Unmarshal(b, &upd); err != nil {
		t.Fatalf("PUT: bad json: %v", err)
	}
	if len(upd.Records) != 1 || len(upd.Records[0].IP) != 1 || upd.Records[0].IP[0] != "5.6.7.8" {
		t.Fatalf("PUT: expected single 5.6.7.8, got %+v", upd.Records)
	}
	reload()

	// Edit rename: old host removed, new host carries the list.
	resp, b = do("PUT", "/dns/static", []byte(`{"old_host":"smartproxy.lan","host":"panel.lan","ip":["127.0.0.1","::1"]}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT rename: expected 200, got %d: %s", resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, &upd); err != nil {
		t.Fatalf("PUT rename: bad json: %v", err)
	}
	if len(upd.Records) != 1 || upd.Records[0].Host != "panel.lan" ||
		len(upd.Records[0].IP) != 2 || upd.Records[0].IP[1] != "::1" {
		t.Fatalf("PUT rename: unexpected %+v", upd.Records)
	}
	disk, _ := os.ReadFile(cfgPath)
	var onDisk config.Config
	if err := json.Unmarshal(disk, &onDisk); err != nil {
		t.Fatalf("config on disk invalid: %v", err)
	}
	if len(onDisk.DNS.StaticRecords) != 1 || onDisk.DNS.StaticRecords[0].Host != "panel.lan" {
		t.Fatalf("config not persisted: %+v", onDisk.DNS.StaticRecords)
	}

	// Missing old_host / empty host / bad ip → 400.
	resp, _ = do("PUT", "/dns/static", []byte(`{"host":"x.lan","ip":["1.2.3.4"]}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("PUT missing old_host: expected 400, got %d", resp.StatusCode)
	}
	resp, _ = do("PUT", "/dns/static", []byte(`{"old_host":"panel.lan","host":"  ","ip":["1.2.3.4"]}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("PUT empty host: expected 400, got %d", resp.StatusCode)
	}
	resp, _ = do("PUT", "/dns/static", []byte(`{"old_host":"panel.lan","host":"x.lan","ip":["oops"]}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("PUT bad ip: expected 400, got %d", resp.StatusCode)
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

// TestAdmin_TCPHTTPSRedirectAndServe: with TLS enabled, a plaintext HTTP request on
// the TCP port must be 301-redirected to the https:// URL (same host:port, original
// path), and a real TLS request must be served through the mux.
func TestAdmin_TCPHTTPSRedirectAndServe(t *testing.T) {
	// Reserve a free port (Start treats port 0 as "disabled"), then release it.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	s := newTestServer(t)
	s.SetTCPPort(port)
	s.SetTLS("", "", true)
	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(s.Stop)

	base := fmt.Sprintf("127.0.0.1:%d", port)

	// Wait until the listener is accepting.
	ready := false
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", base, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("TCP listener not ready")
	}

	// Plaintext HTTP → 301 to https on the same host:port.
	plain := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := plain.Get("http://" + base + "/stats")
	if err != nil {
		t.Fatalf("plaintext GET failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("expected 301 for plaintext HTTP, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://"+base+"/stats" {
		t.Fatalf("Location = %q, want %q", loc, "https://"+base+"/stats")
	}

	// HTTPS with the auto-generated self-signed cert → 200 through the mux.
	secure := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp2, err := secure.Get("https://" + base + "/stats")
	if err != nil {
		t.Fatalf("TLS GET failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 via HTTPS, got %d", resp2.StatusCode)
	}
}

// TestBuildTLSConfig_AutoGenerated: no cert files and no config path → an in-memory
// self-signed certificate with a sane validity window.
func TestBuildTLSConfig_AutoGenerated(t *testing.T) {
	s := &Server{}
	cfg, err := s.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig auto: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse generated cert: %v", err)
	}
	if !leaf.NotBefore.Before(time.Now()) || !leaf.NotAfter.After(time.Now()) {
		t.Fatal("generated cert not currently valid")
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > 400*24*time.Hour {
		t.Errorf("cert validity %v exceeds 397 days", leaf.NotAfter.Sub(leaf.NotBefore))
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		t.Error("generated cert has no SANs")
	}
}

// TestAdminCertDownload: GET /admin.crt serves the public certificate as a PEM download and
// never the private key; the downloaded cert still carries the configured admin_cert_sans.
func TestAdminCertDownload(t *testing.T) {
	s := &Server{}
	s.SetTLS("", "", true, "192.168.1.1")
	if _, err := s.buildTLSConfig(); err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if len(s.certPEM) == 0 {
		t.Fatal("certPEM not captured at buildTLSConfig")
	}

	rec := httptest.NewRecorder()
	s.handleAdminCert(rec, httptest.NewRequest(http.MethodGet, "/admin.crt", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("Content-Type = %q, want application/x-pem-file", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "admin.crt") {
		t.Errorf("Content-Disposition = %q, want attachment filename admin.crt", cd)
	}
	body := rec.Body.Bytes()
	if !bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("body missing PEM certificate")
	}
	if bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Error("body must never contain the private key")
	}
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatal("body is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse downloaded cert: %v", err)
	}
	var sawSAN bool
	for _, ip := range cert.IPAddresses {
		if ip.String() == "192.168.1.1" {
			sawSAN = true
		}
	}
	if !sawSAN {
		t.Error("downloaded cert missing the configured admin_cert_sans IP")
	}
}

// TestAdminCertDownload_NoTLS: with HTTPS off (buildTLSConfig never ran) the download is a
// 404 with a hint, not a panic.
func TestAdminCertDownload_NoTLS(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleAdminCert(rec, httptest.NewRequest(http.MethodGet, "/admin.crt", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestBuildTLSConfig_ExplicitFiles: configured cert/key PEM paths are loaded.
func TestBuildTLSConfig_ExplicitFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if _, err := genSelfSigned(certPath, keyPath); err != nil {
		t.Fatalf("genSelfSigned: %v", err)
	}
	s := &Server{certFile: certPath, keyFile: keyPath}
	cfg, err := s.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig with files: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
}

// TestBuildTLSConfig_PersistsNextToConfig: with a config path but no explicit files,
// the self-signed pair is written next to the config file and reused on rebuild.
func TestBuildTLSConfig_PersistsNextToConfig(t *testing.T) {
	dir := t.TempDir()
	s := &Server{configPath: filepath.Join(dir, "config.json")}
	cfg, err := s.buildTLSConfig()
	if err != nil {
		t.Fatalf("first buildTLSConfig: %v", err)
	}
	certPath, keyPath := filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key")
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("admin.crt not written next to config: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("admin.key not written next to config: %v", err)
	}
	first := cfg.Certificates[0].Certificate[0]
	cfg2, err := s.buildTLSConfig()
	if err != nil {
		t.Fatalf("second buildTLSConfig: %v", err)
	}
	second := cfg2.Certificates[0].Certificate[0]
	if !bytes.Equal(first, second) {
		t.Error("rebuilt config did not reuse the persisted certificate")
	}
}

// TestGenSelfSigned_ExtraSANs: extraSANs are written into the generated cert as
// DNSName (hostnames) and IPAddress (IP literals) entries, and wildcard-ish bind
// addresses ("::", "0.0.0.0", "*") are dropped as invalid SANs.
func TestGenSelfSigned_ExtraSANs(t *testing.T) {
	cert, err := genSelfSigned("", "", "192.168.1.1", "panel.example.com")
	if err != nil {
		t.Fatalf("genSelfSigned: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated cert: %v", err)
	}
	if !slices.Contains(leaf.DNSNames, "panel.example.com") {
		t.Errorf("expected DNSName panel.example.com, got %v", leaf.DNSNames)
	}
	if !hasSANIP(leaf.IPAddresses, "192.168.1.1") {
		t.Errorf("expected IP SAN 192.168.1.1, got %v", leaf.IPAddresses)
	}
	// The cert must be a CA (IsCA + CertSign) so Android's installer accepts it
	// as a CA certificate without demanding the private key.
	if !leaf.IsCA {
		t.Error("generated cert must have IsCA set")
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("generated cert must include KeyUsageCertSign")
	}

	cert, err = genSelfSigned("", "", "::", "0.0.0.0", "*")
	if err != nil {
		t.Fatalf("genSelfSigned wildcards: %v", err)
	}
	leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse wildcard cert: %v", err)
	}
	if len(leaf.DNSNames) != 1 || len(leaf.IPAddresses) != 2 {
		t.Errorf("expected only built-in SANs after dropping wildcards, got dns=%v ip=%v", leaf.DNSNames, leaf.IPAddresses)
	}
}

// TestCertCoversSANs: a persisted cert is only reused while it covers the requested
// extra SANs; an added admin_cert_sans entry must force regeneration.
func TestCertCoversSANs(t *testing.T) {
	base, err := genSelfSigned("", "")
	if err != nil {
		t.Fatalf("genSelfSigned base: %v", err)
	}
	if !certCoversSANs(base, nil) {
		t.Error("built-in cert should cover the default (no extra) SANs")
	}
	if certCoversSANs(base, []string{"192.168.1.1"}) {
		t.Error("built-in cert must not cover an unlisted LAN IP")
	}
	with, err := genSelfSigned("", "", "192.168.1.1")
	if err != nil {
		t.Fatalf("genSelfSigned extra: %v", err)
	}
	if !certCoversSANs(with, []string{"192.168.1.1"}) {
		t.Error("cert with the extra SAN should cover it")
	}
}

func hasSANIP(ips []net.IP, want string) bool {
	for _, ip := range ips {
		if ip.String() == want {
			return true
		}
	}
	return false
}

package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"smartproxy/internal/config"
)

func TestDeviceManager_BlockUnblockPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dm := newDeviceManager(tmpDir)

	if dm.isBlocked("192.168.1.10", "AA:BB:CC:DD:EE:FF") {
		t.Fatal("device should not be blocked initially")
	}

	// Block device
	if err := dm.block("192.168.1.10", "AA:BB:CC:DD:EE:FF", "phone-1"); err != nil {
		t.Fatalf("block failed: %v", err)
	}

	if !dm.isBlocked("192.168.1.10", "") {
		t.Error("expected 192.168.1.10 to be blocked by IP")
	}
	if !dm.isBlocked("", "aa:bb:cc:dd:ee:ff") {
		t.Error("expected AA:BB:CC:DD:EE:FF to be blocked by MAC (case-insensitive)")
	}

	// Verify file persisted
	persistedPath := filepath.Join(tmpDir, "blocked_devices.json")
	if _, err := os.Stat(persistedPath); err != nil {
		t.Fatalf("expected blocked_devices.json to exist: %v", err)
	}

	// Reload in a new manager
	dm2 := newDeviceManager(tmpDir)
	if !dm2.isBlocked("192.168.1.10", "") {
		t.Error("expected reloaded manager to remember blocked IP")
	}
	list := dm2.getBlockedList()
	if len(list) != 1 || list[0].Hostname != "phone-1" {
		t.Errorf("unexpected blocked list: %+v", list)
	}

	// Unblock
	if err := dm2.unblock("192.168.1.10", "aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("unblock failed: %v", err)
	}
	if dm2.isBlocked("192.168.1.10", "") {
		t.Error("expected device to no longer be blocked")
	}
	if len(dm2.getBlockedList()) != 0 {
		t.Error("expected blocked list to be empty after unblock")
	}
}

func TestDeviceManager_CalculateRates(t *testing.T) {
	dm := newDeviceManager("")
	up, down := dm.calculateRates("192.168.1.5", 1000, 2000)
	if up != 0 || down != 0 {
		t.Errorf("first sample rate should be 0, got up=%d down=%d", up, down)
	}

	time.Sleep(150 * time.Millisecond)
	up, down = dm.calculateRates("192.168.1.5", 10000, 20000)
	if up <= 0 || down <= 0 {
		t.Errorf("second sample rate should be > 0, got up=%d down=%d", up, down)
	}
}

func TestAdmin_DevicesProtectionAndEndpoints(t *testing.T) {
	s := newTestServer(t)
	tmpDir := t.TempDir()
	s.configPath = filepath.Join(tmpDir, "config.json")

	var killedIP string
	var blockedIP string
	var unblockedIP string

	s.SetDeviceHooks(
		func() string {
			return `{"apps":[{"conns":[{"src_ip":"192.168.1.20","up":1024,"down":2048}]}]}`
		},
		func(ip string) int {
			killedIP = ip
			return 1
		},
		func(ip string) {
			blockedIP = ip
		},
		func(ip string) {
			unblockedIP = ip
		},
		func(ip string) bool {
			return ip == blockedIP
		},
	)

	// 1. GET /api/devices
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	req.RemoteAddr = "192.168.1.100:54321" // Current managing client
	w := httptest.NewRecorder()
	s.handleDevices(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("handleDevices status = %d, want 200", w.Code)
	}
	var resp struct {
		Devices        []TetheredDevice `json:"devices"`
		BlockedDevices []BlockedRecord  `json:"blocked_devices"`
		CurrentIP      string           `json:"current_ip"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal resp: %v", err)
	}
	if resp.CurrentIP != "192.168.1.100" {
		t.Errorf("current_ip got %q, want 192.168.1.100", resp.CurrentIP)
	}

	// 2. Disconnect current client -> MUST BE 403 Forbidden
	reqSelf := httptest.NewRequest(http.MethodPost, "/api/devices/disconnect?ip=192.168.1.100", nil)
	reqSelf.RemoteAddr = "192.168.1.100:54321"
	wSelf := httptest.NewRecorder()
	s.handleDevicesDisconnect(wSelf, reqSelf)
	if wSelf.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden when disconnecting current client, got %d", wSelf.Code)
	}

	// 3. Disconnect other client -> 200 OK
	reqOther := httptest.NewRequest(http.MethodPost, "/api/devices/disconnect?ip=192.168.1.20", nil)
	reqOther.RemoteAddr = "192.168.1.100:54321"
	wOther := httptest.NewRecorder()
	s.handleDevicesDisconnect(wOther, reqOther)
	if wOther.Code != http.StatusOK {
		t.Errorf("expected 200 OK when disconnecting other client, got %d", wOther.Code)
	}
	if killedIP != "192.168.1.20" {
		t.Errorf("killedIP got %q, want 192.168.1.20", killedIP)
	}

	// 4. Block current client -> MUST BE 403 Forbidden
	reqBlockSelf := httptest.NewRequest(http.MethodPost, "/api/devices/block?ip=192.168.1.100", nil)
	reqBlockSelf.RemoteAddr = "192.168.1.100:54321"
	wBlockSelf := httptest.NewRecorder()
	s.handleDevicesBlock(wBlockSelf, reqBlockSelf)
	if wBlockSelf.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden when blocking current client, got %d", wBlockSelf.Code)
	}

	// 5. Block other client -> 200 OK
	reqBlockOther := httptest.NewRequest(http.MethodPost, "/api/devices/block?ip=192.168.1.50&mac=aa:bb:cc:11:22:33&hostname=guest", nil)
	reqBlockOther.RemoteAddr = "192.168.1.100:54321"
	wBlockOther := httptest.NewRecorder()
	s.handleDevicesBlock(wBlockOther, reqBlockOther)
	if wBlockOther.Code != http.StatusOK {
		t.Errorf("expected 200 OK when blocking other client, got %d", wBlockOther.Code)
	}
	if blockedIP != "192.168.1.50" {
		t.Errorf("blockedIP got %q, want 192.168.1.50", blockedIP)
	}

	// 6. Unblock other client -> 200 OK
	reqUnblock := httptest.NewRequest(http.MethodPost, "/api/devices/unblock?ip=192.168.1.50&mac=aa:bb:cc:11:22:33", nil)
	wUnblock := httptest.NewRecorder()
	s.handleDevicesUnblock(wUnblock, reqUnblock)
	if wUnblock.Code != http.StatusOK {
		t.Errorf("expected 200 OK when unblocking client, got %d", wUnblock.Code)
	}
	if unblockedIP != "192.168.1.50" {
		t.Errorf("unblockedIP got %q, want 192.168.1.50", unblockedIP)
	}
}

func TestAdmin_HealthProxyPersistsEnableState(t *testing.T) {
	s := newTestServer(t)
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfg := config.DefaultConfig()
	cfg.Upstream.Proxies = []config.ProxyEntry{
		{Alias: "ss-local", URL: "socks5://127.0.0.1:1080"},
	}
	cfgData, _ := json.Marshal(cfg)
	os.WriteFile(cfgPath, cfgData, 0644)

	s.SetConfigPath(cfgPath)
	s.SetConfigSrc(func() *config.Config {
		c, _ := config.Load(cfgPath)
		return c
	})
	s.SetReloadConfig(func() {})

	startServer(t, s)

	// Disable proxy
	resp, err := httpPost(s.sockPath, "/health/proxy?alias=ss-local&action=disable")
	if err != nil {
		t.Fatalf("POST /health/proxy disable failed: %v", err)
	}
	resp.Body.Close()

	// Verify config.json has enable = false
	savedBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config.json failed: %v", err)
	}
	var savedCfg config.Config
	if err := json.Unmarshal(savedBytes, &savedCfg); err != nil {
		t.Fatalf("unmarshal saved config failed: %v", err)
	}
	if len(savedCfg.Upstream.Proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(savedCfg.Upstream.Proxies))
	}
	if !savedCfg.Upstream.Proxies[0].IsDisabled() {
		t.Error("expected saved config proxy to have IsDisabled() == true")
	}

	// Re-enable proxy
	resp2, err := httpPost(s.sockPath, "/health/proxy?alias=ss-local&action=enable")
	if err != nil {
		t.Fatalf("POST /health/proxy enable failed: %v", err)
	}
	resp2.Body.Close()

	savedBytes, _ = os.ReadFile(cfgPath)
	var savedCfg2 config.Config
	json.Unmarshal(savedBytes, &savedCfg2)
	if savedCfg2.Upstream.Proxies[0].IsDisabled() {
		t.Error("expected saved config proxy to have IsDisabled() == false after enable")
	}
}

type mockTetheringBridge struct {
	clients        string
	blockedClients string
	blockedMACs    []string
	unblockedMACs  []string
}

func (m *mockTetheringBridge) GetTetheredClients() string {
	return m.clients
}
func (m *mockTetheringBridge) BlockClient(mac string) bool {
	m.blockedMACs = append(m.blockedMACs, mac)
	return true
}
func (m *mockTetheringBridge) UnblockClient(mac string) bool {
	m.unblockedMACs = append(m.unblockedMACs, mac)
	return true
}
func (m *mockTetheringBridge) GetBlockedClients() string {
	return m.blockedClients
}

func TestAdmin_TetheringBridgeIntegration(t *testing.T) {
	s := newTestServer(t)
	tmpDir := t.TempDir()
	s.configPath = filepath.Join(tmpDir, "config.json")

	bridge := &mockTetheringBridge{
		clients: `[{"mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.43.101","hostname":"Laptop","assigned_ips":["192.168.43.101"]}]`,
		blockedClients: `["99:88:77:66:55:44"]`,
	}
	s.SetTetheringBridge(bridge)

	s.SetDeviceHooks(
		func() string {
			return `{"apps":[{"conns":[{"src_ip":"192.168.43.101","up":5000,"down":10000}]}]}`
		},
		func(ip string) int { return 1 },
		func(ip string) {},
		func(ip string) {},
		func(ip string) bool { return false },
	)

	// 1. Initial list with bridge client
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	req.RemoteAddr = "192.168.43.1:8080"
	w := httptest.NewRecorder()
	s.handleDevices(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("handleDevices status = %d", w.Code)
	}

	var resp struct {
		Devices        []TetheredDevice `json:"devices"`
		BlockedDevices []BlockedRecord  `json:"blocked_devices"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(resp.Devices))
	}
	dev := resp.Devices[0]
	if dev.MAC != "aa:bb:cc:dd:ee:ff" || dev.IP != "192.168.43.101" || dev.Hostname != "Laptop" {
		t.Errorf("unexpected device: %+v", dev)
	}
	if dev.UpBytes != 5000 || dev.DownBytes != 10000 || dev.ActiveConns != 1 {
		t.Errorf("unexpected traffic: up=%d down=%d conns=%d", dev.UpBytes, dev.DownBytes, dev.ActiveConns)
	}
	// Hardware blocked MAC should be synced
	if len(resp.BlockedDevices) != 1 || resp.BlockedDevices[0].MAC != "99:88:77:66:55:44" {
		t.Errorf("unexpected blocked devices: %+v", resp.BlockedDevices)
	}

	// 2. Client reconnected with new MAC and IP (e.g. true MAC instead of randomized MAC)
	bridge.clients = `[{"mac":"11:22:33:44:55:66","ip":"192.168.43.102","hostname":"Laptop-Real","assigned_ips":["192.168.43.102"]}]`
	w2 := httptest.NewRecorder()
	s.handleDevices(w2, req)
	var resp2 struct {
		Devices []TetheredDevice `json:"devices"`
	}
	json.Unmarshal(w2.Body.Bytes(), &resp2)
	if len(resp2.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(resp2.Devices))
	}
	if resp2.Devices[0].MAC != "11:22:33:44:55:66" || resp2.Devices[0].IP != "192.168.43.102" {
		t.Errorf("expected only new MAC device, got: %+v", resp2.Devices[0])
	}

	// 3. Block client via API -> should call bridge.BlockClient
	reqBlock := httptest.NewRequest(http.MethodPost, "/api/devices/block?ip=192.168.43.102&mac=11:22:33:44:55:66", nil)
	wBlock := httptest.NewRecorder()
	s.handleDevicesBlock(wBlock, reqBlock)
	if wBlock.Code != http.StatusOK {
		t.Fatalf("handleDevicesBlock status = %d", wBlock.Code)
	}
	if len(bridge.blockedMACs) != 1 || bridge.blockedMACs[0] != "11:22:33:44:55:66" {
		t.Errorf("expected bridge to receive block for MAC, got: %+v", bridge.blockedMACs)
	}

	// 4. Unblock client via API -> should call bridge.UnblockClient
	reqUnblock := httptest.NewRequest(http.MethodPost, "/api/devices/unblock?ip=192.168.43.102&mac=11:22:33:44:55:66", nil)
	wUnblock := httptest.NewRecorder()
	s.handleDevicesUnblock(wUnblock, reqUnblock)
	if wUnblock.Code != http.StatusOK {
		t.Fatalf("handleDevicesUnblock status = %d", wUnblock.Code)
	}
	if len(bridge.unblockedMACs) != 1 || bridge.unblockedMACs[0] != "11:22:33:44:55:66" {
		t.Errorf("expected bridge to receive unblock for MAC, got: %+v", bridge.unblockedMACs)
	}
}

func TestAdmin_Devices_LifetimeMonotonicTrafficAndExtraIPs(t *testing.T) {
	s := newTestServer(t)
	tmpDir := t.TempDir()
	s.configPath = filepath.Join(tmpDir, "config.json")

	bridge := &mockTetheringBridge{
		clients: `[{"mac":"d8:a4:91:21:a3:c7","ip":"10.152.206.152","hostname":"JER-AN20","assigned_ips":["10.152.206.152","2001:db8:9877:0:6dbe:cdc5:e837:fd12"]}]`,
	}
	s.SetTetheringBridge(bridge)

	// 模拟首次采样: 产生 1500 上传, 8500 下载
	statsJSON := `{"client_traffic":[{"ip":"10.152.206.152","up":1500,"down":8500,"active_conns":2}]}`
	s.SetDeviceHooks(
		func() string { return statsJSON },
		func(ip string) int { return 1 },
		func(ip string) {},
		func(ip string) {},
		func(ip string) bool { return false },
	)

	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	w := httptest.NewRecorder()
	s.handleDevices(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("handleDevices status = %d", w.Code)
	}

	var resp struct {
		Devices []TetheredDevice `json:"devices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(resp.Devices))
	}
	dev := resp.Devices[0]
	if dev.IP != "10.152.206.152" || dev.MAC != "d8:a4:91:21:a3:c7" {
		t.Errorf("unexpected IP or MAC: %+v", dev)
	}
	if dev.UpBytes != 1500 || dev.DownBytes != 8500 || dev.ActiveConns != 2 {
		t.Errorf("unexpected traffic: %+v", dev)
	}
	hasIPv6 := false
	for _, extra := range dev.ExtraIPs {
		if extra == "2001:db8:9877:0:6dbe:cdc5:e837:fd12" {
			hasIPv6 = true
			break
		}
	}
	if !hasIPv6 {
		t.Errorf("expected ExtraIPs to contain IPv6 address, got: %v", dev.ExtraIPs)
	}

	// 模拟连接断开/空闲, 快照中无连接或流量跳变为 0 (短连接淘汰)
	statsJSON = `{"client_traffic":[{"ip":"10.152.206.152","up":0,"down":0,"active_conns":0}]}`
	w2 := httptest.NewRecorder()
	s.handleDevices(w2, req)
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(resp.Devices))
	}
	devAfter := resp.Devices[0]
	if devAfter.UpBytes != 1500 || devAfter.DownBytes != 8500 {
		t.Errorf("expected cumulative traffic not to reset, got up=%d down=%d", devAfter.UpBytes, devAfter.DownBytes)
	}
	if devAfter.ActiveConns != 0 {
		t.Errorf("expected activeConns=0, got %d", devAfter.ActiveConns)
	}
}

func TestAdmin_Devices_AuthoritativeBridgeTrafficAndRates(t *testing.T) {
	s := newTestServer(t)
	bridgeJSON := `[
		{
			"ip": "10.152.206.152",
			"mac": "d8:a4:91:21:a3:c7",
			"hostname": "JER-AN20",
			"type": 0,
			"is_random_mac": false,
			"up_bytes": 612966,
			"down_bytes": 3879731,
			"up_bps": 1536,
			"down_bps": 63078,
			"active_conns": 13,
			"is_blocked": false,
			"extra_ips": [
				"2001:db8:9877:0:c538:a56a:9a5d:f831",
				"fe80::1785:5425:3d14:4b4"
			]
		}
	]`
	s.SetTetheringBridge(&mockTetheringBridge{clients: bridgeJSON})

	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	w := httptest.NewRecorder()
	s.handleDevices(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("handleDevices status = %d", w.Code)
	}

	var resp struct {
		Devices []TetheredDevice `json:"devices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(resp.Devices))
	}
	dev := resp.Devices[0]
	if dev.IP != "10.152.206.152" || dev.MAC != "d8:a4:91:21:a3:c7" || dev.Hostname != "JER-AN20" {
		t.Errorf("unexpected device identification: %+v", dev)
	}
	if dev.UpBytes != 612966 || dev.DownBytes != 3879731 {
		t.Errorf("unexpected traffic: up=%d down=%d", dev.UpBytes, dev.DownBytes)
	}
	if dev.UpBps != 1536 || dev.DownBps != 63078 {
		t.Errorf("unexpected bps: upBps=%d downBps=%d", dev.UpBps, dev.DownBps)
	}
	if dev.ActiveConns != 13 {
		t.Errorf("unexpected active conns: %d", dev.ActiveConns)
	}
	if len(dev.ExtraIPs) != 2 || dev.ExtraIPs[0] != "2001:db8:9877:0:c538:a56a:9a5d:f831" {
		t.Errorf("unexpected extra IPs: %v", dev.ExtraIPs)
	}
}

func TestAdmin_Devices_ConnsDetail(t *testing.T) {
	s := newTestServer(t)

	bridgeJSON := `[
		{
			"ip": "192.168.43.102",
			"mac": "11:22:33:44:55:66",
			"hostname": "test-device"
		}
	]`
	s.SetTetheringBridge(&mockTetheringBridge{clients: bridgeJSON})

	// 测试从 statsJSON 收集活跃连接明细并关联到设备
	statsJSON := `{
		"apps": [
			{
				"uid": 1000,
				"conns": [
					{"proto": 6, "host": "example.com", "port": 443, "src_ip": "192.168.43.102", "up": 1024, "down": 2048},
					{"proto": 17, "host": "8.8.8.8", "port": 53, "src_ip": "192.168.43.102", "up": 128, "down": 256}
				]
			}
		],
		"client_traffic": [
			{"ip": "192.168.43.102", "up": 1152, "down": 2304, "active_conns": 2}
		]
	}`

	s.SetDeviceHooks(
		func() string { return statsJSON },
		func(ip string) int { return 1 },
		func(ip string) {},
		func(ip string) {},
		func(ip string) bool { return false },
	)

	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	w := httptest.NewRecorder()
	s.handleDevices(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("handleDevices status = %d", w.Code)
	}

	var resp struct {
		Devices []TetheredDevice `json:"devices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(resp.Devices))
	}
	dev := resp.Devices[0]
	if len(dev.Conns) != 2 {
		t.Fatalf("expected 2 active connections, got %d", len(dev.Conns))
	}
	if dev.Conns[0].Host != "example.com" || dev.Conns[0].Proto != 6 || dev.Conns[0].Port != 443 {
		t.Errorf("unexpected first conn: %+v", dev.Conns[0])
	}
	if dev.Conns[1].Host != "8.8.8.8" || dev.Conns[1].Proto != 17 || dev.Conns[1].Port != 53 {
		t.Errorf("unexpected second conn: %+v", dev.Conns[1])
	}
}

func TestDevices_VirtualGatewayProtection(t *testing.T) {
	s := newTestServer(t)
	startServer(t, s)

	// Disconnecting virtual gateway 192.0.2.2 must be rejected with 403 Forbidden
	reqDisc := httptest.NewRequest(http.MethodPost, "/api/devices/disconnect?ip=192.0.2.2", nil)
	wDisc := httptest.NewRecorder()
	s.handleDevicesDisconnect(wDisc, reqDisc)
	if wDisc.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disconnecting 192.0.2.2, got %d", wDisc.Code)
	}

	// Blocking virtual gateway 192.0.2.2 must be rejected with 403 Forbidden
	reqBlock := httptest.NewRequest(http.MethodPost, "/api/devices/block?ip=192.0.2.2", nil)
	wBlock := httptest.NewRecorder()
	s.handleDevicesBlock(wBlock, reqBlock)
	if wBlock.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for blocking 192.0.2.2, got %d", wBlock.Code)
	}

	// Devices list must exclude 192.0.2.2 / 热点共享流量池
	bridgeJSON := `[
		{"ip": "192.168.43.102", "mac": "11:22:33:44:55:66", "hostname": "real-client"},
		{"ip": "192.0.2.2", "mac": "", "hostname": "热点共享流量池"}
	]`
	s.SetTetheringBridge(&mockTetheringBridge{clients: bridgeJSON})

	reqDevs := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	wDevs := httptest.NewRecorder()
	s.handleDevices(wDevs, reqDevs)
	if wDevs.Code != http.StatusOK {
		t.Fatalf("handleDevices status = %d", wDevs.Code)
	}

	var resp struct {
		Devices []TetheredDevice `json:"devices"`
	}
	if err := json.Unmarshal(wDevs.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	for _, d := range resp.Devices {
		if d.IP == "192.0.2.2" || d.Hostname == "热点共享流量池" {
			t.Fatalf("expected virtual gateway 192.0.2.2 to be excluded from devices, got: %+v", d)
		}
	}
}



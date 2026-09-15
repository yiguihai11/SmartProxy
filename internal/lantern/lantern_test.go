package lantern

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestHeaders(t *testing.T) {
	h := buildHeaders("test-dev-id", 12345, "test-token")
	if h.Get("X-Lantern-Device-Id") != "test-dev-id" {
		t.Errorf("expected device id, got %s", h.Get("X-Lantern-Device-Id"))
	}
	if h.Get("X-Lantern-User-Id") != "12345" {
		t.Errorf("expected user id 12345, got %s", h.Get("X-Lantern-User-Id"))
	}
	if h.Get("X-Lantern-Pro-Token") != "test-token" {
		t.Errorf("expected token, got %s", h.Get("X-Lantern-Pro-Token"))
	}
	if h.Get("X-Lantern-App") != "lantern" {
		t.Errorf("expected app lantern, got %s", h.Get("X-Lantern-App"))
	}
	if len(h.Get("X-Lantern-Rand")) == 0 {
		t.Errorf("expected non-empty rand")
	}
}

func TestDatacapParsing_JSON(t *testing.T) {
	rawJSON := []byte(`{
		"enabled": true,
		"usage": {
			"bytesAllotted": "2147483648",
			"bytesUsed": "104857600",
			"allotmentStartTime": "2026-09-13T00:00:00Z",
			"allotmentEndTime": "2026-09-14T00:00:00Z"
		}
	}`)

	res, err := parseDatacap(rawJSON, 1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.QuotaOK {
		t.Errorf("expected quota ok")
	}
	if res.Allot != 2147483648 {
		t.Errorf("expected allot 2147483648, got %d", res.Allot)
	}
	if res.Used != 104857600 {
		t.Errorf("expected used 104857600, got %d", res.Used)
	}
	if res.Remain != 2042626048 {
		t.Errorf("expected remain 2042626048, got %d", res.Remain)
	}
	if res.ResetUnix <= 0 {
		t.Errorf("expected parsed reset unix, got %d", res.ResetUnix)
	}
}

func TestDatacapParsing_BinaryFallback(t *testing.T) {
	// Simulate binary payload containing numbers
	binaryPayload := []byte("\x08\x01\x12\x1a\n\x0a2147483648\x12\x071048576")
	res, err := parseDatacap(binaryPayload, 1024*1024)
	if err != nil {
		t.Fatalf("unexpected error on binary fallback: %v", err)
	}
	if !res.QuotaOK {
		t.Errorf("expected quota ok on binary fallback")
	}
	if res.Allot != 2147483648 {
		t.Errorf("expected allot 2147483648, got %d", res.Allot)
	}
	if res.Used != 1048576 {
		t.Errorf("expected used 1048576, got %d", res.Used)
	}
}

func TestFilterOutbounds(t *testing.T) {
	raws := []json.RawMessage{
		json.RawMessage(`{"type":"direct","tag":"direct"}`),
		json.RawMessage(`{"type":"dns","tag":"dns-out"}`),
		json.RawMessage(`{"type":"water","tag":"water-node"}`),
		json.RawMessage(`{"type":"reflex","tag":"reflex-node"}`),
		json.RawMessage(`{"type":"shadowsocks","tag":"ss-node","server":"1.2.3.4","server_port":8388}`),
		json.RawMessage(`{"type":"hysteria2","tag":"hy2-node","server":"1.2.3.4","server_port":443}`),
		json.RawMessage(`{"type":"vless","tag":"vless-node","server":"1.2.3.4","server_port":443}`),
	}

	filtered := filterOutbounds(raws)
	if len(filtered) != 3 {
		t.Fatalf("expected exactly 3 filtered standard nodes, got %d", len(filtered))
	}

	var tags []string
	for _, raw := range filtered {
		var meta struct {
			Tag string `json:"tag"`
		}
		_ = json.Unmarshal(raw, &meta)
		tags = append(tags, meta.Tag)
	}

	expected := []string{"ss-node", "hy2-node", "vless-node"}
	for i, exp := range expected {
		if tags[i] != exp {
			t.Errorf("expected tag %s, got %s", exp, tags[i])
		}
	}
}

func TestAccountManager_Max5Accounts(t *testing.T) {
	dir := t.TempDir()
	am, err := NewAccountManager(dir, "accounts.json", 5, 1024*1024)
	if err != nil {
		t.Fatalf("failed to create AccountManager: %v", err)
	}

	// Add 5 accounts
	for i := 1; i <= 5; i++ {
		if !am.CanRegister() {
			t.Fatalf("expected CanRegister=true at account %d", i)
		}
		acc := Account{
			DeviceID:       filepath.Join("dev", string(rune('0'+i))),
			UserID:         int64(1000 + i),
			ProToken:       "tok",
			Allot:          2000,
			Used:           int64(i * 100),
			Remain:         int64(2000 - i*100),
			QuotaOK:        true,
			ExhaustedUntil: 0,
		}
		if err := am.AddAccount(acc); err != nil {
			t.Fatalf("failed to add account %d: %v", i, err)
		}
	}

	// 6th account must be rejected
	if am.CanRegister() {
		t.Errorf("expected CanRegister=false after 5 accounts")
	}
	err6 := am.AddAccount(Account{DeviceID: "dev6"})
	if err6 != ErrMaxAccountsReached {
		t.Errorf("expected ErrMaxAccountsReached, got %v", err6)
	}

	// Best available account should be dev1 (highest remain: 1900)
	best, ok := am.PickAvailable()
	if !ok || best.DeviceID != "dev/1" {
		t.Errorf("expected dev/1 with highest remain, got %+v", best)
	}

	// Verify persistence
	amReloaded, err := NewAccountManager(dir, "accounts.json", 5, 1024*1024)
	if err != nil {
		t.Fatalf("failed to reload AccountManager: %v", err)
	}
	if len(amReloaded.List()) != 5 {
		t.Errorf("expected 5 persisted accounts, got %d", len(amReloaded.List()))
	}
}

func TestBuildCompleteSingBoxConfig(t *testing.T) {
	nodes := []json.RawMessage{
		json.RawMessage(`{"type":"shadowsocks","tag":"node-ss","server":"1.2.3.4","server_port":8388}`),
		json.RawMessage(`{"type":"hysteria2","tag":"node-hy2","server":"1.2.3.4","server_port":443}`),
	}

	cfgBytes, err := BuildCompleteSingBoxConfig(nodes, 2080)
	if err != nil {
		t.Fatalf("failed to build sing-box config: %v", err)
	}

	var parsed SingBoxCompleteConfig
	if err := json.Unmarshal(cfgBytes, &parsed); err != nil {
		t.Fatalf("generated invalid json: %v", err)
	}

	if len(parsed.Inbounds) != 1 || parsed.Inbounds[0].ListenPort != 2080 {
		t.Errorf("expected inbound socks port 2080, got %+v", parsed.Inbounds)
	}
	if parsed.Route.Final != "proxy" {
		t.Errorf("expected final route proxy, got %s", parsed.Route.Final)
	}
}

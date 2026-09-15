package singbox

import (
	"encoding/json"
	"testing"
)

func TestParseVLESS_Reality(t *testing.T) {
	link := "vless://bf6dfd00-4b53-41bb-98f5-46f9e612803c@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com&fp=chrome&pbk=Z1_wYx77w4Oq_tK5x_tG6t_jF3k_gL2a_fE1d_cC0b_a&sid=6ba7b810&spx=%2F#HongKong-Reality"
	out, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	if out.Tag != "HongKong-Reality" {
		t.Errorf("expected tag HongKong-Reality, got %s", out.Tag)
	}
	if out.Type != "vless" {
		t.Errorf("expected type vless, got %s", out.Type)
	}
	if out.Server != "example.com" {
		t.Errorf("expected server example.com, got %s", out.Server)
	}
	if out.Port != 443 {
		t.Errorf("expected port 443, got %d", out.Port)
	}

	var m map[string]any
	if err := json.Unmarshal(out.RawJSON, &m); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}
	tls, ok := m["tls"].(map[string]any)
	if !ok || tls["enabled"] != true {
		t.Fatalf("expected tls.enabled=true")
	}
	reality, ok := tls["reality"].(map[string]any)
	if !ok || reality["enabled"] != true {
		t.Fatalf("expected reality.enabled=true")
	}
	if reality["public_key"] != "Z1_wYx77w4Oq_tK5x_tG6t_jF3k_gL2a_fE1d_cC0b_a" {
		t.Errorf("unexpected public_key: %v", reality["public_key"])
	}
}

func TestParseHysteria2(t *testing.T) {
	link := "hysteria2://mysecretpass@hy2.example.com:8443?sni=hy2.example.com&insecure=1&mport=20000-30000#Fast-Hy2"
	out, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	if out.Tag != "Fast-Hy2" {
		t.Errorf("expected tag Fast-Hy2, got %s", out.Tag)
	}
	if out.Type != "hysteria2" {
		t.Errorf("expected type hysteria2, got %s", out.Type)
	}
	if out.Server != "hy2.example.com" {
		t.Errorf("expected server hy2.example.com, got %s", out.Server)
	}
	if out.Port != 8443 {
		t.Errorf("expected port 8443, got %d", out.Port)
	}

	var m map[string]any
	if err := json.Unmarshal(out.RawJSON, &m); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}
	if m["password"] != "mysecretpass" {
		t.Errorf("expected password mysecretpass, got %v", m["password"])
	}
	if m["server_ports"] != "20000-30000" {
		t.Errorf("expected server_ports 20000-30000, got %v", m["server_ports"])
	}
}

func TestParseTrojan(t *testing.T) {
	link := "trojan://trojanpass@trojan.example.com:443?sni=trojan.example.com&alpn=h2,http/1.1#Trojan-Node"
	out, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	if out.Tag != "Trojan-Node" {
		t.Errorf("expected tag Trojan-Node, got %s", out.Tag)
	}
	if out.Type != "trojan" {
		t.Errorf("expected type trojan, got %s", out.Type)
	}

	var m map[string]any
	if err := json.Unmarshal(out.RawJSON, &m); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}
	if m["password"] != "trojanpass" {
		t.Errorf("expected password trojanpass, got %v", m["password"])
	}
}

func TestParseTUIC(t *testing.T) {
	link := "tuic://myuuid:mypassword@tuic.example.com:8443?congestion_control=bbr&sni=tuic.example.com#TUIC-Node"
	out, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	if out.Tag != "TUIC-Node" {
		t.Errorf("expected tag TUIC-Node, got %s", out.Tag)
	}
	if out.Type != "tuic" {
		t.Errorf("expected type tuic, got %s", out.Type)
	}
}

func TestParseVMess(t *testing.T) {
	// {"v":"2","ps":"VMess-Node","add":"vmess.example.com","port":443,"id":"12345678-1234-1234-1234-123456789abc","aid":0,"net":"ws","type":"none","host":"vmess.example.com","path":"/ws","tls":"tls"}
	b64 := "eyJ2IjoiMiIsInBzIjoiVk1lc3MtTm9kZSIsImFkZCI6InZtZXNzLmV4YW1wbGUuY29tIiwicG9ydCI6NDQzLCJpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OWFiYyIsImFpZCI6MCwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJ2bWVzcy5leGFtcGxlLmNvbSIsInBhdGgiOiIvd3MiLCJ0bHMiOiJ0bHMifQ=="
	link := "vmess://" + b64
	out, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	if out.Tag != "VMess-Node" {
		t.Errorf("expected tag VMess-Node, got %s", out.Tag)
	}
	if out.Type != "vmess" {
		t.Errorf("expected type vmess, got %s", out.Type)
	}
	if out.Server != "vmess.example.com" {
		t.Errorf("expected server vmess.example.com, got %s", out.Server)
	}
	if out.Port != 443 {
		t.Errorf("expected port 443, got %d", out.Port)
	}
}

func TestParseRawJSON(t *testing.T) {
	raw := `{
		"type": "shadowsocks",
		"tag": "custom-ss",
		"server": "1.2.3.4",
		"server_port": 8388,
		"method": "aes-128-gcm",
		"password": "secret"
	}`
	out, err := ParseLink(raw)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	if out.Tag != "custom-ss" {
		t.Errorf("expected tag custom-ss, got %s", out.Tag)
	}
	if out.Type != "shadowsocks" {
		t.Errorf("expected type shadowsocks, got %s", out.Type)
	}
	if out.Server != "1.2.3.4" {
		t.Errorf("expected server 1.2.3.4, got %s", out.Server)
	}
	if out.Port != 8388 {
		t.Errorf("expected port 8388, got %d", out.Port)
	}
}

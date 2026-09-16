package subscription

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func TestParseSubscriptionUserInfo(t *testing.T) {
	header := "upload=1024; download=204800; total=107374182400; expire=1735689600"
	u := ParseSubscriptionUserInfo(header)
	if u == nil {
		t.Fatalf("expected non-nil userinfo")
	}
	if u.Upload != 1024 {
		t.Errorf("expected upload=1024, got %d", u.Upload)
	}
	if u.Download != 204800 {
		t.Errorf("expected download=204800, got %d", u.Download)
	}
	if u.Total != 107374182400 {
		t.Errorf("expected total=107374182400, got %d", u.Total)
	}
	if u.Expire != 1735689600 {
		t.Errorf("expected expire=1735689600, got %d", u.Expire)
	}
}

func TestParseSIP008(t *testing.T) {
	sip008JSON := `{
		"version": 1,
		"servers": [
			{
				"id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
				"remarks": "Hong Kong SS",
				"server": "1.2.3.4",
				"server_port": 8388,
				"password": "secretpassword",
				"method": "chacha20-ietf-poly1305"
			},
			{
				"id": "7842c068-c667-41f2-8f7d-04feece3cb67",
				"remarks": "US Obfs SS",
				"server": "5.6.7.8",
				"server_port": 8443,
				"password": "password2",
				"method": "aes-128-gcm",
				"plugin": "obfs-local",
				"plugin_opts": "obfs=http;obfs-host=example.com"
			}
		],
		"bytes_used": 5368709120,
		"bytes_remaining": 10737418240
	}`

	entries, uinfo, err := ParseContent("auto", nil, []byte(sip008JSON))
	if err != nil {
		t.Fatalf("failed to parse SIP008: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Alias != "Hong Kong SS" {
		t.Errorf("unexpected alias[0]: %s", entries[0].Alias)
	}
	if entries[1].Alias != "US Obfs SS" {
		t.Errorf("unexpected alias[1]: %s", entries[1].Alias)
	}
	if uinfo == nil {
		t.Fatalf("expected uinfo from SIP008")
	}
	if uinfo.Download != 5368709120 {
		t.Errorf("expected download=%d, got %d", 5368709120, uinfo.Download)
	}
	if uinfo.Total != 5368709120+10737418240 {
		t.Errorf("expected total=%d, got %d", 5368709120+10737418240, uinfo.Total)
	}
}

func TestParseBase64Lines(t *testing.T) {
	rawLinks := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@1.2.3.4:8388#Hong%20Kong\n" +
		"vless://uuid1@5.6.7.8:443?security=tls&sni=example.com#US-Vless\n" +
		"hysteria2://pass1@9.10.11.12:443?sni=example2.com#SG-Hy2\n"

	b64 := base64.StdEncoding.EncodeToString([]byte(rawLinks))
	headers := http.Header{}
	headers.Set("Subscription-Userinfo", "upload=100; download=200; total=5000; expire=1800000000")

	entries, uinfo, err := ParseContent("auto", headers, []byte(b64))
	if err != nil {
		t.Fatalf("failed to parse Base64: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Alias != "Hong Kong" {
		t.Errorf("expected alias[0]='Hong Kong', got %q", entries[0].Alias)
	}
	if entries[1].Alias != "US-Vless" {
		t.Errorf("expected alias[1]='US-Vless', got %q", entries[1].Alias)
	}
	if entries[2].Alias != "SG-Hy2" {
		t.Errorf("expected alias[2]='SG-Hy2', got %q", entries[2].Alias)
	}
	if uinfo == nil || uinfo.Total != 5000 {
		t.Errorf("expected uinfo.Total=5000, got %+v", uinfo)
	}
}

func TestParsePlaintextLines(t *testing.T) {
	rawLinks := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@1.2.3.4:8388#Hong Kong\n" +
		"# comment line\n" +
		"socks5://127.0.0.1:1080#Local-Socks5\n"

	entries, _, err := ParseContent("auto", nil, []byte(rawLinks))
	if err != nil {
		t.Fatalf("failed to parse plaintext lines: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Alias != "Hong Kong" {
		t.Errorf("expected alias[0]='Hong Kong', got %q", entries[0].Alias)
	}
	if entries[1].Alias != "Local-Socks5" {
		t.Errorf("expected alias[1]='Local-Socks5', got %q", entries[1].Alias)
	}
}

func TestParseSingBox(t *testing.T) {
	singboxJSON := `{
		"outbounds": [
			{
				"type": "shadowsocks",
				"tag": "SS-Out",
				"server": "1.2.3.4",
				"server_port": 8388,
				"method": "2022-blake3-aes-128-gcm",
				"password": "examplepassword=="
			},
			{
				"type": "direct",
				"tag": "direct"
			},
			{
				"type": "vless",
				"tag": "VLESS-Out",
				"server": "5.6.7.8",
				"server_port": 443,
				"uuid": "00000000-0000-0000-0000-000000000000"
			}
		]
	}`

	entries, _, err := ParseContent("sing-box", nil, []byte(singboxJSON))
	if err != nil {
		t.Fatalf("failed to parse sing-box outbounds: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 proxy entries (filtered direct), got %d", len(entries))
	}
	if entries[0].Alias != "SS-Out" {
		t.Errorf("expected tag SS-Out, got %s", entries[0].Alias)
	}
	if entries[1].Alias != "VLESS-Out" {
		t.Errorf("expected tag VLESS-Out, got %s", entries[1].Alias)
	}
}

func TestParseClashYAML(t *testing.T) {
	clashYAML := `
proxies:
  - name: "Clash-SS"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: pass
  - name: "Clash-Trojan"
    type: trojan
    server: 5.6.7.8
    port: 443
    password: pass
    sni: example.com
`
	entries, _, err := ParseContent("auto", nil, []byte(clashYAML))
	if err != nil {
		t.Fatalf("failed to parse Clash YAML: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Alias != "Clash-SS" {
		t.Errorf("expected Clash-SS, got %s", entries[0].Alias)
	}
	if entries[1].Alias != "Clash-Trojan" {
		t.Errorf("expected Clash-Trojan, got %s", entries[1].Alias)
	}
}

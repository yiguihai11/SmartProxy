package upstream

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Sample link from the user: sample ss://...?plugin=v2ray-plugin%3Bhost%3Dwww.10010.com
func TestParseV2rayPluginSample(t *testing.T) {
	cfg, err := parseV2rayPluginOptions("v2ray-plugin;host=www.10010.com")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if cfg.id != "v2ray-plugin" {
		t.Errorf("id = %q, want v2ray-plugin", cfg.id)
	}
	if cfg.mode != "websocket" {
		t.Errorf("mode = %q, want websocket (default)", cfg.mode)
	}
	if cfg.tls {
		t.Error("tls = true, want false (no bare tls key)")
	}
	if cfg.host != "www.10010.com" {
		t.Errorf("host = %q, want www.10010.com", cfg.host)
	}
	if cfg.path != "/" {
		t.Errorf("path = %q, want / (default)", cfg.path)
	}
	if cfg.mux != 1 {
		t.Errorf("mux = %d, want 1 (default)", cfg.mux)
	}
	if cfg.serviceName != "GunService" {
		t.Errorf("serviceName = %q, want GunService (default)", cfg.serviceName)
	}
	if cfg.certRaw != "" {
		t.Errorf("certRaw = %q, want empty", cfg.certRaw)
	}
}

// Mapping of the Android version's 5 modes to protocol parameters (consistent with ConfigFragment.kt).
func TestParseV2rayPluginAllAndroidModes(t *testing.T) {
	cases := []struct {
		opts string
		mode string
		tls  bool
	}{
		{"v2ray-plugin;mode=websocket;host=cdn.example.com", "websocket", false},    // websocket-http
		{"v2ray-plugin;mode=websocket;tls;host=cdn.example.com", "websocket", true}, // websocket-tls
		{"v2ray-plugin;mode=quic;host=cdn.example.com", "quic", false},              // quic-tls (quic forces tls)
		{"v2ray-plugin;mode=grpc;host=cdn.example.com", "grpc", false},              // grpc
		{"v2ray-plugin;mode=grpc;tls;host=cdn.example.com", "grpc", true},           // grpc-tls
	}
	for _, c := range cases {
		cfg, err := parseV2rayPluginOptions(c.opts)
		if err != nil {
			t.Fatalf("parse %q failed: %v", c.opts, err)
		}
		if cfg.mode != c.mode {
			t.Errorf("%q: mode = %q, want %q", c.opts, cfg.mode, c.mode)
		}
		if cfg.tls != c.tls {
			t.Errorf("%q: tls = %v, want %v", c.opts, cfg.tls, c.tls)
		}
	}
}

func TestParseV2rayPluginExtras(t *testing.T) {
	// xray-plugin is supported too
	cfg, err := parseV2rayPluginOptions("xray-plugin;mode=websocket")
	if err != nil {
		t.Fatalf("xray-plugin parse failed: %v", err)
	}
	if cfg.id != "xray-plugin" {
		t.Errorf("id = %q, want xray-plugin", cfg.id)
	}

	// mux=0 disables multiplexing
	cfg, err = parseV2rayPluginOptions("v2ray-plugin;mode=websocket;mux=0")
	if err != nil {
		t.Fatalf("mux=0 parse failed: %v", err)
	}
	if cfg.mux != 0 {
		t.Errorf("mux = %d, want 0", cfg.mux)
	}

	// non-numeric mux -> keep default 1 (same fallback as v2ray-plugin's Atoi)
	cfg, err = parseV2rayPluginOptions("v2ray-plugin;mode=websocket;mux=abc")
	if err != nil {
		t.Fatalf("mux=abc parse failed: %v", err)
	}
	if cfg.mux != 1 {
		t.Errorf("mux = %d, want 1", cfg.mux)
	}

	// grpc serviceName
	cfg, err = parseV2rayPluginOptions("v2ray-plugin;mode=grpc;serviceName=MyService")
	if err != nil {
		t.Fatalf("grpc parse failed: %v", err)
	}
	if cfg.serviceName != "MyService" {
		t.Errorf("serviceName = %q, want MyService", cfg.serviceName)
	}

	// unknown keys are ignored
	if _, err = parseV2rayPluginOptions("v2ray-plugin;fast-open;mptcp;__android_vpn;mode=grpc"); err != nil {
		t.Errorf("unknown keys should be ignored, got %v", err)
	}
}

func TestParseV2rayPluginErrors(t *testing.T) {
	for _, opts := range []string{
		"other-plugin;mode=websocket",     // not a v2ray/xray binary
		"v2ray-plugin;mode=trojan",        // unsupported mode
		"v2ray-plugin;mode=websocket;tls", // valid, must not error (placeholder, guard)
	} {
		_, err := parseV2rayPluginOptions(opts)
		if opts == "v2ray-plugin;mode=websocket;tls" {
			if err != nil {
				t.Errorf("valid opts %q unexpectedly failed: %v", opts, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("opts %q: expected error", opts)
		}
	}
}

func TestNormalizeV2rayCertRaw(t *testing.T) {
	const pemBody = "MIIBEXAMPLE=="
	full := "-----BEGIN CERTIFICATE-----\n" + pemBody + "\n-----END CERTIFICATE-----"

	// already a full PEM: returned as-is
	if got := normalizeV2rayCertRaw(full); got != full {
		t.Errorf("full PEM passthrough failed: %q", got)
	}
	// bare body: wrap with BEGIN/END lines (consistent with v2ray-plugin readCertificate)
	if got := normalizeV2rayCertRaw(pemBody); got != full {
		t.Errorf("bare body wrap failed: %q", got)
	}
	// base64-encoded full PEM: decode and return
	enc := base64.StdEncoding.EncodeToString([]byte(full))
	if got := normalizeV2rayCertRaw(enc); got != full {
		t.Errorf("base64 PEM decode failed: %q", got)
	}
	// URL-safe base64 also supported
	enc = base64.RawURLEncoding.EncodeToString([]byte(full))
	if got := normalizeV2rayCertRaw(enc); got != full {
		t.Errorf("url-safe base64 PEM decode failed: %q", got)
	}
	// empty string
	if got := normalizeV2rayCertRaw(""); got != "" {
		t.Errorf("empty should stay empty, got %q", got)
	}
}

// ssPluginKind plugin type dispatch: obfs / v2ray / unknown.
func TestSSPluginKind(t *testing.T) {
	cases := []struct {
		plugin string
		want   string
	}{
		{"", ""},
		{"obfs-local;obfs=http", "obfs-local"},
		{"v2ray-plugin;mode=websocket", "v2ray-plugin"},
		{"xray-plugin;mode=grpc", "xray-plugin"},
	}
	for _, c := range cases {
		p, err := NewProxy("ss://" + b64url("aes-128-gcm:secret") + "@127.0.0.1:8388")
		if err != nil {
			t.Fatalf("NewProxy failed: %v", err)
		}
		p.Plugin = c.plugin
		kind, err := p.ssPluginKind()
		if err != nil {
			t.Fatalf("plugin %q: unexpected error: %v", c.plugin, err)
		}
		if kind != c.want {
			t.Errorf("plugin %q: kind = %q, want %q", c.plugin, kind, c.want)
		}
	}

	p, _ := NewProxy("ss://" + b64url("aes-128-gcm:secret") + "@127.0.0.1:8388")
	p.Plugin = "no-such-plugin;x=y"
	if _, err := p.ssPluginKind(); err == nil || !strings.Contains(err.Error(), "unsupported SIP003 plugin") {
		t.Errorf("expected unsupported plugin error, got %v", err)
	}
}

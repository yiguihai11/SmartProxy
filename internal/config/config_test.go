package config

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.LogLevel != "INFO" {
		t.Errorf("expected LogLevel=INFO, got %s", cfg.LogLevel)
	}
	if cfg.Listen.Host != "::" {
		t.Errorf("expected Listen.Host=::, got %s", cfg.Listen.Host)
	}
	if cfg.Listen.Port != 1080 {
		t.Errorf("expected Listen.Port=1080, got %d", cfg.Listen.Port)
	}
	if cfg.Upstream.Default != "failover" {
		t.Errorf("expected Upstream.Default=failover, got %s", cfg.Upstream.Default)
	}
	if cfg.SmartProxy.Timeout != 3 {
		t.Errorf("expected SmartProxy.Timeout=3, got %d", cfg.SmartProxy.Timeout)
	}
	if len(cfg.SmartProxy.Ports) != 2 {
		t.Errorf("expected 2 smart ports, got %d", len(cfg.SmartProxy.Ports))
	}
	if cfg.DNS.QueryTimeout != 3 {
		t.Errorf("expected DNS.QueryTimeout=3, got %d", cfg.DNS.QueryTimeout)
	}
	if cfg.Upstream.HealthCheck.UDPProbeDNS != "1.1.1.1:53" {
		t.Errorf("expected UDPProbeDNS=1.1.1.1:53, got %q", cfg.Upstream.HealthCheck.UDPProbeDNS)
	}
	if cfg.Upstream.HealthCheck.UDPProbeDomain != "dns.google" {
		t.Errorf("expected UDPProbeDomain=dns.google, got %q", cfg.Upstream.HealthCheck.UDPProbeDomain)
	}
	if !cfg.Listen.AdminHTTPS {
		t.Error("expected Listen.AdminHTTPS=true by default")
	}
	if len(cfg.Listen.AdminCertSANs) != 0 {
		t.Errorf("expected no default AdminCertSANs, got %v", cfg.Listen.AdminCertSANs)
	}
}

func TestValidate_AdminCertKeyPair(t *testing.T) {
	cfg := DefaultConfig()
	// both unset: valid (auto self-signed)
	cfg.Listen.AdminCertFile, cfg.Listen.AdminKeyFile = "", ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("both empty should validate, got: %v", err)
	}
	// cert only: invalid
	cfg.Listen.AdminCertFile = "/tmp/x.crt"
	if err := cfg.Validate(); err == nil {
		t.Fatal("cert without key should fail validation")
	}
	// key only: invalid
	cfg.Listen.AdminCertFile, cfg.Listen.AdminKeyFile = "", "/tmp/x.key"
	if err := cfg.Validate(); err == nil {
		t.Fatal("key without cert should fail validation")
	}
	// both set: valid
	cfg.Listen.AdminCertFile, cfg.Listen.AdminKeyFile = "/tmp/x.crt", "/tmp/x.key"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("both set should validate, got: %v", err)
	}
}

func TestValidate_PortZero(t *testing.T) {
	cfg := DefaultConfig()
	// port 0 = socks5 disabled (Android fd-mode default): valid
	cfg.Listen.Port = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("listen.port=0 should validate, got: %v", err)
	}
	// negative: invalid
	cfg.Listen.Port = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("listen.port=-1 should fail validation")
	}
}

func TestLoad_PortZero(t *testing.T) {
	dir := t.TempDir()
	// explicit "port": 0 must survive Load (socks5 disabled)
	p := filepath.Join(dir, "port0.json")
	if err := os.WriteFile(p, []byte(`{"listen":{"port":0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen.Port != 0 {
		t.Fatalf("explicit port=0 must stay 0, got %d", cfg.Listen.Port)
	}
	// absent "port" falls back to DefaultConfig's 1080
	p2 := filepath.Join(dir, "noport.json")
	if err := os.WriteFile(p2, []byte(`{"listen":{"host":"::"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2, err := Load(p2)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Listen.Port != 1080 {
		t.Fatalf("absent port should default to 1080, got %d", cfg2.Listen.Port)
	}
}

func TestValidate_AdminCertSans(t *testing.T) {
	cfg := DefaultConfig()
	// no SANs: valid
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty admin_cert_sans should validate, got: %v", err)
	}
	// valid entries: valid
	cfg.Listen.AdminCertSANs = []string{"192.168.1.1", "panel.example.com"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid admin_cert_sans should validate, got: %v", err)
	}
	// empty entry: invalid
	cfg.Listen.AdminCertSANs = []string{"192.168.1.1", "  "}
	if err := cfg.Validate(); err == nil {
		t.Fatal("empty admin_cert_sans entry should fail validation")
	}
}

func TestLoad_HealthCheckUDPProbe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
	  "upstream": {
	    "health_check": {
	      "enabled": true,
	      "udp_probe_dns": "8.8.8.8:5353",
	      "udp_probe_domain": "example.org"
	    }
	  }
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream.HealthCheck.UDPProbeDNS != "8.8.8.8:5353" {
		t.Errorf("expected udp_probe_dns=8.8.8.8:5353, got %q", cfg.Upstream.HealthCheck.UDPProbeDNS)
	}
	if cfg.Upstream.HealthCheck.UDPProbeDomain != "example.org" {
		t.Errorf("expected udp_probe_domain=example.org, got %q", cfg.Upstream.HealthCheck.UDPProbeDomain)
	}
}

func TestLoad_MinimalConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
  "listen": {
    "port": 9999
  },
  "upstream": {
    "default": "round_robin"
  }
}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen.Port != 9999 {
		t.Errorf("expected port 9999, got %d", cfg.Listen.Port)
	}
	if cfg.Upstream.Default != "round_robin" {
		t.Errorf("expected round_robin, got %s", cfg.Upstream.Default)
	}

	if cfg.Listen.Host != "::" {
		t.Errorf("expected default host ::, got %s", cfg.Listen.Host)
	}
}

func TestLoad_FullConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
  "log_level": "DEBUG",
  "listen": {
    "host": "0.0.0.0",
    "port": 2080,
    "auth": {
      "username": "admin",
      "password": "secret"
    }
  },
  "upstream": {
    "default": "random",
    "proxies": [
      {
        "alias": "proxy1",
        "url": "socks5://user:pass@10.0.0.1:1080"
      },
      {
        "alias": "proxy2",
        "url": "http://10.0.0.2:8080"
      }
    ]
  },
  "routing": {
    "chnroute_file": "/data/chnroute.txt",
    "acl_file": "/data/acl.txt"
  },
  "dns_hijack": {
    "enabled": true,
    "virtual_ip4": "10.255.0.1",
    "target_ip4": "8.8.8.8:53",
    "virtual_ip6": "fd00::1",
    "target_ip6": "[2001:4860:4860::8888]:53"
  },
  "dns": {
    "enabled": true,
    "cache": {
      "size": 5000,
      "ttl": 600
    },
    "foreign": {
      "ipv4": "1.1.1.1:53",
      "ipv6": "[2606:4700:4700::1111]:53"
    },
    "query_timeout": 5,
    "speed_check_mode": "tcp:80,443"
  },
  "smart_proxy": {
    "enabled": false,
    "timeout": 5,
    "ports": [22, 80, 443],
    "blacklist_ttl": 600,
    "udp_idle_timeout": 120
  }
}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.LogLevel != "DEBUG" {
		t.Errorf("LogLevel: got %s, want DEBUG", cfg.LogLevel)
	}
	if cfg.Listen.Host != "0.0.0.0" {
		t.Errorf("Listen.Host: got %s, want 0.0.0.0", cfg.Listen.Host)
	}
	if cfg.Listen.Port != 2080 {
		t.Errorf("Listen.Port: got %d, want 2080", cfg.Listen.Port)
	}
	if cfg.Listen.Auth == nil {
		t.Error("Listen.Auth should not be nil")
	} else {
		if cfg.Listen.Auth.Username != "admin" {
			t.Errorf("Auth.Username: got %s", cfg.Listen.Auth.Username)
		}
		if cfg.Listen.Auth.Password != "secret" {
			t.Errorf("Auth.Password: got %s", cfg.Listen.Auth.Password)
		}
	}
	if cfg.Upstream.Default != "random" {
		t.Errorf("Upstream.Default: got %s", cfg.Upstream.Default)
	}
	if len(cfg.Upstream.Proxies) != 2 {
		t.Errorf("expected 2 proxies, got %d", len(cfg.Upstream.Proxies))
	}
	if cfg.Upstream.Proxies[0].Alias != "proxy1" {
		t.Errorf("Proxies[0].Alias: got %q, want proxy1", cfg.Upstream.Proxies[0].Alias)
	}
	if cfg.Upstream.Proxies[1].Alias != "proxy2" {
		t.Errorf("Proxies[1].Alias: got %q, want proxy2", cfg.Upstream.Proxies[1].Alias)
	}
	if cfg.Routing.ChnrouteFile != "/data/chnroute.txt" {
		t.Errorf("ChnrouteFile: got %s", cfg.Routing.ChnrouteFile)
	}
	if cfg.Routing.ACLFile != "/data/acl.txt" {
		t.Errorf("ACLFile: got %s", cfg.Routing.ACLFile)
	}
	if !cfg.DNS.Enabled {
		t.Error("DNS should be enabled")
	}
	if cfg.DNS.Cache.Size != 5000 {
		t.Errorf("Cache.Size: got %d", cfg.DNS.Cache.Size)
	}
	if cfg.DNS.Cache.TTL != 600 {
		t.Errorf("Cache.TTL: got %d", cfg.DNS.Cache.TTL)
	}
	if cfg.DNS.Foreign.IPv4 != "1.1.1.1:53" {
		t.Errorf("Foreign.IPv4: got %s", cfg.DNS.Foreign.IPv4)
	}
	if cfg.DNS.QueryTimeout != 5 {
		t.Errorf("QueryTimeout: got %d", cfg.DNS.QueryTimeout)
	}
	if cfg.DNS.SpeedCheckMode != "tcp:80,443" {
		t.Errorf("SpeedCheckMode: got %s", cfg.DNS.SpeedCheckMode)
	}
	if cfg.SmartProxy.Enabled {
		t.Error("SmartProxy should be disabled")
	}
	if cfg.SmartProxy.Timeout != 5 {
		t.Errorf("SmartProxy.Timeout: got %d", cfg.SmartProxy.Timeout)
	}
	if len(cfg.SmartProxy.Ports) != 3 {
		t.Errorf("expected 3 smart ports, got %d", len(cfg.SmartProxy.Ports))
	}
	if cfg.SmartProxy.BlacklistTTL != 600 {
		t.Errorf("BlacklistTTL: got %d", cfg.SmartProxy.BlacklistTTL)
	}
}

func TestLoad_ACLFilePriority(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
  "routing": {
    "acl_file": "/data/acl.txt",
    "blocklist_file": "/data/blocklist.txt"
  }
}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Routing.ACLFile != "/data/acl.txt" {
		t.Errorf("acl_file should take priority, got %s", cfg.Routing.ACLFile)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestApplyDefaults_EmptyFields(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	if cfg.LogLevel != "INFO" {
		t.Errorf("LogLevel: got %s", cfg.LogLevel)
	}
	if cfg.Listen.Host != "::" {
		t.Errorf("Listen.Host: got %s", cfg.Listen.Host)
	}
	// Port is intentionally NOT defaulted by applyDefaults (0 = socks5 disabled;
	// the 1080 default comes from DefaultConfig, which Load() always starts from).
	if cfg.Listen.Port != 0 {
		t.Errorf("Listen.Port: got %d, want 0 (applyDefaults must not touch port)", cfg.Listen.Port)
	}
	if cfg.Upstream.Default != "failover" {
		t.Errorf("Upstream.Default: got %s", cfg.Upstream.Default)
	}
	if cfg.Routing.ChnrouteFile != "chnroute.txt" {
		t.Errorf("ChnrouteFile: got %s", cfg.Routing.ChnrouteFile)
	}
	if cfg.Routing.ACLFile != "acl.txt" {
		t.Errorf("ACLFile: got %s", cfg.Routing.ACLFile)
	}
	if cfg.DNS.QueryTimeout != 3 {
		t.Errorf("QueryTimeout: got %d", cfg.DNS.QueryTimeout)
	}
	if len(cfg.SmartProxy.Ports) != 2 {
		t.Errorf("SmartProxy.Ports: got %d", len(cfg.SmartProxy.Ports))
	}
}

func TestValidate_StaticRecords(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.DNS.StaticRecords) != 0 {
		t.Errorf("expected no default static records, got %v", cfg.DNS.StaticRecords)
	}
	// valid entry
	cfg.DNS.StaticRecords = []StaticRecord{{Host: "smartproxy.lan", IP: IPList{"192.168.1.1"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid static record should validate, got: %v", err)
	}
	// empty host
	cfg.DNS.StaticRecords = []StaticRecord{{Host: "  ", IP: IPList{"192.168.1.1"}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("empty host should fail validation")
	}
	// invalid IP
	cfg.DNS.StaticRecords = []StaticRecord{{Host: "smartproxy.lan", IP: IPList{"not-an-ip"}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid IP should fail validation")
	}
	// empty IP list
	cfg.DNS.StaticRecords = []StaticRecord{{Host: "smartproxy.lan", IP: nil}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("empty IP list should fail validation")
	}
}

func TestStaticRecordsMap(t *testing.T) {
	cfg := DNSConf{}
	if m := cfg.StaticRecordsMap(); m != nil {
		t.Errorf("expected nil map for empty records, got %v", m)
	}

	cfg.StaticRecords = []StaticRecord{
		{Host: "SmartProxy.LAN.", IP: IPList{"192.168.1.1"}},
		{Host: "smartproxy.lan", IP: IPList{"fc00::1"}},
		{Host: "  ", IP: IPList{"1.2.3.4"}},       // empty host → skipped
		{Host: "bad.example", IP: IPList{"oops"}}, // invalid IP → skipped
	}
	m := cfg.StaticRecordsMap()
	if len(m) != 1 {
		t.Fatalf("expected 1 host after normalization, got %d", len(m))
	}
	ips := m["smartproxy.lan"]
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs grouped for smartproxy.lan, got %d", len(ips))
	}
	var hasV4, hasV6 bool
	for _, ip := range ips {
		if ip.To4() != nil {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	if !hasV4 || !hasV6 {
		t.Errorf("expected both v4 and v6 grouped, got %v", ips)
	}
}

func TestRemoveStaticRecordIP(t *testing.T) {
	records := []StaticRecord{
		{Host: "smartproxy.lan", IP: IPList{"192.168.1.1", "::1"}},
		{Host: "other.lan", IP: IPList{"10.0.0.1"}},
	}
	// Remove one address of a multi-family record → other family stays.
	out := RemoveStaticRecordIP(records, "SmartProxy.LAN.", net.ParseIP("192.168.1.1"))
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %+v", len(out), out)
	}
	if len(out[0].IP) != 1 || out[0].IP[0] != "::1" {
		t.Fatalf("expected only v6 left, got %v", out[0].IP)
	}
	// Remove the last address → whole record dropped.
	out = RemoveStaticRecordIP(out, "smartproxy.lan", net.ParseIP("::1"))
	if len(out) != 1 || out[0].Host != "other.lan" {
		t.Fatalf("expected empty record dropped, got %+v", out)
	}
	// Removing a non-existent IP is a no-op.
	out = RemoveStaticRecordIP(records, "smartproxy.lan", net.ParseIP("9.9.9.9"))
	if len(out) != 2 || len(out[0].IP) != 2 {
		t.Fatalf("expected no-op, got %+v", out)
	}
	// Input not mutated.
	if len(records[0].IP) != 2 || records[0].IP[0] != "192.168.1.1" {
		t.Fatalf("input mutated: %+v", records[0].IP)
	}
}

func TestRemoveStaticRecord(t *testing.T) {
	records := []StaticRecord{
		{Host: "smartproxy.lan", IP: IPList{"192.168.1.1", "::1"}},
		{Host: "other.lan", IP: IPList{"10.0.0.1"}},
	}
	out := RemoveStaticRecord(records, "SmartProxy.LAN.")
	if len(out) != 1 || out[0].Host != "other.lan" {
		t.Fatalf("expected other.lan only, got %+v", out)
	}
	// Unknown host → unchanged.
	out = RemoveStaticRecord(records, "nope.lan")
	if len(out) != 2 {
		t.Fatalf("expected unchanged, got %+v", out)
	}
	// Input not mutated.
	if len(records) != 2 || records[0].Host != "smartproxy.lan" {
		t.Fatalf("input mutated: %+v", records)
	}
}

func TestReplaceStaticRecord(t *testing.T) {
	records := []StaticRecord{
		{Host: "smartproxy.lan", IP: IPList{"192.168.1.1", "::1"}},
		{Host: "other.lan", IP: IPList{"10.0.0.1"}},
	}
	// In-place: swap the address list wholesale (drops v4, adds a new v4+v6 set).
	out := ReplaceStaticRecord(records, "smartproxy.lan", "smartproxy.lan", []net.IP{net.ParseIP("1.2.3.4")})
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %+v", len(out), out)
	}
	for _, r := range out {
		if r.Host == "smartproxy.lan" {
			if len(r.IP) != 1 || r.IP[0] != "1.2.3.4" {
				t.Fatalf("expected replaced single address, got %+v", r.IP)
			}
		}
	}
	// Rename: old host gone, new host carries the list.
	out = ReplaceStaticRecord(records, "smartproxy.lan", "panel.lan", []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")})
	if len(out) != 2 {
		t.Fatalf("expected 2 records after rename, got %d: %+v", len(out), out)
	}
	var found bool
	for _, r := range out {
		if r.Host == "smartproxy.lan" {
			t.Fatal("old host should be gone")
		}
		if r.Host == "panel.lan" {
			found = true
			if len(r.IP) != 2 || r.IP[0] != "::1" || r.IP[1] != "127.0.0.1" {
				t.Fatalf("renamed record wrong: %+v", r.IP)
			}
		}
	}
	if !found {
		t.Fatal("new host not found")
	}
	// Renaming onto an existing host collapses both into one record (each host
	// keeps exactly one entry after the call).
	out = ReplaceStaticRecord(records, "other.lan", "smartproxy.lan", []net.IP{net.ParseIP("9.9.9.9")})
	if len(out) != 1 {
		t.Fatalf("expected 1 record, got %d: %+v", len(out), out)
	}
	if out[0].Host != "smartproxy.lan" || len(out[0].IP) != 1 || out[0].IP[0] != "9.9.9.9" {
		t.Fatalf("expected collapsed smartproxy.lan=9.9.9.9, got %+v", out[0])
	}
	// Empty IP list removes the record without adding.
	out = ReplaceStaticRecord(records, "smartproxy.lan", "smartproxy.lan", nil)
	if len(out) != 1 || out[0].Host != "other.lan" {
		t.Fatalf("expected record removed, got %+v", out)
	}
	// Input not mutated.
	if len(records) != 2 || len(records[0].IP) != 2 || records[0].IP[0] != "192.168.1.1" {
		t.Fatalf("input mutated: %+v", records)
	}
}

func TestSetStaticRecordIP(t *testing.T) {
	// New host → appended record.
	out := SetStaticRecordIP(nil, "smartproxy.lan", net.ParseIP("127.0.0.1"))
	if len(out) != 1 || out[0].Host != "smartproxy.lan" || len(out[0].IP) != 1 || out[0].IP[0] != "127.0.0.1" {
		t.Fatalf("new host append failed: %+v", out)
	}
	// Existing host, new family added alongside the old one.
	out = SetStaticRecordIP(out, "SmartProxy.LAN.", net.ParseIP("::1"))
	if len(out) != 1 {
		t.Fatalf("expected host merge, got %d records", len(out))
	}
	got := out[0].IP
	if len(got) != 2 || got[0] != "127.0.0.1" || got[1] != "::1" {
		t.Fatalf("expected both families kept, got %v", got)
	}
	// Replacing the v4 address drops only v4, keeps v6.
	out = SetStaticRecordIP(out, "smartproxy.lan", net.ParseIP("192.168.1.1"))
	if len(out[0].IP) != 2 || out[0].IP[0] != "::1" || out[0].IP[1] != "192.168.1.1" {
		t.Fatalf("expected v4 replaced, v6 kept, got %v", out[0].IP)
	}
	// Replacing the v6 address drops only v6, keeps v4.
	out = SetStaticRecordIP(out, "smartproxy.lan", net.ParseIP("fd00::2"))
	if len(out[0].IP) != 2 || out[0].IP[0] != "192.168.1.1" || out[0].IP[1] != "fd00::2" {
		t.Fatalf("expected v6 replaced, v4 kept, got %v", out[0].IP)
	}
	// Input slice is never mutated.
	src := []StaticRecord{{Host: "a.lan", IP: IPList{"1.1.1.1"}}}
	_ = SetStaticRecordIP(src, "a.lan", net.ParseIP("2.2.2.2"))
	if src[0].IP[0] != "1.1.1.1" || len(src[0].IP) != 1 {
		t.Fatalf("input slice was mutated: %+v", src)
	}
}

func TestSetStaticRecordIPs(t *testing.T) {
	// Batch into a fresh host → all addresses kept in order.
	out := SetStaticRecordIPs(nil, "example.com", []net.IP{net.ParseIP("9.9.9.9"), net.ParseIP("8.8.4.4")})
	if len(out) != 1 || len(out[0].IP) != 2 || out[0].IP[0] != "9.9.9.9" || out[0].IP[1] != "8.8.4.4" {
		t.Fatalf("fresh-host batch failed: %+v", out)
	}
	// Batch replaces the same family wholesale but preserves the opposite family.
	out = SetStaticRecordIPs(out, "example.com", []net.IP{net.ParseIP("7.7.7.7")})
	if len(out[0].IP) != 1 || out[0].IP[0] != "7.7.7.7" {
		t.Fatalf("expected v4 replaced wholesale, got %v", out[0].IP)
	}
	out = SetStaticRecordIP(out, "example.com", net.ParseIP("2001:db8::1"))
	out = SetStaticRecordIPs(out, "example.com", []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")})
	if len(out[0].IP) != 3 || out[0].IP[0] != "2001:db8::1" || out[0].IP[1] != "1.1.1.1" || out[0].IP[2] != "2.2.2.2" {
		t.Fatalf("expected v6 kept + both v4 written, got %v", out[0].IP)
	}
	// Empty input is a no-op.
	before := SetStaticRecordIPs(nil, "x.lan", []net.IP{net.ParseIP("1.1.1.1")})
	after := SetStaticRecordIPs(before, "x.lan", nil)
	if len(after) != 1 || after[0].IP[0] != "1.1.1.1" {
		t.Fatalf("empty batch mutated records: %+v", after)
	}
}

// TestStaticRecords_JSONForms verifies the "ip" field accepts both a single
// address string and an array of addresses.
func TestStaticRecords_JSONForms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
	  "dns": {
	    "enabled": true,
	    "static_records": [
	      { "host": "single.lan", "ip": "1.2.3.4" },
	      { "host": "smartproxy.lan", "ip": ["192.168.1.1", "::1"] }
	    ]
	  }
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNS.StaticRecords) != 2 {
		t.Fatalf("expected 2 records, got %d", len(cfg.DNS.StaticRecords))
	}
	if len(cfg.DNS.StaticRecords[0].IP) != 1 || cfg.DNS.StaticRecords[0].IP[0] != "1.2.3.4" {
		t.Errorf("single-address form failed: %v", cfg.DNS.StaticRecords[0].IP)
	}
	if len(cfg.DNS.StaticRecords[1].IP) != 2 ||
		cfg.DNS.StaticRecords[1].IP[0] != "192.168.1.1" || cfg.DNS.StaticRecords[1].IP[1] != "::1" {
		t.Errorf("array form failed: %v", cfg.DNS.StaticRecords[1].IP)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("both forms should validate, got: %v", err)
	}
	m := cfg.DNS.StaticRecordsMap()
	if len(m["smartproxy.lan"]) != 2 {
		t.Errorf("expected 2 IPs for smartproxy.lan, got %v", m["smartproxy.lan"])
	}
}

func TestMarshal_NilSlicesRenderEmptyArray(t *testing.T) {
	// A config with the IPv6/address slices left nil (e.g. the key removed from
	// the file) must serialize as [] — never JSON null — so the panel /config
	// view and raw config.json stay self-documenting for hand-editing.
	var cfg Config
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"inet4_address", "inet6_address", "route_exclude_ports"} {
		want := `"` + key + `":[]`
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("%s rendered as null, want %s; full json: %s", key, want, b)
		}
	}
	if bytes.Contains(b, []byte(`"inet6_address":null`)) {
		t.Errorf("inet6_address serialized as null, want []")
	}
}

// --- smart_proxy.quic：默认值只在 Enabled 时填充、Validate 只在 Enabled 时生效 ---

func TestQuicApplyDefaults_WhenEnabled(t *testing.T) {
	cfg := &Config{SmartProxy: SmartProxyConf{Enabled: true, Timeout: 3, BlacklistTTL: 300, Quic: SmartProxyQuicConf{Enabled: true}}}
	cfg.applyDefaults()
	q := cfg.SmartProxy.Quic
	if len(q.Ports) != 3 || q.Ports[0] != 443 || q.Ports[1] != 8443 || q.Ports[2] != 853 {
		t.Errorf("Quic.Ports: got %v, want [443 8443 853]", q.Ports)
	}
	if q.MaxBuffered != 2048 {
		t.Errorf("Quic.MaxBuffered: got %d, want 2048", q.MaxBuffered)
	}
	if q.HoldMs != 8 {
		t.Errorf("Quic.HoldMs: got %d, want 8", q.HoldMs)
	}
	if q.TimeoutMs != 1000 {
		t.Errorf("Quic.TimeoutMs: got %d, want 1000", q.TimeoutMs)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestQuicApplyDefaults_NotWhenDisabled(t *testing.T) {
	// Enabled=false 时 applyDefaults 必须原样放过 QUIC 字段 —— 保持与历史行为逐字节一致
	cfg := &Config{SmartProxy: SmartProxyConf{Enabled: true, Timeout: 3, BlacklistTTL: 300}}
	cfg.applyDefaults()
	q := cfg.SmartProxy.Quic
	if q.Enabled {
		t.Error("Quic.Enabled must stay false by default")
	}
	if len(q.Ports) != 0 || q.MaxBuffered != 0 || q.HoldMs != 0 || q.TimeoutMs != 0 {
		t.Errorf("disabled quic must stay zero-valued, got %+v", q)
	}
}

func TestQuicValidate_RejectsBadWhenEnabled(t *testing.T) {
	cfg := DefaultConfig()
	q := &cfg.SmartProxy.Quic
	q.Enabled = true
	q.Ports = []int{443, 70000} // 越界端口
	q.MaxBuffered = 0
	q.TimeoutMs = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for enabled quic with bad fields")
	}
	// 修好应放行
	q.Ports = []int{443}
	q.MaxBuffered = 2048
	q.HoldMs = 8
	q.TimeoutMs = 1000
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate after fixing: %v", err)
	}
}

func TestQuicValidate_IgnoredWhenDisabled(t *testing.T) {
	// Enabled=false 时即便字段全零也不报错 —— 老配置(没有 quic 段)必须照常加载
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config with quic disabled must validate, got %v", err)
	}
}

package config

import (
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
	if cfg.Listen.Port != 1080 {
		t.Errorf("Listen.Port: got %d", cfg.Listen.Port)
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
		{Host: "  ", IP: IPList{"1.2.3.4"}},      // empty host → skipped
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

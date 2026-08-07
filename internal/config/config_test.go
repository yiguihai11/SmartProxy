package config

import (
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
        "url": "socks5://user:pass@10.0.0.1:1080",
        "udp_addr": "1080",
        "udp_only": true
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
	if cfg.Upstream.Proxies[0].UDPAddr != "1080" {
		t.Errorf("Proxies[0].UDPAddr: got %q, want 1080", cfg.Upstream.Proxies[0].UDPAddr)
	}
	if !cfg.Upstream.Proxies[0].UDPOnly {
		t.Error("Proxies[0].UDPOnly: expected true (udp_only parsed)")
	}
	if cfg.Upstream.Proxies[1].UDPOnly {
		t.Error("Proxies[1].UDPOnly: expected false (udp_only defaults off)")
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

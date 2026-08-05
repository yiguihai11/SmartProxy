package config

import (
	"encoding/json"
	"os"
)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.LogLevel == "" {
		c.LogLevel = "INFO"
	}
	if c.Listen.Host == "" {
		c.Listen.Host = "::"
	}
	if c.Listen.Port == 0 {
		c.Listen.Port = 1080
	}
	if c.Upstream.Default == "" {
		c.Upstream.Default = "failover"
	}
	if c.Routing.ChnrouteFile == "" {
		c.Routing.ChnrouteFile = "chnroute.txt"
	}
	if c.Routing.ACLFile == "" {
		c.Routing.ACLFile = "acl.txt"
	}
	if c.DNS.Cache.Size == 0 {
		c.DNS.Cache.Size = 10000
	}
	if c.DNS.Cache.TTL == 0 {
		c.DNS.Cache.TTL = 300
	}
	if c.DNS.QueryTimeout == 0 {
		c.DNS.QueryTimeout = 3
	}
	if c.SmartProxy.Timeout == 0 {
		c.SmartProxy.Timeout = 3
	}
	if c.SmartProxy.BlacklistTTL == 0 {
		c.SmartProxy.BlacklistTTL = 300
	}
	if len(c.SmartProxy.Ports) == 0 {
		c.SmartProxy.Ports = []int{80, 443}
	}
	if c.Listen.UDPAssociateIdleTimeout == 0 {
		c.Listen.UDPAssociateIdleTimeout = 60
	}
	if c.Listen.AdminRefreshInterval <= 0 {
		c.Listen.AdminRefreshInterval = 3
	}
}

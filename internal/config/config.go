package config

import (
	"fmt"
	"strings"
)

type Config struct {
	LogLevel   string         `json:"log_level"`
	Listen     ListenConfig   `json:"listen"`
	TUN        TUNConfig      `json:"tun"`
	Upstream   UpstreamConf   `json:"upstream"`
	Routing    RoutingConf    `json:"routing"`
	DNS        DNSConf        `json:"dns"`
	SmartProxy SmartProxyConf `json:"smart_proxy"`
}

type TUNConfig struct {
	Enabled        bool     `json:"enabled"`
	Name           string   `json:"name"`
	MTU            int      `json:"mtu"`
	Inet4Address   []string `json:"inet4_address"`
	Inet6Address   []string `json:"inet6_address"`
	AutoRoute      bool     `json:"auto_route"`
	FileDescriptor int      `json:"-"`
	Stack          string   `json:"stack"`
	// OutputMark applies SO_MARK to outbound connections made by the router itself
	// (so routing rules can identify and exclude it, preventing loops). 0 = disabled
	// (default, zero behavior change); >0 = enabled and uses this mark value.
	// When auto_route=true, it automatically adds an ip rule (fwmark→main) and an
	// nftables output-chain rule to exclude itself and the ports listed in
	// RouteExcludePorts.
	OutputMark int `json:"output_mark"`
	// RouteExcludePorts lists local ports excluded by OutputMark (default [22] SSH),
	// effective only when auto_route=true and output_mark>0.
	RouteExcludePorts []int `json:"route_exclude_ports"`
}

type ListenConfig struct {
	Host                    string         `json:"host"`
	Port                    int            `json:"port"`
	Auth                    *AuthConf      `json:"auth"`
	RelaxedUDPOriginCheck   bool           `json:"relaxed_udp_origin_check"`
	UDPAssociateIdleTimeout int            `json:"udp_associate_idle_timeout"`
	AdminSocket             string         `json:"admin_socket"`
	AdminPort               int            `json:"admin_port"`
	AdminAuth               *AdminAuthConf `json:"admin_auth"`
	AdminRefreshInterval    int            `json:"admin_refresh_interval"`
	// AdminHTTPS serves the TCP admin listener over TLS and 301-redirects plain
	// HTTP to https (same host:port, dual-protocol sniffing). Default true: a
	// self-signed cert+key is auto-generated next to the config file unless
	// AdminCertFile/AdminKeyFile point at real ones. Set false to keep plain HTTP.
	AdminHTTPS bool `json:"admin_https"`
	// AdminCertFile/AdminKeyFile are optional PEM paths overriding the auto-generated
	// self-signed certificate. Both must be set together.
	AdminCertFile string `json:"admin_cert_file"`
	AdminKeyFile  string `json:"admin_key_file"`
}

type AdminAuthConf struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthConf struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UpstreamConf struct {
	Default     string          `json:"default"`
	HealthCheck HealthCheckConf `json:"health_check"`
	Proxies     []ProxyEntry    `json:"proxies"`
}

type HealthCheckConf struct {
	Enabled            bool   `json:"enabled"`
	URL                string `json:"url"`
	Interval           int    `json:"interval"`
	Timeout            int    `json:"timeout"`
	FailuresThreshold  int    `json:"failures"`
	SuccessesThreshold int    `json:"successes"`
	OpenCoolDown       int    `json:"open_cool_down"`
	AutoDisableSingle  bool   `json:"auto_disable_if_single_proxy"`
	// UDPProbeDNS is the DNS server the active UDP health probe queries through a
	// UDP-capable upstream (host:port, default "1.1.1.1:53"). A valid DNS response
	// means the node's UDP relay works.
	UDPProbeDNS string `json:"udp_probe_dns,omitempty"`
	// UDPProbeDomain is the query name the UDP health probe resolves (default "dns.google").
	UDPProbeDomain string `json:"udp_probe_domain,omitempty"`
}

type ProxyEntry struct {
	Alias string `json:"alias"`
	URL   string `json:"url"`
}

type RoutingConf struct {
	ChnrouteFile string `json:"chnroute_file"`
	ACLFile      string `json:"acl_file"`
}

type DNSConf struct {
	Enabled        bool       `json:"enabled"`
	Cache          DNSCacheC  `json:"cache"`
	Foreign        DNSForeign `json:"foreign"`
	QueryTimeout   int        `json:"query_timeout"`
	SpeedCheckMode string     `json:"speed_check_mode"`
}

type DNSCacheC struct {
	Size int `json:"size"`
	TTL  int `json:"ttl"`
}

type DNSForeign struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

type SmartProxyConf struct {
	Enabled      bool  `json:"enabled"`
	Timeout      int   `json:"timeout"`
	Ports        []int `json:"ports"`
	BlacklistTTL int   `json:"blacklist_ttl"`
}

func (c *Config) Validate() error {
	var errs []string

	if c.Listen.Port <= 0 || c.Listen.Port > 65535 {
		errs = append(errs, "listen.port must be between 1 and 65535")
	}
	if c.DNS.QueryTimeout <= 0 {
		errs = append(errs, "dns.query_timeout must be positive")
	}
	if c.SmartProxy.Timeout <= 0 {
		errs = append(errs, "smart_proxy.timeout must be positive")
	}
	if c.SmartProxy.BlacklistTTL <= 0 {
		errs = append(errs, "smart_proxy.blacklist_ttl must be positive")
	}
	for i, p := range c.Upstream.Proxies {
		if p.URL == "" {
			errs = append(errs, fmt.Sprintf("upstream.proxies[%d].url is empty", i))
		}
	}
	if c.DNS.Cache.Size <= 0 {
		errs = append(errs, "dns.cache.size must be positive")
	}
	if hc := c.Upstream.HealthCheck; hc.Enabled {
		if hc.URL == "" {
			errs = append(errs, "upstream.health_check.url must not be empty")
		}
		if hc.Interval <= 0 {
			errs = append(errs, "upstream.health_check.interval must be positive")
		}
		if hc.Timeout <= 0 {
			errs = append(errs, "upstream.health_check.timeout must be positive")
		}
	}
	if lc := c.Listen; (lc.AdminCertFile == "") != (lc.AdminKeyFile == "") {
		errs = append(errs, "listen.admin_cert_file and listen.admin_key_file must be both set or both empty")
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
}

func DefaultConfig() *Config {
	return &Config{
		LogLevel: "INFO",
		Listen: ListenConfig{
			Host:                    "::",
			Port:                    1080,
			RelaxedUDPOriginCheck:   true,
			UDPAssociateIdleTimeout: 60,
			AdminRefreshInterval:    3,
			AdminHTTPS:              true,
		},
		TUN: TUNConfig{
			Enabled:           false,
			Name:              "tun0",
			MTU:               1500,
			Inet4Address:      []string{"172.19.0.1/30"},
			AutoRoute:         false,
			Stack:             "gvisor",
			RouteExcludePorts: []int{22},
		},
		Upstream: UpstreamConf{
			Default: "failover",
			HealthCheck: HealthCheckConf{
				Enabled:            false,
				URL:                "http://wifi.vivo.com.cn/generate_204",
				Interval:           60,
				Timeout:            5,
				FailuresThreshold:  2,
				SuccessesThreshold: 1,
				OpenCoolDown:       30,
				AutoDisableSingle:  true,
				UDPProbeDNS:        "1.1.1.1:53",
				UDPProbeDomain:     "dns.google",
			},
		},
		Routing: RoutingConf{
			ChnrouteFile: "chnroute.txt",
		},
		DNS: DNSConf{
			Enabled:      true,
			QueryTimeout: 3,
			Cache: DNSCacheC{
				Size: 10000,
				TTL:  300,
			},
			Foreign: DNSForeign{
				IPv4: "1.1.1.1:53",
				IPv6: "[2606:4700:4700::1111]:53",
			},
		},
		SmartProxy: SmartProxyConf{
			Enabled:      true,
			Timeout:      3,
			Ports:        []int{80, 443},
			BlacklistTTL: 300,
		},
	}
}

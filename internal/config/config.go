package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
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
	// DNSServers lists the DNS server addresses the TUN advertises to the system
	// resolver on Android (fed to VpnService.Builder.addDnsServer). Index 0 = IPv4
	// (default 223.5.5.5), index 1 = IPv6 (default 2400:3200::1). Not read on
	// desktop; harmless when absent.
	DNSServers     []string `json:"dns_servers"`
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
	// AdminCertSANs lists extra hostnames or IP addresses to include in the
	// auto-generated self-signed certificate's SAN (beyond the built-in
	// localhost/127.0.0.1/::1) — e.g. the LAN IP the panel is reached through
	// ("192.168.1.1") — so the browser's hostname-mismatch warning disappears for
	// that address. Ignored when AdminCertFile/AdminKeyFile are set.
	AdminCertSANs []string `json:"admin_cert_sans"`
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
	// UDPInTCP selects the hev UDP-in-TCP relay (socks5/socks5h only, see
	// upstream.Proxy.UDPInTCP): UDP is framed over the node's TCP connection, so the
	// node needs no UDP listener. Edited from the panel's Add/Edit Proxy checkbox.
	UDPInTCP bool `json:"udp_in_tcp,omitempty"`
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
	// StaticRecords maps hostnames to fixed IPs served directly by the built-in DNS
	// interceptor (hosts-override semantics; checked before block rules and cache).
	// The same host may appear multiple times to attach both an IPv4 and an IPv6
	// address. Edited by hand in the config file.
	StaticRecords []StaticRecord `json:"static_records"`
}

// StaticRecord is a single host→IP(s) static DNS entry. The same host may carry
// multiple entries or one entry with multiple IPs to attach both an IPv4 and an
// IPv6 address.
type StaticRecord struct {
	Host string `json:"host"`
	IP   IPList `json:"ip"`
}

// IPList is a []string that also unmarshals from a plain JSON string, so a static
// record's "ip" field accepts either a single address ("1.2.3.4") or an array of
// addresses (["1.2.3.4", "::1"]).
type IPList []string

func (l *IPList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*l = nil
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*l = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*l = []string{s}
	return nil
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

	if c.Listen.Port < 0 || c.Listen.Port > 65535 {
		errs = append(errs, "listen.port must be 0 (socks5 disabled) or between 1 and 65535")
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
	for i, san := range c.Listen.AdminCertSANs {
		if strings.TrimSpace(san) == "" {
			errs = append(errs, fmt.Sprintf("listen.admin_cert_sans[%d] must not be empty", i))
		}
	}
	for i, sr := range c.DNS.StaticRecords {
		if strings.TrimSpace(sr.Host) == "" {
			errs = append(errs, fmt.Sprintf("dns.static_records[%d].host must not be empty", i))
		}
		if len(sr.IP) == 0 {
			errs = append(errs, fmt.Sprintf("dns.static_records[%d].ip must not be empty", i))
		}
		for j, ip := range sr.IP {
			if net.ParseIP(strings.TrimSpace(ip)) == nil {
				errs = append(errs, fmt.Sprintf("dns.static_records[%d].ip[%d] must be a valid IP", i, j))
			}
		}
	}
	for i, d := range c.TUN.DNSServers {
		if net.ParseIP(strings.TrimSpace(d)) == nil {
			errs = append(errs, fmt.Sprintf("tun.dns_servers[%d] must be a valid IP", i))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
}

// normHost lowercases a hostname and strips a trailing dot, the canonical form
// used for static-record host lookups and merging.
func normHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// SetStaticRecordIP inserts ip into host's static record, replacing existing
// addresses of the same address family (IPv4 vs IPv6) while preserving the other
// family — so pinning a new IPv4 on a host that already has both families keeps its
// IPv6 untouched. When host has no record yet, a new one is appended. The input
// slice is not modified; a new slice is returned.
func SetStaticRecordIP(records []StaticRecord, host string, ip net.IP) []StaticRecord {
	host = normHost(host)
	newAddr := ip.String()
	wantV4 := ip.To4() != nil
	for i := range records {
		cur := normHost(records[i].Host)
		if cur != host {
			continue
		}
		var kept IPList
		for _, a := range records[i].IP {
			parsed := net.ParseIP(a)
			if parsed == nil {
				continue
			}
			if (parsed.To4() != nil) == wantV4 {
				continue // drop the family being replaced
			}
			kept = append(kept, a)
		}
		kept = append(kept, newAddr)
		// Copy the whole slice and set the new IP on the copied element so the
		// caller's slice is never mutated.
		next := make([]StaticRecord, len(records))
		copy(next, records)
		next[i].IP = kept
		return next
	}
	return append(records, StaticRecord{Host: host, IP: IPList{newAddr}})
}

// SetStaticRecordIPs is the batch form of SetStaticRecordIP: it replaces host's
// addresses of the same family as the given ips wholesale with the full new list,
// while preserving addresses of the opposite family. Used to pin a multi-answer
// cache row (all entries share the row's family) as a static record.
func SetStaticRecordIPs(records []StaticRecord, host string, ips []net.IP) []StaticRecord {
	host = normHost(host)
	if len(ips) == 0 {
		return records
	}
	addrs := make(IPList, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	familyV4 := ips[0].To4() != nil
	for i := range records {
		cur := normHost(records[i].Host)
		if cur != host {
			continue
		}
		var kept IPList
		for _, a := range records[i].IP {
			parsed := net.ParseIP(a)
			if parsed == nil {
				continue
			}
			if (parsed.To4() != nil) == familyV4 {
				continue // drop the family being replaced wholesale
			}
			kept = append(kept, a)
		}
		kept = append(kept, addrs...)
		// Copy the whole slice and set the new IPs on the copied element so the
		// caller's slice is never mutated.
		next := make([]StaticRecord, len(records))
		copy(next, records)
		next[i].IP = kept
		return next
	}
	return append(records, StaticRecord{Host: host, IP: addrs})
}

// RemoveStaticRecordIP removes ip from host's static record; when the record's IP
// list becomes empty the whole host record is dropped. The input slice is not
// modified; a new slice is returned.
func RemoveStaticRecordIP(records []StaticRecord, host string, ip net.IP) []StaticRecord {
	host = normHost(host)
	out := make([]StaticRecord, 0, len(records))
	for _, r := range records {
		if normHost(r.Host) != host {
			out = append(out, r)
			continue
		}
		var kept IPList
		for _, a := range r.IP {
			parsed := net.ParseIP(a)
			if parsed != nil && parsed.Equal(ip) {
				continue
			}
			kept = append(kept, a)
		}
		if len(kept) > 0 {
			r.IP = kept
			out = append(out, r)
		}
	}
	return out
}

// RemoveStaticRecord drops host's static record entirely. The input slice is not
// modified; a new slice is returned.
func RemoveStaticRecord(records []StaticRecord, host string) []StaticRecord {
	host = normHost(host)
	out := make([]StaticRecord, 0, len(records))
	for _, r := range records {
		if normHost(r.Host) != host {
			out = append(out, r)
		}
	}
	return out
}

// ReplaceStaticRecord is the edit operation: it drops oldHost's record (and, if
// different, any existing record already carrying host) and sets host's record to
// exactly ips, so every host ends up with at most one record. When host == oldHost
// the record's IP list is replaced in place. A host with no ips is simply removed.
// The input slice is not modified; a new slice is returned.
func ReplaceStaticRecord(records []StaticRecord, oldHost, host string, ips []net.IP) []StaticRecord {
	oldHost = normHost(oldHost)
	host = normHost(host)
	ipStrs := make(IPList, 0, len(ips))
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	out := make([]StaticRecord, 0, len(records)+1)
	for _, r := range records {
		cur := normHost(r.Host)
		if cur == oldHost {
			continue // the record being edited is dropped
		}
		if host != "" && cur == host {
			continue // a pre-existing record for the new host is replaced below
		}
		out = append(out, r)
	}
	if host != "" && len(ipStrs) > 0 {
		out = append(out, StaticRecord{Host: host, IP: ipStrs})
	}
	return out
}

// StaticRecordsMap normalizes the static record list into a host→IPs lookup table:
// host is lowercased with a trailing dot stripped, all listed IPs for a host are
// grouped (so an IPv4 and an IPv6 address coexist for one host), and invalid
// entries are skipped. Returns nil when no records are configured.
func (d DNSConf) StaticRecordsMap() map[string][]net.IP {
	var m map[string][]net.IP
	for _, r := range d.StaticRecords {
		host := normHost(r.Host)
		if host == "" {
			continue
		}
		for _, entry := range r.IP {
			ip := net.ParseIP(strings.TrimSpace(entry))
			if ip == nil {
				continue
			}
			if m == nil {
				m = make(map[string][]net.IP)
			}
			m[host] = append(m[host], ip)
		}
	}
	return m
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
			DNSServers:        []string{"223.5.5.5", "2400:3200::1"},
			AutoRoute:         false,
			Stack:             "gvisor",
			RouteExcludePorts: []int{22},
		},
		Upstream: UpstreamConf{
			Default: "failover",
			HealthCheck: HealthCheckConf{
				Enabled:            false,
				URL:                "http://cp.cloudflare.com/generate_204",
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

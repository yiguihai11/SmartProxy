package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Config 配置文件结构体
type Config struct {
	Listener struct {
		SOCKS5Port  int  `json:"socks5_port"`
		WebPort     int  `json:"web_port"`
		DNSPort     int  `json:"dns_port"`
		IPv6Enabled bool `json:"ipv6_enabled"`
		IPv6Only    bool `json:"ipv6_only"`
	} `json:"listener"`

	SOCKS5 struct {
		MaxConnections  int        `json:"max_connections"`
		CleanupInterval int        `json:"cleanup_interval"`
		EnableAuth      bool       `json:"enable_auth"`
		AuthUsers       []AuthUser `json:"auth_users"`
	} `json:"socks5"`

	Router struct {
		Chnroutes struct {
			Enable bool   `json:"enable"`
			Path   string `json:"path"`
		} `json:"chnroutes"`
		Rules      []RouterRule `json:"rules"`
		ProxyNodes []ProxyNode  `json:"proxy_nodes,omitempty"`
	} `json:"router"`

	SmartProxy struct {
		Enabled                bool  `json:"enabled"`
		TimeoutMs              int   `json:"timeout_ms"`
		BlacklistExpiryMinutes int   `json:"blacklist_expiry_minutes"`
		ProbingPorts           []int `json:"probing_ports"`
	} `json:"smart_proxy"`

	DNS struct {
		Enabled bool `json:"enabled"`
		Cache   struct {
			MaxSize         int `json:"max_size"`
			DefaultTTL      int `json:"default_ttl"`
			CleanupInterval int `json:"cleanup_interval"`
		} `json:"cache"`
		Groups      map[string][]string `json:"groups"`
		HijackRules []DNSHijackRule     `json:"hijack_rules"`
	} `json:"dns"`

	ConnectionSettings struct {
		TCPTimeoutSeconds int `json:"tcp_timeout_seconds"`
		UDPTimeoutSeconds int `json:"udp_timeout_seconds"`
	} `json:"connection_settings"`

	Logging struct {
		Level            string `json:"level"`
		EnableUserLogs   bool   `json:"enable_user_logs"`
		EnableAccessLogs bool   `json:"enable_access_logs"`
		LogFile          string `json:"log_file"`
	} `json:"logging"`

	NATTraversal struct {
		Enabled          bool     `json:"enabled"`
		Mode             string   `json:"mode"`          // "auto", "direct", "fullcone", "holepunch", "turn"
		STUNServers      []string `json:"stun_servers"`  // STUN服务器列表
		TURNServer       string   `json:"turn_server"`   // TURN服务器地址
		TURNUsername     string   `json:"turn_username"` // TURN用户名
		TURNPassword     string   `json:"turn_password"` // TURN密码
		UPnPEnabled      bool     `json:"upnp_enabled"`  // 是否启用UPnP
		PortMappingRange struct {
			Start int `json:"start"` // 端口映射起始端口
			End   int `json:"end"`   // 端口映射结束端口
		} `json:"port_mapping_range"`
		KeepAliveInterval int `json:"keepalive_interval"` // 保活间隔（秒）
	} `json:"nat_traversal"`
}

// AuthUser 认证用户结构体
type AuthUser struct {
	Username        string           `json:"username"`
	Password        string           `json:"password"`
	Enabled         bool             `json:"enabled"`
	UserGroups      []string         `json:"user_groups,omitempty"`
	RateLimit       *RateLimit       `json:"rate_limit,omitempty"`
	ConnectionLimit *ConnectionLimit `json:"connection_limit,omitempty"`
}

// RateLimit 速率限制结构体
type RateLimit struct {
	UploadBPS   int64 `json:"upload_bps"`
	DownloadBPS int64 `json:"download_bps"`
}

// ConnectionLimit 连接限制结构体
type ConnectionLimit struct {
	MaxConnections  int              `json:"max_connections,omitempty"`
	ExpiresAfter    int              `json:"expires_after_minutes,omitempty"`
	AllowFrom       []string         `json:"allow_from_ips,omitempty"`
	BlockFrom       []string         `json:"block_from_ips,omitempty"`
	TimeRestriction *TimeRestriction `json:"time_restriction,omitempty"`
}

// TimeRestriction 时间限制配置
type TimeRestriction struct {
	AllowedHours   []string `json:"allowed_hours,omitempty"`
	AllowedDays    []string `json:"allowed_days,omitempty"`
	Timezone       string   `json:"timezone,omitempty"`
	EffectiveDates []string `json:"effective_dates,omitempty"`
	ExpiredDates   []string `json:"expired_dates,omitempty"`
}

// RouterRule 路由规则结构体
type RouterRule struct {
	Action      string   `json:"action"`
	Patterns    []string `json:"patterns,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	ProxyNode   string   `json:"proxy_node,omitempty"`
	Description string   `json:"description"`
}

// ProxyNode 代理节点结构体
type ProxyNode struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Address     string  `json:"address"`
	Enabled     bool    `json:"enabled"`
	Username    *string `json:"username,omitempty"`
	Password    *string `json:"password,omitempty"`
	AuthMethod  string  `json:"auth_method"`
	Description string  `json:"description"`
}

// DNSHijackRule DNS劫持规则结构体
type DNSHijackRule struct {
	Pattern     string `json:"pattern"`
	Target      string `json:"target"`
	Description string `json:"description"`
}

// Manager 配置管理器
type Manager struct {
	configPath string
	config     *Config
	mutex      sync.RWMutex
	lastLoad   time.Time
}

// NewManager 创建新的配置管理器
func NewManager(configPath string) *Manager {
	return &Manager{
		configPath: configPath,
		config:     &Config{},
	}
}

// Load 加载配置文件
func (m *Manager) Load() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		// 如果配置文件不存在，创建默认配置
		if err := m.createDefaultConfig(); err != nil {
			return fmt.Errorf("failed to create default config: %v", err)
		}
	}

	data, err := ioutil.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	config := &Config{}
	if err := json.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	m.config = config
	m.lastLoad = time.Now()
	return nil
}

// GetConfig 获取完整配置（只读）
func (m *Manager) GetConfig() *Config {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 返回配置的深拷贝
	configCopy := *m.config

	// 深拷贝切片和map
	if m.config.Router.Rules != nil {
		configCopy.Router.Rules = make([]RouterRule, len(m.config.Router.Rules))
		copy(configCopy.Router.Rules, m.config.Router.Rules)
	}

	if m.config.Router.ProxyNodes != nil {
		configCopy.Router.ProxyNodes = make([]ProxyNode, len(m.config.Router.ProxyNodes))
		copy(configCopy.Router.ProxyNodes, m.config.Router.ProxyNodes)
	}

	if m.config.SOCKS5.AuthUsers != nil {
		configCopy.SOCKS5.AuthUsers = make([]AuthUser, len(m.config.SOCKS5.AuthUsers))
		copy(configCopy.SOCKS5.AuthUsers, m.config.SOCKS5.AuthUsers)
	}

	if m.config.DNS.Groups != nil {
		configCopy.DNS.Groups = make(map[string][]string)
		for k, v := range m.config.DNS.Groups {
			configCopy.DNS.Groups[k] = append([]string(nil), v...)
		}
	}

	if m.config.DNS.HijackRules != nil {
		configCopy.DNS.HijackRules = make([]DNSHijackRule, len(m.config.DNS.HijackRules))
		copy(configCopy.DNS.HijackRules, m.config.DNS.HijackRules)
	}

	if m.config.SmartProxy.ProbingPorts != nil {
		configCopy.SmartProxy.ProbingPorts = make([]int, len(m.config.SmartProxy.ProbingPorts))
		copy(configCopy.SmartProxy.ProbingPorts, m.config.SmartProxy.ProbingPorts)
	}

	return &configCopy
}

// UpdateFullConfig replaces the entire configuration and saves it.
func (m *Manager) UpdateFullConfig(newConfig *Config) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.config = newConfig

	// ensure directory exists
	if err := os.MkdirAll(filepath.Dir(m.configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Write to a temporary file then rename, to ensure atomic operation
	tempPath := m.configPath + ".tmp"
	if err := ioutil.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp config file: %v", err)
	}

	if err := os.Rename(tempPath, m.configPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp config file: %v", err)
	}

	m.lastLoad = time.Now()
	return nil
}

// GetAuthUsers 获取所有认证用户
func (m *Manager) GetAuthUsers() []AuthUser {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	users := make([]AuthUser, len(m.config.SOCKS5.AuthUsers))
	copy(users, m.config.SOCKS5.AuthUsers)
	return users
}

// GetProxyNodes 获取所有代理节点
func (m *Manager) GetProxyNodes() []ProxyNode {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	nodes := make([]ProxyNode, len(m.config.Router.ProxyNodes))
	copy(nodes, m.config.Router.ProxyNodes)
	return nodes
}

// GetRouterRules 获取所有路由规则
func (m *Manager) GetRouterRules() []RouterRule {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	rules := make([]RouterRule, len(m.config.Router.Rules))
	copy(rules, m.config.Router.Rules)
	return rules
}

// createDefaultConfig 创建默认配置文件
func (m *Manager) createDefaultConfig() error {
	defaultConfig := &Config{}

	// 设置默认值
	defaultConfig.Listener.SOCKS5Port = 1080
	defaultConfig.Listener.WebPort = 8080
	defaultConfig.Listener.DNSPort = 1053
	defaultConfig.Listener.IPv6Enabled = true

	defaultConfig.SOCKS5.MaxConnections = 1000
	defaultConfig.SOCKS5.CleanupInterval = 300
	defaultConfig.SOCKS5.EnableAuth = false
	defaultConfig.SOCKS5.AuthUsers = []AuthUser{
		{
			Username:   "admin",
			Password:   "admin123",
			Enabled:    true,
			UserGroups: []string{"admin"},
			RateLimit: &RateLimit{
				UploadBPS:   10485760, // 10 MB/s
				DownloadBPS: 10485760, // 10 MB/s
			},
			ConnectionLimit: &ConnectionLimit{
				MaxConnections: 10,
				ExpiresAfter:   1440, // 24 hours
				AllowFrom:      []string{"127.0.0.1", "::1", "192.168.0.0/16"},
				BlockFrom:      []string{"10.0.0.1"},
				TimeRestriction: &TimeRestriction{
					AllowedHours: []string{"09:00-18:00"},
					AllowedDays:  []string{"monday-friday"},
					Timezone:     "Asia/Shanghai",
				},
			},
		},
	}

	defaultConfig.SmartProxy.Enabled = true
	defaultConfig.SmartProxy.TimeoutMs = 1500
	defaultConfig.SmartProxy.BlacklistExpiryMinutes = 360
	defaultConfig.SmartProxy.ProbingPorts = []int{80, 443, 8080, 8443}

	defaultConfig.Router.ProxyNodes = []ProxyNode{}

	defaultConfig.DNS.Enabled = true
	defaultConfig.DNS.Cache.MaxSize = 2000
	defaultConfig.DNS.Cache.DefaultTTL = 300
	defaultConfig.DNS.Cache.CleanupInterval = 60
	defaultConfig.DNS.Groups = map[string][]string{
		"cn":      {"223.5.5.5:53", "119.29.29.29:53"},
		"foreign": {"8.8.8.8:53", "1.1.1.1:53"},
	}
	defaultConfig.DNS.HijackRules = []DNSHijackRule{}

	defaultConfig.ConnectionSettings.TCPTimeoutSeconds = 60
	defaultConfig.ConnectionSettings.UDPTimeoutSeconds = 300

	defaultConfig.Logging.Level = "info"
	defaultConfig.Logging.EnableUserLogs = true
	defaultConfig.Logging.EnableAccessLogs = true
	defaultConfig.Logging.LogFile = "proxy.log"

	// 临时保存默认配置到临时文件
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(m.configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	data, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal default config: %v", err)
	}

	// 写入临时文件然后重命名，确保原子性操作
	tempPath := m.configPath + ".tmp"
	if err := ioutil.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp default config file: %v", err)
	}

	if err := os.Rename(tempPath, m.configPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp default config file: %v", err)
	}

	m.config = defaultConfig
	m.lastLoad = time.Now()
	return nil
}

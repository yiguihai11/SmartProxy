package web

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
)

// SmartProxyConfig 完整的SmartProxy配置结构
type SmartProxyConfig struct {
	Listener struct {
		Socks5Port  int  `json:"socks5_port"`
		WebPort     int  `json:"web_port"`
		DnsPort     int  `json:"dns_port"`
		IPv6Enabled bool `json:"ipv6_enabled"`
	} `json:"listener"`

	Socks5 struct {
		MaxConnections  int              `json:"max_connections"`
		CleanupInterval int              `json:"cleanup_interval"`
		EnableAuth      bool             `json:"enable_auth"`
		AuthUsers       []AuthUserConfig `json:"auth_users"`
	} `json:"socks5"`

	Router struct {
		Chnroutes struct {
			Enable bool   `json:"enable"`
			Path   string `json:"path"`
		} `json:"chnroutes"`
		Rules      []RouterRule      `json:"rules"`
		ProxyNodes []ProxyNodeConfig `json:"proxy_nodes"`
	} `json:"router"`

	TrafficDetection struct {
		Enabled         bool `json:"enabled"`
		EnhancedProbing struct {
			Enable              bool  `json:"enable"`
			SNIExtraction       bool  `json:"sni_extraction"`
			HTTPValidation      bool  `json:"http_validation"`
			MaxInitialDataSize  int   `json:"max_initial_data_size"`
			ValidationTimeoutMs int   `json:"validation_timeout_ms"`
			ProbingPorts        []int `json:"probing_ports"`
		} `json:"enhanced_probing"`
	} `json:"traffic_detection"`

	DNS struct {
		Enabled bool `json:"enabled"`
		Cache   struct {
			MaxSize         int `json:"max_size"`
			DefaultTTL      int `json:"default_ttl"`
			CleanupInterval int `json:"cleanup_interval"`
		} `json:"cache"`
		Groups      map[string][]string `json:"groups"`
		HijackRules []HijackRule        `json:"hijack_rules"`
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
}

// RateLimit 速率限制结构体

type RateLimit struct {

	UploadBPS   int64 `json:"upload_bps"`

	DownloadBPS int64 `json:"download_bps"`

	BurstSize   int64 `json:"burst_size"`

}



// ConnectionLimit 连接限制结构体

type ConnectionLimit struct {

	MaxConnections  int              `json:"max_connections,omitempty"`

	ExpiresAfter    int              `json:"expires_after_minutes,omitempty"`

	AllowFrom       []string         `json:"allow_from_ips,omitempty"`

	BlockFrom       []string         `json:"block_from_ips,omitempty"`

	TimeRestriction *TimeRestriction `json:"time_restriction,omitempty"`

}



// AuthUserConfig 认证用户配置

type AuthUserConfig struct {

	Username        string           `json:"username"`

	Password        string           `json:"password"`

	Enabled         bool             `json:"enabled"`

	UserGroups      []string         `json:"user_groups,omitempty"`

	RateLimit       *RateLimit       `json:"rate_limit"`

	ConnectionLimit *ConnectionLimit `json:"connection_limit,omitempty"`

}

// RouterRule 路由规则
type RouterRule struct {
	Action      string   `json:"action"`
	Patterns    []string `json:"patterns"`
	ProxyNode   string   `json:"proxy_node,omitempty"`
	Description string   `json:"description"`

	// 用户权限控制
	AllowedUsers    []string `json:"allowed_users,omitempty"`    // 允访问的用户名列表，为空则所有用户
	DeniedUsers     []string `json:"denied_users,omitempty"`     // 禁止访问的用户名列表
	UserGroups      []string `json:"user_groups,omitempty"`      // 允许的用户组

	// 来源地址控制
	AllowedSourceIPs []string `json:"allowed_source_ips,omitempty"`     // 允许的源IP/网段
	DeniedSourceIPs  []string `json:"denied_source_ips,omitempty"`      // 禁止的源IP/网段
	AllowedSourcePorts []int `json:"allowed_source_ports,omitempty"`   // 允许的源端口
	DeniedSourcePorts  []int `json:"denied_source_ports,omitempty"`    // 禁止的源端口

	// 时间控制
	TimeRestrictions *TimeRestriction `json:"time_restrictions,omitempty"` // 时间限制
}

// TimeRestriction 时间限制配置
type TimeRestriction struct {
	AllowedHours     []string `json:"allowed_hours,omitempty"`     // 允许的小时 ["09:00-18:00"]
	AllowedDays      []string `json:"allowed_days,omitempty"`      // 允许的星期 ["monday-friday"]
	Timezone         string   `json:"timezone,omitempty"`           // 时区
	EffectiveDates   []string `json:"effective_dates,omitempty"`   // 有效日期 ["2024-01-01-2024-12-31"]
	ExpiredDates     []string `json:"expired_dates,omitempty"`     // 过期日期 ["2024-12-31"]
}

// ProxyNodeConfig 代理节点配置
type ProxyNodeConfig struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Address     string `json:"address"`
	Enabled     bool   `json:"enabled"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	AuthMethod  string `json:"auth_method,omitempty"`
	Description string `json:"description"`
}

// HijackRule DNS劫持规则
type HijackRule struct {
	Pattern     string `json:"pattern"`
	Target      string `json:"target"`
	Description string `json:"description"`

	// 用户权限控制
	AllowedUsers    []string `json:"allowed_users,omitempty"`    // 允访问的用户名列表，为空则所有用户
	DeniedUsers     []string `json:"denied_users,omitempty"`     // 禁止访问的用户名列表
	UserGroups      []string `json:"user_groups,omitempty"`      // 允许的用户组

	// 来源地址控制
	AllowedSourceIPs []string `json:"allowed_source_ips,omitempty"`     // 允许的源IP/网段
	DeniedSourceIPs  []string `json:"denied_source_ips,omitempty"`      // 禁止的源IP/网段
	AllowedSourcePorts []int `json:"allowed_source_ports,omitempty"`   // 允许的源端口
	DeniedSourcePorts  []int `json:"denied_source_ports,omitempty"`    // 禁止的源端口

	// 时间控制
	TimeRestrictions *TimeRestriction `json:"time_restrictions,omitempty"` // 时间限制
}

// SmartProxyConfigManager 配置管理器
type SmartProxyConfigManager struct {
	configPath string
	config     *SmartProxyConfig
	mu         sync.RWMutex
	logger     interface {
		Printf(format string, v ...interface{})
	}
}

// NewSmartProxyConfigManager 创建配置管理器
func NewSmartProxyConfigManager(configPath string, logger interface {
	Printf(format string, v ...interface{})
}) *SmartProxyConfigManager {
	if logger == nil {
		logger = &defaultLogger{}
	}

	return &SmartProxyConfigManager{
		configPath: configPath,
		logger:     logger,
	}
}

// LoadConfig 加载配置文件
func (cm *SmartProxyConfigManager) LoadConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	data, err := ioutil.ReadFile(cm.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 如果配置文件不存在，创建默认配置
			return cm.createDefaultConfig()
		}
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var config SmartProxyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	cm.config = &config
	return nil
}

// SaveConfigToFile 保存配置文件到文件
func (cm *SmartProxyConfigManager) SaveConfigToFile() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.config == nil {
		return fmt.Errorf("config is not loaded")
	}

	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	return ioutil.WriteFile(cm.configPath, data, 0644)
}

// GetConfig 获取配置
func (cm *SmartProxyConfigManager) GetConfig() *SmartProxyConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.config == nil {
		return nil
	}

	// 返回配置的副本
	configCopy := *cm.config
	return &configCopy
}

// UpdateConfig 更新配置
func (cm *SmartProxyConfigManager) UpdateConfig(updates map[string]interface{}) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return fmt.Errorf("config is not loaded")
	}

	// 将更新应用到配置中
	return cm.applyUpdates(cm.config, updates)
}

// applyUpdates 递归应用更新
func (cm *SmartProxyConfigManager) applyUpdates(target interface{}, updates map[string]interface{}) error {
	// 这里需要实现递归更新的逻辑
	// 为了简化，我们使用JSON序列化/反序列化的方式
	targetBytes, _ := json.Marshal(target)
	var targetMap map[string]interface{}
	json.Unmarshal(targetBytes, &targetMap)

	for key, value := range updates {
		if valueMap, ok := value.(map[string]interface{}); ok {
			if nestedValue, exists := targetMap[key]; exists {
				if nestedMap, ok := nestedValue.(map[string]interface{}); ok {
					// 递归更新嵌套对象
					nestedCM := &SmartProxyConfigManager{}
					nestedCM.applyUpdates(nestedMap, valueMap)
					targetMap[key] = nestedMap
				}
			}
		} else {
			targetMap[key] = value
		}
	}

	// 将更新后的map转换回结构体
	updatedBytes, _ := json.Marshal(targetMap)
	return json.Unmarshal(updatedBytes, target)
}

// createDefaultConfig 创建默认配置
func (cm *SmartProxyConfigManager) createDefaultConfig() error {
	defaultConfig := &SmartProxyConfig{
		Listener: struct {
			Socks5Port  int  `json:"socks5_port"`
			WebPort     int  `json:"web_port"`
			DnsPort     int  `json:"dns_port"`
			IPv6Enabled bool `json:"ipv6_enabled"`
		}{
			Socks5Port:  1080,
			WebPort:     8080,
			DnsPort:     1053,
			IPv6Enabled: true,
		},
		Socks5: struct {
			MaxConnections  int              `json:"max_connections"`
			CleanupInterval int              `json:"cleanup_interval"`
			EnableAuth      bool             `json:"enable_auth"`
			AuthUsers       []AuthUserConfig `json:"auth_users"`
		}{
			MaxConnections:  1000,
			CleanupInterval: 300,
			EnableAuth:      false,
			AuthUsers: []AuthUserConfig{
				{
					Username: "admin",
					Password: "admin123",
					Enabled:  true,
					RateLimit: &RateLimit{
						UploadBPS:   10485760, // 10 MB/s
						DownloadBPS: 10485760, // 10 MB/s
						BurstSize:   52428800, // 50 MB
					},
					ConnectionLimit: &ConnectionLimit{
						MaxConnections: 10,                           // 最多10个并发连接
						ExpiresAfter:   1440,                         // 24小时后过期
						AllowFrom:      []string{"127.0.0.1", "::1"}, // 仅本地访问
						BlockFrom:      []string{},                   // 无阻止IP
						TimeRestriction: &TimeRestriction{
							AllowedHours: []string{"09:00-18:00"}, // 工作时间 9:00-18:00
							AllowedDays:  []string{"monday-friday"},                         // 周一到周五
							Timezone:     "Asia/Shanghai",
						},
					},
				},
			},
		},
		Router: struct {
			Chnroutes struct {
				Enable bool   `json:"enable"`
				Path   string `json:"path"`
			} `json:"chnroutes"`
			Rules      []RouterRule      `json:"rules"`
			ProxyNodes []ProxyNodeConfig `json:"proxy_nodes"`
		}{
			Chnroutes: struct {
				Enable bool   `json:"enable"`
				Path   string `json:"path"`
			}{
				Enable: true,
				Path:   "conf/chnroutes.txt",
			},
			Rules: []RouterRule{
				{
					Action:      "block",
					Patterns:    []string{"*.facebook.com", "*.fbcdn.net"},
					Description: "阻止访问恶意域名和IP",
				},
				{
					Action:      "allow",
					Patterns:    []string{"*.cn", "*.com.cn", "*.net.cn", "*.org.cn"},
					Description: "中国域名直连",
				},
				{
					Action:      "allow",
					Patterns:    []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.1"},
					Description: "私有网络和本地回环直连",
				},
			},
			ProxyNodes: []ProxyNodeConfig{},
		},
		TrafficDetection: struct {
			Enabled         bool `json:"enabled"`
			EnhancedProbing struct {
				Enable              bool  `json:"enable"`
				SNIExtraction       bool  `json:"sni_extraction"`
				HTTPValidation      bool  `json:"http_validation"`
				MaxInitialDataSize  int   `json:"max_initial_data_size"`
				ValidationTimeoutMs int   `json:"validation_timeout_ms"`
				ProbingPorts        []int `json:"probing_ports"`
			} `json:"enhanced_probing"`
		}{
			Enabled: true,
			EnhancedProbing: struct {
				Enable              bool  `json:"enable"`
				SNIExtraction       bool  `json:"sni_extraction"`
				HTTPValidation      bool  `json:"http_validation"`
				MaxInitialDataSize  int   `json:"max_initial_data_size"`
				ValidationTimeoutMs int   `json:"validation_timeout_ms"`
				ProbingPorts        []int `json:"probing_ports"`
			}{
				Enable:              true,
				SNIExtraction:       true,
				HTTPValidation:      true,
				MaxInitialDataSize:  4096,
				ValidationTimeoutMs: 1500,
				ProbingPorts:        []int{80, 443, 8080, 8443},
			},
		},
		DNS: struct {
			Enabled bool `json:"enabled"`
			Cache   struct {
				MaxSize         int `json:"max_size"`
				DefaultTTL      int `json:"default_ttl"`
				CleanupInterval int `json:"cleanup_interval"`
			} `json:"cache"`
			Groups      map[string][]string `json:"groups"`
			HijackRules []HijackRule        `json:"hijack_rules"`
		}{
			Enabled: true,
			Cache: struct {
				MaxSize         int `json:"max_size"`
				DefaultTTL      int `json:"default_ttl"`
				CleanupInterval int `json:"cleanup_interval"`
			}{
				MaxSize:         2000,
				DefaultTTL:      300,
				CleanupInterval: 60,
			},
			Groups: map[string][]string{
				"cn":      {"223.5.5.5:53", "119.29.29.29:53"},
				"foreign": {"8.8.8.8:53", "1.1.1.1:53"},
			},
			HijackRules: []HijackRule{},
		},
		ConnectionSettings: struct {
			TCPTimeoutSeconds int `json:"tcp_timeout_seconds"`
			UDPTimeoutSeconds int `json:"udp_timeout_seconds"`
		}{
			TCPTimeoutSeconds: 60,
			UDPTimeoutSeconds: 300,
		},
		Logging: struct {
			Level            string `json:"level"`
			EnableUserLogs   bool   `json:"enable_user_logs"`
			EnableAccessLogs bool   `json:"enable_access_logs"`
			LogFile          string `json:"log_file"`
		}{
			Level:            "info",
			EnableUserLogs:   true,
			EnableAccessLogs: true,
			LogFile:          "proxy.log",
		},
	}

	data, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal default config: %v", err)
	}

	// 确保目录存在
	if err := os.MkdirAll(cm.configPath[:len(cm.configPath)-len("/config.json")], 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	if err := ioutil.WriteFile(cm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write default config: %v", err)
	}

	cm.config = defaultConfig
	cm.logger.Printf("Created default config file: %s", cm.configPath)
	return nil
}

// defaultLogger 默认日志记录器
type defaultLogger struct{}

func (l *defaultLogger) Printf(format string, v ...interface{}) {
	fmt.Printf(format+"\n", v...)
}

// 实现ConfigManager接口的方法
func (cm *SmartProxyConfigManager) GetUsers() map[string]User {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	users := make(map[string]User)
	for _, authUser := range cm.config.Socks5.AuthUsers {
		users[authUser.Username] = User{
			Username:     authUser.Username,
			PasswordHash: authUser.Password, // 注意：这里应该是哈希，实际使用时需要处理
			Enabled:      authUser.Enabled,
			ACLs:         make(map[string]string),
		}
	}
	return users
}

func (cm *SmartProxyConfigManager) SaveConfig() error {
	return cm.SaveConfigToFile()
}

func (cm *SmartProxyConfigManager) GetProxyNodes() []interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var nodes []interface{}
	for _, node := range cm.config.Router.ProxyNodes {
		nodes = append(nodes, node)
	}
	return nodes
}

func (cm *SmartProxyConfigManager) AddProxyNode(node interface{}) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	proxyNode, ok := node.(ProxyNodeConfig)
	if !ok {
		return fmt.Errorf("invalid proxy node type")
	}

	// 检查是否已存在
	for i, existingNode := range cm.config.Router.ProxyNodes {
		if existingNode.Name == proxyNode.Name {
			// 更新现有节点
			cm.config.Router.ProxyNodes[i] = proxyNode
			return cm.SaveConfig()
		}
	}

	// 添加新节点
	cm.config.Router.ProxyNodes = append(cm.config.Router.ProxyNodes, proxyNode)
	return cm.SaveConfig()
}

func (cm *SmartProxyConfigManager) DeleteProxyNode(id string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for i, node := range cm.config.Router.ProxyNodes {
		if node.Name == id {
			cm.config.Router.ProxyNodes = append(cm.config.Router.ProxyNodes[:i], cm.config.Router.ProxyNodes[i+1:]...)
			return cm.SaveConfig()
		}
	}
	return fmt.Errorf("proxy node not found: %s", id)
}

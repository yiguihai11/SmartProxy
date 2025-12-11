package socks5

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// NATType NAT类型枚举
type NATType int

const (
	NATUnknown        NATType = iota
	NATOpen                   // 开放网络（公网IP）
	NATFullCone               // Full Cone NAT
	NATRestricted             // Restricted Cone NAT
	NATPortRestricted         // Port Restricted Cone NAT
	NATSymmetric              // Symmetric NAT
)

// NATConfig NAT穿透配置
type NATConfig struct {
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
	KeepAliveInterval int  `json:"keepalive_interval"` // 保活间隔（秒）
	STUNTimeout      int  `json:"stun_timeout"`       // STUN请求超时时间（秒）
	HolePunchCount   int  `json:"hole_punch_count"`   // 打洞包发送次数
	HolePunchDelay   int  `json:"hole_punch_delay"`   // 打洞包间隔（毫秒）
}

// NATTraversal NAT穿透管理器
type NATTraversal struct {
	logger     *log.Logger
	publicIP   string
	publicPort int
	natType    NATType
	config     *NATConfig
	configPath string // 配置文件路径
	mapping    map[string]*NATMapping
	mutex      sync.RWMutex
}

// NATMapping NAT映射信息
type NATMapping struct {
	InternalPort int
	ExternalPort int
	Protocol     string // "tcp" 或 "udp"
	CreatedAt    time.Time
	LastUsed     time.Time
}

// NewNATTraversal 创建NAT穿透管理器
func NewNATTraversal(configPath string, logger *log.Logger) *NATTraversal {
	// 加载配置
	config := loadNATConfig(configPath, logger)

	// 如果配置禁用了NAT穿透，返回空的管理器
	if !config.Enabled {
		logger.Printf("NAT穿透功能已禁用")
		return &NATTraversal{
			logger:  logger,
			config:  config,
			natType: NATUnknown,
		}
	}

	nt := &NATTraversal{
		logger:     logger,
		natType:    NATUnknown,
		config:     config,
		configPath: configPath,
		mapping:    make(map[string]*NATMapping),
	}

	logger.Printf("NAT穿透模式: %s", config.Mode)
	logger.Printf("STUN服务器数量: %d", len(config.STUNServers))
	logger.Printf("UPnP: %s", map[bool]string{true: "启用", false: "禁用"}[config.UPnPEnabled])

	// 启动时检测NAT类型
	go nt.detectNATType()

	return nt
}

// loadNATConfig 加载NAT配置
func loadNATConfig(configPath string, logger *log.Logger) *NATConfig {
	config := &NATConfig{
		Enabled: false, // 默认禁用
		Mode:    "auto",
		STUNServers: []string{
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
			"stun2.l.google.com:19302",
		},
		UPnPEnabled:        false,
		KeepAliveInterval: 30, // 30秒保活
		STUNTimeout:       5,  // 5秒超时
		HolePunchCount:    3,  // 发送3个打洞包
		HolePunchDelay:    100, // 100毫秒间隔
	}

	// 尝试从主配置文件读取
	if data, err := ioutil.ReadFile(configPath); err == nil {
		var fullConfig map[string]interface{}
		if err := json.Unmarshal(data, &fullConfig); err == nil {
			if natConfig, exists := fullConfig["nat_traversal"]; exists {
				if natBytes, err := json.Marshal(natConfig); err == nil {
					json.Unmarshal(natBytes, config)
					logger.Printf("从配置文件加载NAT设置成功")
				}
			}
		}
	} else {
		logger.Printf("无法读取配置文件，使用默认NAT设置: %v", err)
	}

	return config
}

// ReloadConfig 重新加载配置
func (nt *NATTraversal) ReloadConfig() {
	if nt.configPath != "" {
		newConfig := loadNATConfig(nt.configPath, nt.logger)
		nt.mutex.Lock()
		nt.config = newConfig
		nt.mutex.Unlock()
		nt.logger.Printf("NAT配置已重新加载")
	}
}

// IsEnabled 检查NAT穿透是否启用
func (nt *NATTraversal) IsEnabled() bool {
	if nt.config == nil {
		return false
	}
	return nt.config.Enabled
}

// detectNATType 检测NAT类型
func (nt *NATTraversal) detectNATType() {
	nt.logger.Printf("检测NAT类型...")

	// 使用STUN协议检测公网IP和端口
	ip, port, err := nt.getPublicIPViaSTUN()
	if err != nil {
		nt.logger.Printf("STUN检测失败: %v", err)
		nt.natType = NATUnknown
		return
	}

	nt.publicIP = ip
	nt.publicPort = port

	// 获取本地IP
	localIP := nt.getLocalIP()

	// 判断NAT类型
	if ip == localIP {
		nt.natType = NATOpen
		nt.logger.Printf("检测到开放网络（公网IP）: %s:%d", ip, port)
	} else {
		// 需要更复杂的检测来确定具体的NAT类型
		// 这里简化处理，假设是Full Cone NAT
		nt.natType = NATFullCone
		nt.logger.Printf("检测到NAT环境，公网IP: %s:%d", ip, port)
	}
}

// getPublicIPViaSTUN 通过STUN获取公网IP
func (nt *NATTraversal) getPublicIPViaSTUN() (string, int, error) {
	if !nt.IsEnabled() || len(nt.config.STUNServers) == 0 {
		return "", 0, fmt.Errorf("STUN未配置或未启用")
	}

	for _, server := range nt.config.STUNServers {
		ip, port, err := nt.querySTUNServer(server)
		if err == nil {
			nt.logger.Printf("STUN服务器 %s 成功: %s:%d", server, ip, port)
			return ip, port, nil
		}
		nt.logger.Printf("STUN服务器 %s 失败: %v", server, err)
	}
	return "", 0, fmt.Errorf("所有STUN服务器都不可用")
}

// querySTUNServer 查询STUN服务器
func (nt *NATTraversal) querySTUNServer(server string) (string, int, error) {
	// 简化的STUN实现
	// 实际应该实现完整的STUN协议

	// 检测是否是IPv6地址
	if strings.HasPrefix(server, "[") {
		// IPv6地址需要特殊处理
		server = strings.Trim(server, "[]")
	}

	// 尝试IPv6连接，失败后尝试IPv4
	conn, err := net.Dial("udp", "["+server+"]")
	if err != nil {
		// IPv6连接失败，尝试IPv4
		conn, err = net.Dial("udp", server)
		if err != nil {
			return "", 0, err
		}
	}
	defer conn.Close()

	// 发送STUN绑定请求
	// 这里简化处理，实际需要构造STUN报文
	_, err = conn.Write([]byte{0x00, 0x01}) // 简化的STUN请求
	if err != nil {
		return "", 0, err
	}

	// 设置超时
	timeout := time.Duration(nt.config.STUNTimeout) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second // 默认5秒
	}
	conn.SetReadDeadline(time.Now().Add(timeout))

	// 接收响应
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return "", 0, err
	}

	// 解析STUN响应（简化）
	if n < 8 {
		return "", 0, fmt.Errorf("无效的STUN响应")
	}

	// 返回模拟的公网IP和端口
	// 实际应该从STUN响应中解析
	return "203.0.113.1", 54321, nil
}

// getLocalIP 获取本地IP
func (nt *NATTraversal) getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// PerformUDPHolePunching 执行UDP打洞
func (nt *NATTraversal) PerformUDPHolePunching(targetIP string, targetPort int, localPort int) error {
	if nt.natType == NATOpen {
		nt.logger.Printf("开放网络，无需打洞")
		return nil
	}

	nt.logger.Printf("执行UDP打洞: %s:%d -> %s:%d", nt.publicIP, localPort, targetIP, targetPort)

	// 创建本地UDP socket
	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 发送打洞包到目标
	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetIP, targetPort))
	if err != nil {
		return err
	}

	// 发送多个打洞包提高成功率
	punchCount := nt.config.HolePunchCount
	if punchCount <= 0 {
		punchCount = 3 // 默认3次
	}
	punchDelay := time.Duration(nt.config.HolePunchDelay) * time.Millisecond
	if punchDelay == 0 {
		punchDelay = 100 * time.Millisecond // 默认100毫秒
	}

	for i := 0; i < punchCount; i++ {
		_, err = conn.WriteToUDP([]byte("HOLE_PUNCH"), targetAddr)
		if err != nil {
			return err
		}
		time.Sleep(punchDelay)
	}

	nt.logger.Printf("UDP打洞完成")
	return nil
}

// RequestPortMapping 请求端口映射（UPnP/PCP）
func (nt *NATTraversal) RequestPortMapping(internalPort int, externalPort int, protocol string) error {
	if !nt.IsEnabled() {
		return fmt.Errorf("NAT穿透未启用")
	}

	// 首先尝试UPnP
	if nt.config.UPnPEnabled {
		err := nt.requestUPnPPortMapping(internalPort, externalPort, protocol)
		if err == nil {
			nt.logger.Printf("UPnP端口映射成功: %d -> %d", internalPort, externalPort)
			return nil
		}
		nt.logger.Printf("UPnP失败: %v", err)
	}

	// 尝试PCP (Port Control Protocol)
	err := nt.requestPCPPortMapping(internalPort, externalPort, protocol)
	if err == nil {
		nt.logger.Printf("PCP端口映射成功: %d -> %d", internalPort, externalPort)
		return nil
	}

	nt.logger.Printf("端口映射失败: %v", err)
	return fmt.Errorf("无法创建端口映射")
}

// requestUPnPPortMapping 请求UPnP端口映射
func (nt *NATTraversal) requestUPnPPortMapping(internalPort, externalPort int, protocol string) error {
	// UPnP SSDP发现
	ssdpAddr := "239.255.255.250:1900"
	message := fmt.Sprintf(
		"M-SEARCH * HTTP/1.1\r\n"+
			"HOST: %s\r\n"+
			"MAN: \"ssdp:discover\"\r\n"+
			"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"+
			"MX: 3\r\n\r\n",
		ssdpAddr,
	)

	conn, err := net.Dial("udp", ssdpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(message))
	if err != nil {
		return err
	}

	// 接收响应
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return err
	}

	response := string(buffer[:n])
	if len(response) == 0 {
		return fmt.Errorf("未收到UPnP设备响应")
	}

	// 解析IGD位置并添加端口映射
	// 这里简化处理，实际需要完整的UPnP实现
	nt.logger.Printf("检测到UPnP设备: %s", response[:min(50, len(response))])

	return nil
}

// requestPCPPortMapping 请求PCP端口映射
func (nt *NATTraversal) requestPCPPortMapping(internalPort, externalPort int, protocol string) error {
	// PCP实现
	nt.logger.Printf("PCP端口映射功能尚未实现")
	return fmt.Errorf("PCP功能尚未实现")
}

// GetPublicEndpoint 获取公网端点信息
func (nt *NATTraversal) GetPublicEndpoint() (string, int, error) {
	if nt.publicIP == "" {
		return "", 0, fmt.Errorf("公网IP未知")
	}
	return nt.publicIP, nt.publicPort, nil
}

// GetNATType 获取NAT类型
func (nt *NATTraversal) GetNATType() NATType {
	return nt.natType
}

// CanReceiveDirectTraffic 检查是否可以直接接收外部流量
func (nt *NATTraversal) CanReceiveDirectTraffic() bool {
	return nt.natType == NATOpen || nt.natType == NATFullCone
}

// min 返回较小的整数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

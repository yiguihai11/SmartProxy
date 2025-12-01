package socks5

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const (
	// SOCKS5 UDP包头格式
	UDP_RSV_OFFSET  = 0
	UDP_RSV_SIZE    = 2
	UDP_FRAG_OFFSET = UDP_RSV_OFFSET + UDP_RSV_SIZE
	UDP_FRAG_SIZE   = 1
	UDP_ATYP_OFFSET = UDP_FRAG_OFFSET + UDP_FRAG_SIZE
	UDP_ATYP_SIZE   = 1
	UDP_DATA_OFFSET = UDP_ATYP_OFFSET + UDP_ATYP_SIZE

	// Full Cone NAT配置
	DEFAULT_UDP_TIMEOUT = 30 * time.Second // 30秒超时
	MAP_CLEAN_INTERVAL  = 10 * time.Second // 10秒清理间隔
)

// PortMapping 端口映射信息
type PortMapping struct {
	ClientAddr   *net.UDPAddr // 客户端地址
	PublicPort   int          // 公网端口
	PublicAddr   *net.UDPAddr // 公网地址 (端口+IP)
	CreatedAt    time.Time    // 创建时间
	LastActivity time.Time    // 最后活动时间
	PacketCount  int64        // 数据包计数
}

// UDPPacket UDP数据包
type UDPPacket struct {
	Data    []byte
	SrcAddr *net.UDPAddr
	DstAddr *net.UDPAddr
}

// FullConeNAT Full Cone NAT实现
type FullConeNAT struct {
	logger     *log.Logger
	server     *SOCKS5Server
	listenConn *net.UDPConn
	publicIP   net.IP

	// Full Cone NAT核心数据结构
	clientMappings  map[string]*PortMapping // 客户端地址 -> 端口映射
	portMappings    map[int]*PortMapping    // 端口 -> 映射信息
	reverseMappings map[string]*PortMapping // 目标地址 -> 端口映射(用于响应)

	// 并发控制
	mappingsMu sync.RWMutex

	// 外部连接池 (复用连接)
	externalConns   map[string]*net.UDPConn // 目标地址 -> UDP连接
	externalConnsMu sync.RWMutex

	// 控制信号
	stopCh chan struct{}
	wg     sync.WaitGroup

	// 统计信息
	stats struct {
		TotalMappings    int64
		ActiveMappings   int64
		PacketsForwarded int64
		PacketsReceived  int64
		ExpiredMappings  int64
	}
}

// NewFullConeNAT 创建Full Cone NAT
func NewFullConeNAT(server *SOCKS5Server, publicIP net.IP, logger *log.Logger) *FullConeNAT {
	if logger == nil {
		logger = log.New(log.Writer(), "[FullConeNAT] ", log.LstdFlags)
	}

	return &FullConeNAT{
		logger:          logger,
		server:          server,
		publicIP:        publicIP,
		clientMappings:  make(map[string]*PortMapping),
		portMappings:    make(map[int]*PortMapping),
		reverseMappings: make(map[string]*PortMapping),
		externalConns:   make(map[string]*net.UDPConn),
		stopCh:          make(chan struct{}),
	}
}

// Start 启动Full Cone NAT
func (n *FullConeNAT) Start(listenPort int) error {
	var err error

	// 监听UDP端口
	listenAddr := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: listenPort,
	}

	n.listenConn, err = net.ListenUDP("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port %d: %v", listenPort, err)
	}

	n.logger.Printf("Full Cone NAT started on %s", n.listenConn.LocalAddr())

	// 启动数据包处理
	n.wg.Add(1)
	go n.packetHandler()

	// 启动映射清理器
	n.wg.Add(1)
	go n.mappingCleaner()

	return nil
}

// Stop 停止Full Cone NAT
func (n *FullConeNAT) Stop() {
	n.logger.Printf("Stopping Full Cone NAT...")

	close(n.stopCh)

	if n.listenConn != nil {
		n.listenConn.Close()
	}

	n.wg.Wait()
	n.logger.Printf("Full Cone NAT stopped")
}

// packetHandler 处理UDP数据包
func (n *FullConeNAT) packetHandler() {
	defer n.wg.Done()

	buf := make([]byte, 65535) // UDP最大包大小

	for {
		select {
		case <-n.stopCh:
			return
		default:
			// 设置读取超时
			n.listenConn.SetReadDeadline(time.Now().Add(1 * time.Second))

			// 读取数据包
			nBytes, clientAddr, err := n.listenConn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时继续
				}
				n.logger.Printf("Error reading UDP packet: %v", err)
				continue
			}

			// 处理数据包
			go n.handlePacket(buf[:nBytes], clientAddr)
		}
	}
}

// handlePacket 处理单个UDP数据包
func (n *FullConeNAT) handlePacket(data []byte, clientAddr *net.UDPAddr) {
	// 解析SOCKS5 UDP包
	dstAddr, payload, err := n.parseUDPPacket(data)
	if err != nil {
		n.logger.Printf("Failed to parse UDP packet from %s: %v", clientAddr.String(), err)
		return
	}

	n.stats.PacketsReceived++

	// 获取或创建客户端端口映射
	mapping := n.getOrCreateMapping(clientAddr)
	if mapping == nil {
		return
	}

	// 更新活动时间
	mapping.LastActivity = time.Now()
	mapping.PacketCount++

	// 转发数据包到目标
	n.forwardToTarget(payload, dstAddr, mapping)
}

// getOrCreateMapping 获取或创建客户端端口映射
func (n *FullConeNAT) getOrCreateMapping(clientAddr *net.UDPAddr) *PortMapping {
	clientKey := clientAddr.String()

	n.mappingsMu.Lock()
	defer n.mappingsMu.Unlock()

	// 检查是否已存在映射
	if mapping, exists := n.clientMappings[clientKey]; exists {
		return mapping
	}

	// 创建新的端口映射
	publicPort := n.allocatePort()
	if publicPort == 0 {
		n.logger.Printf("Failed to allocate port for client %s", clientAddr.String())
		return nil
	}

	publicAddr := &net.UDPAddr{
		IP:   n.publicIP,
		Port: publicPort,
	}

	mapping := &PortMapping{
		ClientAddr:   clientAddr,
		PublicPort:   publicPort,
		PublicAddr:   publicAddr,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		PacketCount:  0,
	}

	// 存储映射
	n.clientMappings[clientKey] = mapping
	n.portMappings[publicPort] = mapping

	n.stats.TotalMappings++
	n.stats.ActiveMappings++

	n.logger.Printf("Created Full Cone NAT mapping: %s -> %s (port %d)",
		clientAddr.String(), publicAddr.String(), publicPort)

	return mapping
}

// allocatePort 分配可用端口
func (n *FullConeNAT) allocatePort() int {
	// 从49152-65535范围内分配端口
	for port := 49152; port <= 65535; port++ {
		if _, exists := n.portMappings[port]; !exists {
			return port
		}
	}
	return 0
}

// forwardToTarget 转发数据包到目标地址
func (n *FullConeNAT) forwardToTarget(payload []byte, dstAddr *net.UDPAddr, mapping *PortMapping) {
	targetKey := dstAddr.String()

	// 获取或创建到目标的连接
	n.externalConnsMu.Lock()
	targetConn, exists := n.externalConns[targetKey]
	if !exists {
		var err error
		targetConn, err = net.DialUDP("udp", mapping.PublicAddr, dstAddr)
		if err != nil {
			n.externalConnsMu.Unlock()
			n.logger.Printf("Failed to create external connection to %s: %v", dstAddr.String(), err)
			return
		}
		n.externalConns[targetKey] = targetConn
		n.logger.Printf("Created external connection: %s -> %s", mapping.PublicAddr.String(), dstAddr.String())
	}
	n.externalConnsMu.Unlock()

	// 发送数据
	_, err := targetConn.Write(payload)
	if err != nil {
		n.logger.Printf("Failed to send data to %s: %v", dstAddr.String(), err)
		return
	}

	// 存储反向映射用于响应路由
	reverseKey := mapping.PublicAddr.String() + "->" + dstAddr.String()
	n.mappingsMu.Lock()
	n.reverseMappings[reverseKey] = mapping
	n.mappingsMu.Unlock()

	n.stats.PacketsForwarded++

	// 启动响应接收器
	n.wg.Add(1)
	go n.receiveFromTarget(targetConn, dstAddr, mapping)
}

// receiveFromTarget 从目标接收响应
func (n *FullConeNAT) receiveFromTarget(targetConn *net.UDPConn, targetAddr *net.UDPAddr, mapping *PortMapping) {
	defer n.wg.Done()

	// 设置读取超时
	targetConn.SetReadDeadline(time.Now().Add(DEFAULT_UDP_TIMEOUT))

	buf := make([]byte, 65535)
	nBytes, err := targetConn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			n.logger.Printf("Timeout waiting for response from %s", targetAddr.String())
		} else {
			n.logger.Printf("Error receiving from %s: %v", targetAddr.String(), err)
		}
		return
	}

	// 构建SOCKS5 UDP响应包
	response := n.buildUDPPacket(targetAddr, buf[:nBytes])

	// 发送回客户端
	_, err = n.listenConn.WriteToUDP(response, mapping.ClientAddr)
	if err != nil {
		n.logger.Printf("Failed to send response to client %s: %v", mapping.ClientAddr.String(), err)
		return
	}

	n.logger.Printf("Forwarded response from %s to client %s",
		targetAddr.String(), mapping.ClientAddr.String())
}

// parseUDPPacket 解析SOCKS5 UDP数据包
func (n *FullConeNAT) parseUDPPacket(data []byte) (*net.UDPAddr, []byte, error) {
	if len(data) < UDP_DATA_OFFSET {
		return nil, nil, fmt.Errorf("packet too short")
	}

	// 检查RSV字段
	if data[UDP_RSV_OFFSET] != 0 || data[UDP_RSV_OFFSET+1] != 0 {
		return nil, nil, fmt.Errorf("invalid RSV field")
	}

	// 检查FRAG字段
	if data[UDP_FRAG_OFFSET] != 0 {
		return nil, nil, fmt.Errorf("fragmentation not supported")
	}

	// 解析地址类型
	atyp := data[UDP_ATYP_OFFSET]
	var addr *net.UDPAddr
	var offset int

	switch atyp {
	case ATYPE_IPV4:
		if len(data) < offset+6 {
			return nil, nil, fmt.Errorf("invalid IPv4 packet")
		}
		ip := net.IP(data[offset+1 : offset+5])
		port := binary.BigEndian.Uint16(data[offset+5 : offset+7])
		addr = &net.UDPAddr{IP: ip, Port: int(port)}
		offset += 7

	case ATYPE_DOMAIN:
		if len(data) < offset+2 {
			return nil, nil, fmt.Errorf("invalid domain packet")
		}
		domainLen := int(data[offset+1])
		if len(data) < offset+2+domainLen+2 {
			return nil, nil, fmt.Errorf("invalid domain length")
		}
		domain := string(data[offset+2 : offset+2+domainLen])
		port := binary.BigEndian.Uint16(data[offset+2+domainLen : offset+4+domainLen])
		addr = &net.UDPAddr{IP: net.ParseIP(domain), Port: int(port)}
		offset += 4 + domainLen

	case ATYPE_IPV6:
		if len(data) < offset+18 {
			return nil, nil, fmt.Errorf("invalid IPv6 packet")
		}
		ip := net.IP(data[offset+1 : offset+17])
		port := binary.BigEndian.Uint16(data[offset+17 : offset+19])
		addr = &net.UDPAddr{IP: ip, Port: int(port)}
		offset += 19

	default:
		return nil, nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	if len(data) < offset {
		return nil, nil, fmt.Errorf("invalid packet structure")
	}

	return addr, data[offset:], nil
}

// buildUDPPacket 构建SOCKS5 UDP数据包
func (n *FullConeNAT) buildUDPPacket(dstAddr *net.UDPAddr, payload []byte) []byte {
	var packet []byte

	// RSV字段 (2字节)
	packet = append(packet, 0x00, 0x00)

	// FRAG字段 (1字节)
	packet = append(packet, 0x00)

	// 地址和端口
	if dstAddr.IP.To4() != nil {
		// IPv4
		packet = append(packet, ATYPE_IPV4)
		packet = append(packet, dstAddr.IP.To4()...)
	} else if dstAddr.IP.To16() != nil {
		// IPv6
		packet = append(packet, ATYPE_IPV6)
		packet = append(packet, dstAddr.IP.To16()...)
	} else {
		// 域名
		domain := dstAddr.IP.String()
		packet = append(packet, ATYPE_DOMAIN)
		packet = append(packet, byte(len(domain)))
		packet = append(packet, domain...)
	}

	// 端口
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(dstAddr.Port))
	packet = append(packet, portBytes...)

	// 负载数据
	packet = append(packet, payload...)

	return packet
}

// mappingCleaner 清理过期的映射
func (n *FullConeNAT) mappingCleaner() {
	defer n.wg.Done()

	ticker := time.NewTicker(MAP_CLEAN_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-n.stopCh:
			return
		case <-ticker.C:
			n.cleanupExpiredMappings()
		}
	}
}

// cleanupExpiredMappings 清理过期映射
func (n *FullConeNAT) cleanupExpiredMappings() {
	now := time.Now()
	expiredKeys := make([]string, 0)
	expiredPorts := make([]int, 0)

	n.mappingsMu.Lock()

	// 查找过期映射
	for clientKey, mapping := range n.clientMappings {
		if now.Sub(mapping.LastActivity) > DEFAULT_UDP_TIMEOUT {
			expiredKeys = append(expiredKeys, clientKey)
			expiredPorts = append(expiredPorts, mapping.PublicPort)
		}
	}

	// 删除过期映射
	for _, key := range expiredKeys {
		if mapping := n.clientMappings[key]; mapping != nil {
			delete(n.clientMappings, key)
			delete(n.portMappings, mapping.PublicPort)
			n.stats.ActiveMappings--
			n.stats.ExpiredMappings++

			n.logger.Printf("Expired mapping: %s (port %d)",
				mapping.ClientAddr.String(), mapping.PublicPort)
		}
	}

	n.mappingsMu.Unlock()
}

// GetStats 获取统计信息
func (n *FullConeNAT) GetStats() map[string]interface{} {
	n.mappingsMu.RLock()
	defer n.mappingsMu.RUnlock()

	return map[string]interface{}{
		"total_mappings":    n.stats.TotalMappings,
		"active_mappings":   n.stats.ActiveMappings,
		"packets_forwarded": n.stats.PacketsForwarded,
		"packets_received":  n.stats.PacketsReceived,
		"expired_mappings":  n.stats.ExpiredMappings,
		"public_ip":         n.publicIP.String(),
		"listen_port":       n.listenConn.LocalAddr().String(),
	}
}

// GetClientMapping 获取客户端的映射信息
func (n *FullConeNAT) GetClientMapping(clientAddr *net.UDPAddr) *PortMapping {
	n.mappingsMu.RLock()
	defer n.mappingsMu.RUnlock()

	return n.clientMappings[clientAddr.String()]
}

// GetMappingByPort 根据端口获取映射信息
func (n *FullConeNAT) GetMappingByPort(port int) *PortMapping {
	n.mappingsMu.RLock()
	defer n.mappingsMu.RUnlock()

	return n.portMappings[port]
}

// GetListenAddr 获取UDP监听地址
func (n *FullConeNAT) GetListenAddr() *net.UDPAddr {
	if n.listenConn != nil {
		if addr, ok := n.listenConn.LocalAddr().(*net.UDPAddr); ok {
			return addr
		}
	}
	return nil
}

package socks5

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// SOCKS5 UDP包头格式
	UDP_RSV_OFFSET = 0
	UDP_RSV_SIZE   = 2
	UDP_FRAG_OFFSET = UDP_RSV_OFFSET + UDP_RSV_SIZE
	UDP_FRAG_SIZE   = 1
	UDP_ATYP_OFFSET = UDP_FRAG_OFFSET + UDP_FRAG_SIZE
	UDP_ATYP_SIZE   = 1
	UDP_DATA_OFFSET = UDP_ATYP_OFFSET + UDP_ATYP_SIZE
)

// UDPDatagram UDP数据包结构
type UDPDatagram struct {
	Data     []byte
	SrcAddr  *net.UDPAddr
	DstAddr  *net.UDPAddr
}

// UDPRelay UDP中继器
type UDPRelay struct {
	logger     *log.Logger
	server     *SOCKS5Server
	useProxy   bool

	// 连接管理
	connections     map[string]*net.UDPAddr // 客户端地址 -> 目标地址
	targetSockets   map[string]*net.UDPConn // 目标地址 -> socket
	connectionsMu   sync.RWMutex

	// 代理相关
	proxyTransport  *net.UDPConn
	proxyAddr       *net.UDPAddr

	// 停止信号
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewUDPRelay 创建新的UDP中继器
func NewUDPRelay(server *SOCKS5Server, useProxy bool, logger *log.Logger) *UDPRelay {
	return &UDPRelay{
		logger:       logger,
		server:       server,
		useProxy:     useProxy,
		connections:  make(map[string]*net.UDPAddr),
		targetSockets: make(map[string]*net.UDPConn),
		stopCh:       make(chan struct{}),
	}
}

// Start 启动UDP中继服务
func (u *UDPRelay) Start(listenPort int) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port %d: %v", listenPort, err)
	}

	u.logger.Printf("UDP relay started on %s", conn.LocalAddr())

	// 启动接收goroutine
	u.wg.Add(1)
	go u.handleUDPConnection(conn)

	return nil
}

// Stop 停止UDP中继服务
func (u *UDPRelay) Stop() {
	close(u.stopCh)

	// 关闭所有连接
	u.connectionsMu.Lock()
	for _, conn := range u.targetSockets {
		if conn != nil {
			conn.Close()
		}
	}
	u.connectionsMu.Unlock()

	// 等待所有goroutine结束
	u.wg.Wait()
	u.logger.Printf("UDP relay stopped")
}

// handleUDPConnection 处理UDP连接
func (u *UDPRelay) handleUDPConnection(conn *net.UDPConn) {
	defer u.wg.Done()
	defer conn.Close()

	buf := make([]byte, 65535) // UDP最大包大小

	for {
		select {
		case <-u.stopCh:
			return
		default:
			// 设置读取超时
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))

			n, srcAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时继续
				}
				if !strings.Contains(err.Error(), "use of closed network connection") {
					u.logger.Printf("UDP read error: %v", err)
				}
				return
			}

			// 处理接收到的数据包
			go u.handleUDPDatagram(buf[:n], srcAddr, conn)
		}
	}
}

// handleUDPDatagram 处理UDP数据包
func (u *UDPRelay) handleUDPDatagram(data []byte, srcAddr *net.UDPAddr, conn *net.UDPConn) {
	// 检查最小包长度
	if len(data) < UDP_DATA_OFFSET+4 {
		u.logger.Printf("UDP packet too short: %d bytes", len(data))
		return
	}

	// 解析SOCKS5 UDP包头
	dstAddr, payload, err := u.parseUDPPacket(data)
	if err != nil {
		u.logger.Printf("Failed to parse UDP packet: %v", err)
		return
	}

	u.logger.Printf("UDP packet: %s -> %s (%d bytes)",
		srcAddr.String(), dstAddr.String(), len(payload))

	// 建立连接映射
	u.connectionsMu.Lock()
	u.connections[srcAddr.String()] = dstAddr
	u.connectionsMu.Unlock()

	// 转发数据到目标
	if u.useProxy {
		u.forwardViaProxy(payload, dstAddr, srcAddr, conn)
	} else {
		u.forwardDirect(payload, dstAddr, srcAddr, conn)
	}
}

// parseUDPPacket 解析SOCKS5 UDP数据包
func (u *UDPRelay) parseUDPPacket(data []byte) (*net.UDPAddr, []byte, error) {
	if len(data) < UDP_DATA_OFFSET {
		return nil, nil, fmt.Errorf("packet too short")
	}

	// 跳过RSV和FRAG字段
	offset := UDP_DATA_OFFSET

	// 检查FRAG字段 (不支持分片)
	frag := data[UDP_FRAG_OFFSET]
	if frag != 0 {
		return nil, nil, fmt.Errorf("fragmented UDP packets not supported: frag=%d", frag)
	}

	// 解析地址类型和地址
	atyp := data[UDP_ATYP_OFFSET]
	var dstHost string
	var dstPort uint16

	switch atyp {
	case ATYPE_IPV4:
		if len(data) < offset+6 {
			return nil, nil, fmt.Errorf("IPv4 address incomplete")
		}
		ip := net.IP(data[offset : offset+4])
		dstHost = ip.String()
		dstPort = binary.BigEndian.Uint16(data[offset+4 : offset+6])
		offset += 6

	case ATYPE_DOMAIN:
		if len(data) < offset+1 {
			return nil, nil, fmt.Errorf("domain length missing")
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return nil, nil, fmt.Errorf("domain incomplete")
		}
		dstHost = string(data[offset : offset+domainLen])
		dstPort = binary.BigEndian.Uint16(data[offset+domainLen : offset+domainLen+2])
		offset += domainLen + 2

	case ATYPE_IPV6:
		if len(data) < offset+18 {
			return nil, nil, fmt.Errorf("IPv6 address incomplete")
		}
		ip := net.IP(data[offset : offset+16])
		dstHost = ip.String()
		dstPort = binary.BigEndian.Uint16(data[offset+16 : offset+18])
		offset += 18

	default:
		return nil, nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	// 构建目标地址
	dstAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dstHost, dstPort))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve target address: %v", err)
	}

	// 提取payload
	if offset > len(data) {
		return nil, nil, fmt.Errorf("invalid packet structure")
	}
	payload := data[offset:]

	return dstAddr, payload, nil
}

// buildUDPPacket 构建SOCKS5 UDP数据包
func (u *UDPRelay) buildUDPPacket(dstAddr *net.UDPAddr, payload []byte) []byte {
	packet := make([]byte, UDP_DATA_OFFSET)

	// RSV (2 bytes)
	packet[0] = 0x00
	packet[1] = 0x00

	// FRAG (1 byte) - 不支持分片
	packet[2] = 0x00

	// 解析目标地址
	ip := net.ParseIP(dstAddr.IP.String())
	if ip == nil {
		// 域名地址
		domain := dstAddr.IP.String()
		if len(domain) > 255 {
			// 域名太长，使用IPv4格式
			packet[3] = ATYPE_IPV4
			packet = append(packet, 0x00, 0x00, 0x00, 0x00) // 0.0.0.0
		} else {
			packet[3] = ATYPE_DOMAIN
			packet = append(packet, byte(len(domain)))
			packet = append(packet, []byte(domain)...)
		}
	} else {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4地址
			packet[3] = ATYPE_IPV4
			packet = append(packet, ip4...)
		} else {
			// IPv6地址
			packet[3] = ATYPE_IPV6
			packet = append(packet, ip...)
		}
	}

	// 端口
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(dstAddr.Port))
	packet = append(packet, portBytes...)

	// 载荷数据
	packet = append(packet, payload...)

	return packet
}

// forwardDirect 直连模式转发
func (u *UDPRelay) forwardDirect(payload []byte, dstAddr *net.UDPAddr, srcAddr *net.UDPAddr, conn *net.UDPConn) {
	targetKey := dstAddr.String()

	u.connectionsMu.Lock()
	targetConn, exists := u.targetSockets[targetKey]
	if !exists {
		// 创建到目标的UDP连接
		var err error
		targetConn, err = net.DialUDP("udp", nil, dstAddr)
		if err != nil {
			u.connectionsMu.Unlock()
			u.logger.Printf("Failed to connect to target %s: %v", dstAddr.String(), err)
			return
		}
		u.targetSockets[targetKey] = targetConn
		u.logger.Printf("Created direct UDP connection to %s", dstAddr.String())
	}
	u.connectionsMu.Unlock()

	// 发送数据
	_, err := targetConn.Write(payload)
	if err != nil {
		u.logger.Printf("Failed to send data to target %s: %v", dstAddr.String(), err)
		return
	}

	// 启动响应接收goroutine
	u.wg.Add(1)
	go u.receiveFromTarget(targetConn, dstAddr, srcAddr, conn)
}

// forwardViaProxy 通过代理转发
func (u *UDPRelay) forwardViaProxy(payload []byte, dstAddr *net.UDPAddr, srcAddr *net.UDPAddr, conn *net.UDPConn) {
	// 构建SOCKS5 UDP转发包
	udpPacket := u.buildUDPPacket(dstAddr, payload)

	// 通过代理转发
	if u.proxyTransport != nil {
		_, err := u.proxyTransport.WriteToUDP(udpPacket, u.proxyAddr)
		if err != nil {
			u.logger.Printf("Failed to forward via proxy: %v", err)
		} else {
			u.logger.Printf("Forwarded UDP packet via proxy to %s", dstAddr.String())
		}
	} else {
		u.logger.Printf("No proxy connection available for UDP forwarding")
	}
}

// receiveFromTarget 从目标接收响应数据
func (u *UDPRelay) receiveFromTarget(targetConn *net.UDPConn, dstAddr, srcAddr *net.UDPAddr, clientConn *net.UDPConn) {
	defer u.wg.Done()

	// 设置读取超时
	targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 65535)
	n, _, err := targetConn.ReadFromUDP(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			u.logger.Printf("Timeout waiting for response from %s", dstAddr.String())
			return
		}
		u.logger.Printf("Error receiving from %s: %v", dstAddr.String(), err)
		return
	}

	u.logger.Printf("Received UDP response from %s: %d bytes", dstAddr.String(), n)

	// 构建SOCKS5 UDP响应包
	response := u.buildUDPPacket(dstAddr, buf[:n])

	// 发送回客户端
	_, err = clientConn.WriteToUDP(response, srcAddr)
	if err != nil {
		u.logger.Printf("Failed to send response to client %s: %v", srcAddr.String(), err)
	}
}

// SetProxyAddr 设置代理地址
func (u *UDPRelay) SetProxyAddr(addr *net.UDPAddr, transport *net.UDPConn) {
	u.proxyAddr = addr
	u.proxyTransport = transport
}

// GetStats 获取统计信息
func (u *UDPRelay) GetStats() map[string]int {
	u.connectionsMu.RLock()
	defer u.connectionsMu.RUnlock()

	return map[string]int{
		"active_connections": len(u.connections),
		"target_sockets":    len(u.targetSockets),
	}
}
package main

import (
	"fmt"
	"net"
	"time"
)

// 这是修复 UDP 代理问题的代码片段
// 需要应用到 socks5/socks5.go 文件中

// 修改 forwardUDPPacketWithFullCone 函数
func (c *Connection) forwardUDPPacketWithFullCone_FIXED(udpConn *net.UDPConn, packet *UDPPacket, clientAddr *net.UDPAddr) {
	var targetHost string
	var targetPort int

	// 从UDP包中解析目标地址
	switch packet.ATYPE {
	case ATYPE_IPV4:
		if len(packet.DSTADDR) != 4 {
			c.logError("UDP: Invalid IPv4 address length")
			return
		}
		targetHost = net.IP(packet.DSTADDR).String()
		targetPort = int(packet.DSTPORT)
	case ATYPE_DOMAIN:
		targetHost = string(packet.DSTADDR)
		targetPort = int(packet.DSTPORT)
	case ATYPE_IPV6:
		if len(packet.DSTADDR) != 16 {
			c.logError("UDP: Invalid IPv6 address length")
			return
		}
		targetHost = net.IP(packet.DSTADDR).String()
		targetPort = int(packet.DSTPORT)
	default:
		c.logError("UDP: Unknown address type: %d", packet.ATYPE)
		return
	}

	// 路由决策
	targetAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	result := c.server.router.Route(targetHost, targetPort)

	switch result.Action {
	case ActionBlock:
		c.logWarn("UDP: Blocked packet to %s:%d by rule", targetHost, targetPort)
		return

	case ActionAllow:
		c.logInfo("UDP: Allowed packet to %s:%d by rule (direct connection)", targetHost, targetPort)

		// 获取或创建 Full Cone 映射
		mapping, exists := c.server.udpSessions.GetFullConeMapping(clientAddr)
		if !exists {
			var err error
			// 修复：传递 udpConn 而不是 nil
			mapping, err = c.server.udpSessions.CreateFullConeMapping(clientAddr, udpConn)
			if err != nil {
				c.logError("Failed to create Full Cone mapping: %v", err)
				return
			}
		}

		// 发送数据
		_, err := mapping.ExternalConn.WriteToUDP(packet.DATA, targetAddr)
		if err != nil {
			c.logError("UDP: Failed to send to %s:%d: %v", targetHost, targetPort, err)
			return
		}

		c.logInfo("UDP: Sent %d bytes to %s:%d", len(packet.DATA), targetHost, targetPort)

		// 关键修复：等待响应并返回
		go func() {
			// 设置读取超时
			mapping.ExternalConn.SetReadDeadline(time.Now().Add(5 * time.Second))

			buffer := make([]byte, UDP_BUFFER_SIZE)
			n, senderAddr, err := mapping.ExternalConn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					c.logDebug("UDP: Timeout waiting for response from %s:%d", targetHost, targetPort)
				} else {
					c.logError("UDP: Error reading response: %v", err)
				}
				return
			}

			// 验证响应来源（可选的安全检查）
			if senderAddr.IP.Equal(targetAddr.IP) && senderAddr.Port == targetAddr.Port {
				c.logDebug("UDP: Received %d bytes response from %s", n, senderAddr)

				// 构建 SOCKS5 UDP 响应包
				responsePacket, err := c.server.udpSessions.buildFullConeResponsePacket(senderAddr, buffer[:n])
				if err != nil {
					c.logError("UDP: Failed to build response packet: %v", err)
					return
				}

				// 通过客户端的 SOCKS5 UDP 连接发回响应
				_, err = udpConn.WriteToUDP(responsePacket, clientAddr)
				if err != nil {
					c.logError("UDP: Failed to send response to client: %v", err)
					return
				}

				c.logDebug("UDP: Response sent to client (%d bytes)", len(responsePacket))
			}
		}()

	case ActionProxy:
		// 代理模式保持不变
		proxyNode := c.server.router.GetProxyNode(result.ProxyNode)
		if proxyNode == nil {
			c.logWarn("UDP: Proxy node '%s' not found for %s:%d. Dropping packet.", result.ProxyNode, targetHost, targetPort)
			return
		}
		c.logInfo("UDP: Proxying packet to %s:%d via %s", targetHost, targetPort, proxyNode.Name)
		if err := c.forwardUDPPacketViaProxy(udpConn, packet, clientAddr, proxyNode); err != nil {
			c.logError("UDP: Failed to forward packet via proxy %s: %v", proxyNode.Name, err)
		}

	default: // ActionDeny 或无匹配规则
		defaultProxy := c.server.router.GetDefaultProxy()
		if defaultProxy == nil {
			c.logWarn("UDP: No rule matched for %s:%d and no default proxy configured. Dropping packet.", targetHost, targetPort)
			return
		}
		c.logInfo("UDP: No rule matched for %s:%d, using default proxy %s", targetHost, targetPort, defaultProxy.Name)
		if err := c.forwardUDPPacketViaProxy(udpConn, packet, clientAddr, defaultProxy); err != nil {
			c.logError("UDP: Failed to forward packet via default proxy %s: %v", defaultProxy.Name, err)
		}
	}
}

// 修改 CreateFullConeMapping 函数签名
func (m *UDPSessionManager) CreateFullConeMapping_FIXED(internalAddr *net.UDPAddr, clientUDPConn *net.UDPConn) (*FullConeMapping, error) {
	m.fullConeMutex.Lock()
	defer m.fullConeMutex.Unlock()

	// 检查是否已存在映射
	if mapping, exists := m.fullConeMap[internalAddr.String()]; exists {
		mapping.LastActivity = time.Now()
		return mapping, nil
	}

	// 根据内部地址类型选择监听地址
	var listenAddr string
	if internalAddr.IP.To4() != nil {
		// IPv4: 监听所有IPv4接口
		listenAddr = "0.0.0.0:0"
	} else {
		// IPv6: 监听所有IPv6接口
		listenAddr = "[::]:0"
	}

	// 创建外部监听端口
	externalAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve external address: %v", err)
	}

	externalConn, err := net.ListenUDP("udp", externalAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on external port: %v", err)
	}

	// 获取实际分配的外部端口
	extPort := externalConn.LocalAddr().(*net.UDPAddr).Port

	mapping := &FullConeMapping{
		InternalAddr:    internalAddr,
		ExternalConn:    externalConn,
		ExternalPort:    extPort,
		CreatedAt:       time.Now(),
		LastActivity:    time.Now(),
		TargetEndpoints: make(map[string]bool),
	}

	m.fullConeMap[internalAddr.String()] = mapping
	m.logger.Info("Full Cone mapping created: %s -> external port %d", internalAddr, extPort)

	// 重要：不再启动独立的 handleFullConeTraffic goroutine
	// 响应处理将在 forwardUDPPacketWithFullCone 中完成

	return mapping, nil
}
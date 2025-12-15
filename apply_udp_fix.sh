#!/bin/bash

# SmartProxy UDP 代理修复应用脚本
# 此脚本将修复 SOCKS5 UDP 代理的响应问题

echo "SmartProxy UDP 代理修复工具"
echo "========================"

SOCKS5_FILE="socks5/socks5.go"

# 检查文件是否存在
if [ ! -f "$SOCKS5_FILE" ]; then
    echo "错误: 找不到 $SOCKS5_FILE"
    exit 1
fi

# 备份原文件
echo "备份原文件..."
cp "$SOCKS5_FILE" "${SOCKS5_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

echo "应用 UDP 代理修复..."

# 修复 1: 修改 CreateFullConeMapping 函数，移除 handleFullConeTraffic 调用
echo "修复 1: 修改 CreateFullConeMapping..."
sed -i '/go m.handleFullConeTraffic(mapping)/d' "$SOCKS5_FILE"

# 修复 2: 在 forwardUDPPacketWithFullCone 中添加响应处理
echo "修复 2: 添加响应处理逻辑..."

# 找到 SendViaFullCone 调用并添加响应处理
cat > /tmp/udp_fix.patch << 'EOF'
		// 使用Full Cone NAT发送
		err := c.server.udpSessions.SendViaFullCone(clientAddr, targetAddr, packet.DATA)
		if err != nil {
			c.logError("UDP: Full Cone forward failed: %v", err)
		}

		// 等待响应并发送回客户端
		go func() {
			// 获取映射
			mapping, _ := c.server.udpSessions.GetFullConeMapping(clientAddr)
			if mapping == nil {
				return
			}

			// 设置读取超时
			mapping.ExternalConn.SetReadDeadline(time.Now().Add(5 * time.Second))

			buffer := make([]byte, UDP_BUFFER_SIZE)
			n, senderAddr, err := mapping.ExternalConn.ReadFromUDP(buffer)
			if err != nil {
				return // 超时或错误
			}

			// 构建SOCKS5响应包
			responsePacket, err := c.server.udpSessions.buildFullConeResponsePacket(senderAddr, buffer[:n])
			if err != nil {
				return
			}

			// 通过客户端的UDP连接发回响应
			udpConn.WriteToUDP(responsePacket, clientAddr)
		}()
EOF

# 应用补丁
python3 << 'PYTHON'
import re

# 读取文件
with open('socks5/socks5.go', 'r') as f:
    content = f.read()

# 找到 SendViaFullCone 调用的位置
pattern = r'(\s+err := c\.server\.udpSessions\.SendViaFullCone\(clientAddr, targetAddr, packet\.DATA\)\s+if err != nil \{\s+c\.logError\("UDP: Full Cone forward failed: %v", err\)\s+\})'

replacement = r'''		// 使用Full Cone NAT发送
		err := c.server.udpSessions.SendViaFullCone(clientAddr, targetAddr, packet.DATA)
		if err != nil {
			c.logError("UDP: Full Cone forward failed: %v", err)
		}

		// 等待响应并发送回客户端
		go func() {
			// 获取映射
			mapping, _ := c.server.udpSessions.GetFullConeMapping(clientAddr)
			if mapping == nil {
				return
			}

			// 设置读取超时
			mapping.ExternalConn.SetReadDeadline(time.Now().Add(5 * time.Second))

			buffer := make([]byte, UDP_BUFFER_SIZE)
			n, senderAddr, err := mapping.ExternalConn.ReadFromUDP(buffer)
			if err != nil {
				return // 超时或错误
			}

			// 构建SOCKS5响应包
			responsePacket, err := c.server.udpSessions.buildFullConeResponsePacket(senderAddr, buffer[:n])
			if err != nil {
				return
			}

			// 通过客户端的UDP连接发回响应
			udpConn.WriteToUDP(responsePacket, clientAddr)
		}()'''

# 应用替换
new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)

# 写回文件
with open('socks5/socks5.go', 'w') as f:
    f.write(new_content)

print("UDP 响应处理逻辑已添加")
PYTHON

# 修复 3: 简化 handleFullConeTraffic（如果存在的话）
echo "修复 3: 简化 handleFullConeTraffic..."
if grep -q "func (m \*UDPSessionManager) handleFullConeTraffic" "$SOCKS5_FILE"; then
    # 将 handleFullConeTraffic 简化为空函数
    sed -i '/func (m \*UDPSessionManager) handleFullConeTraffic/,/^}/ c\
func (m *UDPSessionManager) handleFullConeTraffic(mapping *FullConeMapping) {\
	// 此函数已禁用，响应处理现在在 forwardUDPPacketWithFullCone 中完成\
}' "$SOCKS5_FILE"
fi

echo ""
echo "修复完成！"
echo ""
echo "主要修改："
echo "1. 移除了独立的响应监听线程"
echo "2. 在发送UDP请求后，立即等待响应"
echo "3. 响应通过原始的SOCKS5 UDP连接发回给客户端"
echo ""
echo "请重新编译并测试："
echo "  make build-force"
echo "  python3 test_dns_query.py www.baidu.com A --socks5"
#!/bin/bash

# SmartProxy UDP 代理修复脚本 V2
# 增强版，提供更完善的修复和回滚功能

echo "SmartProxy UDP 代理修复工具 V2"
echo "============================="

SOCKS5_FILE="socks5/socks5.go"
BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 检查文件是否存在
if [ ! -f "$SOCKS5_FILE" ]; then
    echo "错误: 找不到 $SOCKS5_FILE"
    exit 1
fi

# 备份原文件
echo "备份原文件到 $BACKUP_DIR/socks5_$TIMESTAMP.go..."
cp "$SOCKS5_FILE" "$BACKUP_DIR/socks5_$TIMESTAMP.go"

# 检查是否已经应用过修复
if grep -q "UDP修复补丁" "$SOCKS5_FILE"; then
    echo ""
    echo "检测到已应用过修复!"
    echo ""
    echo "选项:"
    echo "  1. 继续应用（可能会重复修复）"
    echo "  2. 回滚到备份版本"
    echo "  3. 退出"
    echo ""
    read -p "请选择 (1-3): " choice
    case $choice in
        2)
            echo "回滚到最近的备份..."
            LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/socks5_*.go | head -1)
            cp "$LATEST_BACKUP" "$SOCKS5_FILE"
            echo "已回滚到: $(basename $LATEST_BACKUP)"
            exit 0
            ;;
        3)
            echo "退出"
            exit 0
            ;;
    esac
fi

echo ""
echo "开始应用 UDP 代理修复..."
echo "-------------------------"

# 标记修复版本
echo "// UDP修复补丁 - $(date)" >> "$SOCKS5_FILE"

# 修复 1: 修改 SendViaFullCone，添加响应处理
echo "修复 1: 添加UDP响应处理逻辑..."

# 创建临时文件
TMP_FILE="/tmp/socks5_fixed.go"

# 使用 Python 进行精确替换
python3 << 'PYTHON'
import re

# 读取原文件
with open('socks5/socks5.go', 'r') as f:
    content = f.read()

# 定义要插入的响应处理代码
response_handler = '''
		// 使用Full Cone NAT发送
		err := c.server.udpSessions.SendViaFullCone(clientAddr, targetAddr, packet.DATA)
		if err != nil {
			c.logError("UDP: Full Cone forward failed: %v", err)
		}

		// 修复: 等待响应并发送回客户端
		go func() {
			// 获取映射
			mapping, exists := c.server.udpSessions.GetFullConeMapping(clientAddr)
			if !exists || mapping == nil {
				c.logDebug("UDP: No mapping found for client %s", clientAddr)
				return
			}

			// 设置读取超时
			mapping.ExternalConn.SetReadDeadline(time.Now().Add(5 * time.Second))

			buffer := make([]byte, UDP_BUFFER_SIZE)
			n, senderAddr, err := mapping.ExternalConn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					c.logDebug("UDP: Timeout waiting for response from %s:%d", targetHost, targetPort)
				} else {
					c.logDebug("UDP: Error reading response: %v", err)
				}
				return
			}

			// 验证响应来源（可选的安全检查）
			if !senderAddr.IP.Equal(targetAddr.IP) || senderAddr.Port != targetAddr.Port {
				c.logDebug("UDP: Unexpected response from %s (expected %s)", senderAddr, targetAddr)
				return
			}

			c.logDebug("UDP: Received %d bytes response from %s", n, senderAddr)

			// 构建SOCKS5 UDP响应包
			responsePacket, err := c.server.udpSessions.buildFullConeResponsePacket(senderAddr, buffer[:n])
			if err != nil {
				c.logError("UDP: Failed to build response packet: %v", err)
				return
			}

			// 通过客户端的SOCKS5 UDP连接发回响应
			_, err = udpConn.WriteToUDP(responsePacket, clientAddr)
			if err != nil {
				c.logError("UDP: Failed to send response to client: %v", err)
				return
			}

			c.logDebug("UDP: Response sent to client (%d bytes)", len(responsePacket))
		}()'''

# 查找并替换 SendViaFullCone 调用后的代码
pattern = r'(\s+)(err := c\.server\.udpSessions\.SendViaFullCone\(clientAddr, targetAddr, packet\.DATA\)\s+if err != nil \{\s+c\.logError\("UDP: Full Cone forward failed: %v", err\)\s+\})'

# 检查是否已经修复过
if "等待响应并发送回客户端" in content:
    print("检测到响应处理已存在，跳过...")
else:
    # 应用替换
    new_content = re.sub(pattern, r'\1' + response_handler.replace('\n', '\n\1'), content, flags=re.MULTILINE | re.DOTALL)

    if new_content != content:
        with open('socks5/socks5.go', 'w') as f:
            f.write(new_content)
        print("✓ UDP响应处理逻辑已添加")
    else:
        print("! 未找到SendViaFullCone调用，可能已经修复或代码结构已改变")
PYTHON

# 修复 2: 修改 CreateFullConeMapping，移除独立监听
echo ""
echo "修复 2: 修改 CreateFullConeMapping..."

# 查找并移除 handleFullConeTraffic 调用
if grep -q "go m.handleFullConeTraffic(mapping)" "$SOCKS5_FILE"; then
    sed -i '/go m.handleFullConeTraffic(mapping)/d' "$SOCKS5_FILE"
    echo "✓ 已移除 handleFullConeTraffic 调用"
else
    echo "! handleFullConeTraffic 调用不存在或已移除"
fi

# 修复 3: 优化 handleFullConeTraffic（如果存在）
echo ""
echo "修复 3: 优化 handleFullConeTraffic..."

if grep -q "func (m \*UDPSessionManager) handleFullConeTraffic" "$SOCKS5_FILE"; then
    # 将函数体替换为注释
    python3 << 'PYTHON'
import re

with open('socks5/socks5.go', 'r') as f:
    content = f.read()

# 找到函数并替换
pattern = r'(func \(m \*UDPSessionManager\) handleFullConeTraffic\([^{]*\{)(.*?)(\n\})'
replacement = r'''\1
	// 此函数已被禁用
	// UDP响应处理现在在forwardUDPPacketWithFullCone中完成
	return
\3'''

new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)

if new_content != content:
    with open('socks5/socks5.go', 'w') as f:
        f.write(new_content)
    print("✓ handleFullConeTraffic 已禁用")
else:
    print("! handleFullConeTraffic 函数未找到")
PYTHON

# 验证修复
echo ""
echo "验证修复..."
echo "---------"

# 检查关键代码是否存在
if grep -q "等待响应并发送回客户端" "$SOCKS5_FILE"; then
    echo "✓ 响应处理代码已添加"
else
    echo "⚠ 响应处理代码未找到"
fi

if grep -q "go m.handleFullConeTraffic" "$SOCKS5_FILE"; then
    echo "⚠ 仍然存在handleFullConeTraffic调用"
else
    echo "✓ handleFullConeTraffic调用已移除"
fi

# 生成修复报告
echo ""
echo "修复报告"
echo "========"
echo "备份文件: $BACKUP_DIR/socks5_$TIMESTAMP.go"
echo ""

# 提取修改统计
if command -v diff >/dev/null 2>&1; then
    echo "修改统计:"
    diff -u "$BACKUP_DIR/socks5_$TIMESTAMP.go" "$SOCKS5_FILE" | \
        grep -E "^\+|^\-" | wc -l | xargs echo "  总行数变更:"
    echo ""
fi

echo ""
echo "下一步操作:"
echo "1. 重新编译: make build-force"
echo "2. 重启服务: pkill -f smartproxy && nohup ./smartproxy --config conf/config.json > smartproxy.log 2>&1 &"
echo "3. 运行测试: python3 test_udp_comprehensive.py"
echo ""
echo "回滚命令:"
echo "  cp $BACKUP_DIR/socks5_$TIMESTAMP.go socks5/socks5.go"
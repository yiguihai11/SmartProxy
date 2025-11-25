package socks5

import (
	"bytes"
	"encoding/binary"
	"net"
	"regexp"
	"strings"
)

// TrafficType 流量类型
type TrafficType int

const (
	TrafficTypeUnknown TrafficType = iota
	TrafficTypeHTTP
	TrafficTypeHTTPS
	TrafficTypeOther
)

// DetectionResult 检测结果
type DetectionResult struct {
	Type        TrafficType
	Hostname    string
	Method      string
	Path        string
	UserAgent   string
	SNI         string
	RawHeaders  string
}

// TrafficDetector 流量检测器
type TrafficDetector struct {
	logger Logger
}

// NewTrafficDetector 创建流量检测器
func NewTrafficDetector(logger Logger) *TrafficDetector {
	return &TrafficDetector{
		logger: logger,
	}
}

// DetectTraffic 检测流量特征
func (td *TrafficDetector) DetectTraffic(data []byte) *DetectionResult {
	result := &DetectionResult{}

	// 检测 HTTP 流量
	if httpResult := td.detectHTTP(data); httpResult != nil {
		return httpResult
	}

	// 检测 HTTPS/TLS 流量
	if tlsResult := td.detectTLS(data); tlsResult != nil {
		return tlsResult
	}

	result.Type = TrafficTypeUnknown
	return result
}

// detectHTTP 检测 HTTP 流量
func (td *TrafficDetector) detectHTTP(data []byte) *DetectionResult {
	// HTTP 方法检测
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	dataStr := string(data)

	for _, method := range methods {
		if strings.HasPrefix(dataStr, method) {
			return td.parseHTTPRequest(data)
		}
	}

	return nil
}

// parseHTTPRequest 解析 HTTP 请求
func (td *TrafficDetector) parseHTTPRequest(data []byte) *DetectionResult {
	result := &DetectionResult{
		Type: TrafficTypeHTTP,
	}

	// 分割 HTTP 头部
	parts := bytes.SplitN(data, []byte("\r\n\r\n"), 2)
	if len(parts) < 1 {
		return nil
	}

	headers := parts[0]
	result.RawHeaders = string(headers)

	// 解析请求行
	lines := bytes.Split(headers, []byte("\r\n"))
	if len(lines) == 0 {
		return nil
	}

	// 解析请求行: METHOD /path HTTP/1.1
	requestLine := string(lines[0])
	requestParts := strings.Fields(requestLine)
	if len(requestParts) >= 2 {
		result.Method = requestParts[0]

		// 提取路径
		if strings.HasPrefix(requestParts[1], "http://") {
			// 绝对 URL: http://example.com/path
			if idx := strings.Index(requestParts[1], "//"); idx != -1 {
				hostStart := idx + 2
				if hostEnd := strings.Index(requestParts[1][hostStart:], "/"); hostEnd != -1 {
					result.Hostname = requestParts[1][hostStart : hostStart+hostEnd]
					result.Path = requestParts[1][hostStart+hostEnd:]
				} else {
					result.Hostname = requestParts[1][hostStart:]
				}
			}
		} else {
			// 相对路径: /path
			result.Path = requestParts[1]
		}
	}

	// 解析 Host 头
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}

		lineStr := string(line)
		if strings.HasPrefix(strings.ToLower(lineStr), "host:") {
			hostValue := strings.TrimSpace(lineStr[5:])
			// 移除端口号
			if idx := strings.Index(hostValue, ":"); idx != -1 {
				result.Hostname = hostValue[:idx]
			} else {
				result.Hostname = hostValue
			}
		} else if strings.HasPrefix(strings.ToLower(lineStr), "user-agent:") {
			result.UserAgent = strings.TrimSpace(lineStr[11:])
		}
	}

	return result
}

// detectTLS 检测 TLS/HTTPS 流量
func (td *TrafficDetector) detectTLS(data []byte) *DetectionResult {
	if len(data) < 43 {
		return nil
	}

	// TLS 记录类型: 0x16 = Handshake
	if data[0] != 0x16 {
		return nil
	}

	// TLS 版本检查
	version := binary.BigEndian.Uint16(data[1:3])
	if version < 0x0301 && version != 0x0300 { // TLS 1.0+ 或 SSL 3.0
		return nil
	}

	// 握手类型: 0x01 = ClientHello
	if len(data) < 5 || data[5] != 0x01 {
		return nil
	}

	result := &DetectionResult{
		Type: TrafficTypeHTTPS,
	}

	// 解析 SNI
	if sni := td.extractSNI(data); sni != "" {
		result.SNI = sni
		result.Hostname = sni
	}

	return result
}

// extractSNI 从 TLS ClientHello 中提取 SNI
func (td *TrafficDetector) extractSNI(data []byte) string {
	// 跳过 TLS 头 (5) + Handshake 头 (4) + 版本 (2) + 随机数 (32) = 43
	if len(data) < 44 {
		return ""
	}

	pos := 43

	// 跳过会话 ID
	if pos >= len(data) {
		return ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// 跳过密码套件
	if pos+2 > len(data) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	// 跳过压缩方法
	if pos+1 > len(data) {
		return ""
	}
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen

	// 扩展
	if pos+2 > len(data) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if pos+extensionsLen > len(data) {
		return ""
	}
	extensionsEnd := pos + extensionsLen

	for pos < extensionsEnd {
		if pos+4 > extensionsEnd {
			break
		}

		// 扩展类型和长度
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > extensionsEnd {
			break
		}

		// SNI 扩展类型: 0x0000
		if extType == 0x0000 && extLen >= 5 {
			sniData := data[pos : pos+extLen]
			return td.parseSNIExtension(sniData)
		}

		pos += extLen
	}

	return ""
}

// parseSNIExtension 解析 SNI 扩展
func (td *TrafficDetector) parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// 跳过 SNI 列表长度 (2)
	pos := 2

	// SNI 类型: 0x00 (hostname)
	if data[pos] != 0x00 {
		return ""
	}
	pos++

	// SNI 长度
	if pos+2 > len(data) {
		return ""
	}
	sniLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if pos+sniLen > len(data) {
		return ""
	}

	sni := string(data[pos : pos+sniLen])

	// 验证 SNI 格式
	if !td.isValidHostname(sni) {
		return ""
	}

	return sni
}

// isValidHostname 验证主机名格式
func (td *TrafficDetector) isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 255 {
		return false
	}

	// 基本格式检查
	if !regexp.MustCompile(`^[a-zA-Z0-9.-]+$`).MatchString(hostname) {
		return false
	}

	// 不能以 . 或 - 开始或结束
	if strings.HasPrefix(hostname, ".") || strings.HasPrefix(hostname, "-") ||
		strings.HasSuffix(hostname, ".") || strings.HasSuffix(hostname, "-") {
		return false
	}

	return true
}

// DetectFromConnection 从连接中检测流量信息
func (td *TrafficDetector) DetectFromConnection(conn net.Conn, initialData []byte) *DetectionResult {
	result := td.DetectTraffic(initialData)

	if result == nil {
		return &DetectionResult{
			Type:     TrafficTypeUnknown,
			Hostname: conn.RemoteAddr().String(),
		}
	}

	// 如果没有检测到主机名，使用连接地址
	if result.Hostname == "" {
		if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
			result.Hostname = host
		} else {
			result.Hostname = conn.RemoteAddr().String()
		}
	}

	td.logger.Printf("Traffic detected: Type=%v, Host=%s, Method=%s",
		result.Type, result.Hostname, result.Method)

	return result
}

// GetLoggerType 获取日志类型标识
func (tt TrafficType) String() string {
	switch tt {
	case TrafficTypeHTTP:
		return "HTTP"
	case TrafficTypeHTTPS:
		return "HTTPS"
	default:
		return "Unknown"
	}
}
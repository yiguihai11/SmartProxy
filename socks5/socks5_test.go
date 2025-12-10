package socks5

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// MockNetConn 模拟 net.Conn 接口
type MockNetConn struct {
	net.Conn
	ReadBuffer  bytes.Buffer
	WriteBuffer bytes.Buffer
	Closed      bool
	ReadError   error
	WriteError  error
	CloseError  error
	DialDelay   time.Duration // 模拟连接建立延迟
}

func (m *MockNetConn) Read(b []byte) (n int, err error) {
	if m.ReadError != nil {
		return 0, m.ReadError
	}
	return m.ReadBuffer.Read(b)
}

func (m *MockNetConn) Write(b []byte) (n int, err error) {
	if m.WriteError != nil {
		return 0, m.WriteError
	}
	return m.WriteBuffer.Write(b)
}

func (m *MockNetConn) Close() error {
	m.Closed = true
	return m.CloseError
}

func (m *MockNetConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000}
}

func (m *MockNetConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}
}

func (m *MockNetConn) SetDeadline(t time.Time) error { return nil }
func (m *MockNetConn) SetReadDeadline(t time.Time) error { return nil }
func (m *MockNetConn) SetWriteDeadline(t time.Time) error { return nil }

// MockBlacklistManager 模拟 BlacklistManager
type MockBlacklistManager struct {
	mu         sync.Mutex
	blacklisted map[string]bool
	addedCount map[string]int
}

func NewMockBlacklistManager() *MockBlacklistManager {
	return &MockBlacklistManager{
		blacklisted: make(map[string]bool),
		addedCount:  make(map[string]int),
	}
}

func (m *MockBlacklistManager) Add(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blacklisted[ip] = true
	m.addedCount[ip]++
}

func (m *MockBlacklistManager) IsBlacklisted(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blacklisted[ip]
}

func (m *MockBlacklistManager) GetStats() map[string]interface{} {
	return make(map[string]interface{})
}

func (m *MockBlacklistManager) Remove(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blacklisted, ip)
}

// GetAddedCount 获取某个IP被添加到黑名单的次数
func (m *MockBlacklistManager) GetAddedCount(ip string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addedCount[ip]
}

// Reset 清空黑名单和计数
func (m *MockBlacklistManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blacklisted = make(map[string]bool)
	m.addedCount = make(map[string]int)
}

// MockRouter 模拟 Router
type MockRouter struct {
	defaultProxy *ProxyNode
}

func (m *MockRouter) GetDefaultProxy() *ProxyNode {
	return m.defaultProxy
}

func (m *MockRouter) MatchRule(targetAddr, detectedHost string, targetPort int) MatchResult {
	return MatchResult{Action: ActionDeny} // 模拟总是需要走代理的情况
}

func (m *MockRouter) GetProxyNode(name string) *ProxyNode {
	return m.defaultProxy
}

func (m *MockRouter) GetStats() map[string]int {
	return make(map[string]int)
}

func (m *MockRouter) IsChinaIP(ip string) bool {
	return false
}

// createMockDialer creates a dialer that returns a MockNetConn with specified behavior
func createMockDialer(delay time.Duration, connErr error) func(network, address string, timeout time.Duration) (net.Conn, error) {
	return func(network, address string, timeout time.Duration) (net.Conn, error) {
		time.Sleep(delay)
		if connErr != nil {
			return nil, connErr
		}
		return &MockNetConn{}, nil // Return a successful mock connection
	}
}

// TestTryDirectConnectionBlacklist 测试 tryDirectConnection 在目标被列入黑名单时是否跳过直连
func TestTryDirectConnectionBlacklist(t *testing.T) {
	// 模拟 Logger
	var logBuffer bytes.Buffer
	testLogger := log.New(&logBuffer, "[TEST] ", log.LstdFlags)

	// 模拟 SOCKS5Server
	mockBlacklist := NewMockBlacklistManager()
	mockServer := &SOCKS5Server{
		logger:    testLogger,
		blacklist: mockBlacklist,
	}

	// 模拟 Connection
	conn := &Connection{
		server: mockServer,
		logger: testLogger, // Fix: Set conn.logger
		dialer: createMockDialer(0, nil), // 不应被调用，但为了完整性赋值
	}

	targetAddr := "192.168.1.1"
	targetPort := uint16(80)

	// 将目标地址添加到黑名单
	mockBlacklist.Add(targetAddr)

	resultChan := make(chan *connectionAttempt, 1)

	// 调用 tryDirectConnection
	conn.tryDirectConnection(targetAddr, targetPort, resultChan)

	// 检查结果
	result := <-resultChan
	if result.success {
		t.Errorf("Expected direct connection to fail because target is blacklisted, but it succeeded.")
	}
	expectedErr := fmt.Sprintf("target %s is blacklisted", targetAddr)
	if result.err == nil || result.err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got '%v'", expectedErr, result.err)
	}

	// 检查日志输出
	logOutput := logBuffer.String()
	expectedLog := fmt.Sprintf("Direct connection to %s:80 skipped: target is blacklisted.", targetAddr)
	if !strings.Contains(logOutput, expectedLog) {
		t.Errorf("Expected log message '%s' not found in output:\n%s", expectedLog, logOutput)
	}
}

// TestTryParallelConnectionsHappyEyeballs 测试 tryParallelConnections 的 Happy Eyeballs 逻辑
func TestTryParallelConnectionsHappyEyeballs(t *testing.T) {
	tests := []struct {
		name                 string
		directDelay          time.Duration
		directErr            error
		proxyDelay           time.Duration
		proxyErr             error
		expectedConnType     string
		expectedBlacklistAdd bool
		expectedErrorMsg     string
	}{
		{
			name:             "Direct wins (fastest)",
			directDelay:      50 * time.Millisecond,
			directErr:        nil,
			proxyDelay:       200 * time.Millisecond, // Slower than direct and HE delay
			proxyErr:         nil,
			expectedConnType: "direct",
		},
		{
			name:                 "Proxy wins (direct fails fast)",
			directDelay:          10 * time.Millisecond,
			directErr:            errors.New("connection reset by peer"),
			proxyDelay:           50 * time.Millisecond,
			proxyErr:             nil,
			expectedConnType:     "proxy",
			expectedBlacklistAdd: true,
		},
		{
			name:             "Proxy wins (direct is slow, but succeeds eventually)",
			directDelay:      500 * time.Millisecond, // Slower than HE delay (100ms) + proxy setup (50ms)
			directErr:        nil,
			proxyDelay:       50 * time.Millisecond,
			proxyErr:         nil,
			expectedConnType: "proxy",
			expectedBlacklistAdd: false,
		},
		{
			name:                 "Proxy wins (direct is slow, eventually fails)",
			directDelay:          500 * time.Millisecond,
			directErr:            errors.New("dial timeout"),
			proxyDelay:           50 * time.Millisecond,
			proxyErr:             nil,
			expectedConnType:     "proxy",
			expectedBlacklistAdd: true,
		},
		{
			name:             "Both fail",
			directDelay:      10 * time.Millisecond,
			directErr:        errors.New("direct failed"),
			proxyDelay:       10 * time.Millisecond,
			proxyErr:         errors.New("proxy failed"),
			expectedConnType: "", // Expect error
			expectedErrorMsg: "all connection attempts failed: direct (direct failed), proxy (proxy failed)",
		},
		{
			name:             "Overall timeout",
			directDelay:      2500 * time.Millisecond,
			directErr:        nil,
			proxyDelay:       2500 * time.Millisecond,
			proxyErr:         nil,
			expectedConnType: "", // Expect error
			expectedErrorMsg: "all connection attempts timed out.",
		},

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 模拟 Logger
			var logBuffer bytes.Buffer
			testLogger := log.New(&logBuffer, "[TEST] ", log.LstdFlags)

			mockBlacklist := NewMockBlacklistManager()
			mockRouter := &MockRouter{
				defaultProxy: &ProxyNode{Name: "default-proxy", Address: "1.2.3.4:1080"},
			}

			mockServer := &SOCKS5Server{
				logger:              testLogger,
				blacklist:           mockBlacklist,
				router:              mockRouter,
				smartProxyEnabled:   true,
				probingPorts:        []int{80},
				smartProxyTimeoutMs: 1500, // 1.5s used in tryDirectConnection as its timeout
			}

			conn := &Connection{
				server:     mockServer,
				targetAddr: "example.com",
				targetHost: "example.com",
				logger:     testLogger,
			}

			conn.dialer = func(network, address string, timeout time.Duration) (net.Conn, error) {
				if strings.Contains(address, mockRouter.defaultProxy.Address) {
					return createMockDialer(tt.proxyDelay, tt.proxyErr)(network, address, timeout)
				}
				return createMockDialer(tt.directDelay, tt.directErr)(network, address, timeout)
			}


			resultConn, connType, _, err := conn.tryParallelConnections("example.com", 80)

			if tt.expectedConnType == "" { // Expect error
				if err == nil {
					t.Errorf("Expected an error, but got success")
				}
				if tt.expectedErrorMsg != "" && err != nil && err.Error() != tt.expectedErrorMsg {
					// Use Contains because the error message might have more details
					if !strings.Contains(err.Error(), tt.expectedErrorMsg) {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
				if resultConn != nil {
					resultConn.Close()
				}
			} else {
				if err != nil {
					t.Errorf("Expected success, but got error: %v", err)
				}
				if resultConn == nil {
					t.Errorf("Expected a connection, but got nil")
				}
				if connType != tt.expectedConnType {
					t.Errorf("Expected connection type %s, got %s", tt.expectedConnType, connType)
				}
				if resultConn != nil {
					resultConn.Close()
				}
			}

			if tt.expectedBlacklistAdd {
				if !mockBlacklist.IsBlacklisted("example.com") {
					t.Errorf("Expected example.com to be blacklisted, but it was not.")
				}
			} else {
				if mockBlacklist.IsBlacklisted("example.com") {
					t.Errorf("Did not expect example.com to be blacklisted, but it was.")
				}
			}
		})
	}
}

package socks5

import (
	"fmt"
	"net"
	"smartproxy/logger"
	"testing"
	"time"
)

// 测试已确认存在的核心功能

func TestFormatNetworkAddress(t *testing.T) {
	testCases := []struct {
		addr     string
		port     uint16
		expected string
	}{
		{"192.168.1.1", 80, "192.168.1.1:80"},
		{"127.0.0.1", 8080, "127.0.0.1:8080"},
		{"0.0.0.0", 443, "0.0.0.0:443"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s:%d", tc.addr, tc.port), func(t *testing.T) {
			got := formatNetworkAddress(tc.addr, tc.port)
			if got != tc.expected {
				t.Errorf("formatNetworkAddress(%q, %d) = %q, want %q",
					tc.addr, tc.port, got, tc.expected)
			}
		})
	}
}

func TestGenerateSessionID(t *testing.T) {
	// 生成多个会话ID验证唯一性
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateSessionID()
		if id == "" {
			t.Error("generateSessionID should not return empty string")
		}

		if ids[id] {
			t.Errorf("Session ID %q already generated (collision)", id)
		}
		ids[id] = true

		if len(id) < 10 || len(id) > 100 {
			t.Errorf("Session ID length unusual: %q", id)
		}
	}
}

func TestNewUDPSessionManager(t *testing.T) {
	log := logger.NewLogger().WithField("prefix", "[TEST]")
	manager := NewUDPSessionManager(log)

	if manager == nil {
		t.Fatal("NewUDPSessionManager should not return nil")
	}

	// 验证初始状态
	if count := manager.GetSessionCount(); count != 0 {
		t.Errorf("Expected initial session count 0, got %d", count)
	}
}

func TestUDPSessionManager_BasicOperations(t *testing.T) {
	log := logger.NewLogger().WithField("prefix", "[TEST]")
	manager := NewUDPSessionManager(log)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	targetAddr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	targetHost := "dns.google"

	// 添加会话
	session := manager.AddSession(clientAddr, targetAddr, targetHost)
	if session == nil {
		t.Fatal("AddSession should not return nil")
	}

	// 验证会话数量
	if count := manager.GetSessionCount(); count != 1 {
		t.Errorf("Expected session count 1, got %d", count)
	}

	// 获取会话
	retrievedSession := manager.GetSession(clientAddr)
	if retrievedSession == nil {
		t.Error("GetSession should return the added session")
	}

	// 移除会话
	manager.RemoveSession(clientAddr)
	if count := manager.GetSessionCount(); count != 0 {
		t.Errorf("Expected session count 0 after removal, got %d", count)
	}
}

func TestUDPSessionManager_Concurrent(t *testing.T) {
	log := logger.NewLogger().WithField("prefix", "[TEST]")
	manager := NewUDPSessionManager(log)
	done := make(chan bool, 10)

	// 并发操作测试
	for i := 0; i < 10; i++ {
		go func(id int) {
			clientAddr := &net.UDPAddr{
				IP:   net.ParseIP("192.168.1.100"),
				Port: 20000 + id,
			}
			targetAddr := &net.UDPAddr{
				IP:   net.ParseIP("8.8.8.8"),
				Port: 53,
			}

			session := manager.AddSession(clientAddr, targetAddr, fmt.Sprintf("test%d", id))
			if session != nil {
				retrieved := manager.GetSession(clientAddr)
				if retrieved == nil {
					t.Errorf("Failed to retrieve session %d", id)
				}
				manager.RemoveSession(clientAddr)
			}
			done <- true
		}(i)
	}

	// 等待所有操作完成
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestNewBlockedItem(t *testing.T) {
	item := NewBlockedItem("test.com", ItemTypeDomain)

	if item == nil {
		t.Fatal("NewBlockedItem should not return nil")
	}

	if item.Key != "test.com" {
		t.Errorf("Expected key 'test.com', got %s", item.Key)
	}

	if item.Type != ItemTypeDomain {
		t.Errorf("Expected type %v, got %v", ItemTypeDomain, item.Type)
	}

	// 验证时间字段
	if item.FirstBlocked.IsZero() {
		t.Error("FirstBlocked should be set")
	}
}

func TestBlockedItem_AddAttempt(t *testing.T) {
	item := NewBlockedItem("test.com", ItemTypeDomain)

	// 添加失败尝试
	item.AddAttempt(443, FailureReasonRST, "192.168.1.1")

	if item.TotalAttempts != 1 {
		t.Errorf("Expected 1 total attempt, got %d", item.TotalAttempts)
	}

	// 验证失败原因计数
	if count := item.FailureReasons[FailureReasonRST]; count != 1 {
		t.Errorf("Expected 1 RST failure, got %d", count)
	}

	// 验证端口信息
	portInfo, exists := item.Ports[443]
	if !exists {
		t.Fatal("Port 443 should exist in Ports map")
	}

	if portInfo.Port != 443 {
		t.Errorf("Expected port 443, got %d", portInfo.Port)
	}

	if portInfo.AttemptCount != 1 {
		t.Errorf("Expected attempt count 1, got %d", portInfo.AttemptCount)
	}
}

func TestNewShardedBlockedItemsMap(t *testing.T) {
	mapInstance := NewShardedBlockedItemsMap()

	if mapInstance == nil {
		t.Fatal("NewShardedBlockedItemsMap should not return nil")
	}

	// 验证初始状态
	if count := mapInstance.Count(); count != 0 {
		t.Errorf("Expected initial count 0, got %d", count)
	}
}

func TestShardedBlockedItemsMap_Operations(t *testing.T) {
	mapInstance := NewShardedBlockedItemsMap()

	// 测试不存在的项目
	if mapInstance.Contains("nonexistent.com") {
		t.Error("Should not contain nonexistent item")
	}

	// 添加项目
	mapInstance.Add("test.com", ItemTypeDomain, 443, FailureReasonRST, "192.168.1.1")

	// 验证存在
	if !mapInstance.Contains("test.com") {
		t.Error("Should contain added item")
	}

	// 获取项目
	item, found := mapInstance.Get("test.com")
	if !found {
		t.Error("Should find added item")
	}
	if item == nil {
		t.Fatal("Retrieved item should not be nil")
	}

	// 删除项目
	if !mapInstance.Delete("test.com") {
		t.Error("Delete should return true for existing item")
	}

	// 验证已删除
	if mapInstance.Contains("test.com") {
		t.Error("Should not contain deleted item")
	}
}

func TestNewBlockedItemsManager(t *testing.T) {
	log := logger.NewLogger().WithField("prefix", "[TEST]")
	manager := NewBlockedItemsManager(60, log)

	if manager == nil {
		t.Fatal("NewBlockedItemsManager should not return nil")
	}

	// 验证TTL设置（60分钟）
	if manager.ttl != 60*time.Minute {
		t.Errorf("Expected TTL 60 minutes, got %v", manager.ttl)
	}
}

func TestBlockedItemsManager_AddBlocked(t *testing.T) {
	log := logger.NewLogger().WithField("prefix", "[TEST]")
	manager := NewBlockedItemsManager(60, log)

	// 添加被阻止的域名
	manager.AddBlockedDomain("example.com", "443", FailureReasonRST)
	item, found := manager.GetBlockedInfo("example.com")
	if !found {
		t.Error("Should find blocked domain")
	}
	if item.Type != ItemTypeDomain {
		t.Errorf("Expected Domain type, got %v", item.Type)
	}

	// 添加被阻止的IP
	manager.AddBlockedIP("192.168.1.100", "80", FailureReasonTimeout)
	item, found = manager.GetBlockedInfo("192.168.1.100")
	if !found {
		t.Error("Should find blocked IP")
	}
	if item.Type != ItemTypeIPv4 {
		t.Errorf("Expected IPv4 type, got %v", item.Type)
	}
}

func TestConnection_LogMethods(t *testing.T) {
	log := logger.NewLogger().WithField("prefix", "[TEST]")
	conn := &Connection{
		logger: log,
	}

	// 测试日志方法不会panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Log method panicked: %v", r)
		}
	}()

	conn.logInfo("Test info message")
	conn.logWarn("Test warning message")
	conn.logError("Test error message")
	conn.logDebug("Test debug message")
}

func TestRadixTrie_Basic(t *testing.T) {
	trie := NewRadixTrie()

	// 添加IPv4规则
	rule := &Rule{Description: "test IPv4"}
	err := trie.Insert("192.168.1.0/24", ActionBlock, rule)
	if err != nil {
		t.Fatalf("Insert should not error: %v", err)
	}

	// 测试查找
	action, found, _ := trie.Lookup("192.168.1.100")
	if !found {
		t.Error("Should find IPv4 address")
	}
	if action != ActionBlock {
		t.Errorf("Expected Block action, got %v", action)
	}

	// 测试统计
	ipv4Rules, _, totalRules := trie.GetStats()
	if totalRules == 0 {
		t.Error("Should have at least one rule")
	}
	if ipv4Rules == 0 {
		t.Error("Should have IPv4 rules")
	}
}
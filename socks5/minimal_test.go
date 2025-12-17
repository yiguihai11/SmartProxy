package socks5

import (
	"smartproxy/logger"
	"testing"
	"time"
)

// 最小化的测试集合，确保代码基本功能正常

func TestRadixTrie_BasicOperations(t *testing.T) {
	trie := NewRadixTrie()
	if trie == nil {
		t.Fatal("NewRadixTrie should not return nil")
	}

	// 测试插入
	rule := &Rule{Description: "test"}
	err := trie.Insert("192.168.1.0/24", ActionBlock, rule)
	if err != nil {
		t.Fatalf("Insert should not error: %v", err)
	}

	// 测试查找
	action, found, _ := trie.Lookup("192.168.1.1")
	if !found {
		t.Error("Should find IP in inserted network")
	}
	if action != ActionBlock {
		t.Errorf("Expected Block action, got %v", action)
	}

	// 测试统计
	ipv4Rules, _, totalRules := trie.GetStats()
	if totalRules == 0 {
		t.Error("Should have at least one rule after insertion")
	}
	if ipv4Rules == 0 {
		t.Error("Should have IPv4 rules")
	}
}

func TestBufferPool_BasicOperations(t *testing.T) {
	pool := NewBufferPool()
	if pool == nil {
		t.Fatal("NewBufferPool should not return nil")
	}

	// 测试获取缓冲区
	buf := pool.Get(1024)
	if buf == nil {
		t.Error("Get should not return nil")
	}

	// 测试放回缓冲区
	pool.Put(buf)

	// 再次获取应该正常
	buf2 := pool.Get(2048)
	if buf2 == nil {
		t.Error("Second Get should not return nil")
	}
}

func TestTrafficMonitor_BasicOperations(t *testing.T) {
	tm := NewTrafficMonitor(100 * time.Millisecond)
	if tm == nil {
		t.Fatal("NewTrafficMonitor should not return nil")
	}

	// 测试记录流量（需要connID参数）
	tm.RecordUpload("test-conn", 1024)
	tm.RecordDownload("test-conn", 2048)

	// 获取统计
	stats := tm.GetStats()
	if stats == nil {
		t.Error("GetStats should not return nil")
	}

	// 测试重置
	tm.Reset()
}

func TestTrafficDetector_BasicOperations(t *testing.T) {
	log := logger.NewLogger().WithField("prefix", "[TEST]")
	td := NewTrafficDetector(log)
	if td == nil {
		t.Fatal("NewTrafficDetector should not return nil")
	}

	// 测试流量检测
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	result := td.DetectTraffic(data)
	if result == nil {
		t.Error("DetectTraffic should not return nil")
	}

	// 测试TrafficType String方法
	typ := TrafficTypeHTTP
	str := typ.String()
	if str == "" {
		t.Error("TrafficType String should not return empty")
	}
}

func TestFailureReason_String(t *testing.T) {
	reasons := []FailureReason{
		FailureReasonUnknown,
		FailureReasonRST,
		FailureReasonTimeout,
		FailureReasonHandshakeFailure,
		FailureReasonDNSFailure,
		FailureReasonConnectionRefused,
		FailureReasonHostUnreachable,
	}

	for _, reason := range reasons {
		str := reason.String()
		if str == "" {
			t.Errorf("FailureReason %d String should not be empty", reason)
		}
	}
}

func TestConcurrency_SafeAccess(t *testing.T) {
	// 测试并发访问的基本安全性
	pool := NewBufferPool()
	done := make(chan bool, 10)

	// 并发操作
	for i := 0; i < 10; i++ {
		go func(id int) {
			buf := pool.Get(1024)
			if buf != nil {
				pool.Put(buf)
			}
			done <- true
		}(i)
	}

	// 等待完成
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestEdgeCases_EmptyAndNil(t *testing.T) {
	trie := NewRadixTrie()

	// 测试空搜索
	_, found, _ := trie.Lookup("")
	if found {
		t.Error("Should not find empty IP")
	}

	pool := NewBufferPool()

	// 测试空缓冲区
	buf := pool.Get(0)
	if buf == nil {
		t.Error("Get(0) should return buffer")
	}

	// 测试放回nil
	pool.Put(nil) // 不应该panic

	td := NewTrafficDetector(logger.NewLogger())

	// 测试空数据检测
	result := td.DetectTraffic([]byte{})
	if result == nil {
		t.Error("DetectTraffic should handle empty data")
	}
}
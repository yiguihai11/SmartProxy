package socks5

import (
	"fmt"
	"os"
	"smartproxy/logger"
	"testing"
)

// 辅助函数：创建临时配置文件
func createTempNATConfig(content string) (string, error) {
	tmpFile := "nat_test_config.json"
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	return tmpFile, err
}

func TestNATType_Constants(t *testing.T) {
	// 测试NAT类型常量是否正确定义
	testCases := []struct {
		natType  NATType
		name     string
	}{
		{NATUnknown, "Unknown"},
		{NATOpen, "Open"},
		{NATFullCone, "Full Cone"},
		{NATRestricted, "Restricted Cone"},
		{NATPortRestricted, "Port Restricted Cone"},
		{NATSymmetric, "Symmetric"},
	}

	// 验证常量值不重复
	seen := make(map[NATType]bool)
	for _, tc := range testCases {
		if seen[tc.natType] {
			t.Errorf("Duplicate NAT type value: %d", tc.natType)
		}
		seen[tc.natType] = true
		t.Logf("NAT type %s: %d", tc.name, tc.natType)
	}
}

func TestLoadNATConfig_Valid(t *testing.T) {
	// 测试加载有效配置（需要nat_traversal包装）
	configJSON := `{
		"nat_traversal": {
			"enabled": true,
			"mode": "auto",
			"stun_servers": ["stun.l.google.com:19302", "stun1.l.google.com:19302"]
		}
	}`

	tmpFile, err := createTempNATConfig(configJSON)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	log := logger.NewLogger().WithField("prefix", "[TEST]")
	config := loadNATConfig(tmpFile, log)

	if config == nil {
		t.Fatal("loadNATConfig should not return nil for valid config")
	}

	if !config.Enabled {
		t.Error("Expected enabled=true")
	}

	if config.Mode != "auto" {
		t.Errorf("Expected mode=auto, got %s", config.Mode)
	}

	if len(config.STUNServers) != 2 {
		t.Errorf("Expected 2 STUN servers, got %d", len(config.STUNServers))
	}
}

func TestLoadNATConfig_InvalidFile(t *testing.T) {
	log := logger.NewLogger().WithField("prefix", "[TEST]")
	config := loadNATConfig("/nonexistent/file.json", log)

	if config == nil {
		t.Error("loadNATConfig should return default config for nonexistent file")
	}

	// 验证返回的是默认配置
	if config.Enabled != false {
		t.Error("Default config should have enabled=false")
	}
	if config.Mode != "auto" {
		t.Errorf("Default config should have mode=auto, got %s", config.Mode)
	}
}

func TestLoadNATConfig_EmptyFile(t *testing.T) {
	tmpFile, err := createTempNATConfig("")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	log := logger.NewLogger().WithField("prefix", "[TEST]")
	config := loadNATConfig(tmpFile, log)

	if config == nil {
		t.Error("loadNATConfig should return default config for empty file")
	}

	// 验证返回的是默认配置
	if config.Enabled != false {
		t.Error("Default config should have enabled=false")
	}
}

func TestLoadNATConfig_InvalidJSON(t *testing.T) {
	invalidJSON := `{ "enabled": true, "mode": }`

	tmpFile, err := createTempNATConfig(invalidJSON)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	log := logger.NewLogger().WithField("prefix", "[TEST]")
	config := loadNATConfig(tmpFile, log)

	if config == nil {
		t.Error("loadNATConfig should return default config for invalid JSON")
	}

	// 验证返回的是默认配置
	if config.Enabled != false {
		t.Error("Default config should have enabled=false")
	}
}

func TestNewNATTraversal_Enabled(t *testing.T) {
	configJSON := `{
		"nat_traversal": {
			"enabled": true,
			"mode": "direct"
		}
	}`

	tmpFile, err := createTempNATConfig(configJSON)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	log := logger.NewLogger().WithField("prefix", "[TEST]")
	nt := NewNATTraversal(tmpFile, log)

	if nt == nil {
		t.Fatal("NewNATTraversal should not return nil")
	}

	if !nt.IsEnabled() {
		t.Error("NAT traversal should be enabled")
	}

	if nt.config == nil {
		t.Error("Config should be loaded")
	}
}

func TestNewNATTraversal_Disabled(t *testing.T) {
	configJSON := `{
		"nat_traversal": {
			"enabled": false,
			"mode": "auto"
		}
	}`

	tmpFile, err := createTempNATConfig(configJSON)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	log := logger.NewLogger().WithField("prefix", "[TEST]")
	nt := NewNATTraversal(tmpFile, log)

	if nt == nil {
		t.Fatal("NewNATTraversal should not return nil even when disabled")
	}

	if nt.IsEnabled() {
		t.Error("NAT traversal should be disabled")
	}
}

func TestNewNATTraversal_NoConfig(t *testing.T) {
	log := logger.NewLogger().WithField("prefix", "[TEST]")
	nt := NewNATTraversal("/nonexistent/config.json", log)

	// 应该创建一个默认的NATTraversal实例
	if nt == nil {
		t.Fatal("NewNATTraversal should create default instance when config file doesn't exist")
	}
}

func TestNATTraversal_ReloadConfig(t *testing.T) {
	// 初始配置
	configJSON1 := `{
		"nat_traversal": {
			"enabled": true,
			"mode": "direct"
		}
	}`

	tmpFile, err := createTempNATConfig(configJSON1)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	log := logger.NewLogger().WithField("prefix", "[TEST]")
	nt := NewNATTraversal(tmpFile, log)

	if nt == nil {
		t.Fatal("NewNATTraversal should not return nil")
	}

	// 更改配置
	configJSON2 := `{
		"nat_traversal": {
			"enabled": false,
			"mode": "auto",
			"stun_servers": ["stun.example.com:19302"]
		}
	}`

	err = os.WriteFile(tmpFile, []byte(configJSON2), 0644)
	if err != nil {
		t.Fatalf("Failed to update config file: %v", err)
	}

	// 重新加载配置
	nt.ReloadConfig()

	if nt.IsEnabled() {
		t.Error("NAT traversal should be disabled after reload")
	}

	if len(nt.config.STUNServers) != 1 {
		t.Errorf("Expected 1 STUN server after reload, got %d", len(nt.config.STUNServers))
	}
}

func TestNATTraversal_InitialState(t *testing.T) {
	configJSON := `{
		"nat_traversal": {
			"enabled": true,
			"mode": "auto"
		}
	}`

	tmpFile, err := createTempNATConfig(configJSON)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	log := logger.NewLogger().WithField("prefix", "[TEST]")
	nt := NewNATTraversal(tmpFile, log)

	if nt == nil {
		t.Fatal("NewNATTraversal should not return nil")
	}

	// 验证初始状态
	if nt.publicIP != "" {
		t.Error("Public IP should be empty initially")
	}

	if nt.publicPort != 0 {
		t.Error("Public port should be 0 initially")
	}

	if nt.natType != NATUnknown {
		t.Errorf("Expected NAT type Unknown initially, got %v", nt.natType)
	}
}

func TestNATTraversal_Modes(t *testing.T) {
	modes := []string{"direct", "auto", "fullcone", "holepunch", "turn"}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			configJSON := fmt.Sprintf(`{
				"nat_traversal": {
					"enabled": true,
					"mode": "%s"
				}
			}`, mode)

			tmpFile, err := createTempNATConfig(configJSON)
			if err != nil {
				t.Fatalf("Failed to create temp config file: %v", err)
			}
			defer os.Remove(tmpFile)

			log := logger.NewLogger().WithField("prefix", "[TEST]")
			nt := NewNATTraversal(tmpFile, log)

			if nt == nil {
				t.Fatal("NewNATTraversal should not return nil")
			}

			if nt.config.Mode != mode {
				t.Errorf("Expected mode %s, got %s", mode, nt.config.Mode)
			}
		})
	}
}

func TestNATTraversal_CanReceiveDirectTraffic(t *testing.T) {
	testCases := []struct {
		name     string
		natType  NATType
		expected bool
	}{
		{"Open NAT", NATOpen, true},
		{"Full Cone NAT", NATFullCone, true},
		{"Restricted NAT", NATRestricted, false},
		{"Port Restricted NAT", NATPortRestricted, false},
		{"Symmetric NAT", NATSymmetric, false},
		{"Unknown NAT", NATUnknown, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configJSON := `{
				"nat_traversal": {
					"enabled": true,
					"mode": "auto"
				}
			}`

			tmpFile, err := createTempNATConfig(configJSON)
			if err != nil {
				t.Fatalf("Failed to create temp config file: %v", err)
			}
			defer os.Remove(tmpFile)

			log := logger.NewLogger().WithField("prefix", "[TEST]")
			nt := NewNATTraversal(tmpFile, log)
			if nt == nil {
				t.Fatal("NewNATTraversal should not return nil")
			}

			// 手动设置NAT类型用于测试
			nt.natType = tc.natType

			if got := nt.CanReceiveDirectTraffic(); got != tc.expected {
				t.Errorf("CanReceiveDirectTraffic() = %v, want %v for NAT type %v",
					got, tc.expected, tc.natType)
			}
		})
	}
}

func TestNATTraversal_STUNServers(t *testing.T) {
	servers := []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun2.l.google.com:19302",
	}

	configJSON := fmt.Sprintf(`{
		"nat_traversal": {
			"enabled": true,
			"mode": "auto",
			"stun_servers": %s
		}
	}`, serversToString(servers))

	tmpFile, err := createTempNATConfig(configJSON)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	log := logger.NewLogger().WithField("prefix", "[TEST]")
	nt := NewNATTraversal(tmpFile, log)

	if nt == nil {
		t.Fatal("NewNATTraversal should not return nil")
	}

	if len(nt.config.STUNServers) != len(servers) {
		t.Errorf("Expected %d STUN servers, got %d", len(servers), len(nt.config.STUNServers))
	}

	for i, server := range nt.config.STUNServers {
		if server != servers[i] {
			t.Errorf("STUN server %d mismatch: expected %s, got %s", i, servers[i], server)
		}
	}
}

// 辅助函数
func serversToString(servers []string) string {
	result := "["
	for i, s := range servers {
		if i > 0 {
			result += ", "
		}
		result += `"` + s + `"`
	}
	result += "]"
	return result
}

func TestNATTraversal_ConcurrentAccess(t *testing.T) {
	configJSON := `{
		"nat_traversal": {
			"enabled": true,
			"mode": "auto"
		}
	}`

	tmpFile, err := createTempNATConfig(configJSON)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	log := logger.NewLogger().WithField("prefix", "[TEST]")
	nt := NewNATTraversal(tmpFile, log)

	if nt == nil {
		t.Fatal("NewNATTraversal should not return nil")
	}

	done := make(chan bool, 10)

	// 并发访问测试
	for i := 0; i < 10; i++ {
		go func(id int) {
			// 测试各种方法的并发访问
			nt.IsEnabled()
			nt.GetNATType()
			nt.CanReceiveDirectTraffic()
			nt.GetPublicEndpoint()
			done <- true
		}(i)
	}

	// 等待所有操作完成
	for i := 0; i < 10; i++ {
		<-done
	}

	// 如果没有panic，测试就通过了
	t.Log("Concurrent access test completed successfully")

	// 清理测试文件
	cleanup()
}

// 清理测试文件
func cleanup() {
	os.Remove("nat_test_config.json")
}

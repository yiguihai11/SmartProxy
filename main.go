package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"smartproxy/config"
	"smartproxy/dns"
	"smartproxy/logger"
	"smartproxy/socks5"
	"smartproxy/web"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	port := 1080                     // 默认 SOCKS5 端口
	webPort := 8080                  // 默认 Web 端口
	dnsPort := 1053                  // 默认 DNS 端口
	configPath := "conf/config.json" // 默认配置文件

	// 检查命令行参数
	if len(os.Args) > 1 {
		if p, err := strconv.Atoi(os.Args[1]); err == nil {
			port = p
		} else if os.Args[1] == "--config" && len(os.Args) > 2 {
			configPath = os.Args[2]
			if len(os.Args) > 3 {
				if p, err := strconv.Atoi(os.Args[3]); err == nil {
					port = p
				}
			}
		}
	}

	// 加载主配置
	mainCfgManager := config.NewManager(configPath)
	if err := mainCfgManager.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load main config file: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志系统
	cfg := mainCfgManager.GetConfig()
	logConfig := logger.Config{
		Level:        cfg.Logging.Level,
		OutputFile:   cfg.Logging.OutputFile,
		EnableTime:   cfg.Logging.EnableTime,
		Prefix:       cfg.Logging.Prefix,
		EnableColors: cfg.Logging.EnableColors && cfg.Logging.OutputFile == "", // 文件输出时不启用颜色
	}

	mainLogger, err := logger.New(logConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer mainLogger.Close()

	// 从配置文件读取SOCKS5端口（如果配置文件中有设置则覆盖命令行参数）
	configPort := cfg.Listener.SOCKS5Port
	if configPort > 0 {
		port = configPort // 使用配置文件中的端口
		mainLogger.Info("Using SOCKS5 port from config: %d", configPort)
	} else {
		mainLogger.Info("Using SOCKS5 port from command line or default: %d", port)
	}

	probingPorts := mainCfgManager.GetConfig().SmartProxy.ProbingPorts

	server, err := socks5.NewSOCKS5ServerWithConfig(port, configPath, probingPorts)
	if err != nil {
		logger.Fatal("Failed to create SOCKS5 server: %v", err)
	}

	// 初始化内存监控器
	memoryMonitor := socks5.GetGlobalMemoryMonitor()
	if memoryMonitor == nil {
		memoryMonitor = socks5.NewMemoryMonitor(30 * time.Second) // 30秒更新间隔
		mainLogger.Info("Memory monitor initialized with 30s update interval")
	}

	// 初始化流量监控器
	trafficMonitor := socks5.GetGlobalTrafficMonitor()
	if trafficMonitor == nil {
		trafficMonitor = socks5.NewTrafficMonitor(1 * time.Second) // 1秒更新间隔
		mainLogger.Info("Traffic monitor initialized with 1s update interval")
	}

	// 获取Router实例，用于DNS模块
	router := server.GetRouter()

	// 创建Web服务器配置
	webConfig := web.WebConfig{
		Enabled: true,
		Port:    webPort,
	}

	// 创建Web服务器，传入配置管理器
	webServer := web.NewWebServer(mainCfgManager, webConfig, logger.NewLogger().WithField("prefix", "[Web]"))

	// 从配置文件读取DNS配置
	cfg = mainCfgManager.GetConfig()
	var cnServers []string
	var foreignServers []string

	if cfg.DNS.Enabled {
		// 从配置文件读取DNS服务器
		if group, exists := cfg.DNS.Groups["cn"]; exists {
			cnServers = group
		}
		if group, exists := cfg.DNS.Groups["foreign"]; exists {
			foreignServers = group
		}
	}

	// 如果配置文件中没有设置，使用默认值
	if len(cnServers) == 0 {
		cnServers = []string{"223.5.5.5:53", "119.29.29.29:53"}
	}
	if len(foreignServers) == 0 {
		foreignServers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}

	// 创建DNS服务器配置
	dnsConfig := &dns.Config{
		CNServers:       cnServers,
		ForeignServers:  foreignServers,
		CacheSize:       cfg.DNS.Cache.MaxSize,
		CleanupInterval: time.Duration(cfg.DNS.Cache.CleanupInterval) * time.Second,
		HijackRules:     convertHijackRules(cfg.DNS.HijackRules),
		ProxyNodes:      []dns.ProxyNode{},
	}

	dnsServer := dns.NewSmartDNSServer(dnsConfig, dnsPort, logger.NewLogger().WithField("prefix", "[DNS]"), router)

	// 设置内存监控器的DNS缓存回调
	if memoryMonitor != nil {
		memoryMonitor.SetDNSCacheUpdater(func() int64 {
			if dnsServer != nil {
				return int64(dnsServer.GetCacheSize())
			}
			return 0
		})
	}

	// Web server initialized successfully

	// 设置信号处理

	// 用于等待所有服务停止的WaitGroup
	var wg sync.WaitGroup

	// 获取本地IP地址用于显示
	localIP := getLocalIP()

	// 使用配置文件中的端口，其他服务端口也由配置文件决定
	mainLogger.Info("Config file: %s", configPath)
	mainLogger.Info("Services started:")
	mainLogger.Info("  SOCKS5 proxy: %s:%d", localIP, port)
	mainLogger.Info("  DNS server:   %s:%d", localIP, dnsPort)
	mainLogger.Info("  Web UI:       http://%s:%d", localIP, webPort)

	// 启动SOCKS5服务器
	wg.Add(1)
	go func() {
		defer wg.Done()
		mainLogger.Info("Starting SOCKS5 proxy server on port %d", port)
		if err := server.Start(); err != nil {
			mainLogger.Error("SOCKS5 server error: %v", err)
		}
		mainLogger.Info("SOCKS5 server stopped")
	}()

	// 启动Web服务器
	wg.Add(1)
	go func() {
		defer wg.Done()
		mainLogger.Info("Starting Web interface on port %d", webPort)
		mainLogger.Info("Web interface: http://127.0.0.1:%d", webPort)
		if err := webServer.Start(); err != nil {
			mainLogger.Error("Web server error: %v", err)
		}
		mainLogger.Info("Web server stopped")
	}()

	// 启动DNS服务器
	wg.Add(1)
	go func() {
		defer wg.Done()
		mainLogger.Info("Starting DNS server on port %d", dnsPort)
		if err := dnsServer.Start(); err != nil {
			mainLogger.Error("DNS server error: %v", err)
		}
		mainLogger.Info("DNS server stopped")
	}()

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	mainLogger.Info("\nReceived signal %v, shutting down gracefully...", sig)

	// 并发停止所有服务以加快关闭速度
	var stopWg sync.WaitGroup
	stopWg.Add(4)

	// 停止SOCKS5服务器
	go func() {
		defer stopWg.Done()
		mainLogger.Info("Stopping SOCKS5 server...")
		if err := server.Stop(); err != nil {
			mainLogger.Error("Error stopping SOCKS5 server: %v", err)
		}
	}()

	// 停止Web服务器
	go func() {
		defer stopWg.Done()
		mainLogger.Info("Stopping Web server...")
		if err := webServer.Stop(); err != nil {
			mainLogger.Error("Error stopping Web server: %v", err)
		}
	}()

	// 停止DNS服务器
	go func() {
		defer stopWg.Done()
		mainLogger.Info("Stopping DNS server...")
		if err := dnsServer.Stop(); err != nil {
			mainLogger.Error("Error stopping DNS server: %v", err)
		}
	}()

	// 停止内存监控器
	go func() {
		defer stopWg.Done()
		if memoryMonitor != nil {
			memoryMonitor.Stop()
			mainLogger.Info("Memory monitor stopped")
		}
	}()

	// 等待所有服务停止完成，最多等待5秒
	done := make(chan struct{})
	go func() {
		stopWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		mainLogger.Info("All services stopped gracefully")
	case <-time.After(5 * time.Second):
		mainLogger.Warn("Warning: Some services did not stop within 5 seconds timeout")
	}

	// 等待所有goroutine完成，最多等待5秒
	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	select {
	case <-allDone:
		logger.Info("All services stopped gracefully")
	case <-time.After(5 * time.Second):
		logger.Warn("Warning: Some services did not stop within timeout")
	}

	logger.Info("SmartProxy stopped")
}

// getLocalIP 获取本地IP地址 - 智能选择IPv4/IPv6
func getLocalIP() string {
	// 读取IPv6配置
	ipv6Enabled := false
	configPath := "conf/config.json"
	if data, err := ioutil.ReadFile(configPath); err == nil {
		var config struct {
			Listener struct {
				IPv6Enabled bool `json:"ipv6_enabled"`
			} `json:"listener"`
		}
		if json.Unmarshal(data, &config) == nil {
			ipv6Enabled = config.Listener.IPv6Enabled
		}
	}

	// 根据IPv6配置选择测试目标
	testTargets := []string{"8.8.8.8:80"}
	if ipv6Enabled {
		testTargets = []string{"[2001:4860:4860::8888]:80", "8.8.8.8:80"}
	}

	for _, target := range testTargets {
		if conn, err := net.Dial("udp", target); err == nil {
			localAddr := conn.LocalAddr().(*net.UDPAddr)
			conn.Close()
			// 如果启用了IPv6且获取到IPv6地址，优先返回
			if ipv6Enabled && localAddr.IP.To4() == nil {
				return localAddr.IP.String()
			}
			// 否则返回获取到的地址
			return localAddr.IP.String()
		}
	}

	// 回退到接口地址查询
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				// 如果启用了IPv6，优先返回IPv6
				if ipv6Enabled && ipNet.IP.To4() == nil {
					return ipNet.IP.String()
				}
				// 否则优先返回IPv4
				if ipNet.IP.To4() != nil {
					return ipNet.IP.String()
				}
			}
		}
	}

	// 最后的回退地址
	if ipv6Enabled {
		return "::1"
	}
	return "127.0.0.1"
}

// convertHijackRules 转换配置文件中的劫持规则到DNS模块格式
func convertHijackRules(rules []config.DNSHijackRule) []dns.HijackRule {
	var hijackRules []dns.HijackRule
	for _, rule := range rules {
		// 检查target是否为IP地址（屏蔽）或服务器地址（转发）
		if strings.HasSuffix(rule.Target, ":53") || net.ParseIP(rule.Target) != nil {
			hijackRules = append(hijackRules, dns.HijackRule{
				Pattern: rule.Pattern,
				Target:  rule.Target,
			})
		} else if rule.Target == "0.0.0.0" {
			// 屏蔽到本地
			hijackRules = append(hijackRules, dns.HijackRule{
				Pattern: rule.Pattern,
				Target:  rule.Target,
			})
		} else {
			// 假设是域名，添加默认端口53
			hijackRules = append(hijackRules, dns.HijackRule{
				Pattern: rule.Pattern,
				Target:  rule.Target + ":53",
			})
		}
	}
	return hijackRules
}

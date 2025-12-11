package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"smartproxy/config"
	"smartproxy/dns"
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

	// 加载主配置以获取 probing_ports 和 SOCKS5端口
	mainCfgManager := config.NewManager(configPath)
	if err := mainCfgManager.Load(); err != nil {
		log.Fatalf("Failed to load main config file: %v", err)
	}

	// 从配置文件读取SOCKS5端口（如果配置文件中有设置则覆盖命令行参数）
	configPort := mainCfgManager.GetConfig().Listener.SOCKS5Port
	if configPort > 0 {
		port = configPort // 使用配置文件中的端口
		log.Printf("Using SOCKS5 port from config: %d", configPort)
	} else {
		log.Printf("Using SOCKS5 port from command line or default: %d", port)
	}

	probingPorts := mainCfgManager.GetConfig().SmartProxy.ProbingPorts

	server, err := socks5.NewSOCKS5ServerWithConfig(port, configPath, probingPorts)
	if err != nil {
		log.Fatalf("Failed to create SOCKS5 server: %v", err)
	}

	// 获取Router实例，用于DNS模块
	router := server.GetRouter()

	// 获取BlacklistManager实例，用于Web API统计（现在返回nil，因为使用BlockedItemsManager）
	blacklistManager := server.GetBlacklistManager()

	// 创建Web服务器配置
	webConfig := web.WebConfig{
		Enabled: true,
		Port:    webPort,
	}

	// 创建Web服务器，传入配置管理器
	webServer := web.NewWebServer(mainCfgManager, webConfig, log.New(os.Stdout, "[Web] ", log.LstdFlags))

	// 设置黑名单管理器到Web服务器（现在为空，因为使用BlockedItemsManager）
	if blacklistManager != nil {
		webServer.SetBlacklistManager(blacklistManager)
	}

	// 从配置文件读取DNS配置
	cfg := mainCfgManager.GetConfig()
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

	dnsServer := dns.NewSmartDNSServer(dnsConfig, dnsPort, log.New(os.Stdout, "[DNS] ", log.LstdFlags), router)

	// Web server initialized successfully

	// 设置信号处理

	// 用于等待所有服务停止的WaitGroup
	var wg sync.WaitGroup

	// 获取本地IP地址用于显示
	localIP := getLocalIP()

	// 使用配置文件中的端口，其他服务端口也由配置文件决定
	log.Printf("Config file: %s", configPath)
	log.Printf("Services started:")
	log.Printf("  SOCKS5 proxy: %s:%d", localIP, port)
	log.Printf("  DNS server:   %s:%d", localIP, dnsPort)
	log.Printf("  Web UI:       http://%s:%d", localIP, webPort)

	// 启动SOCKS5服务器
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("Starting SOCKS5 proxy server on port %d", port)
		if err := server.Start(); err != nil {
			log.Printf("SOCKS5 server error: %v", err)
		}
		log.Printf("SOCKS5 server stopped")
	}()

	// 启动Web服务器
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("Starting Web interface on port %d", webPort)
		log.Printf("Web interface: http://127.0.0.1:%d", webPort)
		if err := webServer.Start(); err != nil {
			log.Printf("Web server error: %v", err)
		}
		log.Printf("Web server stopped")
	}()

	// 启动DNS服务器
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("Starting DNS server on port %d", dnsPort)
		if err := dnsServer.Start(); err != nil {
			log.Printf("DNS server error: %v", err)
		}
		log.Printf("DNS server stopped")
	}()

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("\nReceived signal %v, shutting down gracefully...", sig)

	// 优雅关闭各个服务
	log.Printf("Stopping SOCKS5 server...")
	if err := server.Stop(); err != nil {
		log.Printf("Error stopping SOCKS5 server: %v", err)
	}

	log.Printf("Stopping Web server...")
	if err := webServer.Stop(); err != nil {
		log.Printf("Error stopping Web server: %v", err)
	}

	log.Printf("Stopping DNS server...")
	if err := dnsServer.Stop(); err != nil {
		log.Printf("Error stopping DNS server: %v", err)
	}

	// 等待所有goroutine完成，最多等待10秒
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("All services stopped gracefully")
	case <-time.After(10 * time.Second):
		log.Printf("Warning: Some services did not stop within timeout")
	}

	log.Printf("SmartProxy stopped")
}

// getLocalIP 获取本地IP地址
func getLocalIP() string {
	// 尝试创建UDP连接获取本地IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		// 如果失败，尝试其他方法
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipNet.IP.To4() != nil {
						return ipNet.IP.String()
					}
				}
			}
		}
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
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

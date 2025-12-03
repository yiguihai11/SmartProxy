package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"smartproxy/config"
	"smartproxy/dns"
	"smartproxy/socks5"
	"smartproxy/web"
	"strconv"
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

	// 加载主配置以获取 probing_ports
	mainCfgManager := config.NewManager(configPath)
	if err := mainCfgManager.Load(); err != nil {
		log.Fatalf("Failed to load main config file: %v", err)
	}
	probingPorts := mainCfgManager.GetConfig().TrafficDetection.EnhancedProbing.ProbingPorts

	server, err := socks5.NewSOCKS5ServerWithConfig(port, configPath, probingPorts)
	if err != nil {
		log.Fatalf("Failed to create SOCKS5 server: %v", err)
	}

	// 创建Web服务器配置
	webConfig := web.WebConfig{
		Enabled: true,
		Port:    webPort,
	}

	// 创建Web服务器，传入配置管理器
	webServer := web.NewWebServer(mainCfgManager, webConfig, log.New(os.Stdout, "[Web] ", log.LstdFlags))

	// 创建DNS服务器配置（router为nil，将使用默认路由）
	dnsConfig := &dns.Config{
		CNServers:       []string{"223.5.5.5:53", "119.29.29.29:53"},
		ForeignServers:  []string{"8.8.8.8:53", "1.1.1.1:53"},
		CacheSize:       2000,
		CleanupInterval: 60 * time.Second,
		HijackRules:     []dns.HijackRule{},
		ProxyNodes:      []dns.ProxyNode{},
	}

	dnsServer := dns.NewSmartDNSServer(dnsConfig, dnsPort, log.New(os.Stdout, "[DNS] ", log.LstdFlags), nil)

	// 如果web服务器启动成功，可以在这里添加额外的初始化逻辑
	if webServer != nil {
		log.Printf("Web server initialized successfully")
	}

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动SOCKS5服务器
	go func() {
		log.Printf("Starting SOCKS5 proxy server on port %d", port)
		if err := server.Start(); err != nil {
			log.Printf("SOCKS5 server error: %v", err)
			cancel()
		}
	}()

	// 启动Web服务器
	go func() {
		log.Printf("Starting Web interface on port %d", webPort)
		log.Printf("Web interface: http://127.0.0.1:%d", webPort)
		if err := webServer.Start(); err != nil {
			log.Printf("Web server error: %v", err)
		}
	}()

	// 启动DNS服务器
	go func() {
		log.Printf("Starting DNS server on port %d", dnsPort)
		if err := dnsServer.Start(); err != nil {
			log.Printf("DNS server error: %v", err)
		}
	}()

	log.Printf("Config file: %s", configPath)
	log.Printf("使用方法: 设置代理为 127.0.0.1:%d", port)
	log.Printf("DNS服务器: 127.0.0.1:%d", dnsPort)
	log.Printf("")
	log.Printf("服务已启动:")
	log.Printf("  SOCKS5代理: 127.0.0.1:%d", port)
	log.Printf("  DNS服务: 127.0.0.1:%d", dnsPort)
	log.Printf("  Web管理: http://127.0.0.1:%d", webPort)
	log.Printf("")
	log.Printf("示例用法:")
	log.Printf("  ./socks5proxy 1080                    # 使用默认配置")
	log.Printf("  ./socks5proxy --config socks5-config.json 1080  # 使用自定义配置")
	log.Printf("")

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
	case <-ctx.Done():
		log.Printf("Context cancelled, shutting down...")
	}

	// 优雅关闭
	log.Printf("Stopping SOCKS5 server...")
	server.Stop()

	log.Printf("Stopping Web server...")
	webServer.Stop()

	log.Printf("Stopping DNS server...")
	if err := dnsServer.Stop(); err != nil {
		log.Printf("Error stopping DNS server: %v", err)
	}

	log.Printf("SmartProxy stopped gracefully")
}

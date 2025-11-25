package main

import (
	"log"
	"os"
	"strconv"
	"smartproxy/socks5"
)

func main() {
	port := 1080 // 默认 SOCKS5 端口
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

	server, err := socks5.NewSOCKS5ServerWithConfig(port, configPath)
	if err != nil {
		log.Fatalf("Failed to create SOCKS5 server: %v", err)
	}

	log.Printf("Starting SOCKS5 proxy server on port %d", port)
	log.Printf("Config file: %s", configPath)
	log.Printf("使用方法: 设置代理为 127.0.0.1:%d", port)
	log.Printf("")
	log.Printf("示例用法:")
	log.Printf("  ./socks5proxy 1080                    # 使用默认配置")
	log.Printf("  ./socks5proxy --config socks5-config.json 1080  # 使用自定义配置")

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
package main

import (
	"fmt"
	"log"
	"time"

	"../socks5"
)

func main() {
	fmt.Println("SOCKS5 限速功能演示")
	fmt.Println("===================")

	// 创建限速器
	logger := log.New(log.Writer(), "[RateLimitDemo] ", log.LstdFlags)
	rateLimiter := socks5.NewRateLimiter(logger)

	// 设置全局限速：10Mbps上传，20Mbps下载
	rateLimiter.SetGlobalLimits(10*1000*1000, 20*1000*1000)
	fmt.Println("✓ 设置全局限速: 上传 10Mbps, 下载 20Mbps")

	// 添加IP限速规则
	ipRule := &socks5.RateLimitRule{
		ID:            "ip_192_168_1_100",
		Type:          socks5.RateLimitTypeIP,
		Key:           "192.168.1.100",
		UploadLimit:   5 * 1000 * 1000,  // 5Mbps上传
		DownloadLimit: 10 * 1000 * 1000, // 10Mbps下载
		BurstSize:     2 * 1000 * 1000,  // 2MB突发
		Enabled:       true,
		Priority:      1,
	}

	err := rateLimiter.AddRule(ipRule)
	if err != nil {
		fmt.Printf("❌ 添加IP限速规则失败: %v\n", err)
		return
	}
	fmt.Println("✓ 添加IP限速规则: 192.168.1.100 (上传 5Mbps, 下载 10Mbps)")

	// 添加用户限速规则
	userRule := &socks5.RateLimitRule{
		ID:            "user_test",
		Type:          socks5.RateLimitTypeUser,
		Key:           "testuser",
		UploadLimit:   2 * 1000 * 1000,  // 2Mbps上传
		DownloadLimit: 5 * 1000 * 1000,  // 5Mbps下载
		BurstSize:     1 * 1000 * 1000,  // 1MB突发
		Enabled:       true,
		Priority:      2,
	}

	err = rateLimiter.AddRule(userRule)
	if err != nil {
		fmt.Printf("❌ 添加用户限速规则失败: %v\n", err)
		return
	}
	fmt.Println("✓ 添加用户限速规则: testuser (上传 2Mbps, 下载 5Mbps)")

	fmt.Println("\n📊 限速测试:")
	fmt.Println("----------------")

	// 测试限速功能
	testRateLimiting(rateLimiter, "192.168.1.100", 1*1024*1024)  // 1MB数据
	testRateLimiting(rateLimiter, "testuser", 512*1024)         // 512KB数据
	testRateLimiting(rateLimiter, "unlimited_ip", 2*1024*1024) // 无限制IP

	// 显示统计信息
	fmt.Println("\n📈 限速统计:")
	fmt.Println("----------------")
	stats := rateLimiter.GetStats()
	for key, stat := range stats {
		fmt.Printf("%s:\n", key)
		fmt.Printf("  总字节数: %d\n", stat.TotalBytes)
		fmt.Printf("  允许字节数: %d\n", stat.AllowedBytes)
		fmt.Printf("  限制字节数: %d\n", stat.ThrottledBytes)
		fmt.Printf("  丢弃字节数: %d\n", stat.DroppedBytes)
		fmt.Printf("  最后更新: %s\n", stat.LastUpdate.Format("15:04:05"))
		fmt.Println()
	}

	// 显示令牌桶状态
	fmt.Println("🪣 令牌桶状态:")
	fmt.Println("----------------")
	uploadAvail, downloadAvail := rateLimiter.GetBucketStatus("192.168.1.100")
	fmt.Printf("192.168.1.100 上传可用: %d bytes\n", uploadAvail)
	fmt.Printf("192.168.1.100 下载可用: %d bytes\n", downloadAvail)

	uploadAvail, downloadAvail = rateLimiter.GetBucketStatus("testuser")
	fmt.Printf("testuser 上传可用: %d bytes\n", uploadAvail)
	fmt.Printf("testuser 下载可用: %d bytes\n", downloadAvail)

	// 显示使用率
	fmt.Println("\n📊 使用率:")
	fmt.Println("----------------")
	for _, key := range []string{"192.168.1.100", "testuser"} {
		uploadRate, downloadRate := rateLimiter.GetUsageRate(key)
		fmt.Printf("%s 上传使用率: %.1f%%\n", key, uploadRate)
		fmt.Printf("%s 下载使用率: %.1f%%\n", key, downloadRate)
	}

	fmt.Println("\n✅ 限速功能演示完成")
}

func testRateLimiting(rateLimiter *socks5.RateLimiter, identifier string, dataSize int64) {
	fmt.Printf("测试 %s (%d bytes):\n", identifier, dataSize)

	// 测试上传限速
	allowed := rateLimiter.CheckUploadLimit(identifier, dataSize)
	if allowed {
		fmt.Printf("  ✓ 上传: 允许通过 %d bytes\n", dataSize)
	} else {
		fmt.Printf("  ❌ 上传: 被限制 %d bytes\n", dataSize)
	}

	// 测试下载限速
	allowed = rateLimiter.CheckDownloadLimit(identifier, dataSize)
	if allowed {
		fmt.Printf("  ✓ 下载: 允许通过 %d bytes\n", dataSize)
	} else {
		fmt.Printf("  ❌ 下载: 被限制 %d bytes\n", dataSize)
	}

	fmt.Println()
}
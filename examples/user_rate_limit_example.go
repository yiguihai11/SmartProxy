package main

import (
	"fmt"
	"log"

	"../socks5"
)

func main() {
	fmt.Println("基于用户限速功能演示")
	fmt.Println("===================")

	// 创建日志记录器
	logger := log.New(log.Writer(), "[UserRateLimitDemo] ", log.LstdFlags)

	// 创建SOCKS5服务器
	server, err := socks5.NewSOCKS5Server(1080)
	if err != nil {
		fmt.Printf("创建服务器失败: %v\n", err)
		return
	}

	// 启用用户认证
	server.EnableAuthentication(true)
	fmt.Println("✓ 启用用户认证")

	// 添加用户和对应的限速规则
	users := []struct {
		username string
		password string
		role     string
		upload   int64 // 上传限速 (bps)
		download int64 // 下载限速 (bps)
	}{
		{"free_user", "password123", "free", 1 * 1000 * 1000, 5 * 1000 * 1000},   // 1Mbps上传, 5Mbps下载
		{"vip_user", "vip_pass456", "vip", 10 * 1000 * 1000, 50 * 1000 * 1000},  // 10Mbps上传, 50Mbps下载
		{"premium_user", "premium789", "premium", 50 * 1000 * 1000, 200 * 1000 * 1000}, // 50Mbps上传, 200Mbps下载
	}

	for _, user := range users {
		// 添加用户
		err := server.AddUser(user.username, user.password, user.role)
		if err != nil {
			fmt.Printf("❌ 添加用户 %s 失败: %v\n", user.username, err)
			continue
		}
		fmt.Printf("✓ 添加用户: %s (%s)\n", user.username, user.role)

		// 添加对应的限速规则
		rule := &socks5.RateLimitRule{
			ID:            "user_" + user.username,
			Type:          socks5.RateLimitTypeUser,
			Key:           user.username,
			UploadLimit:   user.upload,
			DownloadLimit: user.download,
			BurstSize:     user.upload * 2, // 2秒突发
			Enabled:       true,
			Priority:      1,
		}

		err = server.AddRateLimitRule(rule)
		if err != nil {
			fmt.Printf("❌ 添加限速规则失败 for %s: %v\n", user.username, err)
		} else {
			fmt.Printf("✓ 添加限速规则: %s (上传 %dMbps, 下载 %dMbps)\n",
				user.username, user.upload/1000000, user.download/1000000)
		}
	}

	// 设置全局限速作为后备
	server.ConfigureRateLimits(100*1000*1000, 500*1000*1000) // 100Mbps上传, 500Mbps下载
	fmt.Println("✓ 设置全局限速: 上传 100Mbps, 下载 500Mbps (作为后备)")

	fmt.Println("\n🎯 限速规则说明:")
	fmt.Println("==================")
	fmt.Println("1. free_user:     1Mbps 上传, 5Mbps 下载")
	fmt.Println("2. vip_user:     10Mbps 上传, 50Mbps 下载")
	fmt.Println("3. premium_user: 50Mbps 上传, 200Mbps 下载")
	fmt.Println("4. 未认证用户:   全局限速 (100Mbps上传, 500Mbps下载)")

	fmt.Println("\n📊 测试限速功能:")
	fmt.Println("==================")
	testUserRateLimiting(server, "free_user", 2*1024*1024)      // 2MB数据，应该被限制
	testUserRateLimiting(server, "vip_user", 5*1024*1024)        // 5MB数据，应该通过
	testUserRateLimiting(server, "premium_user", 100*1024*1024) // 100MB数据，应该通过
	testUserRateLimiting(server, "unknown_user", 10*1024*1024)  // 未知用户，使用全局限速

	// 显示用户列表
	fmt.Println("\n👥 当前用户列表:")
	fmt.Println("==================")
	users_list := server.ListUsers()
	for _, user := range users_list {
		fmt.Printf("用户: %s, 角色: %s, 启用: %t\n", user.Username, user.Role, user.Enabled)
	}

	// 显示限速统计
	fmt.Println("\n📈 限速统计:")
	fmt.Println("==================")
	stats := server.GetRateLimitStats()
	for key, stat := range stats {
		fmt.Printf("%s:\n", key)
		fmt.Printf("  总流量: %d bytes (%.2f MB)\n", stat.TotalBytes, float64(stat.TotalBytes)/1024/1024)
		fmt.Printf("  允许流量: %d bytes (%.2f MB)\n", stat.AllowedBytes, float64(stat.AllowedBytes)/1024/1024)
		fmt.Printf("  限制流量: %d bytes (%.2f MB)\n", stat.ThrottledBytes, float64(stat.ThrottledBytes)/1024/1024)
		fmt.Printf("  丢弃流量: %d bytes (%.2f MB)\n", stat.DroppedBytes, float64(stat.DroppedBytes)/1024/1024)
		fmt.Printf("  允许率: %.1f%%\n", float64(stat.AllowedBytes)/float64(stat.TotalBytes)*100)
		fmt.Println()
	}

	// 显示令牌桶状态
	fmt.Println("🪣 令牌桶状态:")
	fmt.Println("==================")
	rateLimiter := server.GetRateLimiter()
	for _, user := range []string{"free_user", "vip_user", "premium_user"} {
		uploadAvail, downloadAvail := rateLimiter.GetBucketStatus(user)
		fmt.Printf("%s:\n", user)
		fmt.Printf("  上传可用: %.2f MB\n", float64(uploadAvail)/1024/1024)
		fmt.Printf("  下载可用: %.2f MB\n", float64(downloadAvail)/1024/1024)

		uploadRate, downloadRate := rateLimiter.GetUsageRate(user)
		fmt.Printf("  上传使用率: %.1f%%\n", uploadRate)
		fmt.Printf("  下载使用率: %.1f%%\n", downloadRate)
		fmt.Println()
	}

	fmt.Println("\n🔧 管理示例:")
	fmt.Println("==================")
	fmt.Println("// 动态添加用户")
	fmt.Println("server.AddUser(\"new_user\", \"newpass123\", \"free\")")
	fmt.Println()
	fmt.Println("// 动态修改限速")
	fmt.Println("newRule := &socks5.RateLimitRule{")
	fmt.Println("    ID: \"user_new_user\",")
	fmt.Println("    Type: socks5.RateLimitTypeUser,")
	fmt.Println("    Key: \"new_user\",")
	fmt.Println("    UploadLimit: 20 * 1000 * 1000,")
	fmt.Println("    DownloadLimit: 100 * 1000 * 1000,")
	fmt.Println("    Enabled: true,")
	fmt.Println("}")
	fmt.Println("server.AddRateLimitRule(newRule)")
	fmt.Println()
	fmt.Println("// 禁用用户")
	fmt.Println("server.RemoveUser(\"free_user\")")

	fmt.Println("\n✅ 基于用户限速功能演示完成")
	fmt.Println("现在可以根据不同的用户等级进行精确的带宽控制！")
}

func testUserRateLimiting(server *socks5.SOCKS5Server, username string, dataSize int64) {
	rateLimiter := server.GetRateLimiter()
	if rateLimiter == nil {
		fmt.Printf("限速器未初始化，跳过测试 %s\n", username)
		return
	}

	fmt.Printf("测试用户 %s (%.2f MB):\n", username, float64(dataSize)/1024/1024)

	// 测试上传限速
	uploadAllowed := rateLimiter.CheckUploadLimit(username, dataSize)
	if uploadAllowed {
		fmt.Printf("  ✓ 上传: 允许通过 %.2f MB\n", float64(dataSize)/1024/1024)
	} else {
		fmt.Printf("  ❌ 上传: 被限制 %.2f MB\n", float64(dataSize)/1024/1024)
	}

	// 测试下载限速
	downloadAllowed := rateLimiter.CheckDownloadLimit(username, dataSize)
	if downloadAllowed {
		fmt.Printf("  ✓ 下载: 允许通过 %.2f MB\n", float64(dataSize)/1024/1024)
	} else {
		fmt.Printf("  ❌ 下载: 被限制 %.2f MB\n", float64(dataSize)/1024/1024)
	}

	fmt.Println()
}
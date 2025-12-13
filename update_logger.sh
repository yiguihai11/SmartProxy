#!/bin/bash

# 批量更新logger使用情况的脚本

FILES=(
    "dns/dns.go"
    "socks5/nat_traversal.go"
    "socks5/proxy_nodes.go"
    "socks5/auth.go"
    "socks5/detection.go"
    "socks5/blocked_items_manager.go"
    "socks5/ratelimit.go"
)

echo "更新logger使用情况..."

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "处理文件: $file"

        # 添加logger import（如果还没有）
        if ! grep -q "smartproxy/logger" "$file"; then
            sed -i 's|"log"|"smartproxy/logger"|g' "$file"
        fi

        # 替换logger.Printf为logger.Info
        sed -i 's/\.logger\.Printf(/.logger.Info(/g' "$file"

        # 替换*log.Logger为*logger.LogrusLogger（在结构体字段中）
        sed -i 's/\\*log\\.Logger/\\*logger.LogrusLogger/g' "$file"

        # 替换logger := log.New为logger := logger.NewStdLogger
        sed -i 's/logger := log\.New(/logger := logger.NewStdLogger(/g' "$file"
    fi
done

echo "更新完成！"
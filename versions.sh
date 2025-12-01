#!/bin/bash

# SmartProxy 版本管理脚本
# 使用方法:
# ./versions.sh save "描述" - 创建新版本
# ./versions.sh list - 列出所有版本
# ./versions.sh checkout <版本号> - 切换到指定版本

VERSION_FILE=".version"
BACKUP_DIR="versions"

function save_version() {
    local message="$1"
    if [ -z "$message" ]; then
        echo "用法: $0 save \"版本描述\""
        exit 1
    fi

    # 获取当前版本号
    local current_version=$(cat "$VERSION_FILE" 2>/dev/null || echo "v1.0.0")
    local new_version=$(echo "$current_version" | awk -F. '{printf("%d.%d.%d", $1+1, $2, $3+1)}')

    # 保存版本信息
    echo "$new_version" > "$VERSION_FILE"
    echo "$message" > "$VERSION_FILE.msg"

    # 创建备份
    mkdir -p "$BACKUP_DIR"
    cp -r web/static "$BACKUP_DIR/static-$new_version"

    # Git提交
    git add .
    git commit -m "Version $new_version: $message"

    # 创建Git标签
    git tag -a "v$new_version" -m "Version $new_version: $message"

    echo "✅ 版本 $new_version 已保存: $message"
}

function list_versions() {
    echo "📦 SmartProxy 版本历史:"
    git tag --sort=-v:refname | sed 's/v//' | head -20

    if [ -f "$VERSION_FILE.msg" ]; then
        echo ""
        echo "📝 当前版本: $(cat "$VERSION_FILE") - $(cat "$VERSION_FILE.msg")"
    fi
}

function checkout_version() {
    local version="$1"
    if [ -z "$version" ]; then
        echo "用法: $0 checkout <版本号>"
        exit 1
    fi

    # 检查版本是否存在
    if ! git tag | grep -q "^v$version$"; then
        echo "❌ 版本 v$version 不存在"
        list_versions
        exit 1
    fi

    # 备份当前修改
    git stash push -m "Backup before switching to v$version"

    # 切换到指定版本
    git checkout "v$version"

    # 更新版本文件
    echo "$version" > "$VERSION_FILE"

    echo "✅ 已切换到版本 v$version"
}

function show_help() {
    echo "SmartProxy 版本管理工具"
    echo ""
    echo "用法: $0 <命令> [参数]"
    echo ""
    echo "命令:"
    echo "  save <描述>     创建新版本"
    echo "  list           列出所有版本"
    echo "  checkout <版本> 切换到指定版本"
    echo "  help          显示帮助"
}

# 主程序
case "$1" in
    "save")
        save_version "$2"
        ;;
    "list")
        list_versions
        ;;
    "checkout")
        checkout_version "$2"
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        echo "❌ 未知命令: $1"
        show_help
        exit 1
        ;;
esac
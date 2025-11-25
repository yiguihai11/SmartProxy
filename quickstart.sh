#!/bin/bash

# Go SOCKS5 代理服务器快速启动脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 显示帮助信息
show_help() {
    echo "Go SOCKS5 代理服务器快速启动脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -p, --port PORT      指定端口号 (默认: 1080)"
    echo "  -c, --config FILE    指定配置文件"
    echo "  -t, --test           启动后进行测试"
    echo "  -b, --build          强制重新编译"
    echo "  -h, --help           显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0                   # 使用默认设置启动"
    echo "  $0 -p 8080          # 指定端口 8080"
    echo "  $0 -c enhanced-config.json -p 1080  # 使用自定义配置"
    echo "  $0 -t               # 启动后进行测试"
    echo ""
}

# 检查依赖
check_dependencies() {
    print_info "检查依赖..."

    if ! command -v go &> /dev/null; then
        print_error "Go 未安装或不在 PATH 中"
        exit 1
    fi

    if ! command -v make &> /dev/null; then
        print_warning "Make 未安装，将使用 go build 直接编译"
        USE_MAKE=false
    else
        USE_MAKE=true
    fi

    print_success "依赖检查完成"
}

# 编译程序
build_program() {
    print_info "编译程序..."

    if [ "$FORCE_BUILD" = true ] || [ ! -f "socks5proxy" ]; then
        if [ "$USE_MAKE" = true ]; then
            make build
        else
            CGO_ENABLED=0 go build -o socks5proxy .
        fi
        print_success "编译完成"
    else
        print_info "程序已存在，跳过编译"
    fi
}

# 测试代理功能
test_proxy() {
    local port=$1
    print_info "测试代理功能 (端口: $port)..."

    # 在后台启动代理
    ./socks5proxy $port > /tmp/socks5_test.log 2>&1 &
    local proxy_pid=$!

    # 等待代理启动
    sleep 2

    # 测试连接
    if command -v curl &> /dev/null; then
        if curl --socks5 127.0.0.1:$port -m 10 -s http://httpbin.org/ip > /dev/null 2>&1; then
            print_success "代理测试成功"
        else
            print_error "代理测试失败"
        fi
    else
        print_warning "curl 未安装，跳过代理测试"
    fi

    # 停止代理
    kill $proxy_pid 2>/dev/null || true
    wait $proxy_pid 2>/dev/null || true
}

# 启动代理
start_proxy() {
    local port=$1
    local config=$2

    print_info "启动 SOCKS5 代理服务器..."
    print_info "端口: $port"
    if [ -n "$config" ]; then
        print_info "配置文件: $config"
        ./socks5proxy --config "$config" "$port"
    else
        print_info "配置文件: 默认"
        ./socks5proxy "$port"
    fi
}

# 主函数
main() {
    # 默认参数
    PORT=1080
    CONFIG=""
    TEST=false
    FORCE_BUILD=false

    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--port)
                PORT="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG="$2"
                shift 2
                ;;
            -t|--test)
                TEST=true
                shift
                ;;
            -b|--build)
                FORCE_BUILD=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                print_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # 显示启动信息
    echo "========================================"
    echo "  Go SOCKS5 代理服务器"
    echo "========================================"
    echo "端口: $PORT"
    if [ -n "$CONFIG" ]; then
        echo "配置文件: $CONFIG"
    fi
    if [ "$TEST" = true ]; then
        echo "测试模式: 开启"
    fi
    echo "========================================"

    # 检查依赖
    check_dependencies

    # 编译程序
    build_program

    # 如果指定了测试，先进行测试
    if [ "$TEST" = true ]; then
        test_proxy "$PORT"
        echo ""
        print_info "测试完成，现在启动代理服务器..."
        echo ""
    fi

    # 启动代理
    start_proxy "$PORT" "$CONFIG"
}

# 信号处理
trap 'print_info "正在停止代理服务器..."; exit 0' INT TERM

# 运行主函数
main "$@"
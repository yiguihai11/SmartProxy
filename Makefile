# Go SOCKS5 代理服务器 Makefile

# 变量定义
BINARY_NAME=smartproxy
BUILD_DIR=build
GO_FILES=$(shell find . -name "*.go" -type f)
STATIC_DIR=web/static
STATIC_FILES=$(shell find $(STATIC_DIR) -name "*.html" -o -name "*.css" -o -name "*.js" -o -name "*.min.js" -type f)
EMBED_GO_FILES=web/server.go

# 检查静态文件是否变化
STATIC_DEPS_FILE=$(BUILD_DIR)/.static_deps
ifeq ($(STATIC_DEPS_FILE),$(shell test -f $(STATIC_DEPS_FILE) && cat $(STATIC_DEPS_FILE) || echo "missing"))
STATIC_CHANGED=1
else
STATIC_CHANGED=0
endif

# 创建依赖标记文件
$(STATIC_DEPS_FILE): $(STATIC_FILES)
	@mkdir -p $(BUILD_DIR)
	@echo "检测静态文件变化..."
	@find $(STATIC_DIR) -name "*.html" -o -name "*.css" -o -name "*.js" -o -name "*.min.js" -type f -exec sha256sum {} \; | cut -d' ' -f1 | sha256sum > $(STATIC_DEPS_FILE)

# 默认目标
.PHONY: all
all: build

# 编译（自动检测静态文件变化）
.PHONY: build
build: $(STATIC_DEPS_FILE)
ifeq ($(STATIC_CHANGED),1)
	@echo "📦 静态文件已变化，强制重新编译 $(BINARY_NAME)..."
	@CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY_NAME) .
	@echo "✅ 编译完成: $(BINARY_NAME)"
	@echo "🔄 请重启服务以加载新版本: ./$(BINARY_NAME) --config conf/config.json"
else
	@echo "📦 静态文件无变化，跳过编译"
	@echo "💡 如需强制重新编译: make build-force"
endif

# 强制编译（忽略静态文件变化检测）
.PHONY: build-force
build-force:
	@echo "🔨 强制重新编译 $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@rm -f $(STATIC_DEPS_FILE)
	@CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY_NAME) .
	@echo "✅ 强制编译完成: $(BINARY_NAME)"
	@echo "🔄 请重启服务: ./$(BINARY_NAME) --config conf/config.json"

# 更新资源版本
.PHONY: update-version
update-version:
	@echo "🔄 更新资源版本..."
	@if [ -f update-assets-version.sh ]; then \
		chmod +x update-assets-version.sh; \
		./update-assets-version.sh --no-rebuild; \
	else \
		echo "❌ update-assets-version.sh 脚本不存在"; \
		exit 1; \
	fi

# 更新资源版本并重新编译
.PHONY: release-version
release-version: build-force update-version
	@echo "🚀 资源版本更新并重新编译完成"

# 开发模式（自动重启）
.PHONY: dev
dev: build-force
	@echo "🛠️ 开发模式：启动服务..."
	@if [ -f conf/test_config.json ]; then \
		./$(BINARY_NAME) --config conf/test_config.json --web 8080; \
	else \
		./$(BINARY_NAME) --config conf/config.json --web 8080; \
	fi

# 清理
.PHONY: clean
clean:
	@echo "🗑️ 清理编译文件和缓存..."
	@rm -f $(BINARY_NAME)
	@rm -rf $(BUILD_DIR)
	@rm -f $(BINARY_NAME)-*
	@echo "✅ 清理完成"

# 深度清理（包括Go缓存）
.PHONY: clean-all
clean-all: clean
	@echo "🗑️ 深度清理：清理Go编译缓存..."
	@go clean -cache
	@rm -rf ~/.cache/go-build
	@echo "✅ 深度清理完成"

# 安装到系统
.PHONY: install
install: build
	@echo "📦 安装 $(BINARY_NAME) 到 /usr/local/bin/..."
	sudo cp $(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "✅ 安装完成"

# 卸载
.PHONY: uninstall
uninstall:
	@echo "🗑️ 卸载 $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "✅ 卸载完成"

# 运行（默认配置）
.PHONY: run
run: build
	@echo "🚀 启动 $(BINARY_NAME) 在端口 1080..."
	./$(BINARY_NAME) --config conf/config.json

# 运行（自定义端口）
.PHONY: run-port
run-port: build
	@if [ -z "$(PORT)" ]; then \
		echo "💡 使用方法: make run-port PORT=8080"; \
		exit 1; \
	fi
	@echo "🚀 启动 $(BINARY_NAME) 在端口 $(PORT)..."
	./$(BINARY_NAME) --config conf/config.json --web $(PORT)

# 运行（自定义配置）
.PHONY: run-config
run-config: build
	@if [ -z "$(CONFIG)" ]; then \
		echo "💡 使用方法: make run-config CONFIG=enhanced-config.json PORT=1080"; \
		exit 1; \
	fi
	@if [ -z "$(PORT)" ]; then \
		echo "💡 使用方法: make run-config CONFIG=enhanced-config.json PORT=1080"; \
		exit 1; \
	fi
	@echo "🚀 使用配置文件 $(CONFIG) 启动 $(BINARY_NAME) 在端口 $(PORT)..."
	./$(BINARY_NAME) --config $(CONFIG) --web $(PORT)

# 测试
.PHONY: test
test:
	@echo "🧪 运行测试..."
	cd examples && go run test_proxy.go 127.0.0.1:1080 http://httpbin.org/ip

# 格式化代码
.PHONY: fmt
fmt:
	@echo "📝 格式化 Go 代码..."
	go fmt ./...

# 检查代码
.PHONY: vet
vet:
	@echo "🔍 运行 go vet..."
	go vet ./...

# 交叉编译
.PHONY: build-all
build-all:
	@echo "🔨 交叉编译..."
	@mkdir -p $(BUILD_DIR)

	# Linux AMD64
	@echo "编译 Linux AMD64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .

	# Linux ARM64
	@echo "编译 Linux ARM64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .

	# macOS AMD64
	@echo "编译 macOS AMD64..."
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .

	# macOS ARM64 (Apple Silicon)
	@echo "编译 macOS ARM64..."
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .

	# Windows AMD64
	@echo "编译 Windows AMD64..."
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .

	@echo "✅ 交叉编译完成:"
	@ls -la $(BUILD_DIR)/

# 打包发布
.PHONY: release
release: build-all
	@echo "📦 创建发布包..."
	@mkdir -p $(BUILD_DIR)/release

	# 复制文件到发布包
	@cp $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(BUILD_DIR)/release/
	@cp $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(BUILD_DIR)/release/
	@cp $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(BUILD_DIR)/release/
	@cp $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(BUILD_DIR)/release/
	@cp $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(BUILD_DIR)/release/

	# 复制配置文件
	@cp -r conf/ $(BUILD_DIR)/release/
	@cp *.json $(BUILD_DIR)/release/ 2>/dev/null || true
	@cp README.md $(BUILD_DIR)/release/ 2>/dev/null || true

	@echo "✅ 发布包创建完成: $(BUILD_DIR)/release/"
	@cd $(BUILD_DIR)/release && ls -la

# 显示帮助
.PHONY: help
help:
	@echo "🔧 SmartProxy Makefile 帮助信息"
	@echo ""
	@echo "可用的 make 目标:"
	@echo "  build          - 编译程序（自动检测静态文件变化）"
	@echo "  build-force    - 强制重新编译程序"
	@echo "  dev            - 开发模式：编译并启动服务"
	@echo "  update-version - 更新资源版本"
	@echo "  release-version - 更新资源版本并重新编译"
	@echo "  clean          - 清理编译文件"
	@echo "  clean-all      - 深度清理（包括Go缓存）"
	@echo "  run            - 运行程序（默认配置）"
	@echo "  run-port       - 运行程序（自定义端口： make run-port PORT=8080）"
	@echo "  run-config     - 运行程序（自定义配置： make run-config CONFIG=enhanced-config.json PORT=1080）"
	@echo "  install        - 安装到系统"
	@echo "  uninstall      - 从系统卸载"
	@echo "  test           - 运行测试"
	@echo "  fmt            - 格式化 Go 代码"
	@echo "  vet            - 检查 Go 代码"
	@echo "  build-all      - 交叉编译到所有平台"
	@echo "  release        - 创建发布包"
	@echo "  help           - 显示此帮助信息"
	@echo ""
	@echo "示例:"
	@echo "  make                    # 编译（智能检测）"
	@echo "  make build-force         # 强制重新编译"
	@echo "  make dev                # 开发模式"
	@echo "  make run-port PORT=8080  # 自定义端口运行"
	@echo "  make update-version      # 更新资源版本"
# Go SOCKS5 代理服务器 Makefile

# 变量定义
BINARY_NAME=socks5proxy
BUILD_DIR=build
GO_FILES=$(shell find . -name "*.go" -type f)

# 默认目标
.PHONY: all
all: build

# 编译
.PHONY: build
build:
	@echo "编译 $(BINARY_NAME)..."
	CGO_ENABLED=0 go build -o $(BINARY_NAME) .
	@echo "编译完成: $(BINARY_NAME)"

# 清理
.PHONY: clean
clean:
	@echo "清理编译文件..."
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)
	@echo "清理完成"

# 安装到系统
.PHONY: install
install: build
	@echo "安装 $(BINARY_NAME) 到 /usr/local/bin/..."
	sudo cp $(BINARY_NAME) /usr/local/bin/
	@echo "安装完成"

# 卸载
.PHONY: uninstall
uninstall:
	@echo "卸载 $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "卸载完成"

# 运行（默认端口）
.PHONY: run
run: build
	@echo "启动 $(BINARY_NAME) 在端口 1080..."
	./$(BINARY_NAME) 1080

# 运行（自定义端口）
.PHONY: run-port
run-port: build
	@if [ -z "$(PORT)" ]; then \
		echo "使用方法: make run-port PORT=8080"; \
		exit 1; \
	fi
	@echo "启动 $(BINARY_NAME) 在端口 $(PORT)..."
	./$(BINARY_NAME) $(PORT)

# 运行（自定义配置）
.PHONY: run-config
run-config: build
	@if [ -z "$(CONFIG)" ]; then \
		echo "使用方法: make run-config CONFIG=enhanced-config.json PORT=1080"; \
		exit 1; \
	fi
	@if [ -z "$(PORT)" ]; then \
		echo "使用方法: make run-config CONFIG=enhanced-config.json PORT=1080"; \
		exit 1; \
	fi
	@echo "使用配置文件 $(CONFIG) 启动 $(BINARY_NAME) 在端口 $(PORT)..."
	./$(BINARY_NAME) --config $(CONFIG) $(PORT)

# 测试
.PHONY: test
test:
	@echo "运行测试..."
	cd examples && go run test_proxy.go 127.0.0.1:1080 http://httpbin.org/ip

# 格式化代码
.PHONY: fmt
fmt:
	@echo "格式化 Go 代码..."
	go fmt ./...

# 检查代码
.PHONY: vet
vet:
	@echo "运行 go vet..."
	go vet ./...

# 交叉编译
.PHONY: build-all
build-all:
	@echo "交叉编译..."
	mkdir -p $(BUILD_DIR)

	# Linux AMD64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .

	# Linux ARM64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .

	# macOS AMD64
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .

	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .

	# Windows AMD64
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .

	@echo "交叉编译完成:"
	@ls -la $(BUILD_DIR)/

# 打包发布
.PHONY: release
release: build-all
	@echo "创建发布包..."
	mkdir -p $(BUILD_DIR)/release

	# 复制文件到发布包
	cp $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(BUILD_DIR)/release/
	cp $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(BUILD_DIR)/release/
	cp $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(BUILD_DIR)/release/
	cp $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(BUILD_DIR)/release/
	cp $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(BUILD_DIR)/release/

	# 复制配置文件
	cp -r conf/ $(BUILD_DIR)/release/
	cp *.json $(BUILD_DIR)/release/
	cp README.md $(BUILD_DIR)/release/

	@echo "发布包创建完成: $(BUILD_DIR)/release/"

# 显示帮助
.PHONY: help
help:
	@echo "可用的 make 目标:"
	@echo "  build        - 编译程序"
	@echo "  clean        - 清理编译文件"
	@echo "  install      - 安装到系统"
	@echo "  uninstall    - 从系统卸载"
	@echo "  run          - 运行程序（默认端口 1080）"
	@echo "  run-port     - 运行程序（自定义端口: make run-port PORT=8080）"
	@echo "  run-config   - 运行程序（自定义配置: make run-config CONFIG=file.json PORT=1080）"
	@echo "  test         - 运行测试"
	@echo "  fmt          - 格式化代码"
	@echo "  vet          - 检查代码"
	@echo "  build-all    - 交叉编译到所有平台"
	@echo "  release      - 创建发布包"
	@echo "  help         - 显示此帮助信息"
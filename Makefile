# Go cross-compile targets
BINARY := smartproxy
MAIN   := ./cmd/smartproxy/
OUTDIR := build

# Version follows git: nearest "v*" version tag (leading "v" stripped), plus
# commit-count suffix (e.g. "1.1.0-3-gabc1234") and "-dirty" when the tree is
# modified. --match 'v*' ignores non-version tags (e.g. ad-hoc backup tags).
# Outside a git repo it falls back to the last release; override explicitly
# with: make build VERSION=x.y.z
GIT_TAG    := $(shell git describe --tags --match 'v*' --always --dirty 2>/dev/null)
VERSION    ?= $(if $(GIT_TAG),$(patsubst v%,%,$(GIT_TAG)),1.0.0)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# Local "YYYY-MM-DD HH:MM:SS". The -X value is wrapped in single quotes because
# go build splits -ldflags with quoted.Split (quotes group a span; backslashes
# do not escape) — the recipe's outer double quotes keep the inner quotes intact.
BUILD_TIME ?= $(shell date +%Y-%m-%d\ %H:%M:%S)

LDFLAGS := -s -w \
	-X smartproxy/internal/version.Version=$(VERSION) \
	-X smartproxy/internal/version.GitCommit=$(GIT_COMMIT) \
	-X 'smartproxy/internal/version.BuildTime=$(BUILD_TIME)'

CROSS := \
	$(OUTDIR)/$(BINARY)-linux-amd64 \
	$(OUTDIR)/$(BINARY)-linux-arm64 \
	$(OUTDIR)/$(BINARY)-linux-arm \
	$(OUTDIR)/$(BINARY)-linux-386 \
	$(OUTDIR)/$(BINARY)-linux-mipsle \
	$(OUTDIR)/$(BINARY)-linux-riscv64 \
	$(OUTDIR)/$(BINARY)-freebsd-amd64 \
	$(OUTDIR)/$(BINARY)-darwin-amd64 \
	$(OUTDIR)/$(BINARY)-darwin-arm64 \
	$(OUTDIR)/$(BINARY)-windows-amd64.exe \
	$(OUTDIR)/$(BINARY)-windows-arm64.exe

GOOS_GOARCH = $(subst -, ,$(subst $(OUTDIR)/$(BINARY)-,,$(subst .exe,,$@)))
GOOS = $(word 1,$(GOOS_GOARCH))
GOARCH = $(word 2,$(GOOS_GOARCH))

.PHONY: all build build-all check test test-verbose test-race clean lint fmt mod run help

## all: build for current platform
all: build

## build: compile for current platform
build: check-js
	@mkdir -p $(OUTDIR)
	go build -tags with_gvisor -ldflags="$(LDFLAGS)" -o $(OUTDIR)/$(BINARY) $(MAIN)
# and also in the "all" default target
all: build

	@echo "=> $(OUTDIR)/$(BINARY)"

## build-all: cross-compile for all target platforms
build-all: $(CROSS)

$(OUTDIR)/$(BINARY)-%:
	@mkdir -p $(OUTDIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -tags with_gvisor -ldflags="$(LDFLAGS)" -o $@ $(MAIN)
	@echo "=> $@"

## test: run all unit tests
test:
	go test ./...

## test-verbose: run all unit tests with verbose output
test-verbose:
	go test -v -count=1 ./...

## test-race: run all tests with race detector
test-race:
	go test -race ./...

## lint: run go vet
lint:
	go vet ./...

## fmt: format source code
fmt:
	go fmt ./...

## mod: tidy module dependencies
mod:
	go mod tidy

## check: fmt + tidy + lint + test (run before commit)
check: fmt mod lint test
	@echo "=> all checks passed"

## clean: remove build artifacts

## check-js: validate dashboard.html JavaScript syntax
check-js:
	@echo "==> checking JS syntax..."
	@node build.js

clean:
	rm -rf $(OUTDIR)

## android: build Android AAR library
android:
	@mkdir -p $(OUTDIR)
	# -javapkg 是"前缀",gomobile 会在后面追加 Go 包名(pkg.Name()=="mobile"),
	# 所以 -javapkg=smartproxy → Java 包 smartproxy.mobile,类 smartproxy.mobile.Mobile。
	# 若写 -javapkg=smartproxy.mobile 会得到 smartproxy.mobile.mobile(多一层),别踩。
	gomobile bind -tags with_gvisor -target=android -javapkg=smartproxy -o $(OUTDIR)/smartproxy.aar ./mobile
	@echo "=> $(OUTDIR)/smartproxy.aar"

## ios: build iOS Framework
ios:
	@mkdir -p $(OUTDIR)
	gomobile bind -tags with_gvisor -target=ios -o $(OUTDIR)/SmartProxy.xcframework ./mobile
	@echo "=> $(OUTDIR)/SmartProxy.xcframework"

## run: build and start the server (pass config path as CONFIG=...)
run: build
	$(OUTDIR)/$(BINARY) $(or $(CONFIG),config.yaml)

## help: show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@sed -n 's/^## //p' Makefile

package socks5

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
)

// TransparentServer 透明转发服务器
type TransparentServer struct {
	listener   net.Listener
	logger     *log.Logger
	targets    map[string]string // 域名 -> 目标地址的映射
	forwarding map[string]net.Conn // 当前转发的连接
	mu         sync.RWMutex
	running     bool
}

// NewTransparentServer 创建透明转发服务器
func NewTransparentServer(port int, logger *log.Logger) *TransparentServer {
	return &TransparentServer{
		logger:  logger,
		targets: make(map[string]string),
		forwarding: make(map[string]net.Conn),
		running:   true,
	}
}

// AddTarget 添加转发目标
func (ts *TransparentServer) AddTarget(domain, target string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.targets[domain] = target
	ts.logger.Printf("Added transparent forwarding target: %s -> %s", domain, target)
}

// Start 启动透明转发服务器
func (ts *TransparentServer) Start(port int) error {
	var err error
	ts.listener, err = net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", port, err)
	}

	ts.logger.Printf("Transparent forwarding server started on port %d", port)

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		select {
		case <-ctx.Done():
			ts.logger.Printf("Transparent server context cancelled")
		case <-sigChan:
			ts.logger.Printf("Received signal, shutting down...")
			ts.running = false
			ts.listener.Close()
		}
	}()

	// 主处理循环
	for ts.running {
		conn, err := ts.listener.Accept()
		if err != nil {
			if ts.running {
				ts.logger.Printf("Accept error: %v", err)
			}
			continue
		}

		// 🎯 简单透明转发：直接读取目标域名并转发
		go ts.handleTransparentConnection(conn)
	}

	return nil
}

// handleTransparentConnection 处理透明转发连接
func (ts *TransparentServer) handleTransparentConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// 读取目标域名
	buffer := make([]byte, 1024)
	n, err := clientConn.Read(buffer)
	if err != nil {
		ts.logger.Printf("Read error: %v", err)
		return
	}

	targetDomain := string(buffer[:n])

	// 查找目标地址
	ts.mu.RLock()
	targetAddr, exists := ts.targets[targetDomain]
	ts.mu.RUnlock()

	if !exists {
		ts.logger.Printf("Unknown target domain: %s", targetDomain)
		return
	}

	ts.logger.Printf("Transparent forwarding: %s -> %s", targetDomain, targetAddr)

	// 直接连接到目标并转发数据
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		ts.logger.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// 保存转发连接
	ts.mu.Lock()
	ts.forwarding[targetDomain] = targetConn
	ts.mu.Unlock()

	// 双向转发数据
	go io.Copy(clientConn, targetConn)
	go io.Copy(targetConn, clientConn)
}

// Stop 停止透明转发服务器
func (ts *TransparentServer) Stop() {
	ts.running = false
	if ts.listener != nil {
		ts.listener.Close()
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	// 关闭所有转发连接
	for _, conn := range ts.forwarding {
		if conn != nil {
			conn.Close()
		}
	}

	ts.logger.Printf("Transparent forwarding server stopped")
}
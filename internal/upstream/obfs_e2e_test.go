//go:build e2e

package upstream

// 端到端验证:SmartProxy 内置 obfs-http / obfs-tls(SIP003 插件)客户端直连真实
// simple-obfs 的 obfs-server,再转发给真实 shadowsocks-rust ssserver —— 复刻标准
// SIP003 服务器侧部署:
//
//	[SmartProxy] --obfs+ss--> [obfs-server:OBFS_PORT] --明文ss--> [ssserver:SS_PORT] --echo target-->
//
// TCP 全链路走 obfs(校验我们与真实 obfs-server 的 wire 互通);UDP 不经插件,
// 直连 SS 服务器端口(obfs 只混淆 TCP,见 ssUDPAssociate 注释)。
//
// 前置条件:
//   - SS_SERVER_BIN 指向编译好的 ssserver(shadowsocks-rust)
//   - OBFS_SERVER_BIN 指向编译好的 obfs-server(simple-obfs;需先装 libev-dev/
//     libcork-dev/pkg-config,再 ./autogen.sh && ./configure --disable-documentation && make)
//
// 运行:
//
//	SS_SERVER_BIN=/path/ssserver OBFS_SERVER_BIN=/path/obfs-server \
//	  go test -tags e2e ./internal/upstream/ -run TestObfsE2E -v

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestObfsE2E 对 http / tls 两种混淆分别做:
//  1. ssserver 以 aes-128-gcm 启动(mode=tcp_and_udp)
//  2. obfs-server 监听 OBFS_PORT,--obfs http|tls,转发 127.0.0.1:SS_PORT
//  3. SmartProxy 用带 ?plugin=obfs-local;obfs=... 的 ss:// URL 连 OBFS_PORT
//  4. TCP 回环 echo,明文往返一致 -> 内置 obfs 客户端与真实 obfs-server 互通
//
// 再验证 UDP:不经 obfs、直连 SS 服务器端口,往返一致。
func TestObfsE2E(t *testing.T) {
	serverBin := os.Getenv("SS_SERVER_BIN")
	obfsServerBin := os.Getenv("OBFS_SERVER_BIN")
	if serverBin == "" || obfsServerBin == "" {
		t.Skip("SS_SERVER_BIN / OBFS_SERVER_BIN not set")
	}

	const (
		method   = "aes-128-gcm"
		password = "smartproxy-obfs-e2e"
	)
	ssPort := freeUDPPort(t)

	// --- ssserver(TCP+UDP) ---
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssserver.json")
	cfg := fmt.Sprintf(`{
	  "server": "127.0.0.1",
	  "server_port": %d,
	  "password": %q,
	  "method": %q,
	  "mode": "tcp_and_udp"
	}`, ssPort, password, method)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ssServer := exec.Command(serverBin, "-c", cfgPath)
	ssServer.Stdout = os.Stderr
	ssServer.Stderr = os.Stderr
	if err := ssServer.Start(); err != nil {
		t.Fatalf("failed to start ssserver: %v", err)
	}
	t.Cleanup(func() {
		ssServer.Process.Kill()
		ssServer.Process.Wait()
	})
	waitForTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ssPort)))

	// 本地回环目标(TCP/UDP echo)
	tcpTarget, udpTarget := startLocalEchoServers(t)
	_, tcpPortStr, _ := net.SplitHostPort(tcpTarget)
	tcpPort, _ := strconv.Atoi(tcpPortStr)
	_, udpPortStr, _ := net.SplitHostPort(udpTarget)
	udpPort, _ := strconv.Atoi(udpPortStr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// --- TCP 经 obfs(http / tls)往返 ---
	for _, obfs := range []string{"http", "tls"} {
		t.Run("obfs-"+obfs, func(t *testing.T) {
			obfsPort := freeUDPPort(t)
			obfsServer := exec.Command(obfsServerBin,
				"-s", "127.0.0.1",
				"-p", strconv.Itoa(obfsPort),
				"-r", fmt.Sprintf("127.0.0.1:%d", ssPort),
				"--obfs", obfs,
			)
			obfsServer.Stdout = os.Stderr
			obfsServer.Stderr = os.Stderr
			if err := obfsServer.Start(); err != nil {
				t.Fatalf("failed to start obfs-server: %v", err)
			}
			t.Cleanup(func() {
				obfsServer.Process.Kill()
				obfsServer.Process.Wait()
			})
			waitForTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(obfsPort)))

			// ss:// 指向 obfs-server 端口,带 SIP003 plugin
			plugin := url.QueryEscape(fmt.Sprintf("obfs-local;obfs=%s;obfs-host=www.bing.com", obfs))
			u := fmt.Sprintf("ss://%s@127.0.0.1:%d?plugin=%s", b64url(method+":"+password), obfsPort, plugin)
			p, err := NewProxy(u)
			if err != nil {
				t.Fatalf("NewProxy: %v", err)
			}

			payload := []byte("hello over " + obfs + " obfs + ss e2e")
			conn, err := p.Connect(ctx, "127.0.0.1", tcpPort)
			if err != nil {
				t.Fatalf("Connect via obfs-%s failed: %v", obfs, err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			echo := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, echo); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if !bytes.Equal(echo, payload) {
				t.Fatalf("echo mismatch: got %q want %q", echo, payload)
			}
			t.Logf("TCP round-trip OK (%d bytes) via real obfs-server (%s)", len(payload), obfs)
		})
	}

	// --- UDP 不经 obfs,直连 SS 服务器端口 ---
	u := fmt.Sprintf("ss://%s@127.0.0.1:%d", b64url(method+":"+password), ssPort)
	p, err := NewProxy(u)
	if err != nil {
		t.Fatalf("NewProxy (udp): %v", err)
	}
	udpConn, err := p.UDPAssociate(ctx, "127.0.0.1", udpPort)
	if err != nil {
		t.Fatalf("UDPAssociate failed: %v", err)
	}
	defer udpConn.Close()

	udpPayload := []byte("hello over ss udp e2e (no obfs)")
	targetIP := net.ParseIP("127.0.0.1").To4()
	frame := []byte{0x00, 0x00, 0x00, 0x01}
	frame = append(frame, targetIP...)
	frame = append(frame, byte(udpPort>>8), byte(udpPort))
	frame = append(frame, udpPayload...)

	udpConn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := udpConn.Write(frame); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	resp := make([]byte, 2048)
	n, err := udpConn.Read(resp)
	if err != nil {
		t.Fatalf("udp read echo: %v", err)
	}
	const hdrLen = 10
	if n <= hdrLen {
		t.Fatalf("udp response too short: %d bytes", n)
	}
	if !bytes.Equal(resp[hdrLen:n], udpPayload) {
		t.Fatalf("udp echo mismatch: got %q want %q", resp[hdrLen:n], udpPayload)
	}
	t.Logf("UDP round-trip OK (%d bytes, bypassing obfs)", len(udpPayload))
}

// waitForTCP 轮询直到 addr 能建立 TCP 连接(替代固定 sleep,避免进程启动抖动)。
func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tcp %s not accepting connections in time", addr)
}

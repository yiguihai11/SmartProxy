//go:build e2e

package upstream

// 端到端验证:SmartProxy 内置 shadowsocks 客户端(ss:// scheme,即"我们就是 sslocal")
// 直连真实 shadowsocks-rust ssserver,验证 AEAD-2022(SIP022)互通。
//
// 注意与 rawrelay_e2e_test.go(裸 UDP relay,Case A)的区别:
//   - rawrelay:代理协议是 socks5,SS 服务器回 rep=0x07 后 SmartProxy 裸 UDP 直发
//     到 sslocal 的监听端口(等价于"发到 sslocal");
//   - 本测试:代理协议是 ss,SmartProxy 直接以 shadowsocks 协议与 ssserver 通讯
//     (等价于"我们就是 sslocal"),不经任何 sslocal / SOCKS5。
//
// 前置条件:SS_SERVER_BIN 指向编译好的 ssserver(需支持 AEAD-2022,>=v1.15)。
//
// 运行:
//
//	SS_SERVER_BIN=/path/ssserver go test -tags e2e ./internal/upstream/ -run TestSS2022E2E -v

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestSS2022E2E 用真实 ssserver 验证 sing 2022 客户端 ↔ rust 2022 服务端互通:
//  1. ssserver 以 2022-blake3-aes-128-gcm 启动(mode=tcp_and_udp,base64 key)
//  2. SmartProxy 用 ss:// URL(NewProxy 完整解析路径)直接连它
//  3. TCP:连本地回环 echo,明文往返一致 -> 2022 TCP 握手(含 timestamp 校验)互通
//  4. UDP:本地回环 echo,经 2022 会话式 UDP(首包 sessionId+packetId)往返一致
func TestSS2022E2E(t *testing.T) {
	serverBin := os.Getenv("SS_SERVER_BIN")
	if serverBin == "" {
		t.Skip("SS_SERVER_BIN not set")
	}

	const (
		method = "2022-blake3-aes-128-gcm"
		key    = "MDEyMzQ1Njc4OWFiY2RlZg==" // base64(16B) "0123456789abcdef",aes-128 用 16 字节 key
	)
	serverPort := freeUDPPort(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssserver2022.json")
	cfg := fmt.Sprintf(`{
	  "server": "127.0.0.1",
	  "server_port": %d,
	  "password": %q,
	  "method": %q,
	  "mode": "tcp_and_udp"
	}`, serverPort, key, method)
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
	time.Sleep(300 * time.Millisecond)

	// 本地回环目标(TCP/UDP echo),全链路不依赖外网
	tcpTarget, udpTarget := startLocalEchoServers(t)
	_, tcpPortStr, _ := net.SplitHostPort(tcpTarget)
	tcpPort, _ := strconv.Atoi(tcpPortStr)
	_, udpPortStr, _ := net.SplitHostPort(udpTarget)
	udpPort, _ := strconv.Atoi(udpPortStr)

	// ss:// URL 走完整解析:base64url(method:key) userinfo -> newSSMethod2022
	u := fmt.Sprintf("ss://%s@127.0.0.1:%d", b64url(method+":"+key), serverPort)
	p, err := NewProxy(u)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// --- TCP 往返 ---
	tcpPayload := []byte("hello over ss 2022 tcp e2e")
	tcpConn, err := p.Connect(ctx, "127.0.0.1", tcpPort)
	if err != nil {
		t.Fatalf("Connect (TCP) via 2022 failed: %v", err)
	}
	defer tcpConn.Close()
	tcpConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := tcpConn.Write(tcpPayload); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	echo := make([]byte, len(tcpPayload))
	if _, err := io.ReadFull(tcpConn, echo); err != nil {
		t.Fatalf("tcp read echo: %v", err)
	}
	if !bytes.Equal(echo, tcpPayload) {
		t.Fatalf("tcp echo mismatch: got %q want %q", echo, tcpPayload)
	}
	t.Logf("TCP round-trip OK (%d bytes) via real ssserver 2022", len(tcpPayload))

	// --- UDP 往返 ---
	udpConn, err := p.UDPAssociate(ctx, "127.0.0.1", udpPort)
	if err != nil {
		t.Fatalf("UDPAssociate via 2022 failed: %v", err)
	}
	defer udpConn.Close()

	udpPayload := []byte("hello over ss 2022 udp e2e")
	targetIP := net.ParseIP("127.0.0.1").To4()
	frame := []byte{0x00, 0x00, 0x00, 0x01} // RSV|RSV|FRAG|ATYP=IPv4
	frame = append(frame, targetIP...)
	frame = append(frame, byte(udpPort>>8), byte(udpPort))
	frame = append(frame, udpPayload...)

	udpConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := udpConn.Write(frame); err != nil {
		t.Fatalf("udp write frame: %v", err)
	}
	resp := make([]byte, 2048)
	n, err := udpConn.Read(resp)
	if err != nil {
		t.Fatalf("udp read echo: %v", err)
	}
	// 响应帧 = SOCKS5 UDP 头(10B,IPv4 目标)+ 原 payload
	const hdrLen = 10
	if n <= hdrLen {
		t.Fatalf("udp response too short: %d bytes", n)
	}
	if !bytes.Equal(resp[hdrLen:n], udpPayload) {
		t.Fatalf("udp echo mismatch: got %q want %q", resp[hdrLen:n], udpPayload)
	}
	t.Logf("UDP round-trip OK (%d bytes) via real ssserver 2022 session", len(udpPayload))
}

// startLocalEchoServers 启动本机 TCP + UDP 回环 echo,返回各自的 127.0.0.1 监听地址。
func startLocalEchoServers(t *testing.T) (tcpAddr, udpAddr string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo
			}(conn)
		}
	}()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], raddr) // echo
		}
	}()

	return ln.Addr().String(), pc.LocalAddr().String()
}

//go:build e2e

package upstream

// 端到端验证:SmartProxy 的裸 UDP relay(udp_addr)直连真实 shadowsocks-rust
// ss-local(udp_only 模式,即 shadowsocks-android 的 UDP 兜底实例等价物)。
//
// 前置条件(由外部脚本准备):
//   - SS_SERVER_BIN 指向编译好的 ssserver
//   - SS_LOCAL_BIN  指向编译好的 sslocal
//   - 这两个进程由本测试自行拉起,测完关闭
//
// 运行:
//
//	SS_SERVER_BIN=/path/ssserver SS_LOCAL_BIN=/path/sslocal go test -tags e2e ./internal/upstream/ -run TestRawRelayE2E -v

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// e2eEnv 持有两个真实二进制路径。
func e2eEnv(t *testing.T) (serverBin, localBin string) {
	t.Helper()
	serverBin = os.Getenv("SS_SERVER_BIN")
	localBin = os.Getenv("SS_LOCAL_BIN")
	if serverBin == "" || localBin == "" {
		t.Skip("SS_SERVER_BIN / SS_LOCAL_BIN not set")
	}
	return serverBin, localBin
}

// startRealSS 启动真实 ssserver + sslocal(udp_only),返回 sslocal 的 UDP 监听地址。
func startRealSS(t *testing.T, serverBin, localBin string) (udpAddr string, cleanup func()) {
	t.Helper()

	method := "aes-256-gcm"
	password := "smartproxy-e2e-pass"
	serverPort := freeUDPPort(t)
	localPort := freeUDPPort(t)

	// 用 JSON 配置(该版本 CLI 把端口并入地址参数,配置文件最稳)
	dir := t.TempDir()

	serverCfg := fmt.Sprintf(`{
	  "server": "127.0.0.1",
	  "server_port": %d,
	  "password": %q,
	  "method": %q,
	  "mode": "tcp_and_udp"
	}`, serverPort, password, method)
	serverCfgPath := filepath.Join(dir, "ssserver.json")
	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	localCfg := fmt.Sprintf(`{
	  "server": "127.0.0.1",
	  "server_port": %d,
	  "local_address": "127.0.0.1",
	  "local_port": %d,
	  "password": %q,
	  "method": %q,
	  "mode": "udp_only"
	}`, serverPort, localPort, password, method)
	localCfgPath := filepath.Join(dir, "sslocal.json")
	if err := os.WriteFile(localCfgPath, []byte(localCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1) ssserver:监听 127.0.0.1:<serverPort>,转发 UDP 到真实目标
	ssServer := exec.Command(serverBin, "-c", serverCfgPath)
	ssServer.Stdout = os.Stderr
	ssServer.Stderr = os.Stderr
	if err := ssServer.Start(); err != nil {
		t.Fatalf("failed to start ssserver: %v", err)
	}

	// 2) sslocal:udp_only 模式,本地 UDP 监听 127.0.0.1:<localPort>
	//    (与 shadowsocks-android UDP 兜底实例同 mode=udp_only)
	ssLocal := exec.Command(localBin, "-c", localCfgPath)
	ssLocal.Stdout = os.Stderr
	ssLocal.Stderr = os.Stderr
	if err := ssLocal.Start(); err != nil {
		ssServer.Process.Kill()
		t.Fatalf("failed to start sslocal: %v", err)
	}

	udpAddr = fmt.Sprintf("127.0.0.1:%d", localPort)

	cleanup = func() {
		ssLocal.Process.Kill()
		ssServer.Process.Kill()
		ssLocal.Process.Wait()
		ssServer.Process.Wait()
	}

	// 等端口真正可写(裸 UDP Dial 恒成功,这里只确认进程起来)
	time.Sleep(300 * time.Millisecond)
	return udpAddr, cleanup
}

// buildDNSQuery 构造一个 example.com 的 A 记录查询(非压缩名,便于按 TXID 校验)。
func buildDNSQuery(t *testing.T) []byte {
	t.Helper()
	txid := uint16(rand.Intn(65535))
	q := make([]byte, 0, 64)
	q = binary.BigEndian.AppendUint16(q, txid) // ID
	q = binary.BigEndian.AppendUint16(q, 0x0100) // flags: RD
	q = binary.BigEndian.AppendUint16(q, 1)      // QDCOUNT
	q = binary.BigEndian.AppendUint16(q, 0)      // ANCOUNT
	q = binary.BigEndian.AppendUint16(q, 0)      // NSCOUNT
	q = binary.BigEndian.AppendUint16(q, 0)      // ARCOUNT
	for _, label := range strings.Split("example.com", ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)                     // root
	q = binary.BigEndian.AppendUint16(q, 1) // A
	q = binary.BigEndian.AppendUint16(q, 1) // IN
	return q
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port
}

// TestRawRelayE2E 用真实 ss-local(udp_only)验证 udp_addr 裸中继端到端通讯:
//  1. Proxy.UDPAddr = "127.0.0.1:<udp端口>"(host:port 形式)
//  2. UDPAssociate 走 rawUDPAssociate,不碰 TCP ASSOCIATE
//  3. 发一条 example.com DNS 查询(SOCKS5 UDP 帧,目标 1.1.1.1:53)
//  4. 收到真实 DNS 响应帧 → 证明数据真的通了
func TestRawRelayE2E(t *testing.T) {
	serverBin, localBin := e2eEnv(t)
	udpAddr, cleanup := startRealSS(t, serverBin, localBin)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(udpAddr)
	udpPort, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	p := &Proxy{
		Scheme:  SchemeSOCKS5,
		Host:    host,
		Port:    udpPort, // 无 TCP 监听;能成功即证明走的是裸 UDP 路径
		UDPAddr: udpAddr, // host:port 强制裸 UDP
	}
	conn, err := p.UDPAssociate(ctx, "1.1.1.1", 53)
	if err != nil {
		t.Fatalf("UDPAssociate(raw) failed: %v", err)
	}
	defer conn.Close()

	// 组 SOCKS5 UDP 帧:RSV|FRAG|ATYP|DST.ADDR|DST.PORT|DNS 查询
	dnsQuery := buildDNSQuery(t)
	targetIP := net.ParseIP("1.1.1.1").To4()
	frame := []byte{0x00, 0x00, 0x00, 0x01}
	frame = append(frame, targetIP...)
	frame = append(frame, 0x00, 0x35) // 53
	frame = append(frame, dnsQuery...)

	t.Logf("sending %d-byte DNS query frame via raw UDP relay to %s", len(frame), udpAddr)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp := buf[:n]
	t.Logf("received %d-byte response frame", n)

	// 校验:响应帧 = SOCKS5 UDP 头 + DNS 响应
	if len(resp) < 4 || resp[0] != 0x00 || resp[1] != 0x00 || resp[2] != 0x00 {
		t.Fatalf("bad SOCKS5 UDP header: %x", resp[:min(len(resp), 4)])
	}
	// 跳过 DST.ADDR/PORT 拿到 DNS payload(目标是我们发的 1.1.1.1:53,IP 形式 10 字节头)
	const hdrLen = 10
	if len(resp) <= hdrLen {
		t.Fatalf("response too short: %d", len(resp))
	}
	dnsResp := resp[hdrLen:]
	if !bytes.Contains(dnsResp, dnsQuery[:2]) {
		t.Fatalf("DNS response TXID mismatch: query id=%x resp=%x", dnsQuery[:2], dnsResp[:2])
	}
	t.Logf("DNS response TXID matched, real end-to-end UDP relay OK")
}

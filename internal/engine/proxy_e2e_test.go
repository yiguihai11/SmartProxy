package engine

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"smartproxy/internal/config"
)

// 代理路径回归测试:引擎 A 把流量交给上游 SOCKS5 引擎 B,B 再直连目标。
//
// 路径断言法:同一个全局计数器,两端各自采样——
//   - A 侧:relay.ProxyBytesUp / udp.ProxyBytesUp 增长 → A 确实把流量转发给了上游;
//   - B 侧:relay.DirectBytesUp / udp.DirectBytesUp 增长 → 上游 B 真收到了数据并直连目标。
//
// 两个断言都过才证明「代理转发」成立;只过 A 侧说明 A 只是嘴上转发、数据没落地,
// 只过 B 侧说明 A 根本没过代理。UDP 同样套路,防止「echo 通了但没走代理」的假绿。

// proxySpec 返回「走上游 up」的引擎装配。
//
//   - chnroute 空 → 127.0.0.1 不在国内段,默认策略走代理;
//   - 规则选择:acl 里 `proxy cidr 127.0.0.0/8 up` 显式指定目标走上游 up;
//   - 默认策略:acl 空 + strategy "up",SelectProxy 对非国内目标返回 fallback →
//     upstream.Connect → ConnectDefault → 上游 up。
func proxySpec(upAddr string) engineSpec {
	return engineSpec{
		chnroute: "",
		upstream: []config.ProxyEntry{{Alias: "up", URL: "socks5://" + upAddr}},
		strategy: "up",
	}
}

// TestEngineProxyTCP_RuleSelected:ACL 规则显式命中 → TCP 走上游。
func TestEngineProxyTCP_RuleSelected(t *testing.T) {
	up := newTestEngine(t)
	eng := startEngine(t, engineSpec{
		chnroute: "",
		acl:      "proxy cidr 127.0.0.0/8 up\n",
		upstream: []config.ProxyEntry{{Alias: "up", URL: "socks5://" + up.listener.Addr().String()}},
	})
	echo := startTCPEcho(t)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	beforeA := sampleCounters()
	beforeB := sampleCounters()
	c := socks5Connect(t, eng.listener.Addr().String(), "127.0.0.1", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("hello smartproxy proxy tcp")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("TCP echo mismatch: got %q want %q", buf, payload)
	}
	// 关闭客户端连接,让 A→B 与 B→echo 两段 relay 依次结算、计数器入账
	c.Close()
	assertProxiedTraffic(t, beforeA, false) // A 确实把流量交给了上游
	assertUpstreamDirect(t, beforeB, false) // B(上游)真收到了并直连了目标
}

// TestEngineProxyUDP_RuleSelected:ACL 规则显式命中 → UDP 走上游。
func TestEngineProxyUDP_RuleSelected(t *testing.T) {
	up := newTestEngine(t)
	eng := startEngine(t, engineSpec{
		chnroute: "",
		acl:      "proxy cidr 127.0.0.0/8 up\n",
		upstream: []config.ProxyEntry{{Alias: "up", URL: "socks5://" + up.listener.Addr().String()}},
	})
	echo := startUDPEcho(t)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	beforeA := sampleCounters()
	beforeB := sampleCounters()
	tcpConn, udpConn := socks5UDPAssociate(t, eng.listener.Addr().String())
	defer tcpConn.Close()
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(20 * time.Second))

	payload := []byte("hello smartproxy proxy udp")
	frame := append([]byte{0, 0, 0}, socks5Addr("127.0.0.1", echoPort)...)
	frame = append(frame, payload...)
	if _, err := udpConn.Write(frame); err != nil {
		t.Fatalf("write udp frame: %v", err)
	}

	buf := make([]byte, 65535)
	n, err := udpConn.Read(buf)
	if err != nil {
		t.Fatalf("read udp reply: %v", err)
	}
	got, err := stripUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("strip header: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("UDP echo mismatch: got %q want %q", got, payload)
	}

	// UDP 计数器逐包同步累加;A 侧 proxy 计数、B 侧 direct 计数都在同一窗口
	assertProxiedTraffic(t, beforeA, true) // A 确实把 UDP 交给了上游
	assertUpstreamDirect(t, beforeB, true) // B(上游)真收到了并直连了目标
}

// ── IPv6 回环代理 ─────────────────────────────────
//
// 主引擎 A 监听 ::1、客户端经 IPv6 接入,目标 echo 在 ::1(ATYP=0x04);
// 上游 B 是 IPv4 的直连 SOCKS5 引擎(A 连 B 走 127.0.0.1 不受影响)。
// 覆盖:IPv6 的 CONNECT/UDP ASSOCIATE 目标地址、B 侧对 ::1 的直连、
// A 的 proxy cidr ::1/128 规则命中(proxyCIDRTrie IPv6 分支)。

// ipv6ProxySpec 返回「::1 走上游 up」、监听 ::1 的装配。
func ipv6ProxySpec(upAddr string) engineSpec {
	return engineSpec{
		chnroute: "::1/128\n",
		acl:      "proxy cidr ::1/128 up\n",
		upstream: []config.ProxyEntry{{Alias: "up", URL: "socks5://" + upAddr}},
		listen:   "::1",
	}
}

func TestEngineProxyTCP_IPv6(t *testing.T) {
	up := newTestEngine(t)
	eng := startEngine(t, ipv6ProxySpec(up.listener.Addr().String()))
	echo := startTCPEcho6(t)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	beforeA := sampleCounters()
	beforeB := sampleCounters()
	c := socks5Connect(t, eng.listener.Addr().String(), "::1", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("hello smartproxy proxy tcp6")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("TCP6 echo mismatch: got %q want %q", buf, payload)
	}
	c.Close()
	assertProxiedTraffic(t, beforeA, false) // A 把 ::1 的流量交给了上游
	assertUpstreamDirect(t, beforeB, false) // B 直连了 ::1
}

func TestEngineProxyUDP_IPv6(t *testing.T) {
	up := newTestEngine(t)
	eng := startEngine(t, ipv6ProxySpec(up.listener.Addr().String()))
	echo := startUDPEcho6(t)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	beforeA := sampleCounters()
	beforeB := sampleCounters()
	tcpConn, udpConn := socks5UDPAssociate(t, eng.listener.Addr().String())
	defer tcpConn.Close()
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(20 * time.Second))

	payload := []byte("hello smartproxy proxy udp6")
	frame := append([]byte{0, 0, 0}, socks5Addr("::1", echoPort)...)
	frame = append(frame, payload...)
	if _, err := udpConn.Write(frame); err != nil {
		t.Fatalf("write udp6 frame: %v", err)
	}

	buf := make([]byte, 65535)
	n, err := udpConn.Read(buf)
	if err != nil {
		t.Fatalf("read udp6 reply: %v", err)
	}
	got, err := stripUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("strip header: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("UDP6 echo mismatch: got %q want %q", got, payload)
	}
	assertProxiedTraffic(t, beforeA, true)
	assertUpstreamDirect(t, beforeB, true)
}

// TestEngineProxyTCP_DefaultStrategy:无 ACL/chnroute 规则,strategy=up 兜底 → TCP 走上游。
func TestEngineProxyTCP_DefaultStrategy(t *testing.T) {
	up := newTestEngine(t)
	eng := startEngine(t, proxySpec(up.listener.Addr().String()))
	echo := startTCPEcho(t)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	beforeA := sampleCounters()
	beforeB := sampleCounters()
	c := socks5Connect(t, eng.listener.Addr().String(), "127.0.0.1", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("default strategy tcp")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("TCP echo mismatch: got %q want %q", buf, payload)
	}
	c.Close()
	assertProxiedTraffic(t, beforeA, false)
	assertUpstreamDirect(t, beforeB, false)
}

// TestEngineProxyUDP_DefaultStrategy:无 ACL/chnroute 规则,strategy=up 兜底 → UDP 走上游。
func TestEngineProxyUDP_DefaultStrategy(t *testing.T) {
	up := newTestEngine(t)
	eng := startEngine(t, proxySpec(up.listener.Addr().String()))
	echo := startUDPEcho(t)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	beforeA := sampleCounters()
	beforeB := sampleCounters()
	tcpConn, udpConn := socks5UDPAssociate(t, eng.listener.Addr().String())
	defer tcpConn.Close()
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(20 * time.Second))

	payload := []byte("default strategy udp")
	frame := append([]byte{0, 0, 0}, socks5Addr("127.0.0.1", echoPort)...)
	frame = append(frame, payload...)
	if _, err := udpConn.Write(frame); err != nil {
		t.Fatalf("write udp frame: %v", err)
	}

	buf := make([]byte, 65535)
	n, err := udpConn.Read(buf)
	if err != nil {
		t.Fatalf("read udp reply: %v", err)
	}
	got, err := stripUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("strip header: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("UDP echo mismatch: got %q want %q", got, payload)
	}

	assertProxiedTraffic(t, beforeA, true)
	assertUpstreamDirect(t, beforeB, true)
}

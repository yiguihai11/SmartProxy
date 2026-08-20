package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"smartproxy/internal/config"
	"smartproxy/internal/relay"
	"smartproxy/internal/udp"
)

// 直连 + ACL 回归测试(基础能力,改动前后必须全绿)。
//
// 这组测试钉死的三个坑:
//
//  1. UDP「流量不走」根因(UDP ASSOCIATE BND 广告)。引擎 UDP socket 绑 0.0.0.0,
//     回复里曾用 getOutboundIPv4() 广告出站接口 IP——loopback 客户端按 BND 发 UDP,
//     源地址变成该出站 IP,与源校验比对的 clientIP(127.0.0.1)不匹配 → 全部丢包;
//     VPN 手机上 getOutboundIPv4 还会拿到 TUN 网段 IP,客户端根本够不着。修法:BND
//     优先广告「客户端实际连到的本地地址」(该地址必可达、源校验必过),见
//     internal/engine/engine.go handleUDPAssociate。这里每次改 UDP 相关代码都要跑。
//
//  2. 路径断言:relay/udp 包都有 DirectBytesUp / ProxyBytesUp 全局计数器。用 delta
//     断言流量真的走了直连(规则 force-direct / 国内直连)还是代理(规则 proxy alias /
//     默认策略),而不是「echo 通了」就算过——echo 通但走了错误路径同样会在这里红。
//
//  3. ACL 优先级:allow 优先于 block / proxy 规则(MatchProxyRule 先查 allow 再查
//     proxy 规则;IsIPBlocked/IsPortBlocked 也先放行 allow)。

// ── 最小 SOCKS5 客户端 ─────────────────────────────

// socks5Addr 编码 host:port 为 SOCKS5 的 ATYP+DST.ADDR+DST.PORT。
func socks5Addr(host string, port int) []byte {
	ip := net.ParseIP(host)
	var b []byte
	if ip4 := ip.To4(); ip4 != nil {
		b = append(b, 0x01)
		b = append(b, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		b = append(b, 0x04)
		b = append(b, ip6...)
	} else {
		b = append(b, 0x03, byte(len(host)))
		b = append(b, host...)
	}
	return append(b, byte(port>>8), byte(port))
}

// readSocks5Reply 读服务器回复,返回 BND.ADDR/BND.PORT;rep 非 0 返回错误。
func readSocks5Reply(c net.Conn) (string, int, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", 0, err
	}
	if hdr[0] != 0x05 {
		return "", 0, fmt.Errorf("bad socks version %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		return "", 0, fmt.Errorf("socks reply rep=%d", hdr[1])
	}
	var alen int
	switch hdr[3] {
	case 0x01:
		alen = 4
	case 0x04:
		alen = 16
	default:
		return "", 0, fmt.Errorf("bad ATYP %d", hdr[3])
	}
	addr := make([]byte, alen)
	if _, err := io.ReadFull(c, addr); err != nil {
		return "", 0, err
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return "", 0, err
	}
	return net.IP(addr).String(), int(binary.BigEndian.Uint16(portBuf)), nil
}

// socks5Greeting 完成无鉴权握手,返回已握手的 TCP 连接。
func socks5Greeting(t *testing.T, serverAddr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		t.Fatalf("greeting: %v", err)
	}
	m := make([]byte, 2)
	if _, err := io.ReadFull(c, m); err != nil {
		c.Close()
		t.Fatalf("method reply: %v", err)
	}
	if m[0] != 0x05 || m[1] != 0x00 {
		c.Close()
		t.Fatalf("no-auth method rejected: %v", m)
	}
	return c
}

// socks5Connect 完成握手并发送 CONNECT,成功返回已连到目标的连接。
func socks5Connect(t *testing.T, serverAddr, host string, port int) net.Conn {
	t.Helper()
	c := socks5Greeting(t, serverAddr)
	req := append([]byte{0x05, 0x01, 0x00}, socks5Addr(host, port)...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		t.Fatalf("connect req: %v", err)
	}
	if _, _, err := readSocks5Reply(c); err != nil {
		c.Close()
		t.Fatalf("connect reply: %v", err)
	}
	return c
}

// socks5UDPAssociate 完成握手并发送 UDP ASSOCIATE,返回控制 TCP 连接和
// 已连到服务器 BND 地址的 UDP 连接。BND 为通配时回退 127.0.0.1。
func socks5UDPAssociate(t *testing.T, serverAddr string) (net.Conn, *net.UDPConn) {
	t.Helper()
	c := socks5Greeting(t, serverAddr)
	// UDP ASSOCIATE 到 0.0.0.0:0
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(req); err != nil {
		c.Close()
		t.Fatalf("udp associate req: %v", err)
	}
	bindHost, bindPort, err := readSocks5Reply(c)
	if err != nil {
		c.Close()
		t.Fatalf("udp associate reply: %v", err)
	}
	if bindHost == "0.0.0.0" || bindHost == "::" || bindHost == "" || bindHost == "[::]" {
		bindHost = "127.0.0.1"
	}
	raddr := net.JoinHostPort(bindHost, fmt.Sprintf("%d", bindPort))
	u, err := net.Dial("udp", raddr)
	if err != nil {
		c.Close()
		t.Fatalf("dial udp bind %s: %v", raddr, err)
	}
	return c, u.(*net.UDPConn)
}

// stripUDPHeader 去掉直连应答的 SOCKS5 UDP 头,返回载荷。
func stripUDPHeader(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("short UDP frame (%d)", len(b))
	}
	switch b[3] {
	case 0x01:
		if len(b) < 10 {
			return nil, fmt.Errorf("short IPv4 frame (%d)", len(b))
		}
		return b[10:], nil
	case 0x04:
		if len(b) < 22 {
			return nil, fmt.Errorf("short IPv6 frame (%d)", len(b))
		}
		return b[22:], nil
	}
	return nil, fmt.Errorf("bad ATYP %d", b[3])
}

// ── echo 服务 ──────────────────────────────────────

// startTCPEchoOn 在指定地址起 TCP echo 服务(127.0.0.1 或 TUN 测试用的本地别名)。
func startTCPEchoOn(t *testing.T, host string) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("tcp echo listen (%s): %v", host, err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l
}

func startTCPEcho(t *testing.T) net.Listener {
	return startTCPEchoOn(t, "127.0.0.1")
}

func startUDPEchoOn(t *testing.T, host string) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("udp echo listen (%s): %v", host, err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.(*net.UDPConn)
}

func startUDPEcho(t *testing.T) *net.UDPConn {
	return startUDPEchoOn(t, "127.0.0.1")
}

// ── IPv6 回环 echo(::1)────────────────────────────

func startTCPEcho6(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("tcp6 echo listen: %v", err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l
}

func startUDPEcho6(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatalf("udp6 echo listen: %v", err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.(*net.UDPConn)
}

// ── 路径计数器断言 ─────────────────────────────────
//
// relay/udp 的 DirectBytesUp/ProxyBytesUp 是「进程级全局」计数器,有两条铁律:
//
//  1. TCP 计数器在 relay copy 循环结束(连接关闭)后才结算,必须轮询等待,不能采样一次就下结论;
//  2. 双引擎测试(引擎 A → 上游 B)里,只有单引擎会动的计数器才能做正断言;跨引擎断「==0」
//     会被另一台引擎的全局计数污染——A 的代理流量必然落进 B 的 proxy 计数窗口,反之亦然。

type pathCounters struct {
	relayDirectUp, relayProxyUp int64
	udpDirectUp, udpProxyUp     int64
}

func sampleCounters() pathCounters {
	return pathCounters{
		relayDirectUp: relay.DirectBytesUp.Load(),
		relayProxyUp:  relay.ProxyBytesUp.Load(),
		udpDirectUp:   udp.DirectBytesUp.Load(),
		udpProxyUp:    udp.ProxyBytesUp.Load(),
	}
}

// awaitIncrease 轮询等待计数器相对基线严格增长(最多 3s)。
func awaitIncrease(t *testing.T, what string, cur func() int64, base int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cur() > base {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("%s did not increase: base=%d cur=%d", what, base, cur())
}

// assertDirectTraffic:单引擎场景下断言走了直连——direct 增长、proxy 未动。
// 使用前提:采样窗口内没有其它引擎的代理流量(纯直连引擎 / ACL allow 测试)。
func assertDirectTraffic(t *testing.T, before pathCounters, udpPath bool) {
	t.Helper()
	if udpPath {
		awaitIncrease(t, "UDP DIRECT up", func() int64 { return udp.DirectBytesUp.Load() }, before.udpDirectUp)
		if udp.ProxyBytesUp.Load() != before.udpProxyUp {
			t.Errorf("UDP should NOT use proxy, proxyUp delta=%d", udp.ProxyBytesUp.Load()-before.udpProxyUp)
		}
	} else {
		awaitIncrease(t, "TCP DIRECT up", func() int64 { return relay.DirectBytesUp.Load() }, before.relayDirectUp)
		if relay.ProxyBytesUp.Load() != before.relayProxyUp {
			t.Errorf("TCP should NOT use proxy, proxyUp delta=%d", relay.ProxyBytesUp.Load()-before.relayProxyUp)
		}
	}
}

// assertProxiedTraffic:双引擎测试中断言主引擎 A 走了代理(proxy 增长)。
// 只做正断言——A 不直连,但 B 的直连流量会污染全局 direct 计数,不能断 direct==0。
func assertProxiedTraffic(t *testing.T, before pathCounters, udpPath bool) {
	t.Helper()
	if udpPath {
		awaitIncrease(t, "UDP PROXY up", func() int64 { return udp.ProxyBytesUp.Load() }, before.udpProxyUp)
	} else {
		awaitIncrease(t, "TCP PROXY up", func() int64 { return relay.ProxyBytesUp.Load() }, before.relayProxyUp)
	}
}

// assertUpstreamDirect:双引擎测试中断言上游引擎 B 收到了流量并直连(direct 增长)。
// 只做正断言——B 不代理,但 A 的代理流量会污染全局 proxy 计数,不能断 proxy==0。
func assertUpstreamDirect(t *testing.T, before pathCounters, udpPath bool) {
	t.Helper()
	if udpPath {
		awaitIncrease(t, "upstream UDP DIRECT up", func() int64 { return udp.DirectBytesUp.Load() }, before.udpDirectUp)
	} else {
		awaitIncrease(t, "upstream TCP DIRECT up", func() int64 { return relay.DirectBytesUp.Load() }, before.relayDirectUp)
	}
}

// ── 引擎装配 ───────────────────────────────────────

// engineSpec 描述一个引擎实例的装配:路由文件内容 + 上游节点。
type engineSpec struct {
	chnroute string              // chnroute.txt 内容(空 = 无国内段,目标都算非国内)
	acl      string              // acl.txt 内容(proxy/allow/block 规则)
	upstream []config.ProxyEntry // 上游节点;空 = 纯直连引擎
	strategy string              // upstream.default 策略(默认代理走谁)
	listen   string              // SOCKS5 监听地址,默认 127.0.0.1;IPv6 测试用 "::1"
	tun      *config.TUNConfig   // 非 nil = 启用真实 TUN 设备(tun_e2e_test.go 用)
}

// startEngine 起一个引擎,SOCKS5 监听随机端口,返回引擎(Stop 由 t.Cleanup 处理)。
func startEngine(t *testing.T, spec engineSpec) *Engine {
	t.Helper()
	host := spec.listen
	if host == "" {
		host = "127.0.0.1"
	}
	dir := t.TempDir()
	chn := filepath.Join(dir, "chnroute.txt")
	acl := filepath.Join(dir, "acl.txt")
	if err := os.WriteFile(chn, []byte(spec.chnroute), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(acl, []byte(spec.acl), 0o644); err != nil {
		t.Fatal(err)
	}

	// 找一个与监听同地址族的空闲端口给 SOCKS5
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("port probe (%s): %v", host, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := &config.Config{
		LogLevel: "warn",
		Listen:   config.ListenConfig{Host: host, Port: port},
		TUN:      config.TUNConfig{Enabled: false},
		Upstream: config.UpstreamConf{Default: spec.strategy, Proxies: spec.upstream},
		Routing:  config.RoutingConf{ChnrouteFile: chn, ACLFile: acl},
		DNS: config.DNSConf{
			Enabled:      false,
			Cache:        config.DNSCacheC{Size: 4096, TTL: 60},
			Foreign:      config.DNSForeign{IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8888"},
			QueryTimeout: 3,
		},
		SmartProxy: config.SmartProxyConf{Timeout: 3, BlacklistTTL: 60},
	}
	if spec.tun != nil {
		cfg.TUN = *spec.tun
	}

	eng, err := New(cfg, dir)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("engine.Start: %v", err)
	}
	t.Cleanup(eng.Stop)
	return eng
}

// newTestEngine 起一个纯直连引擎:ACL 规则把 loopback 强制 force-direct。
func newTestEngine(t *testing.T) *Engine {
	return startEngine(t, engineSpec{
		chnroute: "127.0.0.0/8\n::1/128\n",
		acl:      "proxy cidr 127.0.0.0/8 direct\nproxy cidr ::1/128 direct\n",
	})
}

// ── TCP / UDP 直连 ─────────────────────────────────

func TestEngineDirectTCP(t *testing.T) {
	eng := newTestEngine(t)
	echo := startTCPEcho(t)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	before := sampleCounters()
	c := socks5Connect(t, eng.listener.Addr().String(), "127.0.0.1", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	payload := []byte("hello smartproxy direct tcp")
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
	// 关闭客户端连接,relay 的 c2r copy 才退出、DirectBytesUp 才结算
	c.Close()
	assertDirectTraffic(t, before, false)
}

func TestEngineDirectTCP_LargePayload(t *testing.T) {
	eng := newTestEngine(t)
	echo := startTCPEcho(t)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	c := socks5Connect(t, eng.listener.Addr().String(), "127.0.0.1", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))

	payload := bytes.Repeat([]byte("x"), 1<<20) // 1MB
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("TCP large echo mismatch")
	}
}

func TestEngineDirectUDP(t *testing.T) {
	eng := newTestEngine(t)
	echo := startUDPEcho(t)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	before := sampleCounters()
	tcpConn, udpConn := socks5UDPAssociate(t, eng.listener.Addr().String())
	defer tcpConn.Close()
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("hello smartproxy direct udp")
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
	// UDP 计数器逐包同步累加,读完回包即已入账,无需等待
	assertDirectTraffic(t, before, true)
}

// ── IPv6 回环直连 ──────────────────────────────────
//
// 与 IPv4 用例一一对应:引擎监听 ::1、目标 echo 在 ::1,走 ATYP=0x04。
// 顺带钉死 UDP ASSOCIATE 的 IPv6 BND 分支——IPv6 客户端(tcpLocal.IP=::1)
// 必须广告 ::1,否则源校验照样全丢包。路由与规则侧:proxyCIDRTrie 用
// As16()/128 位遍历,::1/128 规则能命中(见 internal/rules/engine.go)。

func TestEngineDirectTCP_IPv6(t *testing.T) {
	eng := startEngine(t, engineSpec{
		chnroute: "::1/128\n",
		acl:      "proxy cidr ::1/128 direct\n",
		listen:   "::1",
	})
	echo := startTCPEcho6(t)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	before := sampleCounters()
	c := socks5Connect(t, eng.listener.Addr().String(), "::1", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	payload := []byte("hello smartproxy direct tcp6")
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
	assertDirectTraffic(t, before, false)
}

func TestEngineDirectUDP_IPv6(t *testing.T) {
	eng := startEngine(t, engineSpec{
		chnroute: "::1/128\n",
		acl:      "proxy cidr ::1/128 direct\n",
		listen:   "::1",
	})
	echo := startUDPEcho6(t)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	before := sampleCounters()
	tcpConn, udpConn := socks5UDPAssociate(t, eng.listener.Addr().String())
	defer tcpConn.Close()
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("hello smartproxy direct udp6")
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
	assertDirectTraffic(t, before, true)
}

// ── ACL 规则 ───────────────────────────────────────

// TestEngineACL_BlockIP:block ip 命中 TCP CONNECT 回 ReplyNotAllowed,UDP 帧被静默丢弃。
func TestEngineACL_BlockIP(t *testing.T) {
	eng := startEngine(t, engineSpec{
		chnroute: "127.0.0.0/8\n",
		acl:      "block ip 127.0.0.1\n",
	})
	echo := startTCPEcho(t)
	echoPort := echo.Addr().(*net.TCPAddr).Port
	serverAddr := eng.listener.Addr().String()

	// TCP:期望 ReplyNotAllowed(0x02)
	c := socks5Greeting(t, serverAddr)
	req := append([]byte{0x05, 0x01, 0x00}, socks5Addr("127.0.0.1", echoPort)...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != 0x02 {
		t.Fatalf("expected ReplyNotAllowed(0x02) for blocked TCP, got %d", hdr[1])
	}
	c.Close()

	// UDP:帧被丢弃,无回包(短超时断言)
	tcpConn, udpConn := socks5UDPAssociate(t, serverAddr)
	defer tcpConn.Close()
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(2 * time.Second))
	frame := append([]byte{0, 0, 0}, socks5Addr("127.0.0.1", echoPort)...)
	frame = append(frame, []byte("blocked udp")...)
	if _, err := udpConn.Write(frame); err != nil {
		t.Fatal(err)
	}
	if n, err := udpConn.Read(make([]byte, 1024)); err == nil {
		t.Fatalf("expected UDP block to drop the frame, but got a %d-byte reply", n)
	}
}

// TestEngineACL_BlockPort:block port 命中(端口在规则里),TCP/UDP 同 BlockIP 语义。
func TestEngineACL_BlockPort(t *testing.T) {
	echo := startTCPEcho(t)
	echoPort := echo.Addr().(*net.TCPAddr).Port
	eng := startEngine(t, engineSpec{
		chnroute: "127.0.0.0/8\n",
		acl:      fmt.Sprintf("block port %d\n", echoPort),
	})
	serverAddr := eng.listener.Addr().String()

	c := socks5Greeting(t, serverAddr)
	req := append([]byte{0x05, 0x01, 0x00}, socks5Addr("127.0.0.1", echoPort)...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != 0x02 {
		t.Fatalf("expected ReplyNotAllowed(0x02) for blocked port TCP, got %d", hdr[1])
	}
	c.Close()
}

// TestEngineACL_BlockIP_IPv6:block ip ::1 对 IPv6 回环同样生效(ATYP=0x04)。
func TestEngineACL_BlockIP_IPv6(t *testing.T) {
	eng := startEngine(t, engineSpec{
		chnroute: "::1/128\n",
		acl:      "block ip ::1\n",
		listen:   "::1",
	})
	echo := startTCPEcho6(t)
	echoPort := echo.Addr().(*net.TCPAddr).Port
	serverAddr := eng.listener.Addr().String()

	c := socks5Greeting(t, serverAddr)
	req := append([]byte{0x05, 0x01, 0x00}, socks5Addr("::1", echoPort)...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != 0x02 {
		t.Fatalf("expected ReplyNotAllowed(0x02) for blocked IPv6 TCP, got %d", hdr[1])
	}
	c.Close()

	// UDP:帧被静默丢弃
	tcpConn, udpConn := socks5UDPAssociate(t, serverAddr)
	defer tcpConn.Close()
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(2 * time.Second))
	frame := append([]byte{0, 0, 0}, socks5Addr("::1", echoPort)...)
	frame = append(frame, []byte("blocked udp6")...)
	if _, err := udpConn.Write(frame); err != nil {
		t.Fatal(err)
	}
	if n, err := udpConn.Read(make([]byte, 1024)); err == nil {
		t.Fatalf("expected UDP6 block to drop the frame, but got a %d-byte reply", n)
	}
}

// TestEngineACL_AllowOverridesProxy:allow 优先于 proxy 规则——配置了走上游的规则,
// 但 allow 命中后走直连(relay.DirectBytesUp 动、relay.ProxyBytesUp 不动)。
func TestEngineACL_AllowOverridesProxy(t *testing.T) {
	up := newTestEngine(t) // 上游:纯直连 SOCKS5
	eng := startEngine(t, engineSpec{
		chnroute: "127.0.0.0/8\n",
		acl:      "proxy cidr 127.0.0.0/8 up\nallow ip 127.0.0.1\n",
		upstream: []config.ProxyEntry{{Alias: "up", URL: "socks5://" + up.listener.Addr().String()}},
	})
	echo := startTCPEcho(t)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	before := sampleCounters()
	c := socks5Connect(t, eng.listener.Addr().String(), "127.0.0.1", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	payload := []byte("allow should force direct")
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
	// allow 命中后走的是直连,proxy 计数不该动;关闭连接等 relay 结算
	c.Close()
	assertDirectTraffic(t, before, false)
}

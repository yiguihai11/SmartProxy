package upstream

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"smartproxy/internal/config"
)

// startHangingAssociateTCP 是一个"半死"的 SOCKS5 节点:问候语正常应答,但收到 UDP
// ASSOCIATE 请求后永不回复(模拟握手被黑洞/半死节点)。旧实现串行选路会在它身上干等
// 满 10s 才试下一个候选。
func startHangingAssociateTCP(t *testing.T) (tcpPort int, done func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 258)
				if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
					return
				}
				if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				// 读走 ASSOCIATE 请求后彻底沉默:没有任何 reply,连接挂着不放。
				if _, err := io.ReadFull(c, buf[:10]); err != nil {
					return
				}
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() {
		ln.Close()
		for {
			select {
			case c := <-accepted:
				c.Close()
			default:
				return
			}
		}
	}
}

// newUDPFailoverManager 构造关掉健康探测的 UDP 选路管理器。跟 TCP 版一样,serverCleanups
// 必须排在 m.Stop 之前注册(cleanup 是 LIFO),否则挂死 mock 的清理会等满探测超时。
func newUDPFailoverManager(t *testing.T, urls []string, serverCleanups ...func()) *Manager {
	t.Helper()
	for _, c := range serverCleanups {
		t.Cleanup(c)
	}
	entries := make([]ProxyEntry, len(urls))
	for i, u := range urls {
		entries[i] = ProxyEntry{Alias: fmt.Sprintf("n%d", i), URL: u}
	}
	m, err := NewManager(UpstreamConfig{
		Proxies:     entries,
		HealthCheck: config.HealthCheckConf{Enabled: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	m.dialHedgeDelay = 50 * time.Millisecond
	m.dialAttemptTimeout = 3 * time.Second
	return m
}

// TestUDPAssociate_HedgedFailover 回归 UDP 串行 10s:首个节点 ASSOCIATE 被挂死时,旧实现
// 每个新关联都要干等满 SOCKS5 层的 10s 才轮到健康节点。对冲必须快速胜出。
func TestUDPAssociate_HedgedFailover(t *testing.T) {
	hangPort, hangDone := startHangingAssociateTCP(t)
	fdns, dnsPort := startFrameDNSServer(t)

	// 健康节点:标准 ASSOCIATE + 真实 DNS 应答,探针目标也指到它。
	goodPort, _ := startAssociateTCP(t, "standard", dnsPort)

	m := newUDPFailoverManager(t, []string{
		fmt.Sprintf("socks5://127.0.0.1:%d", hangPort),
		fmt.Sprintf("socks5://127.0.0.1:%d", goodPort),
	}, hangDone, func() { fdns.Close() })
	m.healthCfg.UDPProbeDNS = fmt.Sprintf("127.0.0.1:%d", dnsPort)

	start := time.Now()
	conn, err := m.UDPAssociate(context.Background(), "1.1.1.1", 53, "", nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected hedged UDP failover to succeed, got %v", err)
	}
	defer conn.Close()
	if elapsed >= time.Second {
		t.Errorf("UDP failover took %v, hedge should win in ~%v", elapsed, m.dialHedgeDelay)
	}

	uc, ok := conn.(*UDPProxyConn)
	if !ok {
		t.Fatalf("expected *UDPProxyConn, got %T", conn)
	}
	if got := uc.Proxy().Port; got != goodPort {
		t.Errorf("winner port=%d, want the healthy node %d", got, goodPort)
	}
}

// TestUDPAssociate_AllDeadBounded 全部候选都是半死节点时,总耗时必须被 attemptTimeout +
// 错位窗口兜住,不允许退回"每个节点 10s"的串行等待。
func TestUDPAssociate_AllDeadBounded(t *testing.T) {
	hangA, doneA := startHangingAssociateTCP(t)
	hangB, doneB := startHangingAssociateTCP(t)

	m := newUDPFailoverManager(t, []string{
		fmt.Sprintf("socks5://127.0.0.1:%d", hangA),
		fmt.Sprintf("socks5://127.0.0.1:%d", hangB),
	}, doneA, doneB)
	m.dialAttemptTimeout = 400 * time.Millisecond

	start := time.Now()
	_, err := m.UDPAssociate(context.Background(), "1.1.1.1", 53, "", nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error when every UDP candidate is dead")
	}
	if elapsed >= 2*time.Second {
		t.Errorf("all-dead UDP failover took %v, want < 2s", elapsed)
	}
}

// TestUDPAssociate_UnverifiedRawNotFalseSuccess 回归 raw fallback 假成功:节点 TCP 明确
// 拒绝 ASSOCIATE(rep=0x07),同 host:port 也没有 UDP 中继应答。旧实现本地 DialUDP 一成功
// 就返回"连上了",把死节点当赢家;新实现必须补端到端 DNS 问答,验不过就报错。
func TestUDPAssociate_UnverifiedRawNotFalseSuccess(t *testing.T) {
	// reject 策略:ASSOCIATE 回 rep=0x07,触发 rawFallback;裸 UDP 中继无人应答。
	rejectPort, _ := startAssociateTCP(t, "reject", deadUDPPort(t))

	m := newUDPFailoverManager(t, []string{
		fmt.Sprintf("socks5://127.0.0.1:%d", rejectPort),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := m.UDPAssociate(ctx, "1.1.1.1", 53, "", nil)
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatal("raw fallback to a silent relay must NOT be reported as success")
	}
	if elapsed >= 700*time.Millisecond {
		t.Errorf("verification took %v, must fail on the ctx/verify budget, not hang", elapsed)
	}
}

// TestUDPAssociate_UnverifiedRawBlackHoleBounded 黑洞中继(只吞不回)必须被验证预算掐断,
// 不能退回 10s 兜底:raw 回落假成功 + 10s 等待是用户实际咬到的卡顿组合。
func TestUDPAssociate_UnverifiedRawBlackHoleBounded(t *testing.T) {
	// 与 shadowsocks-android 布局一致:SOCKS5 TCP 拒绝 ASSOCIATE,同 host:port 上有个
	// 只吞不回的 UDP 中继。TCP/UDP 端口空间独立,先占住 UDP 端口再在同一个号上开 TCP。
	udpPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := udpPC.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := udpPC.ReadFromUDP(buf); err != nil {
				return
			}
			// 故意不应答:模拟被 DROP 的黑洞中继。
		}
	}()
	t.Cleanup(func() { udpPC.Close() })

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("cannot bind SOCKS5 TCP on the UDP relay port: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 258)
				if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
					return
				}
				if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00})
				if _, err := io.ReadFull(c, buf[:10]); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x07, 0x00, 0x01}) // rep=0x07 → rawFallback
				io.Copy(io.Discard, c)
			}(c)
		}
	}()

	m := newUDPFailoverManager(t, []string{fmt.Sprintf("socks5://127.0.0.1:%d", port)})
	m.udpVerifyTimeout = 300 * time.Millisecond

	start := time.Now()
	conn, err := m.UDPAssociate(context.Background(), "1.1.1.1", 53, "", nil)
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatal("black-holed raw relay must not be reported as success")
	}
	if elapsed >= 2*time.Second {
		t.Errorf("verification took %v, must be bounded by the verify budget", elapsed)
	}
}

// TestUDPAssociate_UnverifiedRawDeadThenHealthy 死节点排第一且只有 raw 回落可用时,选路
// 必须继续落到后面的健康节点上,而不是被假成功截胡。
func TestUDPAssociate_UnverifiedRawDeadThenHealthy(t *testing.T) {
	rejectPort, _ := startAssociateTCP(t, "reject", deadUDPPort(t))
	fdns, dnsPort := startFrameDNSServer(t)
	goodPort, _ := startAssociateTCP(t, "standard", dnsPort)

	m := newUDPFailoverManager(t, []string{
		fmt.Sprintf("socks5://127.0.0.1:%d", rejectPort),
		fmt.Sprintf("socks5://127.0.0.1:%d", goodPort),
	}, func() { fdns.Close() })
	m.healthCfg.UDPProbeDNS = fmt.Sprintf("127.0.0.1:%d", dnsPort)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := m.UDPAssociate(ctx, "1.1.1.1", 53, "", nil)
	if err != nil {
		t.Fatalf("expected failover to the healthy node, got %v", err)
	}
	defer conn.Close()

	uc, ok := conn.(*UDPProxyConn)
	if !ok {
		t.Fatalf("expected *UDPProxyConn, got %T", conn)
	}
	if got := uc.Proxy().Port; got != goodPort {
		t.Errorf("winner port=%d, want the healthy node %d (raw fallback must not win)", got, goodPort)
	}
	// 死节点不得被钉成 sticky raw:没验过的中继不许进快路径。
	if p := m.aliasMap["n0"]; p.UDPCapability() == UDPCapRaw {
		t.Error("unverified raw relay must not be recorded as a known-raw capability")
	}
}

// TestUDPAssociate_RawFastPathStillTrusted 对照用例:udp_only/已知 raw 节点的快路径本地
// 拨号不算"未验证回落",不能被新增的端到端验证拦下来(否则纯 raw 节点彻底不可用)。
func TestUDPAssociate_RawFastPathStillTrusted(t *testing.T) {
	fdns, dnsPort := startFrameDNSServer(t)
	defer fdns.Close()

	// 同一 host:port 上:SOCKS5 TCP(拒绝 ASSOCIATE)+ 裸 UDP 中继(应答真实 DNS)。
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", dnsPort))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 258)
				if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
					return
				}
				if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00})
				if _, err := io.ReadFull(c, buf[:10]); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x07, 0x00, 0x01})
				io.Copy(io.Discard, c)
			}(c)
		}
	}()

	m := newUDPFailoverManager(t, []string{fmt.Sprintf("socks5://127.0.0.1:%d", dnsPort)})
	m.healthCfg.UDPProbeDNS = fmt.Sprintf("127.0.0.1:%d", dnsPort)

	p := m.aliasMap["n0"]
	// 已知 raw 且不在 recheck 期 → 走快路径,不重试注定失败的 ASSOCIATE。
	p.setUDPCapability(UDPCapRaw)
	p.scheduleRawRecheck()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := m.UDPAssociate(ctx, "1.1.1.1", 53, "", nil)
	if err != nil {
		t.Fatalf("known-raw fast path must keep working: %v", err)
	}
	conn.Close()
}

package engine

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"smartproxy/internal/config"
	"smartproxy/internal/udp"
)

// TUN 模式 UDP 计数与 SOCKS5 一致的回归钉。
//
// 背景:曾有一段,TUN UDP 走 tun/handler.go 自己的转发,不经 internal/udp,面板上
// udp.ProxyBytesUp/DirectBytesUp/… 计数器不涨——TUN 与 SOCKS5 的行为影响不一致,
// 用户明确要求两端一致。修复后 TUN 的 udpSend/remoteUDPReader 在转发的同时累加
// 计数器,语义与 internal/udp 完全一致:
//
//   - 直连:上行写纯 payload、下行读纯 payload → DirectBytes*;
//   - 代理:上行写带 SOCKS5 UDP header 的帧、下行读整帧 → ProxyBytes*。
//
// 这两条路径上的探针(TestTUNUDPCounterProbe_*)验证通过后转正,成为永久回归。
// 断言方法论遵守两条铁律(见 docs/e2e-regression.md):UDP 逐包同步累加、读完即
// 入账无需轮询;双引擎共享进程级全局计数器,只做单引擎正断言。

// udpCountSnapshot is a point-in-time read of the process-global panel UDP counters.
type udpCountSnapshot struct {
	directUp, proxyUp     int64
	directDown, proxyDown int64
}

func sampleUDPCounts() udpCountSnapshot {
	return udpCountSnapshot{
		directUp:   udp.DirectBytesUp.Load(),
		proxyUp:    udp.ProxyBytesUp.Load(),
		directDown: udp.DirectBytesDown.Load(),
		proxyDown:  udp.ProxyBytesDown.Load(),
	}
}

// TestEngineTUN_UDPCounters_Direct:ACL 强制直连 → TUN 引擎直连 echo 时自身
// udp.DirectBytesUp/Down 增长,ProxyBytesUp 不动(单引擎场景,可断正负)。
func TestEngineTUN_UDPCounters_Direct(t *testing.T) {
	requireTUN(t)
	addLoAlias(t, tunServerIP)
	_, ifname := startTUNEngine(t, engineSpec{
		chnroute: tunServerNet + "\n",
		acl:      "proxy cidr " + tunServerNet + " direct\n",
	})
	echo := startUDPEchoOn(t, tunServerIP)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	before := sampleUDPCounts()
	c := tunDial(t, ifname, "udp", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("hello tun udp counter direct")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}

	after := sampleUDPCounts()
	t.Logf("TUN direct: udp.DirectBytesUp+%d Down+%d ProxyUp+%d (want Up&Down >0)",
		after.directUp-before.directUp, after.directDown-before.directDown, after.proxyUp-before.proxyUp)
	if after.directUp-before.directUp <= 0 || after.directDown-before.directDown <= 0 {
		t.Fatalf("TUN direct UDP counters did not increase: up=%d down=%d",
			after.directUp-before.directUp, after.directDown-before.directDown)
	}
	if after.proxyUp-before.proxyUp != 0 {
		t.Fatalf("TUN direct UDP should not count proxy bytes, got +%d", after.proxyUp-before.proxyUp)
	}
}

// TestEngineTUN_UDPCounters_Proxy:ACL 走上游 → TUN 引擎把 UDP 交给 SOCKS5 引擎 B,
// A 的 udp.ProxyBytesUp/Down 增长。注意 B 直连 echo 时 B 自己的 udp.DirectBytes*
// 也在同一窗口增长(双引擎共享全局计数器),所以这里只断 A 的 proxy 增长。
func TestEngineTUN_UDPCounters_Proxy(t *testing.T) {
	requireTUN(t)
	addLoAlias(t, tunServerIP)
	up := startEngine(t, engineSpec{
		chnroute: tunServerNet + "\n",
		acl:      "proxy cidr " + tunServerNet + " direct\n",
	})
	_, ifname := startTUNEngine(t, engineSpec{
		acl:      "proxy cidr " + tunServerNet + " up\n",
		upstream: []config.ProxyEntry{{Alias: "up", URL: "socks5://" + up.listener.Addr().String()}},
	})
	echo := startUDPEchoOn(t, tunServerIP)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	before := sampleUDPCounts()
	c := tunDial(t, ifname, "udp", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("hello tun udp counter proxy")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}

	after := sampleUDPCounts()
	t.Logf("TUN proxy: udp.ProxyBytesUp+%d Down+%d (want Up&Down >0)",
		after.proxyUp-before.proxyUp, after.proxyDown-before.proxyDown)
	if after.proxyUp-before.proxyUp <= 0 || after.proxyDown-before.proxyDown <= 0 {
		t.Fatalf("TUN proxy UDP counters did not increase: up=%d down=%d",
			after.proxyUp-before.proxyUp, after.proxyDown-before.proxyDown)
	}
}

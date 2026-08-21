package engine

import (
	"io"
	"net"
	"testing"
	"time"

	"smartproxy/internal/config"
)

// 吞吐压测:真实流量打满 SOCKS5 入口,量的是"引擎处理能力"(relay 拷贝、
// UDP 调度、路由判定),不是路由表查找之类的微基准。四档:
//
//   - 单流直连(1MB 块双向 echo)——最基础的拷贝能力;
//   - 单流代理(A→B 双引擎)——完整代理链,两端各有一层 relay;
//   - 8 流并发直连——贴近 VPN 真实多路场景的聚合吞吐;
//   - UDP 单会话 ping-pong——量每包往返延迟换算的 PPS / MB/s。
//
// 运行:`go test ./internal/engine/ -run '^$' -bench TCP|UDP -benchtime=3s`

const benchBufSize = 1 << 20 // 1MB

// benchTCPEcho 起一个 127.0.0.1 的 TCP echo,经引擎 CONNECT 过去,
// 返回已连好的客户端连接(带 30s 宽松 deadline,Cleanup 时关闭)。
func benchTCPEcho(b *testing.B, eng *Engine) net.Conn {
	b.Helper()
	echo := startTCPEcho(b)
	port := echo.Addr().(*net.TCPAddr).Port
	c := socks5Connect(b, eng.listener.Addr().String(), "127.0.0.1", port)
	c.SetDeadline(time.Now().Add(30 * time.Second))
	b.Cleanup(func() { c.Close() })
	return c
}

// echoOnce 发 1MB 并读回 1MB(echo 服务器回环)。
func echoOnce(b *testing.B, c net.Conn, buf []byte) {
	b.Helper()
	if _, err := c.Write(buf); err != nil {
		b.Fatal(err)
	}
	if _, err := io.ReadFull(c, buf); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkTCPDirectThroughput:单流直连,1MB 块双向 echo,MB/s。
func BenchmarkTCPDirectThroughput(b *testing.B) {
	eng := newTestEngine(b)
	c := benchTCPEcho(b, eng)
	buf := make([]byte, benchBufSize)
	b.SetBytes(2 * int64(benchBufSize)) // 发+收各 1MB
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		echoOnce(b, c, buf)
	}
}

// BenchmarkTCPProxyThroughput:单流走代理链 A→B(双引擎),量完整代理栈。
// A 的 ACL 把 127.0.0.0/8 强制走上游 B,B 是纯直连引擎,流量 A→B→echo→回。
func BenchmarkTCPProxyThroughput(b *testing.B) {
	up := newTestEngine(b) // 上游 B:纯直连
	eng := startEngine(b, engineSpec{
		chnroute: "127.0.0.0/8\n",
		acl:      "proxy cidr 127.0.0.0/8 up\n",
		upstream: []config.ProxyEntry{{Alias: "up", URL: "socks5://" + up.listener.Addr().String()}},
	})
	c := benchTCPEcho(b, eng)
	buf := make([]byte, benchBufSize)
	b.SetBytes(2 * int64(benchBufSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		echoOnce(b, c, buf)
	}
}

// BenchmarkTCPDirectThroughput_MultiStream:8 条并发流聚合直连吞吐。
// 每个 RunParallel worker 持有一条长连接,worker 数少于 8 时
// 剩余连接由 benchTCPEcho 注册的 Cleanup 关闭。
func BenchmarkTCPDirectThroughput_MultiStream(b *testing.B) {
	eng := newTestEngine(b)
	connCh := make(chan net.Conn, 8)
	for i := 0; i < 8; i++ {
		connCh <- benchTCPEcho(b, eng)
	}
	b.SetBytes(2 * int64(benchBufSize))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c := <-connCh
		buf := make([]byte, benchBufSize)
		for pb.Next() {
			if _, err := c.Write(buf); err != nil {
				b.Error(err)
				return
			}
			if _, err := io.ReadFull(c, buf); err != nil {
				b.Error(err)
				return
			}
		}
		c.Close()
	})
}

// BenchmarkUDPThroughput:UDP echo 1200B 包 ping-pong(单会话),PPS 与 MB/s。
func BenchmarkUDPThroughput(b *testing.B) {
	eng := newTestEngine(b)
	echo := startUDPEcho(b)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	tcpConn, udpConn := socks5UDPAssociate(b, eng.listener.Addr().String())
	b.Cleanup(func() { tcpConn.Close() })
	b.Cleanup(func() { udpConn.Close() })
	udpConn.SetDeadline(time.Now().Add(30 * time.Second))

	payload := make([]byte, 1200)
	frame := append([]byte{0, 0, 0}, socks5Addr("127.0.0.1", echoPort)...)
	frame = append(frame, payload...)
	reply := make([]byte, 65535)

	b.SetBytes(int64(len(payload) * 2)) // 发+收各 1200B
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := udpConn.Write(frame); err != nil {
			b.Fatal(err)
		}
		if _, err := udpConn.Read(reply); err != nil {
			b.Fatal(err)
		}
	}
}

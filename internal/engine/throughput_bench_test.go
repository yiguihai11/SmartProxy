package engine

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"smartproxy/internal/config"
)

// startUDPEchoParallel 与 e2e 的 startUDPEcho 不同:每包一个 goroutine + buffer
// 池,echo 端不再串行转发——用来排除"echo 单 goroutine 就是吞吐瓶颈"的干扰,
// 测出引擎/内核各自的真实上限。仅 benchmark 用,不进 e2e。
func startUDPEchoParallel(b *testing.B) *net.UDPConn {
	b.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	var pool = sync.Pool{New: func() any { return make([]byte, 65535) }}
	go func() {
		for {
			buf := pool.Get().([]byte)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			go func(buf []byte, n int, addr net.Addr) {
				pc.WriteTo(buf[:n], addr)
				pool.Put(buf)
			}(buf, n, addr)
		}
	}()
	b.Cleanup(func() { pc.Close() })
	return pc.(*net.UDPConn)
}

// udpEchoPipelined 一组流水线转发:发 inflight 个包、读回 inflight 个包。
// 同步 ping-pong 每次只有一个包在途,测的是 RTT;流水线让多个包同时在飞,
// 才能逼近真实的 UDP 吞吐上限。迭代次数按 b.N 走,SetBytes 按 inflight 折算。
func udpEchoPipelined(b *testing.B, w func(), r func()) {
	b.Helper()
	const inflight = 32
	b.SetBytes(2 * 1200 * inflight)
	b.ResetTimer()
	for k := 0; k < b.N; k++ {
		for i := 0; i < inflight; i++ {
			w()
		}
		for i := 0; i < inflight; i++ {
			r()
		}
	}
}

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

// BenchmarkUDPThroughput_Pipelined:经引擎,32 包在途的流水线吞吐。
// 消除 ping-pong 的 RTT 主导后,这里才是引擎真实的 UDP 吞吐上限。
func BenchmarkUDPThroughput_Pipelined(b *testing.B) {
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

	udpEchoPipelined(b,
		func() {
			if _, err := udpConn.Write(frame); err != nil {
				b.Fatal(err)
			}
		},
		func() {
			if _, err := udpConn.Read(reply); err != nil {
				b.Fatal(err)
			}
		},
	)
}

// BenchmarkUDPThroughput_DirectSocket:不经引擎,直连 echo 的同步 ping-pong——
// 纯内核 loopback 的 RTT 基线(不经过 SmartProxy 任何代码)。
func BenchmarkUDPThroughput_DirectSocket(b *testing.B) {
	echo := startUDPEcho(b)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(30 * time.Second))

	payload := make([]byte, 1200)
	reply := make([]byte, 65535)
	b.SetBytes(int64(len(payload) * 2))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := c.Read(reply); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUDPThroughput_DirectSocketPipelined:不经引擎,32 包在途——
// 纯内核 loopback 的 UDP 吞吐上限,给引擎版提供对比基准。
func BenchmarkUDPThroughput_DirectSocketPipelined(b *testing.B) {
	echo := startUDPEcho(b)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(30 * time.Second))

	payload := make([]byte, 1200)
	reply := make([]byte, 65535)

	udpEchoPipelined(b,
		func() {
			if _, err := c.Write(payload); err != nil {
				b.Fatal(err)
			}
		},
		func() {
			if _, err := c.Read(reply); err != nil {
				b.Fatal(err)
			}
		},
	)
}

// BenchmarkUDPThroughput_PipelinedParallelEcho:引擎 + 并发 echo——echo 不再
// 串行,排除 echo 端瓶颈后引擎的流水线吞吐上限。
func BenchmarkUDPThroughput_PipelinedParallelEcho(b *testing.B) {
	eng := newTestEngine(b)
	echo := startUDPEchoParallel(b)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	tcpConn, udpConn := socks5UDPAssociate(b, eng.listener.Addr().String())
	b.Cleanup(func() { tcpConn.Close() })
	b.Cleanup(func() { udpConn.Close() })
	udpConn.SetDeadline(time.Now().Add(30 * time.Second))

	payload := make([]byte, 1200)
	frame := append([]byte{0, 0, 0}, socks5Addr("127.0.0.1", echoPort)...)
	frame = append(frame, payload...)
	reply := make([]byte, 65535)

	udpEchoPipelined(b,
		func() {
			if _, err := udpConn.Write(frame); err != nil {
				b.Fatal(err)
			}
		},
		func() {
			if _, err := udpConn.Read(reply); err != nil {
				b.Fatal(err)
			}
		},
	)
}

// BenchmarkUDPThroughput_DirectPipelinedParallelEcho:纯内核 + 并发 echo——
// 内核 loopback 的真实 UDP 吞吐上限,与引擎版严格同 echo。
func BenchmarkUDPThroughput_DirectPipelinedParallelEcho(b *testing.B) {
	echo := startUDPEchoParallel(b)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(30 * time.Second))

	payload := make([]byte, 1200)
	reply := make([]byte, 65535)

	udpEchoPipelined(b,
		func() {
			if _, err := c.Write(payload); err != nil {
				b.Fatal(err)
			}
		},
		func() {
			if _, err := c.Read(reply); err != nil {
				b.Fatal(err)
			}
		},
	)
}

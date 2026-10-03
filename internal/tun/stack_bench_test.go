//go:build with_lwip && with_gvisor && cgo

package tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/unix"

	"smartproxy/internal/config"
)

// benchTeardownGuard 把收尾(栈 / 设备的 Close)挡在 ns/op 的计时窗口之外。
//
// testing 的计时窗口一直到 benchmark 函数返回才关闭,所以用裸 defer 注册的 Close
// 会被算进单次耗时里。而 LWIPStack.Close() 在 tun 尚未先关闭时会等满 500ms 的
// 「读循环退出」超时(见 stack_lwip.go),摊到 -benchtime=500x 上正好是 1ms/op ——
// docs/performance.md 里那个「lwIP 单次 TCP 握手 ~1.0ms」就是这么来的:把迭代数
// 换成 2000x,同一个 benchmark 报的是 254µs/op,乘回去总时长始终是 0.5s。
// 真实值约 3µs,与栈本身无关。
//
// 用法:在 b.ResetTimer() 之前 defer 本函数。它比上面的 Close defer 注册得晚,
// 按 LIFO 先于它们执行,于是计时在收尾开始前就停住。
func benchTeardownGuard(b *testing.B) { b.StopTimer() }

type benchGVisorTun struct {
	*pipeTun
	ep *channel.Endpoint
}

func newBenchGVisorTun(name string, mtu uint32) *benchGVisorTun {
	bt := &benchGVisorTun{
		pipeTun: newPipeTun(name),
		ep:      channel.New(4096, mtu, ""),
	}
	go func() {
		for {
			pkt := bt.ep.ReadContext(context.Background())
			if pkt == nil || bt.closed.Load() {
				return
			}
			data := pkt.ToView().AsSlice()
			bt.pipeTun.Write(data)
			pkt.DecRef()
		}
	}()
	return bt
}

func (t *benchGVisorTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	if t.closed.Load() {
		return 0, net.ErrClosed
	}
	data := pkt.ToView().AsSlice()
	return t.pipeTun.Write(data)
}

func (t *benchGVisorTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.ep, stack.NICOptions{}, nil
}

type benchHandler struct {
	onTCP func(conn net.Conn)
	onUDP func(conn N.PacketConn)
}

func (h *benchHandler) JudgeFlow(network uint8, source, destination netip.AddrPort, firstPacket []byte) singtun.FlowVerdict {
	return singtun.FlowVerdict{Action: singtun.ActionAccept}
}

func (h *benchHandler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
}

func (h *benchHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.onTCP != nil {
		h.onTCP(conn)
	} else {
		conn.Close()
	}
}

func (h *benchHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.onUDP != nil {
		h.onUDP(conn)
	} else {
		conn.Close()
	}
}

func TestGVisorStack_Verification(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TUN.Enabled = true
	cfg.TUN.Stack = "gvisor"
	cfg.TUN.Name = "pipe_tun_gvisor"
	cfg.TUN.FileDescriptor = 100

	handler := NewHandler(cfg, nil, nil, nil, nil)
	defer handler.Close()

	tun := newBenchGVisorTun("pipe_tun_gvisor", 1500)
	defer tun.Close()

	oldNewTUN := NewTUN
	oldNewTUNStack := NewTUNStack
	NewTUN = func(opts singtun.Options) (singtun.Tun, error) {
		return tun, nil
	}
	NewTUNStack = createTUNStack
	defer func() {
		NewTUN = oldNewTUN
		NewTUNStack = oldNewTUNStack
	}()

	tunDev, tunStack, err := handler.Start(context.Background(), cfg.TUN)
	require.NoError(t, err)
	defer func() {
		if tunDev != nil {
			tunDev.Close()
		}
		if tunStack != nil {
			tunStack.Close()
		}
	}()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(1, 2, 3, 4)
	clientPort := uint16(54321)
	serverPort := uint16(80)

	syn := testBuildIPv4TCP(clientIP, serverIP, clientPort, serverPort, 1000, 0, 0x02, nil)
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(syn),
	})
	tun.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
	pb.DecRef()

	select {
	case synAck := <-tun.writeCh:
		require.GreaterOrEqual(t, len(synAck), 40)
		t.Logf("gVisor SYN/ACK received successfully: flags=0x%02x len=%d", synAck[33], len(synAck))
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for SYN/ACK from gVisor")
	}
}

func TestGoStack_Verification(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	device, err := singtun.New(singtun.Options{
		FileDescriptor: fds[0],
		MTU:            1500,
		Inet4Address: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.2/24"),
		},
	})
	require.NoError(t, err)
	defer device.Close()

	bh := &benchHandler{}
	s, err := singtun.NewStack("go", singtun.StackOptions{
		Context: context.Background(),
		Tun:     device,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, s.Start())
	defer s.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(1, 2, 3, 4)
	syn := testBuildIPv4TCP(clientIP, serverIP, 54321, 80, 1000, 0, 0x02, nil)

	_, err = unix.Write(fds[1], syn)
	require.NoError(t, err)

	buf := make([]byte, 1500)
	done := make(chan int)
	go func() {
		for {
			n, errno := unix.Read(fds[1], buf)
			if errno == nil && n > 0 {
				done <- n
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	select {
	case n := <-done:
		t.Logf("Go stack SYN/ACK received: len=%d", n)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Go stack SYN/ACK")
	}
}

func TestSystemStack_Verification(t *testing.T) {
	tun := newPipeTun("pipe_tun_system")
	defer tun.Close()

	var received atomic.Int64
	bh := &benchHandler{
		onUDP: func(conn N.PacketConn) {
			defer conn.Close()
			b := buf.NewPacket()
			defer b.Release()
			for {
				b.Reset()
				_, err := conn.ReadPacket(b)
				if err != nil {
					return
				}
				received.Add(int64(b.Len()))
			}
		},
	}
	s, err := singtun.NewStack("system", singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, s.Start())
	defer s.Close()

	clientIP := net.IPv4(127, 0, 0, 2)
	serverIP := net.IPv4(8, 8, 8, 8)
	payload := []byte("hello system stack udp")
	pkt := testBuildIPv4UDP(clientIP, serverIP, 45678, 53, payload)
	tun.readCh <- pkt

	require.Eventually(t, func() bool {
		return received.Load() > 0
	}, 2*time.Second, 10*time.Millisecond)

	// Test TCP SYN packet rewrite by System stack
	syn := testBuildIPv4TCP(net.IPv4(10, 0, 0, 2), net.IPv4(1, 2, 3, 4), 54321, 80, 1000, 0, 0x02, nil)
	tun.readCh <- syn

	select {
	case rewritten := <-tun.writeCh:
		require.GreaterOrEqual(t, len(rewritten), 40)
		t.Logf("System stack rewritten TCP packet received: len=%d", len(rewritten))
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for System stack rewritten TCP packet")
	}
}

func TestMixedStack_Verification(t *testing.T) {
	tun := newBenchGVisorTun("pipe_tun_mixed", 1500)
	defer tun.Close()

	var received atomic.Int64
	bh := &benchHandler{
		onUDP: func(conn N.PacketConn) {
			defer conn.Close()
			b := buf.NewPacket()
			defer b.Release()
			for {
				b.Reset()
				_, err := conn.ReadPacket(b)
				if err != nil {
					return
				}
				received.Add(int64(b.Len()))
			}
		},
	}
	s, err := singtun.NewStack("mixed", singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, s.Start())
	defer s.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(8, 8, 8, 8)
	payload := []byte("hello mixed stack udp")
	pkt := testBuildIPv4UDP(clientIP, serverIP, 45678, 53, payload)
	tun.readCh <- pkt

	require.Eventually(t, func() bool {
		return received.Load() > 0
	}, 2*time.Second, 10*time.Millisecond)

	// Test TCP SYN packet rewrite by Mixed (System TCP engine)
	syn := testBuildIPv4TCP(net.IPv4(10, 0, 0, 2), net.IPv4(1, 2, 3, 4), 54321, 80, 1000, 0, 0x02, nil)
	tun.readCh <- syn

	select {
	case rewritten := <-tun.writeCh:
		require.GreaterOrEqual(t, len(rewritten), 40)
		t.Logf("Mixed stack rewritten TCP packet received: len=%d", len(rewritten))
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Mixed stack rewritten TCP packet")
	}
}

func TestLWIPStack_Verification(t *testing.T) {
	tun := newPipeTun("pipe_tun_lwip")
	defer tun.Close()

	var received atomic.Int64
	bh := &benchHandler{
		onUDP: func(conn N.PacketConn) {
			defer conn.Close()
			b := buf.NewPacket()
			defer b.Release()
			for {
				b.Reset()
				_, err := conn.ReadPacket(b)
				if err != nil {
					return
				}
				received.Add(int64(b.Len()))
			}
		},
	}
	s, err := NewLWIPStack(singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, s.Start())
	defer s.Close()

	// Test UDP
	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(8, 8, 8, 8)
	payload := []byte("hello lwip stack udp")
	pkt := testBuildIPv4UDP(clientIP, serverIP, 45678, 53, payload)
	tun.readCh <- pkt

	require.Eventually(t, func() bool {
		return received.Load() > 0
	}, 2*time.Second, 10*time.Millisecond)

	// Test TCP SYN -> SYN/ACK
	syn := testBuildIPv4TCP(net.IPv4(10, 0, 0, 2), net.IPv4(1, 2, 3, 4), 54321, 80, 1000, 0, 0x02, nil)
	tun.readCh <- syn

	select {
	case synAck := <-tun.writeCh:
		require.GreaterOrEqual(t, len(synAck), 40)
		t.Logf("lwIP stack SYN/ACK received: len=%d", len(synAck))
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for lwIP stack SYN/ACK")
	}
}

func BenchmarkStack_UDP_Throughput_gVisor(b *testing.B) {
	tun := newBenchGVisorTun("bench_udp_gvisor", 1500)
	defer tun.Close()

	var received atomic.Int64
	bh := &benchHandler{
		onUDP: func(conn N.PacketConn) {
			defer conn.Close()
			b := buf.NewPacket()
			defer b.Release()
			for {
				b.Reset()
				_, err := conn.ReadPacket(b)
				if err != nil {
					return
				}
				received.Add(int64(b.Len()))
			}
		},
	}

	gStack, err := singtun.NewStack("gvisor", singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(b, err)
	require.NoError(b, gStack.Start())
	defer gStack.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(8, 8, 8, 8)
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := testBuildIPv4UDP(clientIP, serverIP, 45678, 53, payload)

	b.SetBytes(int64(len(payload)))
	defer benchTeardownGuard(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pkt),
		})
		tun.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
		pb.DecRef()
	}
}

func BenchmarkStack_UDP_Throughput_Go(b *testing.B) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
	require.NoError(b, err)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	device, err := singtun.New(singtun.Options{
		FileDescriptor: fds[0],
		MTU:            1500,
		Inet4Address: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.2/24"),
		},
	})
	require.NoError(b, err)
	defer device.Close()

	var received atomic.Int64
	bh := &benchHandler{
		onUDP: func(conn N.PacketConn) {
			defer conn.Close()
			buf := buf.NewPacket()
			defer buf.Release()
			for {
				buf.Reset()
				_, err := conn.ReadPacket(buf)
				if err != nil {
					return
				}
				received.Add(int64(buf.Len()))
			}
		},
	}

	s, err := singtun.NewStack("go", singtun.StackOptions{
		Context: context.Background(),
		Tun:     device,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(b, err)
	require.NoError(b, s.Start())
	defer s.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(8, 8, 8, 8)
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := testBuildIPv4UDP(clientIP, serverIP, 45678, 53, payload)

	b.SetBytes(int64(len(payload)))
	defer benchTeardownGuard(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = unix.Write(fds[1], pkt)
	}
}

func BenchmarkStack_UDP_Throughput_lwIP(b *testing.B) {
	tun := newPipeTun("bench_udp_lwip")
	defer tun.Close()

	var received atomic.Int64
	bh := &benchHandler{
		onUDP: func(conn N.PacketConn) {
			defer conn.Close()
			b := buf.NewPacket()
			defer b.Release()
			for {
				b.Reset()
				_, err := conn.ReadPacket(b)
				if err != nil {
					return
				}
				received.Add(int64(b.Len()))
			}
		},
	}

	lStack, err := NewLWIPStack(singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(b, err)
	require.NoError(b, lStack.Start())
	defer lStack.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(8, 8, 8, 8)
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := testBuildIPv4UDP(clientIP, serverIP, 45678, 53, payload)

	b.SetBytes(int64(len(payload)))
	defer benchTeardownGuard(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tun.readCh <- pkt
	}
}

func BenchmarkStack_UDP_Throughput_System(b *testing.B) {
	tun := newPipeTun("bench_udp_system")
	defer tun.Close()

	var received atomic.Int64
	bh := &benchHandler{
		onUDP: func(conn N.PacketConn) {
			defer conn.Close()
			b := buf.NewPacket()
			defer b.Release()
			for {
				b.Reset()
				_, err := conn.ReadPacket(b)
				if err != nil {
					return
				}
				received.Add(int64(b.Len()))
			}
		},
	}

	s, err := singtun.NewStack("system", singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(b, err)
	require.NoError(b, s.Start())
	defer s.Close()

	clientIP := net.IPv4(127, 0, 0, 2)
	serverIP := net.IPv4(8, 8, 8, 8)
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := testBuildIPv4UDP(clientIP, serverIP, 45678, 53, payload)

	b.SetBytes(int64(len(payload)))
	defer benchTeardownGuard(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tun.readCh <- pkt
	}
}

func BenchmarkStack_UDP_Throughput_Mixed(b *testing.B) {
	tun := newBenchGVisorTun("bench_udp_mixed", 1500)
	defer tun.Close()

	var received atomic.Int64
	bh := &benchHandler{
		onUDP: func(conn N.PacketConn) {
			defer conn.Close()
			b := buf.NewPacket()
			defer b.Release()
			for {
				b.Reset()
				_, err := conn.ReadPacket(b)
				if err != nil {
					return
				}
				received.Add(int64(b.Len()))
			}
		},
	}

	s, err := singtun.NewStack("mixed", singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(b, err)
	require.NoError(b, s.Start())
	defer s.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(8, 8, 8, 8)
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := testBuildIPv4UDP(clientIP, serverIP, 45678, 53, payload)

	b.SetBytes(int64(len(payload)))
	defer benchTeardownGuard(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tun.readCh <- pkt
	}
}

func BenchmarkStack_TCP_Handshake_gVisor(b *testing.B) {
	tun := newBenchGVisorTun("bench_tcp_gvisor", 1500)
	defer tun.Close()

	bh := &benchHandler{
		onTCP: func(conn net.Conn) {
			conn.Close()
		},
	}

	gStack, err := singtun.NewStack("gvisor", singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(b, err)
	require.NoError(b, gStack.Start())
	defer gStack.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(1, 2, 3, 4)

	defer benchTeardownGuard(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		clientPort := uint16(10000 + (i % 16))
		syn := testBuildIPv4TCP(clientIP, serverIP, clientPort, 80, 1000, 0, 0x02, nil)
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(syn),
		})
		tun.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
		pb.DecRef()

		// Drain the SYN/ACK response
		var synAck []byte
		select {
		case synAck = <-tun.writeCh:
		case <-time.After(500 * time.Millisecond):
			b.Fatal("timeout waiting for SYN/ACK")
		}
		if len(synAck) >= 28 {
			serverSeq := binary.BigEndian.Uint32(synAck[24:28])
			rst := testBuildIPv4TCP(clientIP, serverIP, clientPort, 80, 1001, serverSeq+1, 0x04, nil)
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(rst),
			})
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
			pb.DecRef()
		}
	}
}

func BenchmarkStack_TCP_Handshake_Go(b *testing.B) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
	require.NoError(b, err)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	device, err := singtun.New(singtun.Options{
		FileDescriptor: fds[0],
		MTU:            1500,
		Inet4Address: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.2/24"),
		},
	})
	require.NoError(b, err)
	defer device.Close()

	bh := &benchHandler{
		onTCP: func(conn net.Conn) {
			go func() {
				time.Sleep(10 * time.Millisecond)
				conn.Close()
			}()
		},
	}

	s, err := singtun.NewStack("go", singtun.StackOptions{
		Context: context.Background(),
		Tun:     device,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(b, err)
	require.NoError(b, s.Start())
	defer s.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(1, 2, 3, 4)
	_ = unix.SetNonblock(fds[1], false)
	outCh := make(chan []byte, 1024)
	go func() {
		b := make([]byte, 1500)
		pfd := []unix.PollFd{{Fd: int32(fds[1]), Events: unix.POLLIN}}
		for {
			_, err := unix.Poll(pfd, 1000)
			if err != nil {
				return
			}
			n, err := unix.Read(fds[1], b)
			if err != nil {
				continue
			}
			if n > 0 {
				data := make([]byte, n)
				copy(data, b[:n])
				outCh <- data
			}
		}
	}()

	defer benchTeardownGuard(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		clientPort := uint16(10000 + (i % 16))
		syn := testBuildIPv4TCP(clientIP, serverIP, clientPort, 80, 1000, 0, 0x02, nil)
		_, err := unix.Write(fds[1], syn)
		if err != nil {
			b.Fatalf("write syn error: %v", err)
		}

		select {
		case <-outCh:
		case <-time.After(1000 * time.Millisecond):
			b.Fatalf("iter %d timeout waiting for TCP response", i)
		}
	}
}

func BenchmarkStack_TCP_Handshake_lwIP(b *testing.B) {
	tun := newPipeTun("bench_tcp_lwip")
	defer tun.Close()

	bh := &benchHandler{
		onTCP: func(conn net.Conn) {
			if tc, ok := conn.(interface{ SetLinger(int) error }); ok {
				tc.SetLinger(0)
			}
			conn.Close()
		},
	}

	lStack, err := NewLWIPStack(singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.2/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(b, err)
	require.NoError(b, lStack.Start())
	defer lStack.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(1, 2, 3, 4)

	defer benchTeardownGuard(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		clientPort := uint16(10000 + (i % 16))
		syn := testBuildIPv4TCP(clientIP, serverIP, clientPort, 80, 1000, 0, 0x02, nil)
		tun.readCh <- syn

		select {
		case <-tun.writeCh:
		case <-time.After(500 * time.Millisecond):
			b.Fatal("timeout waiting for SYN/ACK")
		}
	}
}

func BenchmarkStack_TCP_Handshake_System(b *testing.B) {
	tun := newPipeTun("bench_tcp_system")
	defer tun.Close()

	bh := &benchHandler{}
	s, err := singtun.NewStack("system", singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(b, err)
	require.NoError(b, s.Start())
	defer s.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(1, 2, 3, 4)

	defer benchTeardownGuard(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		clientPort := uint16(10000 + (i % 16))
		syn := testBuildIPv4TCP(clientIP, serverIP, clientPort, 80, 1000, 0, 0x02, nil)
		tun.readCh <- syn

		select {
		case <-tun.writeCh:
		case <-time.After(500 * time.Millisecond):
			b.Fatal("timeout waiting for System TCP rewrite response")
		}
	}
}

func BenchmarkStack_TCP_Handshake_Mixed(b *testing.B) {
	tun := newBenchGVisorTun("bench_tcp_mixed", 1500)
	defer tun.Close()

	bh := &benchHandler{}
	s, err := singtun.NewStack("mixed", singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/24"),
			},
		},
		Handler:     bh,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	})
	require.NoError(b, err)
	require.NoError(b, s.Start())
	defer s.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	serverIP := net.IPv4(1, 2, 3, 4)

	defer benchTeardownGuard(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		clientPort := uint16(10000 + (i % 16))
		syn := testBuildIPv4TCP(clientIP, serverIP, clientPort, 80, 1000, 0, 0x02, nil)
		tun.readCh <- syn

		select {
		case <-tun.writeCh:
		case <-time.After(500 * time.Millisecond):
			b.Fatal("timeout waiting for Mixed TCP rewrite response")
		}
	}
}

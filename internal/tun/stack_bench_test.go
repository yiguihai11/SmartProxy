//go:build with_lwip && with_gvisor && cgo

package tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
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

// ---------------- UDP 基准的公共构造 ----------------

// benchUDPPayload 是用例报文承载的载荷。1400B 加上 IP/UDP 头仍在 1500B MTU 的单包
// 以内,不触发分片。
var benchUDPPayload = func() []byte {
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}()

// benchUDPWindow 是带背压用例允许同时在途(已注入、尚未出栈到 handler)的报文数。
//
// 取 64 而不是 1:同步只发生在每批的首尾,摊到 64 个包上可以忽略;而这个窗口又远小于
// 链路上任何一级内部缓冲(pipeTun.readCh 4096、gVisor channel endpoint 4096、lwIP
// inputChan 1024、go 栈 socketpair 约 150 包),栈没办法靠"把包堆在队列里"把耗时藏掉。
const benchUDPWindow = 64

// benchUDPStallTimeout 是一批报文全部出栈的等待上限。超时说明这个栈没有把报文交到
// handler(或者慢到不成样子),报错比挂死好。
const benchUDPStallTimeout = 5 * time.Second

// benchUDPAck 是带背压用例的"出栈"信号:handler 每从栈里读走一个报文就投一个令牌,
// 灌包侧每批收齐令牌后才发下一批。令牌通道容量取窗口大小 —— 灌包侧在发下一批之前一定
// 把上一批的令牌收干净了,在途令牌不会超过窗口,所以下面的非阻塞发送不会丢令牌。
type benchUDPAck struct {
	stackName string
	tokens    chan struct{}
	packets   atomic.Uint64
}

func newBenchUDPAck(stackName string) *benchUDPAck {
	return &benchUDPAck{
		stackName: stackName,
		tokens:    make(chan struct{}, benchUDPWindow),
	}
}

func (a *benchUDPAck) signal() {
	a.packets.Add(1)
	select {
	case a.tokens <- struct{}{}:
	default:
	}
}

// acknowledge 收回 n 个令牌,也就是等这一批报文全部出栈。
//
// 一个报文都没等到时判为环境不支持而不是失败:system / mixed 这类栈的 UDP 出口依赖
// 真实内核 socket,在无权限或断网的基准环境里可能根本不往 handler 交包,那是环境问题,
// 没有理由把 CI 打红 —— 跳过并把原因写进输出即可。已经收到过报文之后再卡住才说明栈
// 本身出了问题,这时才 Fatal。
func (a *benchUDPAck) acknowledge(b *testing.B, n int, stallTimer *time.Timer) {
	for range n {
		select {
		case <-a.tokens:
		case <-stallTimer.C:
			if a.packets.Load() == 0 {
				b.Skipf("带背压用例在本环境下不成立:%s 栈一个 UDP 报文都没有交到 handler", a.stackName)
			}
			b.Fatalf("等待报文出栈超时:%s 栈累计只有 %d 个报文到达 handler", a.stackName, a.packets.Load())
		}
	}
}

// benchUDPHandler 造一个把报文从栈里读走的 handler。ack 非空时每读走一个报文投一个
// 令牌,供带背压用例等待;为空时只读,与无背压用例的行为一致。
func benchUDPHandler(ack *benchUDPAck) *benchHandler {
	return &benchHandler{
		onUDP: func(conn N.PacketConn) {
			defer conn.Close()
			packet := buf.NewPacket()
			defer packet.Release()
			for {
				packet.Reset()
				if _, err := conn.ReadPacket(packet); err != nil {
					return
				}
				if ack != nil {
					ack.signal()
				}
			}
		},
	}
}

// benchUDPStack 是一套 UDP 基准环境。
type benchUDPStack struct {
	// inject 按该栈的方式把一个报文喂进 TUN。
	inject func(pkt []byte)
	// injectBlocking 与 inject 相同,但不允许静默丢弃:go 栈注入用的非阻塞
	// socketpair 在缓冲满时返回 EAGAIN。带背压用例必须用它,否则会一直等一个
	// 根本没进去的报文。
	injectBlocking func(pkt []byte)
	packet         []byte
	closers        []func()
}

// Close 按构造顺序的逆序收尾。
func (s *benchUDPStack) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
}

// newBenchUDPStack 搭起某个栈的 UDP 基准环境。各分支与 docs/performance.md §6.1
// 里原本逐栈重复的那五段搭建代码逐字一致,只是收拢到一处,让无背压与带背压两组用例
// 跑在完全相同的栈上。
func newBenchUDPStack(b *testing.B, stackName string, ack *benchUDPAck) *benchUDPStack {
	s := &benchUDPStack{}
	clientIP := net.IPv4(10, 0, 0, 2)
	inet4Address := "10.0.0.2/24"

	var tun singtun.Tun
	switch stackName {
	case "gvisor":
		gTun := newBenchGVisorTun("bench_udp_gvisor", 1500)
		s.closers = append(s.closers, func() { gTun.Close() })
		tun = gTun
		s.inject = func(pkt []byte) {
			packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			})
			gTun.ep.InjectInbound(header.IPv4ProtocolNumber, packetBuffer)
			packetBuffer.DecRef()
		}
	case "go":
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
		require.NoError(b, err)
		s.closers = append(s.closers, func() { unix.Close(fds[0]) }, func() { unix.Close(fds[1]) })
		device, err := singtun.New(singtun.Options{
			FileDescriptor: fds[0],
			MTU:            1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix(inet4Address),
			},
		})
		require.NoError(b, err)
		s.closers = append(s.closers, func() { device.Close() })
		tun = device
		s.inject = func(pkt []byte) {
			_, _ = unix.Write(fds[1], pkt)
		}
		s.injectBlocking = func(pkt []byte) {
			// 窗口 64 远小于 socketpair 的缓冲(约 150 个包),正常跑不到 EAGAIN;
			// 真撞上说明读端不动了,重试到一个上限就放弃,让出栈等待那边去报错,
			// 而不是在这里挂死。
			deadline := time.Now().Add(benchUDPStallTimeout)
			for {
				if _, err := unix.Write(fds[1], pkt); err != unix.EAGAIN {
					return
				}
				if time.Now().After(deadline) {
					return
				}
				runtime.Gosched()
			}
		}
	case "lwip":
		pTun := newPipeTun("bench_udp_lwip")
		s.closers = append(s.closers, func() { pTun.Close() })
		tun = pTun
		s.inject = func(pkt []byte) { pTun.readCh <- pkt }
	case "system":
		clientIP, inet4Address = net.IPv4(127, 0, 0, 2), "127.0.0.1/24"
		pTun := newPipeTun("bench_udp_system")
		s.closers = append(s.closers, func() { pTun.Close() })
		tun = pTun
		s.inject = func(pkt []byte) { pTun.readCh <- pkt }
	case "mixed":
		inet4Address = "127.0.0.1/24"
		gTun := newBenchGVisorTun("bench_udp_mixed", 1500)
		s.closers = append(s.closers, func() { gTun.Close() })
		tun = gTun
		s.inject = func(pkt []byte) { gTun.readCh <- pkt }
	default:
		b.Fatalf("未知协议栈 %q", stackName)
	}
	if s.injectBlocking == nil {
		s.injectBlocking = s.inject
	}

	stackOptions := singtun.StackOptions{
		Context: context.Background(),
		Tun:     tun,
		TunOptions: singtun.Options{
			MTU: 1500,
			Inet4Address: []netip.Prefix{
				netip.MustParsePrefix(inet4Address),
			},
		},
		Handler:     benchUDPHandler(ack),
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Second,
	}

	var (
		tunStack singtun.Stack
		err      error
	)
	if stackName == "lwip" {
		tunStack, err = NewLWIPStack(stackOptions)
	} else {
		tunStack, err = singtun.NewStack(stackName, stackOptions)
	}
	require.NoError(b, err)
	require.NoError(b, tunStack.Start())
	s.closers = append(s.closers, func() { tunStack.Close() })

	s.packet = testBuildIPv4UDP(clientIP, net.IPv4(8, 8, 8, 8), 45678, 53, benchUDPPayload)
	return s
}

// runBenchUDP 跑一次 UDP 基准。
//
// backpressure 为真时每批只在窗口内灌包、收齐出栈令牌再发下一批,测到的是"报文穿过
// 协议栈交到 handler"的端到端成本;为假时是原有无背压用例 —— 灌包只写进缓冲通道就
// 返回,500 次迭代根本填不满,测到的是把报文喂进 TUN 的成本。两组数据在
// docs/performance.md §6.1 里有对照,不要混用。
func runBenchUDP(b *testing.B, stackName string, backpressure bool) {
	var ack *benchUDPAck
	if backpressure {
		ack = newBenchUDPAck(stackName)
	}
	s := newBenchUDPStack(b, stackName, ack)
	defer s.Close()
	defer benchTeardownGuard(b)

	inject := s.inject
	if backpressure {
		inject = s.injectBlocking
	}

	b.SetBytes(int64(len(benchUDPPayload)))
	b.ResetTimer()
	b.ReportAllocs()

	if !backpressure {
		for i := 0; i < b.N; i++ {
			inject(s.packet)
		}
		return
	}

	stallTimer := time.NewTimer(time.Hour)
	if !stallTimer.Stop() {
		<-stallTimer.C
	}
	defer stallTimer.Stop()

	for i := 0; i < b.N; i += benchUDPWindow {
		batch := min(benchUDPWindow, b.N-i)
		for range batch {
			inject(s.packet)
		}
		stallTimer.Reset(benchUDPStallTimeout)
		ack.acknowledge(b, batch, stallTimer)
	}
}

// 无背压组:灌包不等出栈,测的是注入成本,保留下来作为对照。
func BenchmarkStack_UDP_Throughput_gVisor(b *testing.B) { runBenchUDP(b, "gvisor", false) }
func BenchmarkStack_UDP_Throughput_Go(b *testing.B)     { runBenchUDP(b, "go", false) }
func BenchmarkStack_UDP_Throughput_lwIP(b *testing.B)   { runBenchUDP(b, "lwip", false) }
func BenchmarkStack_UDP_Throughput_System(b *testing.B) { runBenchUDP(b, "system", false) }
func BenchmarkStack_UDP_Throughput_Mixed(b *testing.B)  { runBenchUDP(b, "mixed", false) }

// 带背压组:每批 64 个包,等这一批全部出栈到 handler 再发下一批。
func BenchmarkStack_UDP_Backpressure_gVisor(b *testing.B) { runBenchUDP(b, "gvisor", true) }
func BenchmarkStack_UDP_Backpressure_Go(b *testing.B)     { runBenchUDP(b, "go", true) }
func BenchmarkStack_UDP_Backpressure_lwIP(b *testing.B)   { runBenchUDP(b, "lwip", true) }
func BenchmarkStack_UDP_Backpressure_System(b *testing.B) { runBenchUDP(b, "system", true) }
func BenchmarkStack_UDP_Backpressure_Mixed(b *testing.B)  { runBenchUDP(b, "mixed", true) }

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
			conn.Close()
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
		// Use a fresh 4-tuple on every iteration. Reusing only 16 source ports
		// can collide with the Go stack's still-closing TCP control blocks and
		// make the benchmark fail for reasons unrelated to handshake cost.
		clientPort := uint16(10000 + i)
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

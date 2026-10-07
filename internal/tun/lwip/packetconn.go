//go:build with_lwip && cgo

package lwip

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ net.PacketConn = (*PacketConn)(nil)
	_ N.PacketConn   = (*PacketConn)(nil)
)

type udpInboundPacket struct {
	dst  M.Socksaddr
	data []byte
	buf  *[]byte
}

var udpInboundPacketPool = sync.Pool{
	New: func() any { return new(udpInboundPacket) },
}

var udpRecvBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func acquireUDPRecvBuffer(length int) ([]byte, *[]byte) {
	if length <= 2048 {
		b := udpRecvBufferPool.Get().(*[]byte)
		return (*b)[:length], b
	}
	return make([]byte, length), nil
}

func releaseUDPRecvBuffer(b *[]byte) {
	if b != nil {
		udpRecvBufferPool.Put(b)
	}
}

func releaseUDPInboundPacket(pkt *udpInboundPacket) {
	if pkt == nil {
		return
	}
	releaseUDPRecvBuffer(pkt.buf)
	pkt.data = nil
	pkt.buf = nil
	udpInboundPacketPool.Put(pkt)
}

type udpSendReq struct {
	connID   uint64
	isIPv6   bool
	srcIP    netip.Addr
	srcPort  uint16
	data     []byte
	doneChan chan error
}

func newUDPSendReq(connID uint64, isIPv6 bool, srcIP netip.Addr, srcPort uint16, data []byte) *udpSendReq {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	return &udpSendReq{
		connID:   connID,
		isIPv6:   isIPv6,
		srcIP:    srcIP,
		srcPort:  srcPort,
		data:     dataCopy,
		doneChan: make(chan error, 1),
	}
}

// PacketConn wraps a transparent lwIP UDP PCB into standard net.PacketConn and sing-tun N.PacketConn.
type PacketConn struct {
	engine     *Engine
	id         uint64
	isIPv6     bool
	localAddr  *net.UDPAddr
	remoteAddr *net.UDPAddr
	source     M.Socksaddr
	dest       M.Socksaddr

	recvQueue chan *udpInboundPacket
	closeChan chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool

	readDeadline  atomic.Pointer[time.Time]
	writeDeadline atomic.Pointer[time.Time]
}

func newPacketConn(
	engine *Engine,
	id uint64,
	isIPv6 bool,
	srcIP netip.Addr,
	srcPort uint16,
	dstIP netip.Addr,
	dstPort uint16,
) *PacketConn {
	return &PacketConn{
		engine:     engine,
		id:         id,
		isIPv6:     isIPv6,
		localAddr:  &net.UDPAddr{IP: srcIP.AsSlice(), Port: int(srcPort)},
		remoteAddr: &net.UDPAddr{IP: dstIP.AsSlice(), Port: int(dstPort)},
		source:     M.Socksaddr{Addr: srcIP, Port: srcPort},
		dest:       M.Socksaddr{Addr: dstIP, Port: dstPort},
		recvQueue:  make(chan *udpInboundPacket, 256),
		closeChan:  make(chan struct{}),
	}
}

func (c *PacketConn) onData(dstIP netip.Addr, dstPort uint16, data []byte, dataBuf *[]byte) {
	if c.closed.Load() {
		releaseUDPRecvBuffer(dataBuf)
		return
	}

	pkt := udpInboundPacketPool.Get().(*udpInboundPacket)
	pkt.dst = M.Socksaddr{Addr: dstIP, Port: dstPort}
	pkt.data = data
	pkt.buf = dataBuf

	select {
	case c.recvQueue <- pkt:
	default:
		// Queue full: drop datagram under extreme congestion
		releaseUDPInboundPacket(pkt)
	}
}

// ReadFrom implements net.PacketConn.
func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}

	var timer *time.Timer
	var timerCh <-chan time.Time
	if dl := c.readDeadline.Load(); dl != nil && !dl.IsZero() {
		dur := time.Until(*dl)
		if dur <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(dur)
		defer timer.Stop()
		timerCh = timer.C
	}

	select {
	case <-c.closeChan:
		return 0, nil, net.ErrClosed
	case <-c.engine.doneChan:
		return 0, nil, net.ErrClosed
	case <-timerCh:
		return 0, nil, os.ErrDeadlineExceeded
	case pkt := <-c.recvQueue:
		n = copy(p, pkt.data)
		releaseUDPRecvBuffer(pkt.buf)
		udpAddr := &net.UDPAddr{
			IP:   pkt.dst.Addr.AsSlice(),
			Port: int(pkt.dst.Port),
		}
		pkt.data = nil
		pkt.buf = nil
		udpInboundPacketPool.Put(pkt)
		return n, udpAddr, nil
	}
}

// ReadPacket implements sing-tun / sagernet N.PacketConn.
func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if c.closed.Load() {
		return M.Socksaddr{}, net.ErrClosed
	}

	var timer *time.Timer
	var timerCh <-chan time.Time
	if dl := c.readDeadline.Load(); dl != nil && !dl.IsZero() {
		dur := time.Until(*dl)
		if dur <= 0 {
			return M.Socksaddr{}, os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(dur)
		defer timer.Stop()
		timerCh = timer.C
	}

	select {
	case <-c.closeChan:
		return M.Socksaddr{}, net.ErrClosed
	case <-c.engine.doneChan:
		return M.Socksaddr{}, net.ErrClosed
	case <-timerCh:
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	case pkt := <-c.recvQueue:
		_, _ = buffer.Write(pkt.data)
		dst := pkt.dst
		releaseUDPRecvBuffer(pkt.buf)
		pkt.data = nil
		pkt.buf = nil
		udpInboundPacketPool.Put(pkt)
		return dst, nil
	}
}

// WriteTo implements net.PacketConn.
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("invalid address type for WriteTo")
	}

	var timer *time.Timer
	var timerCh <-chan time.Time
	if dl := c.writeDeadline.Load(); dl != nil && !dl.IsZero() {
		dur := time.Until(*dl)
		if dur <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(dur)
		defer timer.Stop()
		timerCh = timer.C
	}

	isIPv6 := c.isIPv6
	if udpAddr.IP.To4() == nil && len(udpAddr.IP) == 16 {
		isIPv6 = true
	}

srcIP, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return 0, errors.New("invalid UDP address")
	}
	req := newUDPSendReq(c.id, isIPv6, srcIP, uint16(udpAddr.Port), p)

	select {
	case <-c.closeChan:
		return 0, net.ErrClosed
	case <-c.engine.doneChan:
		return 0, net.ErrClosed
	case <-timerCh:
		return 0, os.ErrDeadlineExceeded
	case c.engine.udpCmdChan <- req:
	}

	select {
	case <-c.closeChan:
		return 0, net.ErrClosed
	case <-c.engine.doneChan:
		return 0, net.ErrClosed
	case <-timerCh:
		return 0, os.ErrDeadlineExceeded
	case err := <-req.doneChan:
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
}

// WritePacket implements sing-tun / sagernet N.PacketConn.
func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	data := buffer.Bytes()
	if len(data) == 0 {
		return nil
	}

	var timer *time.Timer
	var timerCh <-chan time.Time
	if dl := c.writeDeadline.Load(); dl != nil && !dl.IsZero() {
		dur := time.Until(*dl)
		if dur <= 0 {
			return os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(dur)
		defer timer.Stop()
		timerCh = timer.C
	}

req := newUDPSendReq(c.id, destination.Addr.Is6(), destination.Addr, destination.Port, data)

	select {
	case <-c.closeChan:
		return net.ErrClosed
	case <-c.engine.doneChan:
		return net.ErrClosed
	case <-timerCh:
		return os.ErrDeadlineExceeded
	case c.engine.udpCmdChan <- req:
	}

	select {
	case <-c.closeChan:
		return net.ErrClosed
	case <-c.engine.doneChan:
		return net.ErrClosed
	case <-timerCh:
		return os.ErrDeadlineExceeded
	case err := <-req.doneChan:
		return err
	}
}

// Close gracefully closes the PacketConn and releases associated resources.
func (c *PacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeChan)
		for {
			select {
			case pkt := <-c.recvQueue:
				releaseUDPInboundPacket(pkt)
			default:
				c.engine.postUDPClose(c.id)
				return
			}
		}
	})
	return nil
}

// LocalAddr returns the local address (client endpoint in transparent mode).
func (c *PacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the initial target destination address.
func (c *PacketConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// Source returns the initial client address as M.Socksaddr.
func (c *PacketConn) Source() M.Socksaddr {
	return c.source
}

// Destination returns the initial target destination address as M.Socksaddr.
func (c *PacketConn) Destination() M.Socksaddr {
	return c.dest
}

// ID returns the internal connection ID.
func (c *PacketConn) ID() uint64 {
	return c.id
}

// SetDeadline sets both read and write deadlines.
func (c *PacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(&t)
	c.writeDeadline.Store(&t)
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(&t)
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(&t)
	return nil
}

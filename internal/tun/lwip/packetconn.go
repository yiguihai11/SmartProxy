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
}

type udpSendReq struct {
	connID   uint64
	isIPv6   bool
	srcIP    net.IP
	srcPort  uint16
	data     []byte
	doneChan chan error
}

func newUDPSendReq(connID uint64, isIPv6 bool, srcIP net.IP, srcPort uint16, data []byte) *udpSendReq {
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
	srcIP net.IP,
	srcPort uint16,
	dstIP net.IP,
	dstPort uint16,
) *PacketConn {
	sAddr, _ := netip.AddrFromSlice(srcIP)
	dAddr, _ := netip.AddrFromSlice(dstIP)

	return &PacketConn{
		engine:     engine,
		id:         id,
		isIPv6:     isIPv6,
		localAddr:  &net.UDPAddr{IP: srcIP, Port: int(srcPort)},
		remoteAddr: &net.UDPAddr{IP: dstIP, Port: int(dstPort)},
		source:     M.Socksaddr{Addr: sAddr, Port: srcPort},
		dest:       M.Socksaddr{Addr: dAddr, Port: dstPort},
		recvQueue:  make(chan *udpInboundPacket, 256),
		closeChan:  make(chan struct{}),
	}
}

func (c *PacketConn) onData(dstIP net.IP, dstPort uint16, data []byte) {
	if c.closed.Load() {
		return
	}

	dAddr, _ := netip.AddrFromSlice(dstIP)
	pkt := &udpInboundPacket{
		dst:  M.Socksaddr{Addr: dAddr, Port: dstPort},
		data: data,
	}

	select {
	case c.recvQueue <- pkt:
	default:
		// Queue full: drop datagram under extreme congestion
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
		udpAddr := &net.UDPAddr{
			IP:   pkt.dst.Addr.AsSlice(),
			Port: int(pkt.dst.Port),
		}
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
		return pkt.dst, nil
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

	req := newUDPSendReq(c.id, isIPv6, udpAddr.IP, uint16(udpAddr.Port), p)

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

	srcIP := destination.Addr.AsSlice()
	req := newUDPSendReq(c.id, destination.Addr.Is6(), srcIP, destination.Port, data)

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
		c.engine.postUDPClose(c.id)
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

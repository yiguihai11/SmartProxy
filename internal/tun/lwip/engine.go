//go:build with_lwip && cgo

package lwip

/*
#cgo CFLAGS: -I${SRCDIR}/c -I${SRCDIR}/c/arch -I${SRCDIR}/../../../third_party/lwip/src/include -DLWIP_NOASSERT -D_POSIX_C_SOURCE=200809L -Wno-tautological-constant-out-of-range-compare
#include <stdint.h>
#include "c/lwip_adapter.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

var (
	engineMu     sync.RWMutex
	engines      = make(map[uint64]*Engine)
	nextEngineID uint64
)

func registerEngine(e *Engine) uint64 {
	engineMu.Lock()
	defer engineMu.Unlock()
	nextEngineID++
	id := nextEngineID
	engines[id] = e
	return id
}

func unregisterEngine(id uint64) {
	engineMu.Lock()
	defer engineMu.Unlock()
	delete(engines, id)
}

func getEngine(id uint64) *Engine {
	engineMu.RLock()
	defer engineMu.RUnlock()
	return engines[id]
}

// Config configures the lwIP Engine.
type Config struct {
	IPv4       net.IP
	Mask       net.IP
	Gateway    net.IP
	MTU        uint16
	OutputFn   func(packet []byte)
	TCPHandler func(conn net.Conn)
	UDPHandler func(conn *PacketConn)
}

type inPacket struct {
	buf  *[]byte
	data []byte
}

var inPacketPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

// Engine manages the lwIP stack and runs the single owner goroutine.
type Engine struct {
	id        uint64
	cfg       Config
	lw        *C.struct_sp_lwip
	inputChan  chan inPacket
	cmdChan    chan any
	udpCmdChan chan *udpSendReq
	doneChan   chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup

	// conns and udpConns are accessed strictly within the single owner goroutine
	conns    map[uint64]*Conn
	udpConns map[uint64]*PacketConn
}

// NewEngine initializes and starts an lwIP engine.
func NewEngine(cfg Config) (*Engine, error) {
	if cfg.OutputFn == nil {
		return nil, errors.New("OutputFn is required")
	}

	lw := C.sp_lwip_new()
	if lw == nil {
		return nil, errors.New("failed to allocate lwip adapter")
	}

	e := &Engine{
		cfg:        cfg,
		lw:         lw,
		inputChan:  make(chan inPacket, 1024),
		cmdChan:    make(chan any, 1024),
		udpCmdChan: make(chan *udpSendReq, 512),
		doneChan:   make(chan struct{}),
		conns:      make(map[uint64]*Conn),
		udpConns:   make(map[uint64]*PacketConn),
	}

	e.id = registerEngine(e)
	bindGoCallbacks(e.lw, e.id)

	ip := cfg.IPv4
	if ip == nil {
		ip = net.IPv4(10, 0, 0, 2)
	}
	mask := cfg.Mask
	if mask == nil {
		mask = net.IPv4(255, 255, 255, 0)
	}
	gw := cfg.Gateway
	if gw == nil {
		gw = net.IPv4(10, 0, 0, 1)
	}

	ip4 := ip.To4()
	mask4 := mask.To4()
	gw4 := gw.To4()
	if ip4 == nil || mask4 == nil || gw4 == nil {
		unregisterEngine(e.id)
		C.sp_lwip_destroy(e.lw)
		return nil, errors.New("invalid IPv4 address configuration")
	}

	var cIP, cMask, cGW C.ip4_addr_t
	C.sp_set_ip4_addr(&cIP, C.uint8_t(ip4[0]), C.uint8_t(ip4[1]), C.uint8_t(ip4[2]), C.uint8_t(ip4[3]))
	C.sp_set_ip4_addr(&cMask, C.uint8_t(mask4[0]), C.uint8_t(mask4[1]), C.uint8_t(mask4[2]), C.uint8_t(mask4[3]))
	C.sp_set_ip4_addr(&cGW, C.uint8_t(gw4[0]), C.uint8_t(gw4[1]), C.uint8_t(gw4[2]), C.uint8_t(gw4[3]))

	ret := C.sp_lwip_init(e.lw, &cIP, &cMask, &cGW)
	if ret != 0 {
		unregisterEngine(e.id)
		C.sp_lwip_destroy(e.lw)
		return nil, fmt.Errorf("sp_lwip_init failed: %d", int(ret))
	}

	if cfg.MTU > 0 {
		C.sp_lwip_set_mtu(e.lw, C.uint16_t(cfg.MTU))
	}

	e.wg.Add(1)
	go e.loop()
	return e, nil
}

// Input delivers a raw IP packet read from the TUN device to the lwIP stack.
func (e *Engine) Input(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}

	var pkt inPacket
	if len(packet) <= 2048 {
		b := inPacketPool.Get().(*[]byte)
		copy(*b, packet)
		pkt = inPacket{buf: b, data: (*b)[:len(packet)]}
	} else {
		data := make([]byte, len(packet))
		copy(data, packet)
		pkt = inPacket{data: data}
	}

	select {
	case e.inputChan <- pkt:
		return nil
	case <-e.doneChan:
		if pkt.buf != nil {
			inPacketPool.Put(pkt.buf)
		}
		return net.ErrClosed
	default:
		// Queue full: drop packet under congestion (standard IP behavior)
		if pkt.buf != nil {
			inPacketPool.Put(pkt.buf)
		}
		return nil
	}
}

// Close gracefully stops the engine and releases all associated resources.
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		close(e.doneChan)
		e.wg.Wait()
	})
	return nil
}

func (e *Engine) postRecved(connID uint64, n uint32) {
	select {
	case e.cmdChan <- &recvedCmd{connID: connID, len: n}:
	case <-e.doneChan:
	}
}

func (e *Engine) postClose(connID uint64) {
	select {
	case e.cmdChan <- &closeCmd{connID: connID}:
	case <-e.doneChan:
	}
}

func (e *Engine) postAbort(connID uint64) {
	select {
	case e.cmdChan <- &abortCmd{connID: connID}:
	case <-e.doneChan:
	}
}

func (e *Engine) postUDPClose(connID uint64) {
	select {
	case e.cmdChan <- &closeUDPCmd{connID: connID}:
	case <-e.doneChan:
	}
}

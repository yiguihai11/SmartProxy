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
	"time"
	"runtime"
	"unsafe"
)

type recvedCmd struct {
	connID uint64
	len    uint32
}

type closeCmd struct {
	connID uint64
}

type abortCmd struct {
	connID uint64
}

type closeUDPCmd struct {
	connID uint64
}

func (e *Engine) loop() {
	defer e.wg.Done()
	defer func() {
		unregisterEngine(e.id)
		for _, conn := range e.conns {
			for _, req := range conn.pendingWrites {
				req.doneChan <- errConnectionClosed
			}
			conn.pendingWrites = nil
			conn.onErr(errConnectionClosed)
			C.sp_lwip_tcp_abort(e.lw, C.uint64_t(conn.id))
		}
		e.conns = nil

		for _, uconn := range e.udpConns {
			uconn.closed.Store(true)
			uconn.closeOnce.Do(func() { close(uconn.closeChan) })
			C.sp_lwip_udp_close(e.lw, C.uint64_t(uconn.id))
		}
		e.udpConns = nil

		for {
			select {
			case pkt := <-e.inputChan:
				if pkt.buf != nil {
					inPacketPool.Put(pkt.buf)
				}
			default:
				goto drainedInput
			}
		}
	drainedInput:

		for {
			select {
			case req := <-e.udpCmdChan:
				req.doneChan <- errConnectionClosed
			default:
				goto drainedUDPCmd
			}
		}
	drainedUDPCmd:

		C.sp_lwip_destroy(e.lw)
	}()

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-e.doneChan:
			return

		case req := <-e.udpCmdChan:
			e.handleUDPSend(req)
			// Drain ready UDP packets immediately for ultra-low latency gaming & DNS responses
			drainMoreUDP := true
			for i := 0; i < 32 && drainMoreUDP; i++ {
				select {
				case u := <-e.udpCmdChan:
					e.handleUDPSend(u)
				default:
					drainMoreUDP = false
				}
			}

		case pkt := <-e.inputChan:
			e.handleInput(pkt)
			// Drain ready packets
			drainMorePkts := true
			for i := 0; i < 32 && drainMorePkts; i++ {
				select {
				case p := <-e.inputChan:
					e.handleInput(p)
				default:
					drainMorePkts = false
				}
			}

		case cmd := <-e.cmdChan:
			e.handleCmd(cmd)
			// Drain ready commands
			drainMoreCmds := true
			for i := 0; i < 32 && drainMoreCmds; i++ {
				select {
				case c := <-e.cmdChan:
					e.handleCmd(c)
				default:
					drainMoreCmds = false
				}
			}

		case <-ticker.C:
			C.sp_lwip_timers()
		}
	}
}

func (e *Engine) handleInput(pkt inPacket) {
	if len(pkt.data) > 0 {
		C.sp_lwip_input(e.lw, unsafe.Pointer(&pkt.data[0]), C.uint32_t(len(pkt.data)))
	}
	if pkt.buf != nil {
		inPacketPool.Put(pkt.buf)
	}
}

func (e *Engine) handleCmd(cmd any) {
	switch v := cmd.(type) {
	case *writeReq:
		e.handleWriteReq(v)
	case *recvedCmd:
		C.sp_lwip_tcp_recved(e.lw, C.uint64_t(v.connID), C.uint32_t(v.len))
	case *closeCmd:
		e.handleClose(v.connID)
	case *abortCmd:
		e.handleAbort(v.connID)
	case *udpSendReq:
		e.handleUDPSend(v)
	case *closeUDPCmd:
		e.handleUDPClose(v.connID)
	}
}

func (e *Engine) handleWriteReq(req *writeReq) {
	conn := e.conns[req.connID]
	if conn == nil {
		req.doneChan <- errConnectionClosed
		return
	}

	if len(conn.pendingWrites) > 0 {
		conn.pendingWrites = append(conn.pendingWrites, req)
		return
	}

	e.drainWriteReq(conn, req)
}

func (e *Engine) drainWriteReq(conn *Conn, req *writeReq) {
	for len(req.data) > 0 {
		n := C.sp_lwip_tcp_write(
			e.lw,
			C.uint64_t(req.connID),
			unsafe.Pointer(&req.data[0]),
			C.uint32_t(len(req.data)),
		)
		if n > 0 {
			req.written += int(n)
			req.data = req.data[n:]
		} else if n == 0 {
			// Backpressure: tcp_sndbuf is full, wait for onTCPSent
			conn.pendingWrites = append(conn.pendingWrites, req)
			return
		} else {
			req.doneChan <- fmt.Errorf("lwip tcp_write error: %d", int(n))
			return
		}
	}
	req.doneChan <- nil
}

func (e *Engine) handleClose(connID uint64) {
	conn := e.conns[connID]
	if conn != nil {
		delete(e.conns, connID)
		for _, req := range conn.pendingWrites {
			req.doneChan <- errConnectionClosed
		}
		conn.pendingWrites = nil
	}
	C.sp_lwip_tcp_close(e.lw, C.uint64_t(connID))
}

func (e *Engine) handleAbort(connID uint64) {
	conn := e.conns[connID]
	if conn != nil {
		delete(e.conns, connID)
		for _, req := range conn.pendingWrites {
			req.doneChan <- errConnectionClosed
		}
		conn.pendingWrites = nil
	}
	C.sp_lwip_tcp_abort(e.lw, C.uint64_t(connID))
}

func (e *Engine) onPacketOutput(pkt []byte) {
	if e.cfg.OutputFn != nil {
		e.cfg.OutputFn(pkt)
	}
}

func (e *Engine) onTCPAccept(connID uint64, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) {
	remoteAddr := &net.TCPAddr{IP: srcIP.AsSlice(), Port: int(srcPort)}
	localAddr := &net.TCPAddr{IP: dstIP.AsSlice(), Port: int(dstPort)}
	conn := newConn(e, connID, remoteAddr, localAddr)
	e.conns[connID] = conn

	if e.cfg.TCPHandler != nil {
		go e.cfg.TCPHandler(conn)
	}
}

func (e *Engine) onTCPRecv(connID uint64, data []byte) {
	conn := e.conns[connID]
	if conn == nil {
		return
	}
	if data == nil {
		conn.onEOF()
		return
	}
	conn.onData(data)
}

func (e *Engine) onTCPSent(connID uint64, length uint16) {
	conn := e.conns[connID]
	if conn == nil || len(conn.pendingWrites) == 0 {
		return
	}

	for len(conn.pendingWrites) > 0 {
		req := conn.pendingWrites[0]
		for len(req.data) > 0 {
			n := C.sp_lwip_tcp_write(
				e.lw,
				C.uint64_t(req.connID),
				unsafe.Pointer(&req.data[0]),
				C.uint32_t(len(req.data)),
			)
			if n > 0 {
				req.written += int(n)
				req.data = req.data[n:]
			} else if n == 0 {
				// Buffer full again
				return
			} else {
				req.doneChan <- fmt.Errorf("lwip tcp_write error: %d", int(n))
				conn.pendingWrites = conn.pendingWrites[1:]
				return
			}
		}
		req.doneChan <- nil
		conn.pendingWrites = conn.pendingWrites[1:]
	}
}

func (e *Engine) onTCPErr(connID uint64, errCode int) {
	conn := e.conns[connID]
	if conn == nil {
		return
	}
	delete(e.conns, connID)

	err := fmt.Errorf("lwip tcp error: %d", errCode)
	for _, req := range conn.pendingWrites {
		req.doneChan <- err
	}
	conn.pendingWrites = nil
	conn.onErr(err)
}

func (e *Engine) handleUDPSend(req *udpSendReq) {
	if len(req.data) == 0 {
		req.doneChan <- nil
		return
	}
	isIPv6 := 0
	var srcIPBytes []byte
	if req.isIPv6 {
		isIPv6 = 1
		if !req.srcIP.Is6() {
			req.doneChan <- errors.New("invalid IPv6 address in UDP send")
			return
		}
		srcIP4 := req.srcIP.As16()
		srcIPBytes = srcIP4[:]
	} else {
		if !req.srcIP.Is4() {
			req.doneChan <- errors.New("invalid IPv4 address in UDP send")
			return
		}
		srcIP4 := req.srcIP.As4()
		srcIPBytes = srcIP4[:]
	}

	var pinner runtime.Pinner
	pinner.Pin(&req.data[0])
	ret := C.sp_lwip_udp_send(
		e.lw,
		C.uint64_t(req.connID),
		C.int(isIPv6),
		unsafe.Pointer(&srcIPBytes[0]),
		C.uint16_t(req.srcPort),
		unsafe.Pointer(&req.data[0]),
		C.uint32_t(len(req.data)),
	)
	pinner.Unpin()
	runtime.KeepAlive(req.data)
	if ret < 0 {
		req.doneChan <- fmt.Errorf("lwip udp_send error: %d", int(ret))
		return
	}
	req.doneChan <- nil
}

func (e *Engine) handleUDPClose(connID uint64) {
	delete(e.udpConns, connID)
	C.sp_lwip_udp_close(e.lw, C.uint64_t(connID))
}

func (e *Engine) onUDPRecv(connID uint64, isIPv6 bool, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, data []byte, dataBuf *[]byte) {
	conn := e.udpConns[connID]
	if conn == nil {
		conn = newPacketConn(e, connID, isIPv6, srcIP, srcPort, dstIP, dstPort)
		e.udpConns[connID] = conn
		if e.cfg.UDPHandler != nil {
			go e.cfg.UDPHandler(conn)
		}
	}
	conn.onData(dstIP, dstPort, data, dataBuf)
}

//go:build with_lwip && cgo

package lwip

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

var (
	errConnectionClosed = net.ErrClosed
)

type writeReq struct {
	connID   uint64
	data     []byte
	written  int
	doneChan chan error
}

var writeReqPool = sync.Pool{
	New: func() any {
		return &writeReq{
			doneChan: make(chan error, 1),
		}
	},
}

func acquireWriteReq(connID uint64, data []byte) *writeReq {
	req := writeReqPool.Get().(*writeReq)
	req.connID = connID
	req.data = data
	req.written = 0
	return req
}

func releaseWriteReq(req *writeReq) {
	if req == nil {
		return
	}
	req.data = nil
	req.written = 0
	select {
	case <-req.doneChan:
	default:
	}
	writeReqPool.Put(req)
}

// Conn represents a TCP connection accepted by the lwIP stack, implementing net.Conn.
type Conn struct {
	id         uint64
	engine     *Engine
	remoteAddr net.Addr // client
	localAddr  net.Addr // target

	mu       sync.Mutex
	readCond *sync.Cond
	recvBuf  []byte
	recvOff  int
	readErr  error
	eof      bool
	closed     bool
	lingerZero bool

	closeChan chan struct{}

	writeMu  sync.Mutex
	writeErr error

	readDeadline  time.Time
	writeDeadline time.Time
	readTimer     *time.Timer

	// pendingWrites is manipulated ONLY by the Engine owner goroutine
	pendingWrites []*writeReq
}

func newConn(engine *Engine, id uint64, remoteAddr, localAddr net.Addr) *Conn {
	c := &Conn{
		id:         id,
		engine:     engine,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
		closeChan:  make(chan struct{}),
	}
	c.readCond = sync.NewCond(&c.mu)
	return c
}

func (c *Conn) ID() uint64 {
	return c.id
}

func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetNoDelay implements the standard TCPConn SetNoDelay interface method.
func (c *Conn) SetNoDelay(noDelay bool) error {
	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		if c.closed {
			return 0, errConnectionClosed
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
		avail := len(c.recvBuf) - c.recvOff
		if avail > 0 {
			n := copy(b, c.recvBuf[c.recvOff:])
			c.recvOff += n
			if c.recvOff >= len(c.recvBuf) {
				c.recvBuf = c.recvBuf[:0]
				c.recvOff = 0
			}
			// Notify lwIP to advance receive window
			c.engine.postRecved(c.id, uint32(n))
			return n, nil
		}
		if c.eof {
			return 0, io.EOF
		}
		if !c.readDeadline.IsZero() && time.Now().After(c.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}

		c.readCond.Wait()
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, errConnectionClosed
	}
	if c.writeErr != nil {
		err := c.writeErr
		c.mu.Unlock()
		return 0, err
	}
	deadline := c.writeDeadline
	c.mu.Unlock()

	req := acquireWriteReq(c.id, b)

	select {
	case c.engine.cmdChan <- req:
	case <-c.closeChan:
		releaseWriteReq(req)
		return 0, errConnectionClosed
	case <-c.engine.doneChan:
		releaseWriteReq(req)
		return 0, errConnectionClosed
	}

	var deadlineChan <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			releaseWriteReq(req)
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		deadlineChan = timer.C
	}

	select {
	case err := <-req.doneChan:
		written := req.written
		releaseWriteReq(req)
		if err != nil {
			return written, err
		}
		return len(b), nil
	case <-deadlineChan:
		return req.written, os.ErrDeadlineExceeded
	case <-c.closeChan:
		return req.written, errConnectionClosed
	case <-c.engine.doneChan:
		return req.written, errConnectionClosed
	}
}

// SetLinger configures whether Close() should abort the connection with a TCP RST segment.
// Setting sec == 0 causes subsequent Close() to emit a TCP RST instead of FIN.
func (c *Conn) SetLinger(sec int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lingerZero = (sec == 0)
	return nil
}

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.recvBuf = nil
	c.recvOff = 0
	isLingerZero := c.lingerZero
	close(c.closeChan)
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	c.readCond.Broadcast()
	c.mu.Unlock()

	if isLingerZero {
		c.engine.postAbort(c.id)
	} else {
		c.engine.postClose(c.id)
	}
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.readDeadline = t
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	if !t.IsZero() {
		d := time.Until(t)
		if d <= 0 {
			c.readCond.Broadcast()
			return nil
		}
		c.readTimer = time.AfterFunc(d, func() {
			c.mu.Lock()
			c.readCond.Broadcast()
			c.mu.Unlock()
		})
	}
	c.readCond.Broadcast()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

// Internal callbacks invoked from Engine owner goroutine

func (c *Conn) onData(b []byte) {
	c.mu.Lock()
	if c.recvOff >= len(c.recvBuf) {
		c.recvBuf = c.recvBuf[:0]
		c.recvOff = 0
	} else if c.recvOff > 0 && c.recvOff >= len(c.recvBuf)/2 {
		n := copy(c.recvBuf, c.recvBuf[c.recvOff:])
		c.recvBuf = c.recvBuf[:n]
		c.recvOff = 0
	}
	c.recvBuf = append(c.recvBuf, b...)
	c.readCond.Signal()
	c.mu.Unlock()
}

func (c *Conn) onEOF() {
	c.mu.Lock()
	c.eof = true
	c.readCond.Broadcast()
	c.mu.Unlock()
}

func (c *Conn) onErr(err error) {
	c.mu.Lock()
	if c.readErr == nil {
		c.readErr = err
	}
	if c.writeErr == nil {
		c.writeErr = err
	}
	c.readCond.Broadcast()
	c.mu.Unlock()
}

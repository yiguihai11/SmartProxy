package relay

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"smartproxy/internal/safego"
)

var (
	ActiveConns     atomic.Int32
	ProxyBytesUp    atomic.Int64
	ProxyBytesDown  atomic.Int64
	DirectBytesUp   atomic.Int64
	DirectBytesDown atomic.Int64
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

var UDPBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 65535)
		return &buf
	},
}

var PacketPool = sync.Pool{
	New: func() interface{} {
		// UDP 报文最大载荷 65507 字节;4KB 缓冲会截断大 EDNS0 DNS 响应。
		buf := make([]byte, 65535)
		return &buf
	},
}

// TCPRelay forwards traffic in both directions. prefix is the leading byte already
// consumed from the remote side that must be replayed first in the r2c direction
// (the 1 byte read during smart-direct direct connection validation); paths without
// a prefix pass nil.
func TCPRelay(ctx context.Context, client, remote net.Conn, proxy bool, prefix []byte) {
	var wg sync.WaitGroup
	wg.Add(2)

	safego.Go("relay.tcp.c2r", func() {
		defer wg.Done()
		relayDirection(ctx, remote, client, "c2r", proxy, nil)
	})

	safego.Go("relay.tcp.r2c", func() {
		defer wg.Done()
		relayDirection(ctx, client, remote, "r2c", proxy, prefix)
	})

	done := make(chan struct{})
	safego.Go("relay.tcp.wait", func() {
		wg.Wait()
		close(done)
	})

	select {
	case <-done:
		slog.Debug("TCP relay finished")
	case <-ctx.Done():
		slog.Debug("TCP relay cancelled by context", "error", ctx.Err())
		client.Close()
		remote.Close()
		wg.Wait()
	}
}

// tcpSplice uses the internal splice optimization of the Go standard library to
// implement zero-copy TCP→TCP forwarding. dst.ReadFrom(src) in Go 1.25 automatically
// uses splice(2) internally when both arguments are *net.TCPConn, and correctly
// handles deadlines and connection closure.
func tcpSplice(dst, src *net.TCPConn) (int64, bool) {
	n, err := dst.ReadFrom(src)
	if n > 0 {
		return n, true
	}
	if err != nil && err != io.EOF {
		return 0, false
	}
	return 0, true
}

func relayDirection(ctx context.Context, dst, src net.Conn, direction string, proxy bool, prefix []byte) {
	total := int64(0)
	var err error

	// The leading byte already read from src during direct-connection validation;
	// write it back to dst first, then continue with splice/copy
	if len(prefix) > 0 {
		wn, werr := dst.Write(prefix)
		total += int64(wn)
		if werr != nil || wn != len(prefix) {
			slog.Debug(direction+" relay prefix write failed", "error", werr)
			goto done
		}
	}

	// For TCP→TCP, first try zero-copy splice
	if tcpDst, ok := dst.(*net.TCPConn); ok {
		if tcpSrc, ok := src.(*net.TCPConn); ok {
			if n, ok := tcpSplice(tcpDst, tcpSrc); ok {
				total += n
				goto done
			}
		}
	}

	// Fall back to a buffered copy when splice conditions are not met or it fails
	{
		buf := bufferPool.Get().([]byte)
		m, cerr := io.CopyBuffer(dst, src, buf)
		bufferPool.Put(buf)
		total += m
		err = cerr
	}
	if err != nil && err != io.EOF {
		slog.Debug(direction+" relay error", "error", err)
	}

done:
	if total > 0 {
		if direction == "c2r" {
			if proxy {
				ProxyBytesUp.Add(total)
			} else {
				DirectBytesUp.Add(total)
			}
		} else {
			if proxy {
				ProxyBytesDown.Add(total)
			} else {
				DirectBytesDown.Add(total)
			}
		}
	}

	if tcpDst, ok := dst.(*net.TCPConn); ok {
		tcpDst.CloseWrite()
	}
	if tcpSrc, ok := src.(*net.TCPConn); ok {
		tcpSrc.CloseRead()
	}
}

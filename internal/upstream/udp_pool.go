package upstream

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

type poolEntry struct {
	conn      *UDPProxyConn
	createdAt time.Time
}

type UDPAssociatePool struct {
	mu      sync.Mutex
	conns   []*poolEntry
	maxSize int
}

func NewUDPAssociatePool(maxSize int) *UDPAssociatePool {
	if maxSize <= 0 {
		maxSize = 4
	}
	return &UDPAssociatePool{
		maxSize: maxSize,
	}
}

func (p *UDPAssociatePool) Acquire(
	ctx context.Context,
	host string, port int,
	provider func(context.Context, string, int) (*UDPProxyConn, error),
) (*UDPProxyConn, error) {

	for i := 0; i < 10; i++ {
		p.mu.Lock()
		if n := len(p.conns); n > 0 {
			entry := p.conns[n-1]
			p.conns = p.conns[:n-1]
			p.mu.Unlock()

			// TTL eviction: a connection older than 15s has likely been closed by the proxy side
			if time.Since(entry.createdAt) > 15*time.Second {
				slog.Debug("udp pool: TTL expired, discarding",
					"age", time.Since(entry.createdAt))
				entry.conn.Close()
				continue
			}

			// Quick TCP control-connection probe (5ms): verify the proxy is still alive
			entry.conn.tcpConn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
			_, probeErr := entry.conn.tcpConn.Read(make([]byte, 1))
			if probeErr != nil {
				if netErr, ok := probeErr.(net.Error); ok && netErr.Timeout() {
					// Timeout = TCP connection is healthy (no data on the control channel is expected)
					entry.conn.UDPConn.SetDeadline(time.Time{})
					entry.conn.tcpConn.SetDeadline(time.Time{})
					slog.Debug("udp pool: acquired from pool",
						"createdAt", entry.createdAt.Format(time.RFC3339))
					return entry.conn, nil
				}
				// Any other error = the connection is dead
				slog.Debug("udp pool: TCP probe failed, discarding",
					"error", probeErr)
				entry.conn.Close()
				continue
			}
			// The control channel should not carry data; if it does, something is wrong
			slog.Debug("udp pool: unexpected data on control channel, discarding")
			entry.conn.Close()
			continue
		}
		p.mu.Unlock()

		slog.Debug("udp pool: pool empty, creating new connection")
		conn, err := provider(ctx, host, port)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	slog.Warn("udp pool: too many stale connections, creating new anyway")
	return provider(ctx, host, port)
}

func (p *UDPAssociatePool) Release(conn *UDPProxyConn) {
	if conn == nil {
		return
	}

	conn.UDPConn.SetDeadline(time.Time{})
	conn.tcpConn.SetDeadline(time.Time{})

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns) < p.maxSize {
		p.conns = append(p.conns, &poolEntry{
			conn:      conn,
			createdAt: time.Now(),
		})
		slog.Debug("udp pool: returned to pool", "poolSize", len(p.conns))
	} else {
		slog.Debug("udp pool: pool full, closing connection")
		conn.Close()
	}
}

func (p *UDPAssociatePool) Discard(conn *UDPProxyConn) {
	if conn == nil {
		return
	}
	slog.Debug("udp pool: discarding connection")
	conn.Close()
}

func (p *UDPAssociatePool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, entry := range p.conns {
		entry.conn.Close()
	}
	p.conns = nil
	slog.Debug("udp pool: closed")
}

func (p *UDPAssociatePool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

package upstream

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

type poolEntry struct {
	conn      net.Conn
	createdAt time.Time
}

// tcpProbeConn 是池里可选实现的活性探测接口。SOCKS5 UDP ASSOCIATE 连接用它探测
// TCP 控制信道;ss UDP / 裸 UDP 没有控制信道,直接视为健康(TTL 淘汰兜底)。
type tcpProbeConn interface {
	ProbeTCP() error
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
	provider func(context.Context, string, int) (net.Conn, error),
) (net.Conn, error) {

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

			// Liveness probe (SOCKS5: 5ms TCP control-channel probe; others: no-op)
			alive := true
			if probe, ok := entry.conn.(tcpProbeConn); ok {
				if err := probe.ProbeTCP(); err != nil {
					alive = false
					slog.Debug("udp pool: probe failed, discarding",
						"error", err)
					entry.conn.Close()
					continue
				}
			}
			if alive {
				slog.Debug("udp pool: acquired from pool",
					"createdAt", entry.createdAt.Format(time.RFC3339))
				return entry.conn, nil
			}
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

func (p *UDPAssociatePool) Release(conn net.Conn) {
	if conn == nil {
		return
	}

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

func (p *UDPAssociatePool) Discard(conn net.Conn) {
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

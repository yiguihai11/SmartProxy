package socks5

import (
	"sync"
)

// BufferPool 字节切片对象池
type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool 创建新的缓冲区池
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
	}
}

// Get 从池中获取缓冲区
func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put 将缓冲区放回池中
func (p *BufferPool) Put(buf []byte) {
	// 只放回正确大小的缓冲区
	if cap(buf) == 4096 {
		p.pool.Put(buf[:4096])
	}
}

// ConnectionPool 连接对象池
type ConnectionPool struct {
	pool sync.Pool
}

// NewConnectionPool 创建连接对象池
func NewConnectionPool() *ConnectionPool {
	return &ConnectionPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &Connection{}
			},
		},
	}
}

// Get 从池中获取连接对象
func (p *ConnectionPool) Get() *Connection {
	return p.pool.Get().(*Connection)
}

// Put 将连接对象放回池中（需要重置）
func (p *ConnectionPool) Put(conn *Connection) {
	// 重置连接对象状态
	conn.clientConn = nil
	conn.targetConn = nil
	conn.username = ""
	conn.targetAddr = ""
	conn.targetHost = ""
	conn.detectedHost = ""
	conn.protocol = ""

	p.pool.Put(conn)
}

// 全局对象池
var (
	// 数据缓冲区池
	bufferPool = NewBufferPool(4096)

	// 连接对象池
	connectionPool = NewConnectionPool()
)

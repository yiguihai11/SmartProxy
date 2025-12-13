package socks5

import (
	"sync"
	"time"
)

// MultiSizeBufferPool 多尺寸缓冲区池
type BufferPool struct {
	pools map[int]*sync.Pool
	sizes []int
	mu    sync.RWMutex
	stats *PoolStats
}

// NewBufferPool 创建多尺寸缓冲区池
func NewBufferPool() *BufferPool {
	sizes := []int{
		64,    // 64B  - 小包头
		256,   // 256B - HTTP头
		1024,  // 1KB  - 小数据包
		4096,  // 4KB  - 默认大小
		8192,  // 8KB  - 中等数据
		16384, // 16KB - 大数据
		32768, // 32KB - 视频包
		65536, // 64KB - 最大缓冲区
	}

	pool := &BufferPool{
		pools: make(map[int]*sync.Pool),
		sizes: sizes,
		mu:    sync.RWMutex{},
		stats: &PoolStats{
			MaxPoolSize: int64(len(sizes)),
			LastAccess:  time.Now(),
		},
	}

	for _, size := range sizes {
		size := size // 创建新的变量
		pool.pools[size] = &sync.Pool{
			New: func() interface{} {
				pool.stats.mutex.Lock()
				pool.stats.PooledObjects++
				pool.stats.PoolMemoryUsed += int64(size)
				pool.stats.mutex.Unlock()
				return make([]byte, size)
			},
		}
	}

	// 注册到全局内存监控器
	if monitor := GetGlobalMemoryMonitor(); monitor != nil {
		monitor.RegisterPoolStats("buffer_pool", pool.stats)
	}

	return pool
}

// Get 获取合适大小的缓冲区
func (p *BufferPool) Get(size int) []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// 更新统计
	p.stats.mutex.Lock()
	p.stats.TotalRequests++
	p.stats.LastAccess = time.Now()
	p.stats.mutex.Unlock()

	// 找到最接近的更大尺寸
	for _, poolSize := range p.sizes {
		if size <= poolSize {
			if pool, ok := p.pools[poolSize]; ok {
				p.stats.mutex.Lock()
				p.stats.Hits++
				p.stats.ActiveObjects++
				p.stats.TotalMemoryUsed += int64(poolSize)
				p.stats.mutex.Unlock()
				return pool.Get().([]byte)
			}
		}
	}

	// 超过最大尺寸，直接创建
	p.stats.mutex.Lock()
	p.stats.Misses++
	p.stats.ActiveObjects++
	p.stats.TotalMemoryUsed += int64(size)
	p.stats.mutex.Unlock()

	return make([]byte, size)
}

// Put 归还缓冲区
func (p *BufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	size := cap(buf)
	p.mu.RLock()
	defer p.mu.RUnlock()

	p.stats.mutex.Lock()
	p.stats.ActiveObjects-- // 活跃对象减少
	p.stats.mutex.Unlock()

	if pool, ok := p.pools[size]; ok {
		// 归还到对应尺寸的池
		pool.Put(buf[:size])
	} else {
		// 不在池中的缓冲区，标记为池内存释放
		p.stats.mutex.Lock()
		if p.stats.PoolMemoryUsed >= int64(size) {
			p.stats.PoolMemoryUsed -= int64(size)
		}
		p.stats.mutex.Unlock()
	}
}

// GetStats 获取缓冲区池统计信息
func (p *BufferPool) GetStats() *PoolStats {
	p.stats.mutex.RLock()
	defer p.stats.mutex.RUnlock()

	// 返回统计信息的深拷贝
	return &PoolStats{
		ActiveObjects:   p.stats.ActiveObjects,
		PooledObjects:   p.stats.PooledObjects,
		TotalRequests:   p.stats.TotalRequests,
		Hits:            p.stats.Hits,
		Misses:          p.stats.Misses,
		Evictions:       p.stats.Evictions,
		TotalMemoryUsed: p.stats.TotalMemoryUsed,
		PoolMemoryUsed:  p.stats.PoolMemoryUsed,
		MaxPoolSize:     p.stats.MaxPoolSize,
		LastAccess:      p.stats.LastAccess,
	}
}

// Cleanup 清理长时间未使用的缓冲区
func (p *BufferPool) Cleanup(maxIdleTime time.Duration) int {
	cleaned := 0
	now := time.Now()

	// 目前Go的sync.Pool没有提供清理机制
	// 这里只是记录日志，实际清理需要依赖GC
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, pool := range p.pools {
		// 理论上可以通过创建新对象并让旧对象被GC回收来"清理"
		// 但sync.Pool的设计是不需要手动清理的
		if now.Sub(p.stats.LastAccess) > maxIdleTime {
			// 记录需要清理的池
			_ = pool
			cleaned++
		}
	}

	return cleaned
}

// GetHitRate 获取命中率
func (p *BufferPool) GetHitRate() float64 {
	p.stats.mutex.RLock()
	defer p.stats.mutex.RUnlock()

	if p.stats.TotalRequests == 0 {
		return 0
	}
	return float64(p.stats.Hits) / float64(p.stats.TotalRequests) * 100
}

// ConnectionPoolStats 连接池统计信息
type ConnectionPoolStats struct {
	ActiveConnections int64     // 当前活跃连接数
	PooledConnections int64     // 池中连接数
	TotalRequests     int64     // 总请求次数
	Hits              int64     // 命中次数
	Misses            int64     // 未命中次数
	CreatedConnections int64    // 新创建连接数
	ReusedConnections  int64    // 重用连接数
	LastAccess        time.Time // 最后访问时间
	mutex             sync.RWMutex
}

// ConnectionPool 连接对象池
type ConnectionPool struct {
	pool  sync.Pool
	stats *ConnectionPoolStats
}

// NewConnectionPool 创建连接对象池
func NewConnectionPool() *ConnectionPool {
	stats := &ConnectionPoolStats{
		LastAccess: time.Now(),
	}

	pool := &ConnectionPool{
		pool: sync.Pool{
			New: func() interface{} {
				stats.mutex.Lock()
				stats.CreatedConnections++
				stats.PooledConnections++
				stats.mutex.Unlock()
				return &Connection{}
			},
		},
		stats: stats,
	}

	// 注册到全局内存监控器
	if monitor := GetGlobalMemoryMonitor(); monitor != nil {
		monitor.RegisterPoolStats("connection_pool", &PoolStats{
			ActiveObjects:   stats.ActiveConnections,
			PooledObjects:   stats.PooledConnections,
			TotalRequests:   stats.TotalRequests,
			Hits:            stats.Hits,
			Misses:          stats.Misses,
			TotalMemoryUsed: 0, // 连接对象的内存使用量难以精确计算
			PoolMemoryUsed:  0,
			MaxPoolSize:     100, // 默认最大池大小
			LastAccess:      stats.LastAccess,
		})
	}

	return pool
}

// Get 从池中获取连接对象
func (p *ConnectionPool) Get() *Connection {
	p.stats.mutex.Lock()
	p.stats.TotalRequests++
	p.stats.ActiveConnections++
	p.stats.LastAccess = time.Now()
	p.stats.mutex.Unlock()

	// 尝试从池中获取
	conn := p.pool.Get().(*Connection)

	// 检查是否是新创建的连接
	if conn.clientConn == nil && conn.targetConn == nil {
		p.stats.mutex.Lock()
		p.stats.Misses++
		p.stats.mutex.Unlock()
	} else {
		p.stats.mutex.Lock()
		p.stats.Hits++
		p.stats.ReusedConnections++
		p.stats.mutex.Unlock()
	}

	return conn
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

	p.stats.mutex.Lock()
	p.stats.ActiveConnections-- // 活跃连接减少
	p.stats.mutex.Unlock()

	p.pool.Put(conn)
}

// GetConnectionStats 获取连接池统计信息
func (p *ConnectionPool) GetConnectionStats() *ConnectionPoolStats {
	p.stats.mutex.RLock()
	defer p.stats.mutex.RUnlock()

	// 返回统计信息的深拷贝
	return &ConnectionPoolStats{
		ActiveConnections: p.stats.ActiveConnections,
		PooledConnections: p.stats.PooledConnections,
		TotalRequests:     p.stats.TotalRequests,
		Hits:              p.stats.Hits,
		Misses:            p.stats.Misses,
		CreatedConnections: p.stats.CreatedConnections,
		ReusedConnections:  p.stats.ReusedConnections,
		LastAccess:        p.stats.LastAccess,
	}
}

// GetConnectionHitRate 获取连接池命中率
func (p *ConnectionPool) GetConnectionHitRate() float64 {
	p.stats.mutex.RLock()
	defer p.stats.mutex.RUnlock()

	if p.stats.TotalRequests == 0 {
		return 0
	}
	return float64(p.stats.Hits) / float64(p.stats.TotalRequests) * 100
}

// GetReuseRate 获取连接重用率
func (p *ConnectionPool) GetReuseRate() float64 {
	p.stats.mutex.RLock()
	defer p.stats.mutex.RUnlock()

	if p.stats.CreatedConnections == 0 {
		return 0
	}
	return float64(p.stats.ReusedConnections) / float64(p.stats.CreatedConnections) * 100
}

// 全局便利函数

// GetBuffer 获取合适大小的缓冲区
func GetBuffer(size int) []byte {
	return bufferPool.Get(size)
}

// PutBuffer 归还缓冲区
func PutBuffer(buf []byte) {
	bufferPool.Put(buf)
}

// 全局对象池
var (
	// 多尺寸数据缓冲区池
	bufferPool = NewBufferPool()

	// 连接对象池
	connectionPool = NewConnectionPool()
)

// 全局池统计访问函数

// GetBufferPoolStats 获取全局缓冲区池统计信息
func GetBufferPoolStats() *PoolStats {
	return bufferPool.GetStats()
}

// GetBufferPoolHitRate 获取全局缓冲区池命中率
func GetBufferPoolHitRate() float64 {
	return bufferPool.GetHitRate()
}

// GetConnectionPoolStats 获取全局连接池统计信息
func GetConnectionPoolStats() *ConnectionPoolStats {
	return connectionPool.GetConnectionStats()
}

// GetConnectionHitRate 获取全局连接池命中率
func GetConnectionHitRate() float64 {
	return connectionPool.GetConnectionHitRate()
}

// GetConnectionReuseRate 获取全局连接池重用率
func GetConnectionReuseRate() float64 {
	return connectionPool.GetReuseRate()
}

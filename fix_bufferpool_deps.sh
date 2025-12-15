#!/bin/bash

echo "修复 BufferPool 对 MemoryMonitor 的依赖"
echo "====================================="

# 1. 备份原始文件
cp socks5/pool.go socks5/pool.go.backup
echo "✓ 已备份 pool.go"

# 2. 从 pool.go 中移除 MemoryMonitor 相关的引用
echo ""
echo "移除 MemoryMonitor 相关代码..."

# 使用 sed 移除相关代码行
sed -i '/stats \*PoolStats/d' socks5/pool.go
sed -i '/stats: &PoolStats{/,/},/d' socks5/pool.go
sed -i '/RegisterPoolStats/d' socks5/pool.go
sed -i '/GetGlobalMemoryMonitor/d' socks5/pool.go

# 3. 移除未使用的方法
echo ""
echo "移除未使用的方法..."

# 移除 GetBufferPoolHitRate 方法
sed -i '/func (p \*BufferPool) GetBufferPoolHitRate/,/^}/d' socks5/pool.go

# 移除 PutBuffer 方法
sed -i '/func (p \*BufferPool) PutBuffer/,/^}/d' socks5/pool.go

# 4. 移除 stats 相关的更新代码
echo ""
echo "移除 stats 更新代码..."

# 移除 stats.Lock/Unlock 相关的代码
sed -i '/pool.stats.mutex.Lock()/,/pool.stats.mutex.Unlock()/d' socks5/pool.go

# 5. 编译测试
echo ""
echo "编译测试..."
make build-force

if [ $? -eq 0 ]; then
    echo "✓ 修复成功，编译通过"
    echo ""
    echo "已执行的操作："
    echo "  - 移除了 BufferPool 对 MemoryMonitor 的依赖"
    echo "  - 移除了未使用的方法：GetBufferPoolHitRate, PutBuffer"
    echo "  - 移除了 stats 统计相关代码"
else
    echo "✗ 修复失败，恢复备份文件"
    cp socks5/pool.go.backup socks5/pool.go
fi

echo ""
echo "修复完成！"
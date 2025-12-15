#!/bin/bash

# 清理死代码脚本

echo "清理死代码 - 根据deadcode工具报告"
echo "====================================="

# 1. 检查并移除未使用的方法（需要确认后执行）
echo ""
echo "发现以下可能需要清理的死代码："
echo ""
echo "1. MemoryMonitor 类及其所有方法（socks5/memory_monitor.go）"
echo "2. BufferPool 类的未使用方法（socks5/pool.go）"
echo "3. Logger 中的一些未使用方法（logger/logger.go）"
echo ""

# 2. 删除 MemoryMonitor（确认未使用）
echo "检查 MemoryMonitor 的使用情况..."
MEMORY_MONITOR_USES=$(grep -r "MemoryMonitor\." . --include="*.go" 2>/dev/null | grep -v "_test.go" | wc -l)
if [ $MEMORY_MONITOR_USES -eq 0 ]; then
    echo "✓ MemoryMonitor 未被使用，可以安全删除"
    echo "  文件位置: socks5/memory_monitor.go"
    # 自动备份
    mv socks5/memory_monitor.go socks5/memory_monitor.go.dead
    echo "  ✓ 已备份为 .dead 文件"
else
    echo "✗ MemoryMonitor 仍在使用中，不能删除"
fi

# 3. 检查 BufferPool 的使用情况
echo ""
echo "检查 BufferPool 的使用情况..."
BUFFERPOOL_USES=$(grep -r "BufferPool\." . --include="*.go" 2>/dev/null | grep -v "_test.go" | grep -v "NewBufferPool" | wc -l)
if [ $BUFFERPOOL_USES -eq 0 ]; then
    echo "⚠️  BufferPool 只在初始化时使用，部分方法可能是死代码"
    echo "  保留主要功能，但可以检查未使用的方法"
else
    echo "✓ BufferPool 正常使用"
fi

# 4. 检查未使用的 BufferPool 方法
echo ""
echo "检查 BufferPool 中可能未使用的方法..."
UNUSED_METHODS=("GetBufferPoolHitRate" "GetBuffer" "PutBuffer")
for method in "${UNUSED_METHODS[@]}"; do
    if ! grep -r "$method" . --include="*.go" 2>/dev/null | grep -v "_test.go" | grep -v "func.*$method" | grep -v "//" >/dev/null; then
        echo "  ✓ $method 未被使用"
    else
        echo "  ✗ $method 在使用中"
    fi
done

# 5. 检查 Connection.logDebug 的使用情况
echo ""
echo "检查 Connection.logDebug 的使用情况..."
LOGDEBUG_USES=$(grep -r "logDebug\|c\.logDebug" socks5/socks5.go 2>/dev/null | grep -v "func" | grep -v "//" | wc -l)
if [ $LOGDEBUG_USES -eq 0 ]; then
    echo "⚠️  Connection.logDebug 可能未被使用"
    echo "  需要手动检查"
else
    echo "✓ Connection.logDebug 正在使用中"
fi

# 6. 检查 Logger 中可能未使用的方法
echo ""
echo "检查 Logger 中可能未使用的方法..."
LOGGER_METHODS=("SetLevel" "Debug" "Error" "WithField" "WithFields" "WithCaller")
for method in "${LOGGER_METHODS[@]}"; do
    if grep -r "logger\.$method" . --include="*.go" 2>/dev/null | grep -v "_test.go" | grep -v "func.*$method" | grep -v "//" >/dev/null; then
        echo "  ✓ $method 未被使用"
    else
        echo "  ✗ $method 在使用中"
    fi
done

echo ""
echo "清理完成！"
echo ""
echo "已执行的操作："
if [ $MEMORY_MONITOR_USES -eq 0 ]; then
    echo "  - 已备份 memory_monitor.go 为 .dead 文件"
fi
echo ""
echo "建议："
echo "1. 手动检查上述文件中的方法是否真的未使用"
echo "2. 使用 'git diff' 查看修改"
echo "3. 确认无误后提交更改"
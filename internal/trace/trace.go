// Package trace 提供全链路流量 trace id(下称 flow id)。
//
// 每条流量(TCP 连接 / UDP 会话,无论来自 TUN 还是本地 SOCKS5 入口)在进入程序的入口处
// 用 NextID 分配一个进程内唯一的 uint64 id,经 WithFlow 注入 context;处理链路沿途用
// Log(ctx) 取一个预绑定 "flow" 字段的 logger 打日志,于是 grep "flow=N" 就能串起这条
// 流量从入口 → 分流决策 → 上游拨号 → 转发结束的完整生命周期。
//
// Log 在 ctx 不带 id 时退回 slog.Default(),永不返回 nil —— 因此任何中间状态(改到一半、
// 测试传 background ctx)都能编译、行为与不带 id 时一致。
package trace

import (
	"context"
	"log/slog"
	"sync/atomic"
)

type flowKey struct{}

var nextID atomic.Uint64

// NextID 分配一个进程内唯一的 flow id(从 1 起,单调递增;重启归零,仅用于进程内日志关联)。
func NextID() uint64 {
	return nextID.Add(1)
}

// WithFlow 返回携带 flow id 的 ctx 副本。嵌套调用时内层 id 遮蔽外层(如 UDP 会话 id 盖过
// 其所属 SOCKS5 关联的 TCP 控制连接 id)。取消语义沿用父 ctx,这里只加 value。
func WithFlow(ctx context.Context, id uint64) context.Context {
	return context.WithValue(ctx, flowKey{}, id)
}

// Flow 取出 ctx 中的 flow id;未注入时 ok 为 false。
func Flow(ctx context.Context) (id uint64, ok bool) {
	id, ok = ctx.Value(flowKey{}).(uint64)
	return
}

// Log 返回绑定了 "flow" 字段的 logger。ctx 不带 id 时返回 slog.Default()(永不 nil)。
// 每次调用按当前 slog.Default() 现绑,保证运行时切换日志级别 / mobile 初始化晚期才
// SetDefault 等情况下,flow 日志仍走最新的 handler;日志点都在连接/会话级(非每包热路径),
// 这点 With 分配可忽略。
func Log(ctx context.Context) *slog.Logger {
	if id, ok := ctx.Value(flowKey{}).(uint64); ok {
		return slog.Default().With("flow", id)
	}
	return slog.Default()
}

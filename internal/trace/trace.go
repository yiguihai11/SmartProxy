// 用 NextID 分配一个进程内单调递增的序号,经 WithFlow 注入 context;处理链路沿途用
// Log(ctx) 取一个预绑定 "flow" 字段的 logger 打日志。展示层把进程级随机前缀拼进
// flow(如 flow=9c4a1f03-17),于是:
//
//   - 同一次进程启动内,序号单调、活会话互斥 → 任意时刻 grep "flow=9c4a1f03-17" 只命中一条会话;
//   - 跨进程重启,随机前缀不同 → 几份启动日志合并归档也不重号、不串会话。
//
// 从入口 → 分流决策 → 上游拨号 → 转发结束,同一个 flow 串起完整生命周期。
//
// Log 在 ctx 不带 id 时退回 slog.Default(),永不返回 nil —— 因此任何中间状态(改到一半、
// 测试传 background ctx)都能编译、行为与不带 id 时一致。
package trace

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type flowKey struct{}

// 会话序号:进程内单调递增,永不重复(2^64 才回绕)。ctx 里存的、以及 udp 会话持有的
// flowID 都是这个纯序号;跨启动的区分只发生在展示层(见 Log),内部类型保持 uint64。
var nextID atomic.Uint64

// 进程级随机盐:首次展示 flow 时惰性生成一次。重启后不同 → 不同启动的日志前缀不同。
var (
	bootOnce sync.Once
	bootSalt uint32
)

// NextID 分配一个进程内唯一的会话序号(从 1 起,单调递增;2^64 内不回绕)。
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
		// 展示层拼「进程随机前缀-序号」:同启动内按序号可排序,跨启动前缀隔离,
		// 合并归档的日志不会把不同进程 / 不同重启的会话串成同一条。
		return slog.Default().With("flow", fmt.Sprintf("%08x-%d", currentBootSalt(), id))
	}
	return slog.Default()
}

func currentBootSalt() uint32 {
	bootOnce.Do(func() {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			// crypto/rand 理论上不会失败;兜底用启动时刻纳秒的低位,伪随机也够用。
			binary.BigEndian.PutUint32(b[:], uint32(time.Now().UnixNano()))
		}
		salt := binary.BigEndian.Uint32(b[:])
		if salt == 0 {
			salt = 1 // 避免 00000000- 前缀被误认成没加盐
		}
		bootSalt = salt
	})
	return bootSalt
}

package logbuf

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type LogEntry struct {
	ID        uint64 `json:"id"`
	Timestamp string `json:"time"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

type RingBuffer struct {
	mu       sync.RWMutex
	entries  []LogEntry
	capacity int
	head     int
	count    int
	seq      uint64
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &RingBuffer{
		entries:  make([]LogEntry, capacity),
		capacity: capacity,
	}
}

var Default = NewRingBuffer(1000)

func (r *RingBuffer) Add(entry LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	entry.ID = r.seq
	r.entries[r.head] = entry
	r.head = (r.head + 1) % r.capacity
	if r.count < r.capacity {
		r.count++
	}
}

func (r *RingBuffer) GetAll() []LogEntry {
	return r.GetSince(0)
}

func (r *RingBuffer) GetSince(sinceID uint64) []LogEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]LogEntry, 0)
	if r.count == 0 {
		return result
	}
	start := 0
	if r.count == r.capacity {
		start = r.head
	}
	for i := 0; i < r.count; i++ {
		idx := (start + i) % r.capacity
		if r.entries[idx].ID > sinceID {
			result = append(result, r.entries[idx])
		}
	}
	return result
}

func (r *RingBuffer) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.head = 0
	r.count = 0
	r.seq = 0
	r.entries = make([]LogEntry, r.capacity)
}

func (r *RingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

type SlogHandler struct {
	handler  slog.Handler
	buffer   *RingBuffer
	attrs    []slog.Attr
	groups   []string
	minLevel slog.Level
	// location, when set, converts each record's time into this zone before the
	// timestamp is stored in the buffer — so the panel's logs match the location
	// the console handler displays (e.g. Asia/Shanghai on a UTC process).
	location *time.Location
}

func NewSlogHandler(h slog.Handler, buf *RingBuffer) *SlogHandler {
	return NewSlogHandlerLevel(h, buf, slog.LevelInfo)
}

func NewSlogHandlerLevel(h slog.Handler, buf *RingBuffer, minLevel slog.Level) *SlogHandler {
	if buf == nil {
		buf = Default
	}
	return &SlogHandler{
		handler:  h,
		buffer:   buf,
		minLevel: minLevel,
		// 默认按上海时间格式化:用户要求面板日志统一显示上海时间,与服务器/浏览器
		// 所在时区无关。WithLocation 可显式覆盖。
		location: shanghaiLocation(),
	}
}

// shanghaiLocation 返回 Asia/Shanghai(恒 UTC+8,无夏令时);异常时退化为固定 +08:00。
func shanghaiLocation() *time.Location {
	if loc, err := time.LoadLocation("Asia/Shanghai"); err == nil {
		return loc
	}
	return time.FixedZone("CST", 8*60*60)
}

// WithLocation overrides the timezone log timestamps are converted into before
// being buffered (default Asia/Shanghai, see shanghaiLocation). Returns the
// receiver for chaining.
func (sh *SlogHandler) WithLocation(loc *time.Location) *SlogHandler {
	if loc == nil {
		loc = time.Local
	}
	sh.location = loc
	return sh
}

func (sh *SlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if sh.handler != nil && !sh.handler.Enabled(ctx, level) {
		return false
	}
	return level >= sh.minLevel
}

func (sh *SlogHandler) Handle(ctx context.Context, r slog.Record) error {
	if sh.buffer != nil {
		var levelStr string
		switch {
		case r.Level >= slog.LevelError:
			levelStr = "ERROR"
		case r.Level >= slog.LevelWarn:
			levelStr = "WARN"
		case r.Level >= slog.LevelInfo:
			levelStr = "INFO"
		default:
			levelStr = "DEBUG"
		}

		var attrs []string
		for _, a := range sh.attrs {
			attrs = append(attrs, fmt.Sprintf("%s=%v", a.Key, a.Value.Any()))
		}
		r.Attrs(func(a slog.Attr) bool {
			attrs = append(attrs, fmt.Sprintf("%s=%v", a.Key, a.Value.Any()))
			return true
		})

		msg := r.Message
		if len(sh.groups) > 0 {
			msg = fmt.Sprintf("[%s] %s", strings.Join(sh.groups, "."), msg)
		}
		if len(attrs) > 0 {
			msg = msg + " " + strings.Join(attrs, " ")
		}

		t := r.Time
		if t.IsZero() {
			t = time.Now()
		}
		if sh.location != nil {
			t = t.In(sh.location)
		}

		sh.buffer.Add(LogEntry{
			Timestamp: t.Format("2006-01-02 15:04:05"),
			Level:     levelStr,
			Message:   msg,
		})
	}

	if sh.handler != nil {
		return sh.handler.Handle(ctx, r)
	}
	return nil
}

func (sh *SlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var next slog.Handler
	if sh.handler != nil {
		next = sh.handler.WithAttrs(attrs)
	}
	newAttrs := make([]slog.Attr, 0, len(sh.attrs)+len(attrs))
	newAttrs = append(newAttrs, sh.attrs...)
	newAttrs = append(newAttrs, attrs...)
	return &SlogHandler{
		handler:  next,
		buffer:   sh.buffer,
		attrs:    newAttrs,
		groups:   sh.groups,
		minLevel: sh.minLevel,
		location: sh.location,
	}
}

func (sh *SlogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return sh
	}
	var next slog.Handler
	if sh.handler != nil {
		next = sh.handler.WithGroup(name)
	}
	newGroups := make([]string, 0, len(sh.groups)+1)
	newGroups = append(newGroups, sh.groups...)
	newGroups = append(newGroups, name)
	return &SlogHandler{
		handler:  next,
		buffer:   sh.buffer,
		attrs:    sh.attrs,
		groups:   newGroups,
		minLevel: sh.minLevel,
		location: sh.location,
	}
}

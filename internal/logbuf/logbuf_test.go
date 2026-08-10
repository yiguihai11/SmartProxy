package logbuf

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRingBuffer(t *testing.T) {
	buf := NewRingBuffer(5)
	assert.Equal(t, 0, buf.Len())
	assert.Empty(t, buf.GetAll())

	// Add 3 entries
	for i := 1; i <= 3; i++ {
		buf.Add(LogEntry{Level: "INFO", Message: fmt.Sprintf("msg-%d", i)})
	}
	assert.Equal(t, 3, buf.Len())
	entries := buf.GetAll()
	assert.Len(t, entries, 3)
	assert.Equal(t, "msg-1", entries[0].Message)
	assert.Equal(t, "msg-3", entries[2].Message)

	// Add 3 more entries (total 6, should evict msg-1)
	for i := 4; i <= 6; i++ {
		buf.Add(LogEntry{Level: "WARN", Message: fmt.Sprintf("msg-%d", i)})
	}
	assert.Equal(t, 5, buf.Len())
	entries = buf.GetAll()
	assert.Len(t, entries, 5)
	assert.Equal(t, "msg-2", entries[0].Message)
	assert.Equal(t, "msg-6", entries[4].Message)

	// Clear
	buf.Clear()
	assert.Equal(t, 0, buf.Len())
	assert.Empty(t, buf.GetAll())
}

func TestRingBufferConcurrent(t *testing.T) {
	buf := NewRingBuffer(500)
	var wg sync.WaitGroup

	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				buf.Add(LogEntry{
					Level:   "INFO",
					Message: fmt.Sprintf("g%d-m%d", goroutineID, i),
				})
			}
		}(g)
	}

	wg.Wait()
	assert.Equal(t, 500, buf.Len())
	assert.Len(t, buf.GetAll(), 500)
}

func TestSlogHandler(t *testing.T) {
	buf := NewRingBuffer(10)
	// Use LevelDebug to let Debug logs through, verifying the level mapping for all four levels (INFO/WARN/ERROR/DEBUG).
	// NewSlogHandler defaults minLevel to LevelInfo, which filters out Debug.
	sh := NewSlogHandlerLevel(nil, buf, slog.LevelDebug)
	logger := slog.New(sh)

	logger.Info("info message", "key", "val")
	logger.Warn("warn message", "num", 42)
	logger.Error("error message")
	logger.Debug("debug message")

	entries := buf.GetAll()
	assert.Len(t, entries, 4)
	assert.Equal(t, "INFO", entries[0].Level)
	assert.Contains(t, entries[0].Message, "info message")
	assert.Contains(t, entries[0].Message, "key=val")

	assert.Equal(t, "WARN", entries[1].Level)
	assert.Contains(t, entries[1].Message, "warn message")

	assert.Equal(t, "ERROR", entries[2].Level)
	assert.Equal(t, "DEBUG", entries[3].Level)
}

func TestSlogHandlerLocation(t *testing.T) {
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skip("Asia/Shanghai tzdata unavailable")
	}
	buf := NewRingBuffer(10)
	sh := NewSlogHandlerLevel(nil, buf, slog.LevelInfo).WithLocation(shanghai)

	// A UTC record (as captured on a UTC process) must be stored in the console
	// handler's display zone so panel and terminal agree.
	utcTime := time.Date(2026, 8, 10, 15, 51, 17, 0, time.UTC)
	var r slog.Record
	r = slog.NewRecord(utcTime, slog.LevelInfo, "smartproxy starting", 0)
	if err := sh.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	entries := buf.GetAll()
	assert.Len(t, entries, 1)
	assert.Equal(t, "2026-08-10 23:51:17", entries[0].Timestamp)

	// WithAttrs/WithGroup copies must keep the location: drive the derived
	// handler directly with the same fixed-time record.
	logger := slog.New(NewSlogHandlerLevel(nil, buf, slog.LevelInfo).WithLocation(shanghai)).
		With("mod", "test").WithGroup("sub")
	if err := logger.Handler().Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	second := buf.GetAll()[1]
	assert.Equal(t, "2026-08-10 23:51:17", second.Timestamp)
	assert.Contains(t, second.Message, "[sub] smartproxy starting")
	assert.Contains(t, second.Message, "mod=test")
}

func TestSlogHandlerWithAttrsAndGroup(t *testing.T) {
	buf := NewRingBuffer(10)
	sh := NewSlogHandler(nil, buf)
	logger := slog.New(sh).With("mod", "test").WithGroup("sub")

	logger.Info("grouped message", "count", 1)

	entries := buf.GetAll()
	assert.Len(t, entries, 1)
	assert.Equal(t, "INFO", entries[0].Level)
	assert.Contains(t, entries[0].Message, "[sub] grouped message")
	assert.Contains(t, entries[0].Message, "mod=test")
	assert.Contains(t, entries[0].Message, "count=1")
}

func BenchmarkRingBufferAdd(b *testing.B) {
	buf := NewRingBuffer(500)
	entry := LogEntry{Level: "INFO", Message: "test log benchmark message"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry.Timestamp = strconv.Itoa(i)
		buf.Add(entry)
	}
}

package trace

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestNextID_ConcurrentUnique(t *testing.T) {
	const n = 200
	var wg sync.WaitGroup
	results := make([][]uint64, 8)
	for g := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ids := make([]uint64, n)
			for i := range ids {
				ids[i] = NextID()
			}
			results[idx] = ids
		}(g)
	}
	wg.Wait()

	seen := make(map[uint64]bool, 8*n)
	for _, ids := range results {
		for _, id := range ids {
			if id == 0 {
				t.Fatal("flow id must never be 0")
			}
			if seen[id] {
				t.Fatalf("duplicate flow id %d across concurrent generators", id)
			}
			seen[id] = true
		}
	}
}

func TestWithFlow_RoundTrip(t *testing.T) {
	ctx := WithFlow(context.Background(), 77)
	id, ok := Flow(ctx)
	if !ok || id != 77 {
		t.Fatalf("Flow() = (%d, %v), want (77, true)", id, ok)
	}
}

func TestFlow_EmptyContext(t *testing.T) {
	if id, ok := Flow(context.Background()); ok || id != 0 {
		t.Fatalf("bare ctx Flow() = (%d, %v), want (0, false)", id, ok)
	}
	if Log(context.Background()) == nil {
		t.Fatal("Log(bare ctx) must never return nil")
	}
}

func TestLog_IncludesFlow(t *testing.T) {
	old := slog.Default()
	defer slog.SetDefault(old)

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	Log(WithFlow(context.Background(), 4242)).Info("marker")
	if !strings.Contains(buf.String(), "flow=4242") || !strings.Contains(buf.String(), "marker") {
		t.Fatalf("log output missing flow id: %q", buf.String())
	}

	// 裸 ctx 不带 flow,日志照常输出但无 flow= 字段。
	buf.Reset()
	Log(context.Background()).Info("plain")
	if !strings.Contains(buf.String(), "plain") || strings.Contains(buf.String(), "flow=") {
		t.Fatalf("bare ctx log should have no flow attr: %q", buf.String())
	}
}

func TestWithFlow_NestedShadows(t *testing.T) {
	outer := WithFlow(context.Background(), 1)
	inner := WithFlow(outer, 2)
	if id, _ := Flow(inner); id != 2 {
		t.Fatalf("inner flow id = %d, want 2 (shadowing)", id)
	}
	if id, _ := Flow(outer); id != 1 {
		t.Fatalf("outer flow id = %d, want 1 (unaffected)", id)
	}
}

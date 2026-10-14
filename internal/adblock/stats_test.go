package adblock

import (
	"fmt"
	"sync"
	"testing"
)

func TestStatsBasicAndSnapshot(t *testing.T) {
	st := NewStats()
	st.hit("ad1.com")
	st.hit("ad1.com")
	st.hit("ad2.com")

	if st.Total() != 3 {
		t.Fatalf("expected total 3, got %d", st.Total())
	}

	snap := st.Snapshot(10)
	if snap.Total != 3 {
		t.Fatalf("expected snap.Total 3, got %d", snap.Total)
	}
	if len(snap.Top) != 2 {
		t.Fatalf("expected 2 top domains, got %d", len(snap.Top))
	}
	if snap.Top[0].Domain != "ad1.com" || snap.Top[0].Hits != 2 {
		t.Fatalf("expected top 1 to be ad1.com with 2 hits, got %+v", snap.Top[0])
	}
}

func TestStatsBoundedCapacity(t *testing.T) {
	st := NewStats()
	for i := 0; i < 600; i++ {
		st.hit(fmt.Sprintf("unique%d.com", i))
	}

	if st.Total() != 600 {
		t.Fatalf("expected total 600, got %d", st.Total())
	}

	snap := st.Snapshot(1000)
	// 上限严格为 512
	if len(snap.Top) > 512 {
		t.Fatalf("expected at most 512 tracked domains, got %d", len(snap.Top))
	}

	// 既有域名继续累加不受限制
	st.hit("unique0.com")
	snap2 := st.Snapshot(10)
	found := false
	for _, item := range snap2.Top {
		if item.Domain == "unique0.com" {
			found = true
			if item.Hits != 2 {
				t.Fatalf("expected unique0.com hits=2, got %d", item.Hits)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected unique0.com to be in top snapshot")
	}
}

func TestStatsConcurrency(t *testing.T) {
	st := NewStats()
	var wg sync.WaitGroup
	const goroutines = 20
	const hitsPerGoroutine = 500

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			d := fmt.Sprintf("worker%d.com", id%5)
			for j := 0; j < hitsPerGoroutine; j++ {
				st.hit(d)
			}
		}(i)
	}

	wg.Wait()
	expectedTotal := int64(goroutines * hitsPerGoroutine)
	if st.Total() != expectedTotal {
		t.Fatalf("expected total %d, got %d", expectedTotal, st.Total())
	}
}

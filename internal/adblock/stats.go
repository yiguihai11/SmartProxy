package adblock

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// maxTrackedHits is the bounded capacity for candidate TOP blocked domains.
const maxTrackedHits = 512

// DomainHit records the hit count for a single blocked domain.
type DomainHit struct {
	Domain string `json:"domain"`
	Hits   int64  `json:"hits"`
}

// StatsSnapshot captures cumulative stats and TOP blocked domains for the admin API.
type StatsSnapshot struct {
	Total int64       `json:"total"`
	Since int64       `json:"since"` // unix timestamp in seconds
	Top   []DomainHit `json:"top"`
}

// Stats tracks cumulative block hits and a bounded TOP domain histogram.
// Managed by Manager, it survives across Set snapshot rebuilds.
type Stats struct {
	mu    sync.Mutex
	hits  map[string]int64
	total atomic.Int64
	since time.Time
}

// NewStats creates an initialized Stats instance.
func NewStats() *Stats {
	return &Stats{
		hits:  make(map[string]int64),
		since: time.Now(),
	}
}

// hit records a block occurrence. Hot path: atomic total increment and bounded map update.
func (s *Stats) hit(domain string) {
	if s == nil {
		return
	}
	s.total.Add(1)
	s.mu.Lock()
	if c, ok := s.hits[domain]; ok {
		s.hits[domain] = c + 1
	} else if len(s.hits) < maxTrackedHits {
		s.hits[domain] = 1
	}
	s.mu.Unlock()
}

// Total returns the cumulative blocked query count.
func (s *Stats) Total() int64 {
	if s == nil {
		return 0
	}
	return s.total.Load()
}

// Since returns the start time of this stats accumulator.
func (s *Stats) Since() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.since
}

// Snapshot returns a point-in-time snapshot with up to limit TOP domains.
func (s *Stats) Snapshot(limit int) StatsSnapshot {
	if s == nil {
		return StatsSnapshot{Top: []DomainHit{}}
	}
	if limit <= 0 {
		limit = 50
	}
	s.mu.Lock()
	items := make([]DomainHit, 0, len(s.hits))
	for d, c := range s.hits {
		items = append(items, DomainHit{Domain: d, Hits: c})
	}
	s.mu.Unlock()

	sort.Slice(items, func(i, j int) bool {
		if items[i].Hits != items[j].Hits {
			return items[i].Hits > items[j].Hits
		}
		return items[i].Domain < items[j].Domain
	})
	if len(items) > limit {
		items = items[:limit]
	}

	return StatsSnapshot{
		Total: s.total.Load(),
		Since: s.since.Unix(),
		Top:   items,
	}
}

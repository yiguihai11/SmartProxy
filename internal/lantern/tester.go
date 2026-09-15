package lantern

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"smartproxy/internal/singbox"
)

// TestAndFilterNodes verifies internet connectivity for each candidate node
// using a zero-port in-memory sing-box outbound engine, and returns only working nodes.
func TestAndFilterNodes(ctx context.Context, nodes []json.RawMessage, testURL string, timeout time.Duration) ([]json.RawMessage, error) {
	if len(nodes) == 0 {
		return nodes, nil
	}

	if testURL == "" {
		testURL = "http://cp.cloudflare.com/generate_204"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	engine := singbox.NewEngine()
	defer engine.Close()

	var tags []string
	for i, raw := range nodes {
		var meta struct {
			Tag string `json:"tag"`
		}
		_ = json.Unmarshal(raw, &meta)
		tag := meta.Tag
		if tag == "" {
			tag = fmt.Sprintf("node-%d", i)
		}
		tags = append(tags, tag)
	}

	if err := engine.RegisterOutbounds(nodes); err != nil {
		return nodes, nil // If registration failed, return raw nodes
	}

	type testResult struct {
		index int
		alive bool
	}

	resChan := make(chan testResult, len(nodes))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // concurrent probing semaphore

	for i, tag := range tags {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, t string) {
			defer wg.Done()
			defer func() { <-sem }()
			alive := probeNodeWithEngine(ctx, engine, t, testURL, timeout)
			resChan <- testResult{index: idx, alive: alive}
		}(i, tag)
	}

	wg.Wait()
	close(resChan)

	aliveMap := make(map[int]bool)
	for res := range resChan {
		if res.alive {
			aliveMap[res.index] = true
		}
	}

	var workingNodes []json.RawMessage
	for i, node := range nodes {
		if aliveMap[i] {
			workingNodes = append(workingNodes, node)
		}
	}

	return workingNodes, nil
}

func probeNodeWithEngine(ctx context.Context, engine *singbox.Engine, tag, testURL string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return engine.DialContext(ctx, tag, network, addr)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

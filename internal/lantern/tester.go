package lantern

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func getFreePorts(count int) ([]int, error) {
	var ports []int
	var listeners []net.Listener
	for i := 0; i < count; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return nil, err
		}
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
		listeners = append(listeners, ln)
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	return ports, nil
}

type testInbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
}

type testRouteRule struct {
	Inbound  []string `json:"inbound"`
	Outbound string   `json:"outbound"`
}

type testSingBoxConfig struct {
	Log struct {
		Level string `json:"level"`
	} `json:"log"`
	Inbounds  []testInbound     `json:"inbounds"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Route     struct {
		Rules []testRouteRule `json:"rules"`
	} `json:"route"`
}

// TestAndFilterNodes verifies internet connectivity for each candidate node
// using an in-process sing-box instance (compiled directly via github.com/sagernet/sing-box,
// requiring NO external binary or subprocess), and returns only working nodes.
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

	ports, err := getFreePorts(len(nodes))
	if err != nil {
		return nil, fmt.Errorf("failed to allocate test ports: %w", err)
	}

	// Prepare sing-box probe config: assign each node an ephemeral SOCKS5 inbound
	var sbCfg testSingBoxConfig
	sbCfg.Log.Level = "warn"
	sbCfg.Outbounds = nodes

	for i, raw := range nodes {
		var meta struct {
			Tag string `json:"tag"`
		}
		_ = json.Unmarshal(raw, &meta)
		tag := meta.Tag
		if tag == "" {
			tag = fmt.Sprintf("node-%d", i)
		}

		inTag := fmt.Sprintf("in-%s", tag)
		sbCfg.Inbounds = append(sbCfg.Inbounds, testInbound{
			Type:       "socks",
			Tag:        inTag,
			Listen:     "127.0.0.1",
			ListenPort: ports[i],
		})

		sbCfg.Route.Rules = append(sbCfg.Route.Rules, testRouteRule{
			Inbound:  []string{inTag},
			Outbound: tag,
		})
	}

	cfgBytes, err := json.Marshal(sbCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize test config: %w", err)
	}

	// Initialize and start sing-box in-process (pure Go library)
	boxCtx := include.Context(ctx)
	var opts option.Options
	if err := opts.UnmarshalJSONContext(boxCtx, cfgBytes); err != nil {
		return nil, fmt.Errorf("failed to parse config into sing-box library: %w", err)
	}

	instance, err := box.New(box.Options{
		Context: boxCtx,
		Options: opts,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create in-process sing-box instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		return nil, fmt.Errorf("failed to start in-process sing-box: %w", err)
	}
	defer instance.Close()

	// Wait briefly (up to 1s) for the first port to start listening
	ready := false
	firstPort := ports[0]
	for i := 0; i < 10; i++ {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", firstPort), 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return nil, fmt.Errorf("in-process sing-box failed to bind listener within timeout")
	}

	// Concurrently probe all candidate nodes through their assigned in-process SOCKS5 inbounds
	type testResult struct {
		index int
		alive bool
	}

	resChan := make(chan testResult, len(nodes))
	var wg sync.WaitGroup

	for i, port := range ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			alive := probeNode(ctx, p, testURL, timeout)
			resChan <- testResult{index: idx, alive: alive}
		}(i, port)
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

func probeNode(ctx context.Context, socksPort int, testURL string, timeout time.Duration) bool {
	proxyURL, err := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	if err != nil {
		return false
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		DisableKeepAlives: true,
	}

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

	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent
}

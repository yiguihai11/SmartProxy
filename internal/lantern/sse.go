package lantern

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// StartSSEListener optionally runs a background SSE stream for datacap events.
// Calls onExhausted when event: cap_exhausted is received.
func StartSSEListener(ctx context.Context, client *http.Client, acc Account, onExhausted func()) {
	backoff := 2 * time.Second
	maxBackoff := 120 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		url := fmt.Sprintf("%s/stream/datacap/%s", BaseURL, acc.DeviceID)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return
		}

		req.Header = buildHeaders(acc.DeviceID, acc.UserID, acc.ProToken)
		req.Header.Set("Accept", "text/event-stream")

		resp, err := client.Do(req)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
		}

		backoff = 2 * time.Second
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				_ = resp.Body.Close()
				return
			default:
			}

			line := strings.TrimSpace(scanner.Text())
			if line == "event: cap_exhausted" {
				_ = resp.Body.Close()
				if onExhausted != nil {
					onExhausted()
				}
				return
			}
		}
		_ = resp.Body.Close()

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

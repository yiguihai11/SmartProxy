package lantern

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

type datacapJSONResponse struct {
	Enabled bool `json:"enabled"`
	Usage   *struct {
		BytesAllotted      string `json:"bytesAllotted"`
		BytesUsed          string `json:"bytesUsed"`
		AllotmentStartTime string `json:"allotmentStartTime"`
		AllotmentEndTime   string `json:"allotmentEndTime"`
	} `json:"usage"`
}

// QuotaResult represents the result of a datacap check.
type QuotaResult struct {
	Allot     int64
	Used      int64
	Remain    int64
	ResetUnix int64 // Parsed from allotmentEndTime, if available
	QuotaOK   bool
}

// parseDatacap parses the datacap response body, supporting both JSON and binary Protobuf fallback.
func parseDatacap(raw []byte, minRemainBytes int64) (QuotaResult, error) {
	if len(raw) == 0 {
		return QuotaResult{QuotaOK: false}, fmt.Errorf("empty datacap response")
	}

	// 1. Try JSON parsing
	var jResp datacapJSONResponse
	if err := json.Unmarshal(raw, &jResp); err == nil {
		if !jResp.Enabled {
			// Unmetered / unlimited
			return QuotaResult{
				Allot:   100 * 1024 * 1024 * 1024, // 100GB dummy
				Used:    0,
				Remain:  100 * 1024 * 1024 * 1024,
				QuotaOK: true,
			}, nil
		}

		if jResp.Usage != nil {
			allot, _ := strconv.ParseInt(jResp.Usage.BytesAllotted, 10, 64)
			used, _ := strconv.ParseInt(jResp.Usage.BytesUsed, 10, 64)
			remain := allot - used

			var resetUnix int64
			if jResp.Usage.AllotmentEndTime != "" {
				if t, err := time.Parse(time.RFC3339, jResp.Usage.AllotmentEndTime); err == nil {
					resetUnix = t.Unix()
				}
			}

			ok := allot > 0 && remain > minRemainBytes
			return QuotaResult{
				Allot:     allot,
				Used:      used,
				Remain:    remain,
				ResetUnix: resetUnix,
				QuotaOK:   ok,
			}, nil
		}
	}

	// 2. Binary Protobuf fallback: extract numeric sequences
	re := regexp.MustCompile(`\d+`)
	matches := re.FindAll(raw, -1)
	if len(matches) >= 2 {
		allot, err1 := strconv.ParseInt(string(matches[0]), 10, 64)
		used, err2 := strconv.ParseInt(string(matches[1]), 10, 64)
		if err1 == nil && err2 == nil {
			remain := allot - used
			ok := allot > 0 && remain > minRemainBytes
			return QuotaResult{
				Allot:   allot,
				Used:    used,
				Remain:  remain,
				QuotaOK: ok,
			}, nil
		}
	}

	return QuotaResult{QuotaOK: false}, fmt.Errorf("unrecognized datacap response format")
}

// CheckAccountQuota queries the current datacap for the given account.
func CheckAccountQuota(ctx context.Context, client *http.Client, acc *Account, minRemainBytes int64) (QuotaResult, error) {
	url := fmt.Sprintf("%s/datacap/%s", BaseURL, acc.DeviceID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return QuotaResult{}, fmt.Errorf("failed to build datacap request: %w", err)
	}

	req.Header = buildHeaders(acc.DeviceID, acc.UserID, acc.ProToken)

	resp, err := client.Do(req)
	if err != nil {
		return QuotaResult{}, fmt.Errorf("datacap request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return QuotaResult{}, fmt.Errorf("failed to read datacap response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return QuotaResult{QuotaOK: false}, fmt.Errorf("datacap returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	res, err := parseDatacap(body, minRemainBytes)
	if err != nil {
		return QuotaResult{QuotaOK: false}, err
	}

	// Update account fields
	acc.Allot = res.Allot
	acc.Used = res.Used
	acc.Remain = res.Remain
	acc.QuotaOK = res.QuotaOK
	if res.ResetUnix > 0 {
		acc.ExhaustedUntil = res.ResetUnix
	}
	acc.LastCheck = time.Now().Unix()

	return res, nil
}

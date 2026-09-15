package lantern

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type configRequest struct {
	SingBoxVersion string   `json:"singbox_version"`
	Platform       string   `json:"platform"`
	AppName        string   `json:"app_name"`
	DeviceID       string   `json:"device_id"`
	UserID         string   `json:"user_id"`
	ProToken       string   `json:"pro_token"`
	WgPublicKey    string   `json:"wg_public_key"`
	Backend        string   `json:"backend"`
	Locale         string   `json:"locale"`
	Protocols      []string `json:"protocols"`
	Capabilities   []string `json:"capabilities"`
}

type configResponse struct {
	Options struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	} `json:"options"`
}

type genericOutbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

// FetchStandardOutbounds pulls raw config from Lantern backend and filters for standard sing-box outbounds.
func FetchStandardOutbounds(ctx context.Context, client *http.Client, acc *Account, etag string) ([]json.RawMessage, string, error) {
	url := fmt.Sprintf("%s/config-new", BaseURL)

	payload := configRequest{
		SingBoxVersion: "unknown",
		Platform:       "android",
		AppName:        "lantern",
		DeviceID:       acc.DeviceID,
		UserID:         fmt.Sprintf("%d", acc.UserID),
		ProToken:       acc.ProToken,
		Backend:        "sing-box",
		Locale:         "zh-CN",
		Protocols:      StandardProtocols,
		Capabilities:   []string{"non_selectable_outbounds"},
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal config request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, "", fmt.Errorf("failed to build config request: %w", err)
	}

	req.Header = buildHeaders(acc.DeviceID, acc.UserID, acc.ProToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("X-Lantern-Idempotent", "1")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("config request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, nil // 304 Not Modified
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read config response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != 206 {
		return nil, "", fmt.Errorf("config request returned status %d: %s", resp.StatusCode, string(body))
	}

	newEtag := resp.Header.Get("ETag")

	var cfgResp configResponse
	if err := json.Unmarshal(body, &cfgResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse config response: %w", err)
	}

	filtered := filterOutbounds(cfgResp.Options.Outbounds)
	return filtered, newEtag, nil
}

// filterOutbounds removes private Lantern protocols and non-proxy infrastructure outbounds.
func filterOutbounds(rawOutbounds []json.RawMessage) []json.RawMessage {
	var result []json.RawMessage
	standardSet := make(map[string]bool)
	for _, p := range StandardProtocols {
		standardSet[p] = true
	}

	for _, raw := range rawOutbounds {
		var meta genericOutbound
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}

		oType := strings.ToLower(meta.Type)
		// Skip infra outbounds
		if InfraProtocols[oType] {
			continue
		}
		// Skip private protocols
		if PrivateProtocols[oType] {
			continue
		}
		// Must be in standard protocol set
		if !standardSet[oType] {
			continue
		}

		result = append(result, raw)
	}

	return result
}

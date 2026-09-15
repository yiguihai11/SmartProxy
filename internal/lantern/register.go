package lantern

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// generateUUID generates a standard random UUID v4 string.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type registerResponse struct {
	UserID int64  `json:"userId"`
	Token  string `json:"token"`
}

// AnonymousRegister creates a new anonymous user account on the Lantern pro server.
func AnonymousRegister(ctx context.Context, client *http.Client) (Account, error) {
	devID := generateUUID()
	url := fmt.Sprintf("%s/user-create", ProServerURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return Account{}, fmt.Errorf("failed to build register request: %w", err)
	}

	req.Header = buildHeaders(devID, 0, "")

	resp, err := client.Do(req)
	if err != nil {
		return Account{}, fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Account{}, fmt.Errorf("failed to read register response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Account{}, fmt.Errorf("register failed with status %d: %s", resp.StatusCode, string(body))
	}

	var regResp registerResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return Account{}, fmt.Errorf("failed to parse register response: %w (raw: %s)", err, string(body))
	}

	acc := Account{
		DeviceID:  devID,
		UserID:    regResp.UserID,
		ProToken:  regResp.Token,
		QuotaOK:   true,
		LastCheck: time.Now().Unix(),
	}

	return acc, nil
}

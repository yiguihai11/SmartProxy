package lantern

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
)

const (
	LanternVersion = "9.1.23"
	ProServerURL   = "https://api.getiantem.org"
	BaseURL        = "https://df.iantem.io/api/v1"
)

// randLowerString generates a random lowercase ASCII string of length n.
func randLowerString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	bytes := make([]byte, n)
	for i := range bytes {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			bytes[i] = letters[i%len(letters)]
		} else {
			bytes[i] = letters[num.Int64()]
		}
	}
	return string(bytes)
}

// buildHeaders builds standard Lantern Android request headers.
func buildHeaders(deviceID string, userID int64, proToken string) http.Header {
	n, err := rand.Int(rand.Reader, big.NewInt(9))
	randLen := 8
	if err == nil {
		randLen = 4 + int(n.Int64())
	}
	randStr := randLowerString(randLen)

	h := make(http.Header)
	h.Set("X-Lantern-App", "lantern")
	h.Set("X-Lantern-Version", LanternVersion)
	h.Set("X-Lantern-App-Version", LanternVersion)
	h.Set("X-Lantern-Platform", "android")
	h.Set("X-Lantern-Device-Id", deviceID)
	h.Set("X-Lantern-Rand", randStr)
	h.Set("X-Lantern-Time-Zone", "Asia/Shanghai")
	h.Set("User-Agent", fmt.Sprintf("Lantern/%s", LanternVersion))

	if userID > 0 {
		h.Set("X-Lantern-User-Id", fmt.Sprintf("%d", userID))
	}
	if proToken != "" {
		h.Set("X-Lantern-Pro-Token", proToken)
	}

	return h
}

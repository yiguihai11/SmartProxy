package admin

import (
	"testing"

	"smartproxy/internal/config"
)

func TestMaskRestoreRoundTrip(t *testing.T) {
	live := &config.Config{}
	live.Upstream.Proxies = []config.ProxyEntry{
		{Alias: "ss1", URL: "ss://chacha20-ietf-poly1305:RealPass%21@1.2.3.4:8388#node", UDPInTCP: true},
		{Alias: "http1", URL: "http://bob:sup3rS3cret@5.6.7.8:8080"},
		{Alias: "plain", URL: "http://9.9.9.9:3128"},
		{Alias: "legacy", URL: "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpyZWFscGFzc0Bob3N0OjgzODg="},
	}

	masked := maskConfigForDisplay(live)
	for _, p := range masked.Upstream.Proxies {
		t.Logf("masked: %s -> %s", p.Alias, p.URL)
		if containsSecret(p.URL) {
			t.Errorf("masked URL %q for %s still contains a secret", p.URL, p.Alias)
		}
	}

	// Simulate the panel round-trip: the client PUTs back the masked config untouched.
	incoming := &config.Config{}
	incoming.Upstream.Proxies = append([]config.ProxyEntry{}, masked.Upstream.Proxies...)
	restoreMaskedProxies(incoming, live)

	for i := range incoming.Upstream.Proxies {
		got := incoming.Upstream.Proxies[i].URL
		want := live.Upstream.Proxies[i].URL
		if got != want {
			t.Errorf("round-trip mismatch %q: got %q want %q", live.Upstream.Proxies[i].Alias, got, want)
		}
	}

	// Simulate an edit: user changes the host only, password untouched (still masked).
	edit := &config.Config{}
	edit.Upstream.Proxies = []config.ProxyEntry{
		{Alias: "ss1", URL: "ss://chacha20-ietf-poly1305:******@9.9.9.9:8388"},
	}
	restoreMaskedProxies(edit, live)
	want := "ss://chacha20-ietf-poly1305:RealPass%21@9.9.9.9:8388"
	if edit.Upstream.Proxies[0].URL != want {
		t.Errorf("host-edit round-trip: got %q want %q", edit.Upstream.Proxies[0].URL, want)
	}
}

func containsSecret(s string) bool {
	for _, secret := range []string{"RealP", "sup3rS3cret", "Y2hhY2hh", "realpass"} {
		for i := 0; i+len(secret) <= len(s); i++ {
			if s[i:i+len(secret)] == secret {
				return true
			}
		}
	}
	return false
}

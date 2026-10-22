package upstream

import (
	"testing"
)

func TestIsDefaultWithFilter(t *testing.T) {
	tests := []struct {
		alias string
		want  bool
	}{
		{"default", false},
		{"DEFAULT", false},
		{"direct", false},
		{"us-node-1", false},
		{"default!eu,au,cn", true},
		{"DEFAULT!EU,AU,CN", true},
		{"default!Eu,Au", true},
		{"default@us,jp", true},
		{"DEFAULT@US,JP", true},
		{" default!cn ", true},
	}

	for _, tt := range tests {
		if got := IsDefaultWithFilter(tt.alias); got != tt.want {
			t.Errorf("IsDefaultWithFilter(%q) = %v, want %v", tt.alias, got, tt.want)
		}
	}
}

func TestParseGeoFilter(t *testing.T) {
	// 1. Lowercase exclusion with EU macro
	f1 := ParseGeoFilter("default!eu,au,cn")
	if f1 == nil {
		t.Fatal("expected non-nil filter for default!eu,au,cn")
	}
	if f1.Mode != "exclude" {
		t.Errorf("want mode exclude, got %s", f1.Mode)
	}
	// EU countries must be expanded
	for _, cc := range []string{"IT", "FR", "DE", "ES", "NL", "AU", "CN"} {
		if !f1.Regions[cc] {
			t.Errorf("expected %s in regions", cc)
		}
	}
	// Non-EU country must not be in regions
	if f1.Regions["US"] {
		t.Errorf("did not expect US in exclusion set")
	}

	// 2. Inclusion with mixed cases and spaces
	f2 := ParseGeoFilter(" @us, Jp , hk ")
	if f2 == nil {
		t.Fatal("expected non-nil filter for @us, Jp , hk")
	}
	if f2.Mode != "include" {
		t.Errorf("want mode include, got %s", f2.Mode)
	}
	if !f2.Regions["US"] || !f2.Regions["JP"] || !f2.Regions["HK"] {
		t.Errorf("expected US, JP, HK in regions, got %+v", f2.Regions)
	}
	if f2.Regions["IT"] {
		t.Errorf("did not expect IT in include set")
	}

	// 3. Invalid inputs
	if ParseGeoFilter("") != nil {
		t.Error("expected nil for empty string")
	}
	if ParseGeoFilter("default") != nil {
		t.Error("expected nil for default without filter")
	}
}

func TestFilterProxiesByGeo(t *testing.T) {
	pUS := &Proxy{Name: "us-node-1", URL: "ss://test@10.0.0.1:1234"}
	pUS.SetCountryCode("US")
	pIT := &Proxy{Name: "it-node-1", URL: "ss://test@10.0.0.2:1234"}
	pIT.SetCountryCode("IT")
	pAU := &Proxy{Name: "au-node-1", URL: "ss://test@10.0.0.3:1234"}
	pAU.SetCountryCode("AU")
	pJP := &Proxy{Name: "jp-node-1", URL: "ss://test@10.0.0.4:1234"}
	pJP.SetCountryCode("JP")

	candidates := []*Proxy{pUS, pIT, pAU, pJP}

	// Exclude EU and AU (lowercase test)
	filterExclude := ParseGeoFilter("default!eu,au")
	filtered, wasFallback := FilterProxiesByGeo(candidates, filterExclude)
	if wasFallback {
		t.Fatal("fallback should not be triggered when valid nodes exist")
	}
	if len(filtered) != 2 {
		t.Fatalf("expected 2 nodes (US, JP), got %d", len(filtered))
	}
	if filtered[0] != pUS || filtered[1] != pJP {
		t.Errorf("expected [US, JP], got %v", filtered)
	}

	// Include only US
	filterInclude := ParseGeoFilter("default@us")
	filteredInc, wasFallbackInc := FilterProxiesByGeo(candidates, filterInclude)
	if wasFallbackInc {
		t.Fatal("fallback should not be triggered")
	}
	if len(filteredInc) != 1 || filteredInc[0] != pUS {
		t.Errorf("expected only US node, got %v", filteredInc)
	}

	// Fallback safety test: exclude everything
	filterExcludeAll := ParseGeoFilter("default!us,eu,au,jp")
	filteredFallback, wasFallbackTriggered := FilterProxiesByGeo(candidates, filterExcludeAll)
	if !wasFallbackTriggered {
		t.Error("expected wasFallback=true when all candidates are excluded")
	}
	if len(filteredFallback) != len(candidates) {
		t.Errorf("expected original candidates returned on fallback, got %d", len(filteredFallback))
	}
}

func BenchmarkParseGeoFilter(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseGeoFilter("default!eu,au,cn")
	}
}

func BenchmarkFilterProxiesByGeo_50Nodes(b *testing.B) {
	candidates := make([]*Proxy, 50)
	countries := []string{"US", "JP", "IT", "DE", "FR", "AU", "SG", "KR", "GB", "CA"}
	for i := 0; i < 50; i++ {
		p := &Proxy{Name: "node", URL: "ss://test@10.0.0.1:1234"}
		p.SetCountryCode(countries[i%len(countries)])
		candidates[i] = p
	}
	filter := ParseGeoFilter("default!eu,au,cn")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = FilterProxiesByGeo(candidates, filter)
	}
}

func BenchmarkFilterProxiesByGeo_200Nodes(b *testing.B) {
	candidates := make([]*Proxy, 200)
	countries := []string{"US", "JP", "IT", "DE", "FR", "AU", "SG", "KR", "GB", "CA"}
	for i := 0; i < 200; i++ {
		p := &Proxy{Name: "node", URL: "ss://test@10.0.0.1:1234"}
		p.SetCountryCode(countries[i%len(countries)])
		candidates[i] = p
	}
	filter := ParseGeoFilter("default!eu,au,cn")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = FilterProxiesByGeo(candidates, filter)
	}
}


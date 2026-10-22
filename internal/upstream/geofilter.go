package upstream

import (
	"strings"
	"sync"
)

// geoFilterCache caches parsed GeoFilter instances to avoid re-parsing and memory allocations
// on the hot routing path.
var geoFilterCache sync.Map // map[string]*GeoFilter

// GeoFilter specifies region / country filtering for the default upstream proxy pool.
type GeoFilter struct {
	Mode    string          // "exclude" for default!..., "include" for default@...
	Regions map[string]bool // Expanded uppercase 2-letter ISO country codes
	Raw     string          // Original raw suffix string, e.g. "!eu,au,cn"
}

// RegionMacros maps high-level region codes to sets of ISO 3166-1 alpha-2 country codes.
var RegionMacros = map[string][]string{
	"EU": {
		"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
		"DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
		"PL", "PT", "RO", "SK", "SI", "ES", "SE",
	},
	"UK": {"GB"},
	"AU": {"AU"},
	"CN": {"CN"},
	"NA": {"US", "CA", "MX"},
	"AP": {"HK", "TW", "JP", "KR", "SG"},
}

// IsDefaultWithFilter reports whether the given alias specifies a default pool with a geo filter,
// e.g. "default!eu,au,cn" or "default@us,jp".
func IsDefaultWithFilter(alias string) bool {
	a := strings.ToLower(strings.TrimSpace(alias))
	return strings.HasPrefix(a, "default!") || strings.HasPrefix(a, "default@")
}

// ParseGeoFilter parses a geo filter from an alias or suffix (e.g. "default!eu,au", "!eu,au", or "@us,jp").
// Case-insensitive: uppercase, lowercase, and mixed cases are fully supported.
// Returns nil if no valid filter is present or if the raw string is empty.
// Results are cached in-memory for zero-alloc high performance on the hot path.
func ParseGeoFilter(s string) *GeoFilter {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Fast-path cache lookup using lowercased key
	cacheKey := strings.ToLower(s)
	if v, ok := geoFilterCache.Load(cacheKey); ok {
		if f, ok := v.(*GeoFilter); ok {
			return f
		}
		return nil
	}

	// Strip "default" prefix if present
	work := s
	if strings.HasPrefix(strings.ToLower(work), "default") {
		work = work[7:]
	}
	if len(work) < 2 {
		geoFilterCache.Store(cacheKey, (*GeoFilter)(nil))
		return nil
	}

	var mode string
	switch work[0] {
	case '!':
		mode = "exclude"
	case '@':
		mode = "include"
	default:
		geoFilterCache.Store(cacheKey, (*GeoFilter)(nil))
		return nil
	}

	tokens := strings.Split(work[1:], ",")
	regions := make(map[string]bool)
	for _, tok := range tokens {
		tok = strings.ToUpper(strings.TrimSpace(tok))
		if tok == "" {
			continue
		}
		// Expand macro if present (e.g. EU, NA, AP, UK)
		if list, ok := RegionMacros[tok]; ok {
			for _, cc := range list {
				regions[cc] = true
			}
		} else {
			regions[tok] = true
		}
	}

	if len(regions) == 0 {
		geoFilterCache.Store(cacheKey, (*GeoFilter)(nil))
		return nil
	}

	filter := &GeoFilter{
		Mode:    mode,
		Regions: regions,
		Raw:     s,
	}
	geoFilterCache.Store(cacheKey, filter)
	return filter
}

// String returns a compact representation of the filter.
func (f *GeoFilter) String() string {
	if f == nil {
		return ""
	}
	return f.Raw
}

// Matches reports whether a given ISO 2-letter country code matches this filter.
func (f *GeoFilter) Matches(cc string) bool {
	if f == nil || f.Mode == "" || cc == "" {
		return false
	}
	return f.Regions[strings.ToUpper(cc)]
}

// FilterProxiesByGeo filters a slice of candidate proxies by the given GeoFilter.
// If all candidates would be filtered out, it returns the original slice and wasFallback=true
// to ensure resilience against total network dropouts.
func FilterProxiesByGeo(candidates []*Proxy, filter *GeoFilter) (filtered []*Proxy, wasFallback bool) {
	if filter == nil || filter.Mode == "" || len(filter.Regions) == 0 || len(candidates) == 0 {
		return candidates, false
	}

	result := make([]*Proxy, 0, len(candidates))
	for _, p := range candidates {
		cc := EffectiveCountryCode(p)
		if filter.Mode == "exclude" {
			// In exclude mode: if the country is known and in the exclusion set, skip it!
			if cc != "" && filter.Regions[cc] {
				continue
			}
		} else if filter.Mode == "include" {
			// In include mode: only keep nodes whose country matches the allowed set
			if !filter.Regions[cc] {
				continue
			}
		}
		result = append(result, p)
	}

	if len(result) == 0 {
		// All candidates were excluded; fallback to all candidates to preserve connectivity
		return candidates, true
	}
	return result, false
}

// EffectiveCountryCode returns the proxy's probed country code (uppercase 2-letter ISO code, e.g. "US", "IT").
// Returns "" if the node has not yet completed geo probing or is unknown.
func EffectiveCountryCode(p *Proxy) string {
	if p == nil {
		return ""
	}
	cc := strings.ToUpper(strings.TrimSpace(p.CountryCode()))
	if cc == "XX" {
		return ""
	}
	return cc
}

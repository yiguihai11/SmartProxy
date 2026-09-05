package admin

import (
	"html"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// normalize mirrors the JS __norm used to build the lookup index: collapse all
// whitespace runs to a single space and trim. Keys, node text, and templates all
// compare after the same normalisation, so "Pinned: x\nPersistent" matches the
// template rendered from JS.
func normI18n(s string) string { return strings.Join(strings.Fields(s), " ") }

func TestUILangNegotiation(t *testing.T) {
	cases := []struct {
		name, accept, want string
	}{
		{"missing header defaults en", "", "en"},
		{"garbage defaults en", "not-a-language", "en"},
		{"explicit english", "en-US,en;q=0.9", "en"},
		{"simplified chinese", "zh-CN,zh;q=0.9,en;q=0.8", "zh"},
		{"zh wins over en when first", "zh-Hans,zh;q=0.9,en;q=0.8", "zh"},
		{"en-only with zh far down", "en;q=0.9,zh;q=0.1", "en"},
	}
	for _, c := range cases {
		if got := matchUILang(c.accept); got != c.want {
			t.Errorf("%s: matchUILang(%q)=%q want %q", c.name, c.accept, got, c.want)
		}
	}
}

func TestDashboardVariantInjection(t *testing.T) {
	// English source stays canonical; zh variant is pre-built and distinct.
	if !strings.Contains(dashboardHTML, `<html lang="en">`) {
		t.Error("dashboard.html must keep English as the canonical <html lang=\"en\">")
	}
	if !strings.Contains(zhDashboardHTML, `<html lang="zh-CN">`) {
		t.Error("zh variant must flip <html lang> to zh-CN")
	}
	if !strings.Contains(zhDashboardHTML, `window.SP_LANG='zh'`) {
		t.Error("zh variant must inject the zh boot dict (SP_LANG='zh')")
	}
	if strings.Contains(dashboardHTML, `window.SP_LANG='zh'`) {
		t.Error("English dashboard must NOT carry the zh boot dict")
	}
	// zhBoot must be injected before </head>, i.e. above the <body>.
	if i := strings.Index(zhDashboardHTML, `window.SP_LANG='zh'`); i < 0 || i > strings.Index(zhDashboardHTML, "<body>") {
		t.Error("zh boot script must land in <head>, before <body>")
	}
}

func TestHandleDashboardServesLangVariants(t *testing.T) {
	s := &Server{}
	do := func(accept, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if accept != "" {
			req.Header.Set("Accept-Language", accept)
		}
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "sp_lang", Value: cookie})
		}
		rec := httptest.NewRecorder()
		s.handleDashboard(rec, req)
		return rec
	}
	if rec := do("en-US,en;q=0.9", ""); rec.Code != http.StatusOK {
		t.Fatalf("en status = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), `<html lang="en">`) || strings.Contains(rec.Body.String(), `SP_LANG='zh'`) {
		t.Error("English request must receive the English variant")
	}
	if rec := do("zh-CN,zh;q=0.9", ""); !strings.Contains(rec.Body.String(), `<html lang="zh-CN">`) {
		t.Error("zh request must receive the zh variant")
	}
	// Cookie beats Accept-Language.
	if rec := do("zh-CN,zh;q=0.9", "en"); !strings.Contains(rec.Body.String(), `<html lang="en">`) {
		t.Error("sp_lang=en cookie must override a zh Accept-Language")
	}
	if rec := do("", "zh"); !strings.Contains(rec.Body.String(), `<html lang="zh-CN">`) {
		t.Error("sp_lang=zh cookie must select zh even without a zh header")
	}
	if rec := do("", ""); rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("dashboard responses must be Cache-Control: no-store (lang variant is per-request)")
	}
}

// Every literal (non-template) key must be reachable: it has to appear verbatim
// (whitespace-insensitive, HTML-entity-insensitive) somewhere in dashboard.html so
// the DOM walker or a t() call can match it. Template keys ("…{0}…") are excluded —
// they are resolved by tf() at call sites and only need their English text.
func TestI18NDictReachable(t *testing.T) {
	doc := html.UnescapeString(dashboardHTML) // "&amp;" in source reads "&" in the DOM
	noSpace := strings.Join(strings.Fields(doc), "")
	for k, v := range zhStrings {
		if strings.TrimSpace(k) == "" {
			t.Errorf("empty dict key")
		}
		if strings.TrimSpace(v) == "" {
			t.Errorf("zh value empty for key %q", k)
		}
		if strings.Contains(k, "{") {
			continue // template, resolved by tf()
		}
		if zhDynamicKeys[k] {
			continue // reachable only via runtime t()/textContent composition
		}
		flat := strings.Join(strings.Fields(k), "")
		if !strings.Contains(noSpace, flat) {
			t.Errorf("zhStrings key %q does not appear in dashboard.html — the walker can never match it", k)
		}
	}
}

// Normalised collisions would silently drop translations (later map key wins in the
// JS index). Keys that only differ by whitespace collide.
func TestI18NNoNormalisedCollision(t *testing.T) {
	seen := map[string]string{}
	for k := range zhStrings {
		n := normI18n(k)
		if prev, dup := seen[n]; dup && prev != k {
			t.Errorf("normalised collision: %q and %q both normalise to %q", prev, k, n)
		}
		seen[n] = k
	}
}

// data-i18n markers must line up 1:1 with the zhHTML whole-subtree swaps.
func TestI18NHTMLMarkersMatch(t *testing.T) {
	// markers: data-i18n="name"
	for name, body := range zhHTML {
		if strings.TrimSpace(body) == "" {
			t.Errorf("zhHTML[%q] empty", name)
		}
		if !strings.Contains(dashboardHTML, `data-i18n="`+name+`"`) {
			t.Errorf("zhHTML marker %q has no data-i18n element in dashboard.html", name)
		}
	}
	// every marker present in the doc must have a translation
	idx := dashboardHTML
	for {
		i := strings.Index(idx, `data-i18n="`)
		if i < 0 {
			break
		}
		idx = idx[i+len(`data-i18n="`):]
		j := strings.Index(idx, `"`)
		if j < 0 {
			break
		}
		mk := idx[:j]
		if _, ok := zhHTML[mk]; !ok {
			t.Errorf("dashboard.html data-i18n=%q has no zhHTML entry", mk)
		}
	}
}

// Prefix dictionary entries must be non-empty and unique. Ordering is sorted
// longest-first by zhBoot before serialisation (JS takes the first startswith
// match), so the author order in the var is deliberately cosmetic — verify the
// serialised order is what JS sees instead.
func TestI18NPrefixOrdered(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range zhPrefixes {
		if p.Pre == "" || p.Zh == "" {
			t.Errorf("empty prefix pair %q", p.Pre)
		}
		if seen[p.Pre] {
			t.Errorf("duplicate prefix %q", p.Pre)
		}
		seen[p.Pre] = true
	}
	sorted := append([]struct{ Pre, Zh string }(nil), zhPrefixes...)
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i].Pre) > len(sorted[j].Pre) })
	for i := 1; i < len(sorted); i++ {
		if len(sorted[i-1].Pre) < len(sorted[i].Pre) {
			t.Errorf("serialised prefix order not longest-first at %q before %q", sorted[i-1].Pre, sorted[i].Pre)
		}
	}
}

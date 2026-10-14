# DNS AdBlock Subscriptions

SmartProxy provides high-performance DNS-level advertising and tracker domain filtering through subscription lists (AdGuard/ABP domain rules, hosts files, and bare domain lists).

This feature operates strictly at the **DNS resolution layer**: it does not inspect HTTP payloads, TLS SNI, QUIC streams, or established TCP/UDP connections. Blocked queries return fake responses (`0.0.0.0` for A, `::` for AAAA, NOERROR, TTL 60).

---

## 1. Configuration

The feature is disabled by default. Configure it in `config.json` under `dns.adblock`:

```json
{
  "dns": {
    "enabled": true,
    "adblock": {
      "enabled": true,
      "auto_update": true,
      "cache_file": "adblock_cache.txt",
      "lists": [
        {
          "name": "AdGuard DNS filter",
          "url": "https://example.com/adguard_dns.txt",
          "enabled": true,
          "update_interval": "24h",
          "use_proxy": true
        }
      ],
      "whitelist": ["example.com"]
    }
  }
}
```

### Fields

- `enabled`: Global toggle for DNS ad filtering.
- `auto_update`: Enable periodic background updating (default: `true`).
- `cache_file`: Local compact cache path (default: `"adblock_cache.txt"`). On Android, the app provides an absolute path.
- `lists`: Array of subscription sources.
  - `name`: Human-readable identifier.
  - `url`: HTTP(S) URL to the rules list.
  - `enabled`: Toggle for this individual subscription.
  - `update_interval`: Update frequency, e.g., `"24h"`, `"12h"` (default: `"24h"`).
  - `use_proxy`: Whether to fetch via proxy upstream nodes (default: `true`).
- `whitelist`: Domain whitelist (up to 5000 items). An allowed domain exempts both the apex domain and all its subdomains.

---

## 2. Rule Syntax and Priority

### Supported Rules

- **AdGuard / ABP domain rules**: `||ads.example.com^` blocks `ads.example.com` and all subdomains (e.g., `sub.ads.example.com`).
- **ABP important rules**: `||ads.example.com^$important` preserves the domain.
- **Whitelist exceptions**: `@@||safe.example.com^` exempts the domain and all subdomains.
- **Hosts files**: `0.0.0.0 ads.example.com` or `127.0.0.1 tracker.example.com` (multiple aliases per line supported). Real-IP mappings (e.g. `1.2.3.4 a.com`) are skipped.
- **Bare domain lists**: Plain domains one per line.
- **$badfilter**: Negates matching rules regardless of evaluation order.

### Unsupported Rules (Skipped and Counted)

Element hiding rules (`##`, `#?#`, `#@#`, `#%#`), URL path patterns with `/`, regular expressions `/.../`, wildcard rules with `*`, and non-DNS options (`$third-party`, `$dnsrewrite`, etc.) are safely ignored and accounted for in the skipped statistics.

### Precedence

1. **User Static DNS Records** (`dns.static_records`): Always evaluated first and takes absolute priority over adblock and ACL.
2. **ACL Block Rules** (`internal/rules`): Evaluated before adblock.
3. **AdBlock Whitelist & @@|| Exceptions**: Exempt matching domain apex and subdomains. ACL `allow domain` rules **do not** exempt adblock filtering.
4. **AdBlock Subscriptions**: Matched via zero-allocation suffix walk.
5. **DNS Cache & Upstream Resolution**: Only queries passing filtering reach cache and upstream servers.
6. **Established Connections**: Adblock affects DNS responses only; already established connections are not terminated.

---

## 3. High Performance Matching

The matcher uses a compact hash set with reverse suffix traversal:
- **Typical lookup latency**: ~60ns/query with **0 heap allocations** and **0 locks** on the hot query path.
- **Suffix compression**: Subdomains whose parent domain is already in the set (e.g., `sub.a.com` when `a.com` is present) are eliminated during compilation.
- **Safe limits**: 8-label depth ceiling, single-label noise rejection (`localhost`, `local` etc. are hard-filtered), 32 MB single download limit, and max 500,000 active rules.

---

## 4. Android & Shizuku Architecture: Two Cores

On Android, SmartProxy runs two independent Go routing engines:
1. **Main Core** (App process, uid = `untrusted_app`): Uses `cacheDir/adblock/adblock_cache.txt`.
2. **Tethering Core** (Shizuku shell service, uid = `shell`): Uses `/data/local/tmp/smartproxy-tethering-state/adblock_cache.txt`.

**Each core fetches and caches independently**:
- Whichever core is active keeps its own filter snapshot up-to-date through its own upstream proxies.
- Hotspot users can manage subscriptions and trigger manual updates via the Tethering Core web dashboard (accessible over Wi-Fi gateway IP).
- Configuration edits made on either core persist and reload dynamically without service restart.

---

## 5. Admin API Endpoints

- `GET /adblock`: Returns operational status, subscription lists with rule/skip counts, whitelist, and TOP blocked domains.
- `POST /adblock/refresh`: Refreshes subscriptions. Body: `{"name":"..."}` (empty or omitted name refreshes all).
- `POST /adblock/save`: Adds or updates a subscription source.
- `POST /adblock/delete`: Removes a subscription source (`?name=...` or JSON body).
- `POST /adblock/toggle`: Toggles global ad blocking or individual list state (`{"enabled": true/false}`).
- `POST /adblock/whitelist`: Adds or removes a whitelist domain (`{"action": "add"|"remove", "domain": "..."}`).

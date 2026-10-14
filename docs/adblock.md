# DNS AdBlock subscriptions

SmartProxy can optionally block DNS queries using domain lists. This is a DNS-layer
feature: it does not inspect HTTP paths, TLS SNI, QUIC payloads, SOCKS streams, or
established connections, and it does not alter ACL routing decisions.

## Configuration

The feature is off by default. Add this object under `dns` in `config.json`:

```json
{
  "adblock": {
    "enabled": true,
    "subscriptions": [
      {
        "name": "example-hosts",
        "url": "https://example.org/hosts.txt",
        "enabled": true
      }
    ]
  }
}
```

Do not enable a list until you trust its source. SmartProxy does not install a default
subscription, which avoids unexpected breakage from an opinionated list.

## Supported rules

- AdGuard/ABP domain rules such as `||ads.example^`
- Domain exceptions such as `@@||safe.ads.example^`
- Hosts rows such as `0.0.0.0 ads.example` and `127.0.0.1 tracker.example`
- Comment and blank lines

Matching includes the domain apex and its subdomains. A more-specific exception
overrides a parent block rule. Static DNS records are checked first and always override
blocklists. Existing ACL block checks keep their existing priority; ACL allow rules do
not bypass AdBlock.

Path/regex rules and conditional options (for example `$third-party`, `$dnsrewrite`,
`$domain=`, and `$client=`) are not applied. Unsupported lines are counted rather than
silently treated as active rules. A list with no accepted rules is rejected, and the
last known-good cache is preserved.

## Subscription lifecycle and cache

Subscriptions are fetched asynchronously at startup and refreshed every 12 hours.
Responses are limited to 16 MiB, use HTTP ETag revalidation, and are cached as JSON in
the engine's config directory. A failed fetch or invalid list does not replace a
previous valid snapshot. DNS queries use an immutable in-memory snapshot; they do not
wait for downloads or parse lists on the hot path.

The admin dashboard has a **DNS AdBlock** page. Its API is:

- `GET /adblock/status` — enabled state, configured subscriptions and parser status.
- `POST /adblock/toggle` with `{"enabled":true}` — enable or disable filtering.
- `GET /adblock/subscriptions` — list configured subscriptions.
- `POST /adblock/subscriptions` with `{"name":"list","url":"https://…","enabled":true}` — add or update a source.
- `DELETE /adblock/subscriptions?name=list` — remove a source.
- `POST /adblock/refresh` with `{"name":"list"}` — refresh one source; an empty object refreshes all sources asynchronously.

Filtering affects DNS answers only. It does not terminate already-established connections.

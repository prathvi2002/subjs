# subjs

Fetches URLs, extracts every JavaScript file reference it can find — script
tags, inline script content, webpack/Next.js chunk manifests, dynamic
`import()`/`require()` calls, and bare module references — and recursively
scans discovered `.js`/`.mjs`/`.cjs` files for further references.

## Build

```bash
go build -o subjs .
```

## Usage

```bash
$ cat urls.txt | subjs
$ subjs -i urls.txt
$ cat hosts.txt | gau | subjs
```

Works with either a page URL (crawls HTML, script tags, and inline scripts)
or a direct `.js` URL (scans the file body directly).

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Input file containing URLs (reads stdin if omitted) | stdin |
| `-c` | Number of concurrent workers | `10` |
| `-t` | HTTP client timeout, in seconds | `30` |
| `-ua` | User-Agent to send | realistic Chrome UA |
| `-H` | Custom header `"Key: Value"`, repeatable | none |
| `-proxy` | HTTP/HTTPS proxy URL to route requests through (e.g. `http://127.0.0.1:8080`) — certificate verification is skipped, so intercepting proxies like Burp work out of the box | none |
| `-tor` | Route requests through the local Tor SOCKS5 proxy at `127.0.0.1:9050`. Takes priority over `-proxy` if both are set | `false` |
| `-version` | Print version and exit | — |

## Examples

```bash
# basic crawl
echo "https://example.com/" | subjs

# through Burp
echo "https://example.com/" | subjs -proxy http://127.0.0.1:8080

# through Tor, with a longer timeout since Tor is slow
echo "https://example.com/" | subjs -tor -t 60

# custom headers (auth, session cookies, etc.)
echo "https://example.com/" | subjs -H "Cookie: session=abc123" -H "X-Api-Key: test"
```

## What it catches

- `<script src="...">` and `<div data-script-src="...">`
- Inline `<script>` tag content (string literals, dynamic imports)
- Absolute cross-domain URLs, protocol-relative URLs, and query strings
- Bare filenames with no path prefix (e.g. sibling-module references)
- Extensionless script URLs assigned via `.src =` (e.g. `js.stripe.com/v3`)
- Webpack/Next.js chunk manifests (`_buildManifest`, `a.u=e=>...` patterns)

## Known limitations

- Static analysis only — no JS execution, so SPA routes/chunks only loaded
  conditionally at runtime (feature flags, auth state, user interaction)
  won't be found.
- Extensionless URLs not assigned via `.src=` (e.g. passed as a function
  argument instead) can be missed.

It is a modified version of [original subjs](https://github.com/lc/subjs) that can also extract JS URLs from within JS files themselves, plus several other improvements.
Original subjs works with subdomains too, BUT THIS MODIFIED VERSION IS NOT MADE IN MIND TO WORK WITH SUBDOMAINS!

# subjs

Fetches URLs, extracts every JavaScript file reference it can find - script
tags, inline script content, webpack/Next.js chunk manifests, dynamic
`import()`/`require()` calls, and bare module references. When `-depth` is
explicitly passed, it also recursively scans discovered `.js`/`.mjs`/`.cjs`
files for further references; by default (`-nodepth`) it only reports what's
directly visible on the input page/file itself. See
[Depth and `-nodepth`](#depth-and--nodepth) below.

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
| `-t` | HTTP client timeout, in seconds. Per-request only - each fetch (top-level or recursively discovered, at any depth) gets this same allowance independently; it never accumulates into a whole-recursion budget | `60` |
| `-ua` | User-Agent to send | realistic Chrome UA |
| `-H` | Custom header `"Key: Value"`, repeatable | none |
| `-proxy` | HTTP/HTTPS proxy URL to route requests through (e.g. `http://127.0.0.1:8080`) , certificate verification is skipped, so intercepting proxies like Burp work out of the box | none |
| `-tor` | Route requests through the local Tor SOCKS5 proxy at `127.0.0.1:9050`. Takes priority over `-proxy` if both are set (a notice is printed to stderr if both are set) | `false` |
| `-max-size` | Maximum response body size to read, in MB. `0` = unlimited | `50` |
| `-depth` | Further hops beyond the directly-linked scripts (which are always fetched). `0` = only report what's referenced inside those, don't fetch it. **No default** - if you don't pass `-depth` at all, `-nodepth` is in effect instead (see below). Cannot be combined with `-nodepth` | none (see `-nodepth`) |
| `-nodepth` | Don't fetch or scan **any** discovered/linked JS file at all - only report the JS URLs directly visible on the input page/file itself (`<script src>`, `<link>` preloads, the `Link` header, inline `<script>` content, etc). Equivalent to `-depth -1`. **On by default** whenever `-depth` isn't explicitly given. Cannot be combined with `-depth` | `true` (unless `-depth` is given) |
| `-scope` | Restrict crawling/reporting to a domain scope. Repeatable, or comma-separated within one flag. Only applies to URLs discovered while crawling - input URLs (stdin/`-i`) are always fetched regardless. See [Scope](#scope) below | none (unrestricted) |
| `-debug` | Print request errors and any non-200 statuses to stderr (silent otherwise). Responses are now always scanned regardless of status code - see [Non-200 responses](#non-200-responses) below | `false` |
| `-version` | Print version and exit | , |

## Scope

`-scope` takes one or more entries (repeat the flag, or comma-separate within a single value) and restricts which discovered hosts get crawled/reported.

> **Note:** this only applies to URLs *discovered while crawling* (script tags, webpack chunks, JS-in-JS references, etc). Whatever you pipe in on stdin/`-i` is always fetched regardless of `-scope` - scope only restrains what the tool goes on to chase from there.

Three kinds of entry are supported, picked automatically by shape:

| Entry | Matches |
|-------|---------|
| `example.com` | that exact host only |
| `*.example.com` | that host, plus any subdomain of it |
| `google` (no dot) | any host containing `google` anywhere, in either the domain or subdomain part - partial matches included (e.g. `google.com`, `mail.google.com`, `evilgoogle.net`) |

```bash
# only crawl example.com itself
echo "https://example.com/" | subjs -scope example.com

# example.com and all its subdomains
echo "https://example.com/" | subjs -scope "*.example.com"

# multiple domains, mixed with a wildcard, in one flag
echo "https://example.com/" | subjs -scope "example.com,*.internal.example.com"

# keyword match: anything with "acme" anywhere in the hostname
echo "https://example.com/" | subjs -scope acme
```

## Examples

```bash
# basic crawl
echo "https://example.com/" | subjs

# through Burp
echo "https://example.com/" | subjs -proxy http://127.0.0.1:8080

# through Tor - the default 60s timeout already accounts for Tor's latency,
# but bump it further still if a target's bundles are large/slow to fetch
echo "https://example.com/" | subjs -tor -t 120

# custom headers (auth, session cookies, etc.)
echo "https://example.com/" | subjs -H "Cookie: session=abc123" -H "X-Api-Key: test"

# cap response size and dig deeper into chunked bundles
echo "https://example.com/" | subjs -max-size 20 -depth 4

# scoped to a target and its subdomains, verbose
echo "https://example.com/" | subjs -scope "*.example.com" -debug

# default behavior (-nodepth): only report JS URLs visible on the page itself,
# don't fetch any of them - equivalent to explicitly passing -nodepth
echo "https://example.com/" | subjs

# explicitly opt into fetching/recursing, e.g. through Tor even if the target
# answers with a non-200 (blocked/challenge) status - the body is scanned anyway
echo "https://www.example.com/" | subjs -tor -depth 1 -debug
```

## Non-200 responses

Every fetched response is scanned for JS references regardless of its HTTP status code - a 403/404/429/503 (or anything else that isn't `200`) is scanned exactly the same as a `200`. This applies both to URLs you feed in and to JS files discovered while crawling. Many sites serve a real, JS-referencing body alongside a non-200 status (a 403 page still using the site's normal layout/scripts, a custom error page, etc.), so a non-200 status is no longer treated as a reason to skip scanning.

With `-debug`, any response whose status isn't exactly `200` is still logged to stderr, since it's often a useful signal that you hit a block/challenge page (rate limiting, a WAF, or - especially over Tor - a CDN simply refusing exit-node traffic) even though the tool went ahead and scanned the body anyway.

## Concurrency

`-c` caps the number of HTTP requests in flight at once - this applies to every fetch the tool makes, not just the input URLs you feed it. Every discovered reference (a script found inside another script, a webpack chunk, a source map, and so on, at any `-depth`) is fetched in its own goroutine and competes for the same pool of `-c` request slots, so sibling references at any depth are fetched concurrently rather than one at a time.

This matters most over a slow transport like `-tor`: a reference chain several hops deep no longer has to be walked strictly one request after another - which is also why a single slow or blocked request deep in one branch no longer prevents progress on every other branch. If you were previously seeing more (or fewer) URLs purely from raising `-t`, this was the underlying cause - `-t` itself has always been, and remains, a per-request timeout (it bounds one HTTP call, never a whole recursive chain); raising it just gave slow individual requests more room to succeed instead of timing out.

## Content-Type handling: input URLs vs. discovered URLs

These are treated differently on purpose:

- **URLs you feed in** (stdin / `-i`) are fetched and handled based on
  whatever they actually turn out to be - JS (scanned directly for further
  references) or HTML (parsed for `<script>`/`<link>`/etc.). No content type
  is required or assumed; give it a page URL or a raw `.js` URL and either
  works.
- **URLs discovered while crawling** (a `<script src>`, a webpack chunk, a
  JS-in-JS reference, an `importScripts()` argument, etc.) are always
  *reported* regardless of what they turn out to be, but are only
  **recursively fetched and scanned as JS** if the response's `Content-Type`
  header (or, failing that, the URL's extension) actually looks like
  JavaScript. This matters because a regex match inside a JS file
  occasionally isn't really a script reference at all - e.g. an analytics
  beacon or tracking-pixel URL that happens to match the `.src=` pattern -
  and such a URL can come back as `image/gif` or similar. Rather than
  regex-scanning that binary/unrelated content as if it were JS source,
  the recursive scan is simply skipped (visible via `-debug`); the URL
  itself is still printed in the output.

## Depth and `-nodepth`

`-depth` controls how many hops of *fetching* happen beyond the page's directly-linked scripts. Reporting is not gated by depth - a discovered URL is always printed the moment it's found, at any depth. `-depth` only decides whether that URL is itself fetched to look for further references inside it.

**`-depth` has no numeric default.** If you don't pass `-depth` at all, `-nodepth` is in effect instead, which is a distinct, shallower mode than any `-depth` value (including `0`) - see below. `-depth` and `-nodepth` cannot be combined; passing both is an error.

### `-depth N` (N >= 0)

Once you explicitly set `-depth`, its behavior is unchanged from before `-nodepth` existed: the page's directly-linked `<script src>`/`<link>` targets are always fetched and scanned regardless of the value you pick (that part isn't optional - it's the tool's baseline behavior once `-depth` is in play). `-depth` counts hops from there:

| `-depth` | What gets fetched | What gets reported |
|----------|--------------------|---------------------|
| `0` | The page + its directly-linked scripts only | Everything above, plus every reference found *inside* those scripts (not fetched) |
| `1` | The page + its directly-linked scripts + everything referenced inside them | All of the above, plus every reference found inside *that* next layer (not fetched) |
| `2` | One hop further than `1` | One layer further than `1` |
| `N` | `N` hops of fetching beyond the directly-linked scripts | `N+1` layers of references reported |

Worked example: `page.html` links `main.js`, which references `stripe.js`, which references `connect.js`.

- `-depth 0`: `main.js` is fetched and scanned. `stripe.js` is **reported but not fetched** - so `connect.js` is never discovered at all, since nothing scanned `stripe.js`'s contents.
- `-depth 1`: `main.js` and `stripe.js` are both fetched and scanned. `connect.js` is **reported but not fetched**.
- `-depth 2`: `main.js`, `stripe.js`, and `connect.js` are all fetched and scanned, and so on for whatever `connect.js` references.

A shared dedup map across all workers and hops means a URL is only ever fetched once regardless of how many places reference it, which is also what keeps recursion bounded even if two files reference each other.

### `-nodepth` (on by default)

`-nodepth` is shallower than even `-depth 0`: it skips fetching the directly-linked scripts entirely. Nothing discovered on the input page/file is ever fetched - only the JS URLs that are directly visible in the input itself are reported: `<script src>` attributes, `<link rel="modulepreload">`/`<link rel="preload" as="script">` hrefs, the HTTP `Link` header, `<div data-script-src>`, and references found by scanning inline `<script>` tag content directly (since that content is already present in the page you fetched - no extra request is needed to see it). It's equivalent to `-depth -1`.

Using the same worked example (`page.html` links `main.js`, which references `stripe.js`, which references `connect.js`) with `-nodepth` (the default): only `main.js` is reported. It is never fetched, so neither `stripe.js` nor `connect.js` is ever discovered.

`-nodepth` is the tool's default whenever `-depth` isn't explicitly passed. To get any of the `-depth` behaviors described above, you must pass `-depth` explicitly.

## What it catches

- `<script src="...">` and `<div data-script-src="...">`
- Inline `<script>` tag content (string literals, dynamic imports)
- Absolute cross-domain URLs, protocol-relative URLs, and query strings
- Bare filenames with no path prefix (e.g. sibling-module references)
- Extensionless script URLs assigned via `.src =` (e.g. `js.stripe.com/v3`)
- Webpack/Next.js chunk manifests (`_buildManifest`, `a.u=e=>...` patterns)

## Known limitations

- Static analysis only , no JS execution, so SPA routes/chunks only loaded
  conditionally at runtime (feature flags, auth state, user interaction)
  won't be found.
- Extensionless URLs not assigned via `.src=` (e.g. passed as a function
  argument instead) can be missed.
- Recursion is bounded by `-depth`, and is skipped entirely by `-nodepth`
  (the default) - see [Depth and `-nodepth`](#depth-and--nodepth) above for
  exactly what each value/flag fetches vs. reports. For a direct `.js` file
  input, the same budget applies starting from that file. A shared dedup
  map across all workers and hops means a URL is only ever fetched once
  regardless of how many places reference it, which is also what keeps
  recursion bounded even if two files reference each other.
- Response bodies are capped at `-max-size` (default `50` MB) to avoid
  buffering an arbitrarily large response into memory; anything beyond that
  is truncated before scanning.

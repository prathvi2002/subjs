package subjs

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/proxy"
)

const version = `1.1.0`

type SubJS struct {
	client     *http.Client
	opts       *Options
	scopeRules []scopeRule
}

const torProxyAddr = "127.0.0.1:9050"

func New(opts *Options) *SubJS {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	if opts.Tor {
		// net/http's built-in ProxyURL only understands HTTP/HTTPS
		// CONNECT proxies, not SOCKS5, so Tor's local proxy needs a
		// dedicated dialer from golang.org/x/net/proxy wired into the
		// transport's DialContext.
		dialer, err := proxy.SOCKS5("tcp", torProxyAddr, nil, proxy.Direct)
		if err != nil {
			log.Fatalf("Could not set up Tor SOCKS5 proxy at %s: %s", torProxyAddr, err)
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
		if opts.Proxy != "" {
			fmt.Fprintln(os.Stderr, "[!] both -tor and -proxy set; -tor takes priority, -proxy is ignored")
		}
	} else if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			log.Fatalf("Invalid -proxy URL %q: %s", opts.Proxy, err)
		}
		// TLSClientConfig above already sets InsecureSkipVerify, which
		// applies to the TLS handshake for HTTPS targets tunneled through
		// this proxy (e.g. Burp/mitmproxy with a self-signed CA) as well
		// as direct connections, so no extra cert handling is needed here.
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	c := &http.Client{
		Timeout:   time.Duration(opts.Timeout) * time.Second,
		Transport: transport,
	}
	return &SubJS{client: c, opts: opts, scopeRules: buildScopeRules(opts.Scope)}
}

// applyHeaders sets the User-Agent and any custom -H headers on a request.
func (s *SubJS) applyHeaders(req *http.Request) {
	if s.opts.UserAgent != "" {
		req.Header.Set("User-Agent", s.opts.UserAgent)
	}
	for _, h := range s.opts.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			continue
		}
		req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
}

// debugf logs to stderr when -debug is set, and is a no-op otherwise. Every
// silent `continue`/`return` in the fetch path (request errors, non-2xx
// status codes, body-read failures, parse failures) is otherwise
// indistinguishable from "genuinely found nothing" - which matters a lot
// when running through Tor or a flaky proxy, where CDNs frequently answer
// with a 403/429/503 challenge page instead of the real asset.
func (s *SubJS) debugf(format string, args ...interface{}) {
	if s.opts.Debug {
		log.Printf("[debug] "+format, args...)
	}
}

// readBody reads a response body, capped at opts.MaxSize bytes (0 means
// unlimited). Without this cap, io.ReadAll happily buffers an arbitrarily
// large response into memory - a target serving (or tricked into serving) a
// multi-GB file would otherwise be read in full before anything else here
// gets a chance to reject it.
func (s *SubJS) readBody(body io.Reader) ([]byte, error) {
	if s.opts.MaxSize <= 0 {
		return io.ReadAll(body)
	}
	return io.ReadAll(io.LimitReader(body, s.opts.MaxSize))
}

// ---- Scope ----

// scopeRule is one parsed -scope entry.
type scopeRule struct {
	kind  string // "exact", "wildcard", or "keyword"
	value string
}

// buildScopeRules parses -scope entries (each of which may itself be a
// comma-separated list) into match rules:
//   - "*.example.com" -> wildcard: matches example.com itself and any subdomain
//   - "example.com"    -> exact: matches that host only
//   - "google"         -> keyword: matches if "google" appears anywhere in
//     the host - subdomain or domain, partial match included - e.g.
//     "google.com", "mail.google.com", and "evilgoogle.net" all match
func buildScopeRules(entries []string) []scopeRule {
	var rules []scopeRule
	for _, entry := range entries {
		for _, part := range strings.Split(entry, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" {
				continue
			}
			switch {
			case strings.HasPrefix(part, "*."):
				rules = append(rules, scopeRule{kind: "wildcard", value: strings.TrimPrefix(part, "*.")})
			case strings.Contains(part, "."):
				rules = append(rules, scopeRule{kind: "exact", value: part})
			default:
				rules = append(rules, scopeRule{kind: "keyword", value: part})
			}
		}
	}
	return rules
}

// matchesScope checks an already-lowercased, port-stripped hostname against
// the configured scope rules. An empty rule set means "no restriction".
func matchesScope(rules []scopeRule, host string) bool {
	if len(rules) == 0 {
		return true
	}
	for _, r := range rules {
		switch r.kind {
		case "exact":
			if host == r.value {
				return true
			}
		case "wildcard":
			if host == r.value || strings.HasSuffix(host, "."+r.value) {
				return true
			}
		case "keyword":
			if strings.Contains(host, r.value) {
				return true
			}
		}
	}
	return false
}

// inScope reports whether a URL's host is within the configured -scope.
// Malformed URLs are treated as out of scope rather than silently allowed
// through. If no -scope was set, everything is in scope.
func (s *SubJS) inScope(rawURL string) bool {
	if len(s.scopeRules) == 0 {
		return true
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return false
	}
	return matchesScope(s.scopeRules, host)
}

// report is the single choke point for "we found a JS-related URL": it
// checks scope, then atomically checks-and-marks the shared dedup map, and
// only forwards genuinely new, in-scope URLs to results. seen is shared
// across every worker goroutine and every recursion depth, which both
// avoids re-fetching the same URL from two different discovery paths and
// acts as the cycle-breaker that lets bounded recursive descent (see
// fetchAndScanJS) terminate even if two JS files reference each other.
func (s *SubJS) report(u string, results chan string, seen *sync.Map) bool {
	if !s.inScope(u) {
		s.debugf("%s: out of scope, skipping", u)
		return false
	}
	if _, loaded := seen.LoadOrStore(u, true); loaded {
		return false
	}
	results <- u
	return true
}

func (s *SubJS) Run() error {
	// setup input
	var input *os.File
	var err error
	// if input file not specified then read from stdin
	if s.opts.InputFile == "" {
		input = os.Stdin
	} else {
		// otherwise read from file
		input, err = os.Open(s.opts.InputFile)
		if err != nil {
			return fmt.Errorf("Could not open input file: %s", err)
		}
		defer input.Close()
	}

	// init channels
	urls := make(chan string)
	results := make(chan string)

	// seen is the shared dedup map across all workers and all recursion
	// depths - see report() above.
	seen := &sync.Map{}

	// start workers
	var w sync.WaitGroup
	for i := 0; i < s.opts.Workers; i++ {
		w.Add(1)
		go func() {
			defer w.Done()
			s.fetch(urls, results, seen)
		}()
	}
	// setup output
	var out sync.WaitGroup
	out.Add(1)
	go func() {
		for result := range results {
			fmt.Println(result)
		}
		out.Done()
	}()
	scan := bufio.NewScanner(input)
	for scan.Scan() {
		u := scan.Text()
		if u != "" {
			// Mark input URLs as already-seen so that if the same URL is
			// later re-discovered during recursion (e.g. a page linking
			// back to itself), it isn't re-fetched a second time. Input
			// URLs are always fetched here regardless of -scope, since the
			// user supplied them explicitly - scope only filters URLs
			// discovered during crawling.
			seen.Store(u, true)
			urls <- u
		}
	}
	close(urls)
	w.Wait()
	close(results)
	out.Wait()
	return nil
}

func (s *SubJS) fetch(urls <-chan string, results chan string, seen *sync.Map) {
	for u := range urls {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			s.debugf("%s: building request failed: %s", u, err)
			continue
		}
		s.applyHeaders(req)
		resp, err := s.client.Do(req)
		if err != nil {
			s.debugf("%s: request failed: %s", u, err)
			continue
		}

		// Read the complete response, capped at -max-size.
		body, err := s.readBody(resp.Body)
		contentType := resp.Header.Get("Content-Type")
		statusCode := resp.StatusCode
		resp.Body.Close()
		if err != nil {
			s.debugf("%s: reading response body failed: %s", u, err)
			continue
		}

		// A non-2xx status is very commonly a block/challenge page (rate
		// limiting, WAF, or - especially over Tor - a CDN simply refusing
		// exit-node traffic) rather than the real asset. Scanning that
		// error body for JS references would either find nothing (silently
		// indistinguishable from a real page with no references) or, worse,
		// produce false positives from an unrelated challenge/CAPTCHA
		// script. Skip it, but only after logging so -debug can surface it.
		if statusCode < 200 || statusCode >= 300 {
			s.debugf("%s: HTTP %d, skipping", u, statusCode)
			continue
		}

		parsedURL, err := url.Parse(u)
		if err != nil {
			s.debugf("%s: parsing URL failed: %s", u, err)
			continue
		}

		// Some servers/CDNs send script preload hints via the HTTP Link
		// response header (RFC 8288) instead of, or in addition to, an
		// HTML <link> tag. Check this unconditionally, before branching
		// on whether the body itself is JS or HTML, since the header is
		// independent of the body's content type.
		s.checkLinkHeaderForScripts(resp.Header, parsedURL, results, seen, s.opts.Depth)

		// If the response itself is a JS file (by Content-Type or URL
		// suffix), scan it directly for further JS references rather
		// than trying to parse it as HTML. This covers the case where
		// the input list contains raw .js URLs, not just pages.
		if isJSResponse(u, contentType) {
			found := s.checkSourceMap(u, results, seen)
			if s.extractJSFromJS(parsedURL, string(body), results, seen, s.opts.Depth) {
				found = true
			}
			if !found {
				s.debugf("%s: scanned as JS, found no further references (no matching quoted .js/.ts/import/require/worker patterns, no source map)", u)
			}
			continue
		}

		// Try to parse as HTML
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		if err != nil {
			s.debugf("%s: HTML parse failed: %s", u, err)
			continue
		}
		htmlFound := false

		// Process script tags - using scriptTag instead of s to avoid shadowing
		doc.Find("script").Each(func(index int, scriptTag *goquery.Selection) {
			js, exists := scriptTag.Attr("src")
			if exists && js != "" {
				// Resolve the URL
				resolvedJS := resolveScriptURL(parsedURL, js)

				// Report the script
				if s.report(resolvedJS, results, seen) {
					htmlFound = true

					// Fetch and scan every discovered external script for
					// further JS references - webpack/Next.js chunk
					// manifests, absolute URLs to third-party SDKs
					// embedded as string literals, etc. - recursing up to
					// -depth further hops.
					s.fetchAndScanJS(resolvedJS, results, seen, s.opts.Depth)
					s.checkSourceMap(resolvedJS, results, seen)
				}
			}

			// Find JS references in script tag content - uses the same
			// jsRefRe/resolveScriptURL logic as extractJSFromJS so
			// absolute cross-domain URLs (e.g. a third-party SDK snippet
			// that builds a script tag from a literal like
			// "https://connect-js.stripe.com/v1.0/connect.js") aren't
			// silently dropped the way the old prefix-only check did.
			if s.scanForJSReferences(parsedURL, scriptTag.Contents().Text(), results, seen, s.opts.Depth) {
				htmlFound = true
			}
		})

		// Process <link rel="modulepreload"> and <link rel="preload"
		// as="script"> tags. Modern bundlers (Vite in particular) often
		// declare eagerly-needed chunks this way instead of - or in
		// addition to - a plain <script src>, so relying on <script>
		// alone misses them.
		doc.Find("link").Each(func(index int, linkTag *goquery.Selection) {
			href, exists := linkTag.Attr("href")
			if !exists || href == "" {
				return
			}
			rel := strings.ToLower(linkTag.AttrOr("rel", ""))
			as := strings.ToLower(linkTag.AttrOr("as", ""))
			if rel != "modulepreload" && !(rel == "preload" && as == "script") {
				return
			}

			resolvedJS := resolveScriptURL(parsedURL, href)
			if s.report(resolvedJS, results, seen) {
				htmlFound = true
				s.fetchAndScanJS(resolvedJS, results, seen, s.opts.Depth)
				s.checkSourceMap(resolvedJS, results, seen)
			}
		})

		// Process div tags with data-script-src attribute - using divTag instead of s
		doc.Find("div").Each(func(index int, divTag *goquery.Selection) {
			js, exists := divTag.Attr("data-script-src")
			if exists && js != "" {
				resolvedJS := resolveScriptURL(parsedURL, js)
				if s.report(resolvedJS, results, seen) {
					htmlFound = true
				}
			}
		})

		if !htmlFound {
			s.debugf("%s: scanned as HTML, found no <script>/<link>/<div data-script-src> references", u)
		}
	}
}

// isJSResponse decides whether a fetched response should be treated as a
// JavaScript file rather than HTML. It checks the Content-Type header
// first, then falls back to the URL's file extension (many CDNs and dev
// servers omit or mislabel Content-Type for static assets).
//
// This also covers raw TypeScript/JSX source (.ts/.tsx/.jsx) for cases
// where a dev server or misconfigured build serves uncompiled source
// directly. Note: ".ts" collides with the MPEG-TS video segment
// extension used by HLS playlists - a video chunk fed in directly as
// input would be misclassified here too, but the cost is just a wasted
// regex scan over binary data, not a false result (binary content won't
// match jsRefRe), so the trade-off favors catching exposed TS source.
func isJSResponse(u string, contentType string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") || strings.Contains(ct, "typescript") {
		return true
	}

	path := u
	if i := strings.IndexAny(path, "?#"); i != -1 {
		path = path[:i]
	}
	for _, ext := range []string{".js", ".mjs", ".cjs", ".tsx", ".jsx", ".ts"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// jsRefRe picks up JS-to-JS references not covered by the Next.js/webpack
// manifest patterns in ProcessWebpackFile: dynamic import()/require() calls,
// fully-qualified cross-domain URLs, relative path string literals, and
// bare filenames with no path prefix at all (e.g. a module map like
// {kids:"kids.js"} that loads siblings of the current script by name).
// Query strings and fragments after the extension are captured too (e.g.
// "main.js?v=123").
//
// jsExt is the shared extension alternation for jsRefRe. TypeScript/JSX
// (.ts/.tsx/.jsx) are included alongside .js/.mjs/.cjs to catch raw
// source exposed by dev servers or misconfigured builds. ".ts" is a
// generic-enough word ending that it carries a small false-positive
// risk (e.g. an unrelated quoted string that happens to end in
// "...ts"), but that risk is limited to the "bare filename" and
// relative-path alternatives below, and a stray extra reported URL is
// low-cost compared to missing real exposed TypeScript source.
const jsExt = `(?:js|mjs|cjs|ts|tsx|jsx)`

var jsRefRe = regexp.MustCompile(
	`(?:import|require)\(\s*["']([^"'()]+\.` + jsExt + `(?:[?#][^"']*)?)["']\s*\)` +
		`|["'](https?://[^"'\s]+\.` + jsExt + `(?:[?#][^"']*)?)["']` +
		`|["'](\.{0,2}/[^"'\s]+\.` + jsExt + `(?:[?#][^"']*)?)["']` +
		`|["']([A-Za-z0-9_.-]+\.` + jsExt + `(?:[?#][^"']*)?)["']`,
)

// looksLikeWebpackRuntime does a cheap content-based check for whether a JS
// file is actually a webpack/Next.js chunk-loading runtime, as opposed to
// arbitrary application JS. The chunk-manifest regexes in
// ProcessWebpackFile are shaped around specific Next.js runtime patterns
// (e.g. `N===e?"path":...`) that unfortunately also match ordinary
// switch/ternary chains in unrelated minified code, so we only run them
// when there's real evidence this is a webpack runtime file.
func looksLikeWebpackRuntime(content string) bool {
	return strings.Contains(content, "__webpack_require__") ||
		strings.Contains(content, "webpackChunk") ||
		strings.Contains(content, "webpackJsonp") ||
		strings.Contains(content, "_buildManifest")
}

// isPlausibleChunkPath filters out matches that are clearly not real file
// paths - e.g. arbitrary string literals from ternary/switch expressions
// that the loose chunk-manifest regexes above can mistakenly pick up in
// non-webpack-runtime code (things like "This Week", "rgb(", "[object
// Undefined]").
func isPlausibleChunkPath(path string) bool {
	if path == "" || !strings.HasSuffix(path, ".js") || strings.ContainsAny(path, " ()[]{}\"'") {
		return false
	}
	for _, r := range path {
		if !(r == '/' || r == '.' || r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// fetchAndScanJS fetches a discovered external script and scans its body
// for further JS references, using the same webpack/Next.js chunk-manifest
// logic and generic reference regex used for directly-provided .js input.
// depth is the number of further hops still allowed after this one: any
// reference found inside jsURL's body is recursively fetched-and-scanned
// only if depth > 0, and the recursive call passes depth-1. Combined with
// the shared `seen` dedup map, this bounds total work to (distinct JS URLs
// discovered) rather than depth^branching-factor, and guarantees
// termination even if two files reference each other.
//
// Unlike the top-level fetch() (which handles whatever content type a
// user-supplied input URL turns out to be, JS or HTML), every URL that
// reaches this function was *discovered* while crawling - a <script src>,
// a webpack chunk, a JS-in-JS reference, etc. - on the assumption that it's
// actually JavaScript. That assumption isn't always true: a JS file can
// contain a string that merely looks like a script reference but is
// actually, say, an analytics beacon or tracking-pixel URL (this is exactly
// what happened with a Stripe beacon URL matched by scriptSrcAssignRe,
// which turned out to serve image/gif). So the Content-Type is checked
// here via isJSResponse before scanning: if it doesn't look like JS, the
// fetch is simply skipped rather than regex-scanning arbitrary binary/HTML
// content as if it were JS source. The URL itself was already reported by
// the caller via report() regardless - only the *recursive scan* of its
// body is skipped.
// Fetch errors are silently ignored - the caller has already reported the
// script's own URL, so a failure to recurse into it just means fewer
// downstream references, not a lost result.
func (s *SubJS) fetchAndScanJS(jsURL string, results chan string, seen *sync.Map, depth int) {
	req, err := http.NewRequest("GET", jsURL, nil)
	if err != nil {
		s.debugf("%s: building request failed: %s", jsURL, err)
		return
	}
	s.applyHeaders(req)
	resp, err := s.client.Do(req)
	if err != nil {
		s.debugf("%s: request failed: %s", jsURL, err)
		return
	}
	body, err := s.readBody(resp.Body)
	contentType := resp.Header.Get("Content-Type")
	statusCode := resp.StatusCode
	resp.Body.Close()
	if err != nil {
		s.debugf("%s: reading response body failed: %s", jsURL, err)
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		s.debugf("%s: HTTP %d, skipping", jsURL, statusCode)
		return
	}
	if !isJSResponse(jsURL, contentType) {
		s.debugf("%s: Content-Type %q / URL suffix doesn't look like JS, skipping recursive scan", jsURL, contentType)
		return
	}

	baseURL, err := url.Parse(jsURL)
	if err != nil {
		s.debugf("%s: parsing URL failed: %s", jsURL, err)
		return
	}

	s.extractJSFromJS(baseURL, string(body), results, seen, depth)
}

// linkHeaderEntryRe splits an RFC 8288 Link header value into individual
// link-value segments: a URL in angle brackets followed by zero or more
// `; param="value"` pairs.
var linkHeaderEntryRe = regexp.MustCompile(`<([^>]+)>((?:\s*;\s*[a-zA-Z]+\s*=\s*"?[^,";]*"?)*)`)
var linkHeaderParamRe = regexp.MustCompile(`([a-zA-Z]+)\s*=\s*"?([^,";]*)"?`)

// checkLinkHeaderForScripts parses the HTTP Link response header (RFC
// 8288) for rel=modulepreload or rel=preload;as=script entries. Some
// servers/CDNs send script hints this way as a header rather than (or
// alongside) an HTML <link> tag, which the HTML-only <link> scan in
// fetch() would otherwise miss entirely. Uses the raw header map instead
// of http.Header.Values (added in a later Go stdlib version than this
// module targets) for broader toolchain compatibility.
func (s *SubJS) checkLinkHeaderForScripts(header http.Header, baseURL *url.URL, results chan string, seen *sync.Map, depth int) {
	for _, headerValue := range header[http.CanonicalHeaderKey("Link")] {
		for _, entry := range linkHeaderEntryRe.FindAllStringSubmatch(headerValue, -1) {
			href := entry[1]
			params := entry[2]

			rel := ""
			as := ""
			for _, p := range linkHeaderParamRe.FindAllStringSubmatch(params, -1) {
				switch strings.ToLower(p[1]) {
				case "rel":
					rel = strings.ToLower(strings.TrimSpace(p[2]))
				case "as":
					as = strings.ToLower(strings.TrimSpace(p[2]))
				}
			}
			if rel != "modulepreload" && !(rel == "preload" && as == "script") {
				continue
			}

			resolvedJS := resolveScriptURL(baseURL, href)
			if s.report(resolvedJS, results, seen) {
				s.fetchAndScanJS(resolvedJS, results, seen, depth)
				s.checkSourceMap(resolvedJS, results, seen)
			}
		}
	}
}

// checkSourceMap probes for a source map sibling of a discovered JS file
// (e.g. "app.js" -> "app.js.map"). Source maps left exposed in production
// are high-value: they reconstruct unminified source, original variable
// names, comments, and sometimes hardcoded secrets/endpoints. This is an
// inference (URL suffix + content sniff), not a text match against
// jsRefRe, since the ".map" reference is essentially never a literal
// string elsewhere in the page/script - it just conventionally exists
// alongside the JS file it maps.
//
// Errors and non-200s just mean no source map was found - the common
// case, not a failure - so they don't affect the exit code or normal
// output, but they are surfaced via debugf when -debug is set. Returns
// true if a source map was found and newly reported.
func (s *SubJS) checkSourceMap(jsURL string, results chan string, seen *sync.Map) bool {
	mapURL := jsURL + ".map"
	if _, exists := seen.Load(mapURL); exists {
		return false
	}

	req, err := http.NewRequest("GET", mapURL, nil)
	if err != nil {
		s.debugf("%s: building request failed: %s", mapURL, err)
		return false
	}
	s.applyHeaders(req)
	resp, err := s.client.Do(req)
	if err != nil {
		s.debugf("%s: request failed: %s", mapURL, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.debugf("%s: HTTP %d, no source map", mapURL, resp.StatusCode)
		return false
	}

	body, err := s.readBody(resp.Body)
	if err != nil {
		s.debugf("%s: reading response body failed: %s", mapURL, err)
		return false
	}

	if looksLikeSourceMap(string(body)) {
		return s.report(mapURL, results, seen)
	}
	s.debugf("%s: HTTP 200 but doesn't look like a source map", mapURL)
	return false
}

// looksLikeSourceMap does a cheap content sniff to confirm a response is
// an actual source map JSON object rather than a soft-404 (many servers
// return HTTP 200 with an HTML/JSON error body for any path), by
// requiring both the "sources" and "mappings" keys that every real
// source map contains per the Source Map spec.
func looksLikeSourceMap(content string) bool {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "{") {
		return false
	}
	return strings.Contains(content, `"sources"`) && strings.Contains(content, `"mappings"`)
}

// workerRefRe catches JS files loaded via Worker/SharedWorker instantiation
// or a service worker registration - `new Worker("worker.js")`,
// `new SharedWorker("shared.js")`, `navigator.serviceWorker.register("sw.js")`.
// None of these look like an import()/require() call or a `.src=`
// assignment, so they need a dedicated pattern. Only the first argument
// is captured, which covers the overwhelmingly common single-string-URL
// usage of all three APIs.
var workerRefRe = regexp.MustCompile(
	`(?:new\s+(?:Shared)?Worker\s*\(|navigator\.serviceWorker\.register\s*\()\s*["']([^"']+)["']`,
)

// importScriptsCallRe finds the argument list of importScripts() calls
// inside worker files. Unlike Worker/register above, importScripts
// accepts multiple comma-separated string arguments (e.g.
// importScripts("a.js", "b.js")), so the whole call body is captured
// here and every quoted string inside it is pulled out separately by
// quotedStringRe in scanForJSReferences.
var importScriptsCallRe = regexp.MustCompile(`importScripts\s*\(([^)]*)\)`)
var quotedStringRe = regexp.MustCompile(`["']([^"']+)["']`)

// scriptSrcAssignRe catches script-injection patterns like
// `s.src = "https://js.stripe.com/v3"` regardless of file extension.
// Unlike jsRefRe, this doesn't require a trailing ".js" - some CDNs (Stripe,
// Google Tag Manager, etc.) serve their SDK from extensionless paths. This
// is a noisier heuristic than jsRefRe (any ".src=" assignment could in
// principle point at a non-script resource), but ".src" assignment is a
// strong enough signal in practice to be worth the trade-off for recon
// completeness.
var scriptSrcAssignRe = regexp.MustCompile(`\.src\s*=\s*["'](https?://[^"'\s]+|/[^"'\s]+|\.{1,2}/[^"'\s]+)["']`)

// jsUnicodeEscapeRe matches literal \uXXXX (and \u{X...} ES6 code-point)
// escape sequences as they appear in a file's raw text.
var jsUnicodeEscapeRe = regexp.MustCompile(`\\u\{?([0-9a-fA-F]{4,6})\}?`)

// jsHexEscapeRe matches literal \xXX hex escapes (e.g. \x22 for '"').
var jsHexEscapeRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// htmlHexEntityRe/htmlNumericEntityRe match HTML character references
// (e.g. &#x22; or &#34; for '"'), which show up when a URL is embedded in
// an HTML attribute or server-rendered template rather than a JS string.
var htmlHexEntityRe = regexp.MustCompile(`&#[xX]([0-9a-fA-F]+);`)
var htmlNumericEntityRe = regexp.MustCompile(`&#(\d+);`)

// htmlNamedEntityReplacer covers the small set of named HTML entities that
// matter for URL/quote reconstruction - not the full HTML5 entity table,
// just the ones that would otherwise break a quote or a URL's own
// separators (&amp; is extremely common inside query strings).
var htmlNamedEntityReplacer = strings.NewReplacer(
	"&quot;", `"`, "&apos;", "'", "&#39;", "'", "&amp;", "&", "&lt;", "<", "&gt;", ">",
)

// decodeCommonJSEscapes reverses the handful of encoding schemes real
// sites actually use to embed a URL/JSON blob inside a JS string or HTML
// attribute without it clashing with the surrounding delimiters: unicode
// escapes (\u0022), hex escapes (\x22), and HTML character references
// (&#x22; / &#34; / &quot;). None of the regexes elsewhere in this file
// look past a literal '"'/'\'' character, so a reference hidden behind any
// of these is otherwise completely invisible - this is exactly what
// happened with Klaviyo's \u0022-encoded chunk manifest.
//
// This only ever produces a scanning copy of a file's content - never
// written back out or executed - so there's no correctness requirement
// beyond "makes hidden references visible to the regexes below". The
// whole pass runs twice to unwrap simple double-encoding (e.g. a JSON
// blob that's itself been JSON-stringified once more) without an
// unbounded loop.
//
// What this deliberately does NOT attempt, because no regex can: strings
// built at runtime via concatenation ("ht"+"tps://"+"x.js"),
// String.fromCharCode()/character-array construction, or base64-encoded
// URLs decoded at runtime. Those require actually executing the JS -
// that's the headless-browser (-render) feature discussed separately, not
// a pattern-matching fix.
func decodeCommonJSEscapes(content string) string {
	decodeOnce := func(s string) string {
		s = jsUnicodeEscapeRe.ReplaceAllStringFunc(s, func(m string) string {
			hex := jsUnicodeEscapeRe.FindStringSubmatch(m)[1]
			codepoint, err := strconv.ParseInt(hex, 16, 32)
			if err != nil {
				return m
			}
			return string(rune(codepoint))
		})
		s = jsHexEscapeRe.ReplaceAllStringFunc(s, func(m string) string {
			hex := jsHexEscapeRe.FindStringSubmatch(m)[1]
			codepoint, err := strconv.ParseInt(hex, 16, 32)
			if err != nil {
				return m
			}
			return string(rune(codepoint))
		})
		s = htmlHexEntityRe.ReplaceAllStringFunc(s, func(m string) string {
			hex := htmlHexEntityRe.FindStringSubmatch(m)[1]
			codepoint, err := strconv.ParseInt(hex, 16, 32)
			if err != nil {
				return m
			}
			return string(rune(codepoint))
		})
		s = htmlNumericEntityRe.ReplaceAllStringFunc(s, func(m string) string {
			dec := htmlNumericEntityRe.FindStringSubmatch(m)[1]
			codepoint, err := strconv.ParseInt(dec, 10, 32)
			if err != nil {
				return m
			}
			return string(rune(codepoint))
		})
		return htmlNamedEntityReplacer.Replace(s)
	}
	return decodeOnce(decodeOnce(content))
}

// scanForJSReferences runs jsRefRe (plus the .src=, Worker, and
// importScripts patterns) over arbitrary text (a full JS file body, or the
// text content of an inline <script> tag), reports every resolved match via
// report (scope + dedup), and - if depth > 0 - fetches and recursively
// scans each newly-found reference at depth-1. Returns true if anything new
// was found.
func (s *SubJS) scanForJSReferences(baseURL *url.URL, content string, results chan string, seen *sync.Map, depth int) bool {
	// Decode escape sequences first (see decodeCommonJSEscapes) so URLs
	// hidden behind \u0022, \x22, &#x22;, &quot;, etc. become visible to
	// every pass below, exactly as if they'd been written with literal
	// quotes.
	content = decodeCommonJSEscapes(content)

	found := false
	handle := func(js string) {
		if js == "" {
			return
		}
		resolved := resolveScriptURL(baseURL, js)
		if s.report(resolved, results, seen) {
			found = true
			if depth > 0 {
				s.fetchAndScanJS(resolved, results, seen, depth-1)
				s.checkSourceMap(resolved, results, seen)
			}
		}
	}

	for _, m := range jsRefRe.FindAllStringSubmatch(content, -1) {
		js := m[1]
		if js == "" {
			js = m[2]
		}
		if js == "" {
			js = m[3]
		}
		if js == "" {
			js = m[4]
		}
		handle(js)
	}

	// Second pass: catch extensionless script URLs (e.g. Stripe's
	// "https://js.stripe.com/v3") via the .src= assignment pattern, which
	// jsRefRe's .js-suffix requirement would otherwise miss entirely.
	for _, m := range scriptSrcAssignRe.FindAllStringSubmatch(content, -1) {
		handle(m[1])
	}

	// Third pass: Worker/SharedWorker instantiation and service worker
	// registration - a JS file loaded this way doesn't match any of the
	// import()/require()/.src= patterns above.
	for _, m := range workerRefRe.FindAllStringSubmatch(content, -1) {
		handle(m[1])
	}

	// Fourth pass: importScripts() calls, which can take multiple
	// comma-separated string arguments rather than just one.
	for _, call := range importScriptsCallRe.FindAllStringSubmatch(content, -1) {
		for _, arg := range quotedStringRe.FindAllStringSubmatch(call[1], -1) {
			handle(arg[1])
		}
	}

	return found
}

// extractJSFromJS scans the body of a JS file for further JS references,
// both via the existing webpack/Next.js chunk-manifest patterns and via a
// simpler relative-path regex, resolving everything against baseURL, and
// recursing (bounded by depth) into whatever it finds. Returns true if
// anything new was found.
func (s *SubJS) extractJSFromJS(baseURL *url.URL, content string, results chan string, seen *sync.Map, depth int) bool {
	found := false

	// Only run the manifest/chunk extraction if this actually looks like a
	// webpack/Next.js runtime file. Running it unconditionally on any JS
	// produces false positives, since the chunk regexes match generic
	// ternary/switch shapes that show up in unrelated minified code.
	if looksLikeWebpackRuntime(content) {
		if s.ProcessWebpackFile(baseURL.String(), content, results, seen, depth) {
			found = true
		}
	}

	if s.scanForJSReferences(baseURL, content, results, seen, depth) {
		found = true
	}

	return found
}

var jsPathRe = regexp.MustCompile(`([A-Za-z0-9_\-./]+\.js)\b`)

// ProcessWebpackFile extracts all JavaScript chunk paths from a webpack
// bundle, reports each newly-found one (scope + dedup via report), and - if
// depth > 0 - fetches and recursively scans each at depth-1. Returns true
// if anything new was found.
func (s *SubJS) ProcessWebpackFile(webpackURL string, content string, results chan string, seen *sync.Map, depth int) bool {
	baseURL, err := url.Parse(webpackURL)
	if err != nil {
		return false
	}

	found := false

	// Ensure path has _next/ prefix if not already present
	ensureNextPrefix := func(path string) string {
		if !strings.HasPrefix(path, "/_next/") && !strings.HasPrefix(path, "_next/") {
			if strings.HasPrefix(path, "/") {
				return "/_next" + path
			}
			return "/_next/" + path
		}
		return path
	}

	emit := func(resolvedURL string) {
		if s.report(resolvedURL, results, seen) {
			found = true
			if depth > 0 {
				s.fetchAndScanJS(resolvedURL, results, seen, depth-1)
				s.checkSourceMap(resolvedURL, results, seen)
			}
		}
	}

	// Pattern 1: Extract direct chunk references
	// Example: a.u=e=>2986===e?"static/chunks/2986-2488e3e4a13aed5b.js"
	directChunkPattern := regexp.MustCompile(`(\d+)===e\?"([^"]+)"`)
	for _, match := range directChunkPattern.FindAllStringSubmatch(content, -1) {
		if !isPlausibleChunkPath(match[2]) {
			continue
		}
		chunkPath := ensureNextPrefix(match[2])
		emit(resolveScriptURL(baseURL, chunkPath))
	}

	// Pattern 2: Complex mapping using two dictionaries
	// Example: "static/chunks/"+(({1027:"4b26d002",...})[e]||e)+"."+({142:"b1a9bae1a2949d82",...})[e]+".js"
	complexPattern := regexp.MustCompile(`"(static/chunks/)"\+\(\({([^}]+)}\)\[e\]\|\|e\)\+"\."\+\({([^}]+)}\)\[e\]\+"\.js"`)
	complexMatches := complexPattern.FindStringSubmatch(content)

	if len(complexMatches) > 3 {
		basePath := complexMatches[1]
		idMapStr := complexMatches[2]
		hashMapStr := complexMatches[3]

		// Parse ID map (maps IDs to prefixes)
		idMap := parseJSMap(idMapStr)

		// Parse hash map (maps IDs to hashes)
		hashMap := parseJSMap(hashMapStr)

		// Generate chunk URLs for each hash entry
		for id, hash := range hashMap {
			var chunkName string
			if namedID, ok := idMap[id]; ok {
				chunkName = namedID
			} else {
				chunkName = id
			}

			chunkPath := basePath + chunkName + "." + hash + ".js"
			chunkPath = ensureNextPrefix(chunkPath)
			emit(resolveScriptURL(baseURL, chunkPath))
		}
	}

	// Pattern 3: Look for a.p (public path) + a.u (chunk URL) patterns
	// Example: a.p+"static/chunks/pages/about-12345.js"
	publicPathPattern := regexp.MustCompile(`a\.p\+"([^"]+\.js)"`)
	for _, match := range publicPathPattern.FindAllStringSubmatch(content, -1) {
		chunkPath := match[1]
		// For this pattern, we use _next/ directly since it's already handled in resolveScriptURL
		emit(resolveScriptURL(baseURL, ensureNextPrefix(chunkPath)))
	}

	// Pattern 4: Match a.u function that maps IDs to file paths
	// Example: a.u=e=>2986===e?"static/chunks/2986-2488e3e4a13aed5b.js":7699===e?"static/chunks/...
	auFunctionPattern := regexp.MustCompile(`a\.u=e=>([^}]+)`)
	auMatches := auFunctionPattern.FindStringSubmatch(content)
	if len(auMatches) > 1 {
		auContent := auMatches[1]

		// Extract each condition and path
		chunkPattern := regexp.MustCompile(`(\d+)===e\?"([^"]+)"`)
		for _, match := range chunkPattern.FindAllStringSubmatch(auContent, -1) {
			if !isPlausibleChunkPath(match[2]) {
				continue
			}
			chunkPath := ensureNextPrefix(match[2])
			emit(resolveScriptURL(baseURL, chunkPath))
		}
	}

	if strings.Contains(webpackURL, "_buildManifest") {
		paths := jsPathRe.FindAllString(content, -1)
		for _, path := range paths {
			emit(resolveScriptURL(baseURL, "_next/"+path))
		}
	}

	return found
}

// parseJSMap extracts key-value pairs from JavaScript object literal strings
func parseJSMap(jsMapStr string) map[string]string {
	result := make(map[string]string)

	// Find all key-value pairs with regex
	// Format: 142:"b1a9bae1a2949d82"
	pairPattern := regexp.MustCompile(`(\d+):"([^"]+)"`)
	for _, match := range pairPattern.FindAllStringSubmatch(jsMapStr, -1) {
		key := match[1]
		value := match[2]
		result[key] = value
	}

	return result
}

// resolveScriptURL resolves a script path relative to a base URL
func resolveScriptURL(baseURL *url.URL, path string) string {
	// Canonicalize Next.js-style root-relative paths that omit the
	// leading slash so they resolve against the host root rather than
	// the current directory.
	if strings.HasPrefix(path, "_next/") {
		path = "/" + path
	}

	ref, err := url.Parse(path)
	if err != nil {
		// Not parseable as a URL/reference at all - return as-is rather
		// than silently dropping or corrupting it.
		return path
	}

	// url.URL.ResolveReference implements RFC 3986 reference resolution:
	// absolute URLs (with a scheme) pass through unchanged, protocol-
	// relative references ("//host/path") inherit the base's scheme,
	// root-relative and dot-relative paths resolve against the base's
	// host/path - and query strings and fragments are preserved
	// correctly in every case, unlike manual string concatenation.
	return baseURL.ResolveReference(ref).String()
}

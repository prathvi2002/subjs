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
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/proxy"
)

const version = `1.0.2`

type SubJS struct {
	client *http.Client
	opts   *Options
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
	}

	c := &http.Client{
		Timeout:   time.Duration(opts.Timeout) * time.Second,
		Transport: transport,
	}
	return &SubJS{client: c, opts: opts}
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

	// start workers
	var w sync.WaitGroup
	for i := 0; i < s.opts.Workers; i++ {
		w.Add(1)
		go func() {
			s.fetch(urls, results)
			w.Done()
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
			urls <- u
		}
	}
	close(urls)
	w.Wait()
	close(results)
	out.Wait()
	return nil
}

func (s *SubJS) fetch(urls <-chan string, results chan string) {
	// Create a set to track processed URLs
	processedURLs := make(map[string]bool)

	for u := range urls {
		if processedURLs[u] {
			continue // Skip already processed URLs
		}
		processedURLs[u] = true

		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		if s.opts.UserAgent != "" {
			req.Header.Add("User-Agent", s.opts.UserAgent)
		}
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}

		// Read the complete response
		body, err := io.ReadAll(resp.Body)
		contentType := resp.Header.Get("Content-Type")
		resp.Body.Close()
		if err != nil {
			continue
		}

		parsedURL, err := url.Parse(u)
		if err != nil {
			continue
		}

		// If the response itself is a JS file (by Content-Type or URL
		// suffix), scan it directly for further JS references rather
		// than trying to parse it as HTML. This covers the case where
		// the input list contains raw .js URLs, not just pages.
		if isJSResponse(u, contentType) {
			s.extractJSFromJS(parsedURL, string(body), results, processedURLs)
			continue
		}

		// Try to parse as HTML
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		if err != nil {
			continue
		}

		// Process script tags - using scriptTag instead of s to avoid shadowing
		doc.Find("script").Each(func(index int, scriptTag *goquery.Selection) {
			js, exists := scriptTag.Attr("src")
			if exists && js != "" {
				// Resolve the URL
				resolvedJS := resolveScriptURL(parsedURL, js)

				// Report the script
				if !processedURLs[resolvedJS] {
					results <- resolvedJS
					processedURLs[resolvedJS] = true

					// Fetch and scan every discovered external script for
					// further JS references - webpack/Next.js chunk
					// manifests, absolute URLs to third-party SDKs
					// embedded as string literals, etc. Previously this
					// only happened for URLs whose filename happened to
					// contain "webpack"/"bundle"/"chunks", which missed
					// ordinary bundle filenames like "main.<hash>.js".
					s.fetchAndScanJS(resolvedJS, results, processedURLs)
				}
			}

			// Find JS references in script tag content - uses the same
			// jsRefRe/resolveScriptURL logic as extractJSFromJS so
			// absolute cross-domain URLs (e.g. a third-party SDK snippet
			// that builds a script tag from a literal like
			// "https://connect-js.stripe.com/v1.0/connect.js") aren't
			// silently dropped the way the old prefix-only check did.
			scanForJSReferences(parsedURL, scriptTag.Contents().Text(), results, processedURLs)
		})

		// Process div tags with data-script-src attribute - using divTag instead of s
		doc.Find("div").Each(func(index int, divTag *goquery.Selection) {
			js, exists := divTag.Attr("data-script-src")
			if exists && js != "" {
				resolvedJS := resolveScriptURL(parsedURL, js)
				if !processedURLs[resolvedJS] {
					results <- resolvedJS
					processedURLs[resolvedJS] = true
				}
			}
		})
	}
}

// isJSResponse decides whether a fetched response should be treated as a
// JavaScript file rather than HTML. It checks the Content-Type header
// first, then falls back to the URL's file extension (many CDNs and dev
// servers omit or mislabel Content-Type for static assets).
func isJSResponse(u string, contentType string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return true
	}

	path := u
	if i := strings.IndexAny(path, "?#"); i != -1 {
		path = path[:i]
	}
	return strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs")
}

// jsRefRe picks up JS-to-JS references not covered by the Next.js/webpack
// manifest patterns in ProcessWebpackFile: dynamic import()/require() calls,
// fully-qualified cross-domain URLs, and relative path string literals.
// Query strings and fragments after ".js" are captured too (e.g.
// "main.js?v=123"), not just the bare filename.
var jsRefRe = regexp.MustCompile(
	`(?:import|require)\(\s*["']([^"'()]+\.js(?:[?#][^"']*)?)["']\s*\)` +
		`|["'](https?://[^"'\s]+\.js(?:[?#][^"']*)?)["']` +
		`|["'](\.{0,2}/[^"'\s]+\.js(?:[?#][^"']*)?)["']`,
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
// Fetch errors are silently ignored - the caller has already reported the
// script's own URL, so a failure to recurse into it just means fewer
// downstream references, not a lost result.
func (s *SubJS) fetchAndScanJS(jsURL string, results chan string, processedURLs map[string]bool) {
	req, err := http.NewRequest("GET", jsURL, nil)
	if err != nil {
		return
	}
	if s.opts.UserAgent != "" {
		req.Header.Add("User-Agent", s.opts.UserAgent)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	baseURL, err := url.Parse(jsURL)
	if err != nil {
		return
	}

	content := string(body)
	if looksLikeWebpackRuntime(content) {
		s.ProcessWebpackFile(jsURL, content, results)
	}
	scanForJSReferences(baseURL, content, results, processedURLs)
}

// scriptSrcAssignRe catches script-injection patterns like
// `s.src = "https://js.stripe.com/v3"` regardless of file extension.
// Unlike jsRefRe, this doesn't require a trailing ".js" - some CDNs (Stripe,
// Google Tag Manager, etc.) serve their SDK from extensionless paths. This
// is a noisier heuristic than jsRefRe (any ".src=" assignment could in
// principle point at a non-script resource), but ".src" assignment is a
// strong enough signal in practice to be worth the trade-off for recon
// completeness.
var scriptSrcAssignRe = regexp.MustCompile(`\.src\s*=\s*["'](https?://[^"'\s]+|/[^"'\s]+|\.{1,2}/[^"'\s]+)["']`)

// scanForJSReferences runs jsRefRe over arbitrary text (a full JS file body,
// or the text content of an inline <script> tag) and forwards every
// resolved match to results, deduping against processedURLs.
func scanForJSReferences(baseURL *url.URL, content string, results chan string, processedURLs map[string]bool) {
	for _, m := range jsRefRe.FindAllStringSubmatch(content, -1) {
		js := m[1]
		if js == "" {
			js = m[2]
		}
		if js == "" {
			js = m[3]
		}
		if js == "" {
			continue
		}

		resolved := resolveScriptURL(baseURL, js)
		if !processedURLs[resolved] {
			results <- resolved
			processedURLs[resolved] = true
		}
	}

	// Second pass: catch extensionless script URLs (e.g. Stripe's
	// "https://js.stripe.com/v3") via the .src= assignment pattern, which
	// jsRefRe's .js-suffix requirement would otherwise miss entirely.
	for _, m := range scriptSrcAssignRe.FindAllStringSubmatch(content, -1) {
		js := m[1]
		if js == "" {
			continue
		}

		resolved := resolveScriptURL(baseURL, js)
		if !processedURLs[resolved] {
			results <- resolved
			processedURLs[resolved] = true
		}
	}
}

// extractJSFromJS scans the body of a JS file for further JS references,
// both via the existing webpack/Next.js chunk-manifest patterns and via a
// simpler relative-path regex, resolving everything against baseURL.
func (s *SubJS) extractJSFromJS(baseURL *url.URL, content string, results chan string, processedURLs map[string]bool) {
	// Only run the manifest/chunk extraction if this actually looks like a
	// webpack/Next.js runtime file. Running it unconditionally on any JS
	// produces false positives, since the chunk regexes match generic
	// ternary/switch shapes that show up in unrelated minified code.
	if looksLikeWebpackRuntime(content) {
		s.ProcessWebpackFile(baseURL.String(), content, results)
	}

	scanForJSReferences(baseURL, content, results, processedURLs)
}

var jsPathRe = regexp.MustCompile(`([A-Za-z0-9_\-./]+\.js)\b`)

// ProcessWebpackFile extracts all JavaScript chunk paths from a webpack bundle
func (s *SubJS) ProcessWebpackFile(webpackURL string, content string, results chan string) {
	baseURL, err := url.Parse(webpackURL)
	if err != nil {
		return
	}

	// Track processed URLs to avoid duplicates
	processedPaths := make(map[string]bool)

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

	// Pattern 1: Extract direct chunk references
	// Example: a.u=e=>2986===e?"static/chunks/2986-2488e3e4a13aed5b.js"
	directChunkPattern := regexp.MustCompile(`(\d+)===e\?"([^"]+)"`)
	for _, match := range directChunkPattern.FindAllStringSubmatch(content, -1) {
		if !isPlausibleChunkPath(match[2]) {
			continue
		}
		chunkPath := ensureNextPrefix(match[2])
		resolvedURL := resolveScriptURL(baseURL, chunkPath)

		if !processedPaths[resolvedURL] {
			results <- resolvedURL
			processedPaths[resolvedURL] = true
		}
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
			resolvedURL := resolveScriptURL(baseURL, chunkPath)

			if !processedPaths[resolvedURL] {
				results <- resolvedURL
				processedPaths[resolvedURL] = true
			}
		}
	}

	// Pattern 3: Look for a.p (public path) + a.u (chunk URL) patterns
	// Example: a.p+"static/chunks/pages/about-12345.js"
	publicPathPattern := regexp.MustCompile(`a\.p\+"([^"]+\.js)"`)
	for _, match := range publicPathPattern.FindAllStringSubmatch(content, -1) {
		chunkPath := match[1]
		// For this pattern, we use _next/ directly since it's already handled in resolveScriptURL
		resolvedURL := resolveScriptURL(baseURL, ensureNextPrefix(chunkPath))

		if !processedPaths[resolvedURL] {
			results <- resolvedURL
			processedPaths[resolvedURL] = true
		}
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
			resolvedURL := resolveScriptURL(baseURL, chunkPath)

			if !processedPaths[resolvedURL] {
				results <- resolvedURL
				processedPaths[resolvedURL] = true
			}
		}
	}

	if strings.Contains(webpackURL, "_buildManifest") {
		paths := jsPathRe.FindAllString(content, -1)
		for _, path := range paths {
			resolvedURL := resolveScriptURL(baseURL, "_next/"+path)
			if !processedPaths[resolvedURL] {
				results <- resolvedURL
				processedPaths[resolvedURL] = true
			}
		}
	}
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

// isWebpackBundle determines if a URL appears to be a webpack bundle
func isWebpackBundle(url string) bool {
	return strings.Contains(url, "webpack") ||
		strings.Contains(url, "bundle") ||
		strings.Contains(url, "chunks") ||
		strings.Contains(url, "_next/static")
}

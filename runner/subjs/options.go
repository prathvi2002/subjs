package subjs

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type Options struct {
	InputFile string
	Workers   int
	Timeout   int
	UserAgent string
	Tor       bool
	Headers   []string
	Proxy     string
	Debug     bool

	// MaxSize is the maximum number of response body bytes read per
	// request, in bytes. 0 means unlimited. Set from -max-size (MB).
	MaxSize int64

	// Depth is how many additional hops of fetch-and-scan are allowed
	// beyond the initial page/file fetch. 0 means: scan the initial
	// response for references and report them, but don't fetch anything
	// discovered inside it.
	Depth int

	// Scope holds the raw -scope entries (each possibly comma-separated).
	// Parsed into scopeRules by buildScopeRules. Empty means unrestricted.
	Scope []string
}

// defaultUserAgent is sent when -ua isn't specified. Go's stdlib default
// ("Go-http-client/1.1") is trivially fingerprinted and blocked by many
// WAFs/CDNs, so a realistic desktop browser UA is used instead.
const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// defaultMaxSizeMB is the default response body cap, in megabytes, applied
// when -max-size isn't specified. 50MB comfortably covers even large
// unminified bundles/source maps while still bounding memory use against a
// target that serves (or is tricked into serving) something huge.
const defaultMaxSizeMB = 50

// defaultDepth is the default number of additional fetch-and-scan hops
// beyond the directly-linked scripts. Note this is *not* the same as the
// tool's original fixed behavior: the directly-linked <script src>/<link>
// targets on a page are always fetched and scanned regardless of this
// value (that part isn't optional, same as before depth support existed).
// -depth only controls whether references found *inside* those already
// count as one extra hop: at the default of 1, references discovered
// inside the directly-linked script are also fetched-and-scanned before
// recursion stops. -depth 0 is what reproduces the tool's original
// single-hop-only behavior (linked script fetched and scanned, but
// anything referenced inside it only reported, not fetched).
const defaultDepth = 1

// headerList implements flag.Value so -H can be passed multiple times,
// e.g. -H "Cookie: session=abc" -H "X-Api-Key: 123".
type headerList []string

func (h *headerList) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerList) Set(value string) error {
	*h = append(*h, value)
	return nil
}

// scopeList implements flag.Value so -scope can be passed multiple times,
// or as a single comma-separated value, or both, e.g.
// -scope example.com -scope "*.foo.com,keyword".
type scopeList []string

func (l *scopeList) String() string {
	return strings.Join(*l, ", ")
}

func (l *scopeList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func ParseOptions() *Options {
	opts := &Options{}
	var headers headerList
	var scope scopeList
	var maxSizeMB int64

	flag.StringVar(&opts.InputFile, "i", "", "Input file containing URLS")
	flag.StringVar(&opts.UserAgent, "ua", defaultUserAgent, "User-Agent to send in requests")
	flag.IntVar(&opts.Workers, "c", 10, "Number of concurrent workers")
	flag.IntVar(&opts.Timeout, "t", 15, "Timeout (in seconds) for http client")
	flag.BoolVar(&opts.Tor, "tor", false, "Route requests through local Tor SOCKS5 proxy (127.0.0.1:9050)")
	flag.Var(&headers, "H", "Custom header 'Key: Value', can be repeated")
	flag.StringVar(&opts.Proxy, "proxy", "", "HTTP/HTTPS proxy URL to route requests through (e.g. http://127.0.0.1:8080). Ignored if -tor is set.")
	flag.BoolVar(&opts.Debug, "debug", false, "Print request errors and non-2xx HTTP status codes to stderr (silent otherwise)")
	flag.Int64Var(&maxSizeMB, "max-size", defaultMaxSizeMB, "Maximum response body size to read, in MB (0 = unlimited)")
	flag.IntVar(&opts.Depth, "depth", defaultDepth, "Additional hops to fetch+scan discovered JS files for further references (0 = report what's found in the initial page/file, but don't fetch it)")
	flag.Var(&scope, "scope", "Restrict crawling/reporting to a domain scope, repeatable or comma-separated. 'example.com' matches that host only, '*.example.com' matches that host plus any subdomain, and a bare word like 'google' matches any host containing it anywhere (subdomain or domain). Only applies to URLs discovered while crawling - URLs read from stdin/-i are always fetched regardless. Unset = no restriction.")
	showVersion := flag.Bool("version", false, "Show version number")
	flag.Parse()
	if *showVersion {
		fmt.Printf("subjs version: %s\n", version)
		os.Exit(0)
	}
	opts.Headers = headers
	opts.Scope = scope

	if maxSizeMB <= 0 {
		opts.MaxSize = 0 // unlimited
	} else {
		opts.MaxSize = maxSizeMB * 1024 * 1024
	}

	return opts
}

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
}

// defaultUserAgent is sent when -ua isn't specified. Go's stdlib default
// ("Go-http-client/1.1") is trivially fingerprinted and blocked by many
// WAFs/CDNs, so a realistic desktop browser UA is used instead.
const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

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

func ParseOptions() *Options {
	opts := &Options{}
	var headers headerList

	flag.StringVar(&opts.InputFile, "i", "", "Input file containing URLS")
	flag.StringVar(&opts.UserAgent, "ua", defaultUserAgent, "User-Agent to send in requests")
	flag.IntVar(&opts.Workers, "c", 10, "Number of concurrent workers")
	flag.IntVar(&opts.Timeout, "t", 30, "Timeout (in seconds) for http client")
	flag.BoolVar(&opts.Tor, "tor", false, "Route requests through local Tor SOCKS5 proxy (127.0.0.1:9050)")
	flag.Var(&headers, "H", "Custom header 'Key: Value', can be repeated")
	flag.StringVar(&opts.Proxy, "proxy", "", "HTTP/HTTPS proxy URL to route requests through (e.g. http://127.0.0.1:8080). Ignored if -tor is set.")
	showVersion := flag.Bool("version", false, "Show version number")
	flag.Parse()
	if *showVersion {
		fmt.Printf("subjs version: %s\n", version)
		os.Exit(0)
	}
	opts.Headers = headers
	return opts
}

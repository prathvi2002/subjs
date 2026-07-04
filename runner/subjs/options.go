package subjs

import (
	"flag"
	"fmt"
	"os"
)

type Options struct {
	InputFile string
	Workers   int
	Timeout   int
	UserAgent string
	Tor       bool
}

func ParseOptions() *Options {
	opts := &Options{}
	flag.StringVar(&opts.InputFile, "i", "", "Input file containing URLS")
	flag.StringVar(&opts.UserAgent, "ua", "", "User-Agent to send in requests")
	flag.IntVar(&opts.Workers, "c", 10, "Number of concurrent workers")
	flag.IntVar(&opts.Timeout, "t", 30, "Timeout (in seconds) for http client")
	flag.BoolVar(&opts.Tor, "tor", false, "Route requests through local Tor SOCKS5 proxy (127.0.0.1:9050)")
	showVersion := flag.Bool("version", false, "Show version number")
	flag.Parse()
	if *showVersion {
		fmt.Printf("subjs version: %s\n", version)
		os.Exit(0)
	}
	return opts
}

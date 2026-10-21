package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"bannerfingerprint/internal/client"
)

func main() {
	input := flag.String("input", "testdata/selftest/input.json", "local JSON file (array or records wrapper)")
	server := flag.String("server", "http://127.0.0.1:8080", "server base URL")
	timeout := flag.Duration("timeout", 15*time.Second, "total request timeout")
	flag.Parse()
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "timeout must be positive")
		os.Exit(1)
	}
	f, err := os.Open(*input)
	if err == nil {
		defer f.Close()
		err = client.Run(context.Background(), *server, f, os.Stdout, &http.Client{Timeout: *timeout})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

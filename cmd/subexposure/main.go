package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/time/rate"
	"io"
	"math"
	"os"
	"os/signal"
	"subexposure/internal/exposure"
	"subexposure/internal/httpcheck"
	"subexposure/internal/models"
	"subexposure/internal/report"
	"subexposure/internal/scope"
	"subexposure/internal/subfinder"
	"sync"
	"time"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(stderr, "Usage: subexposure scan <target> [flags]\nUse only on systems you own or are authorized to audit.")
		return 2
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	workers := fs.Int("workers", 10, "concurrent hosts (1-50)")
	rps := fs.Float64("rate", 5, "global requests/second (0.1-50)")
	timeout := fs.Duration("timeout", 8*time.Second, "per request timeout (1s-60s)")
	output := fs.String("output", "", "new report file (default stdout)")
	format := fs.String("format", "json", "json or jsonl")
	verbose := fs.Bool("verbose", false, "structural progress on stderr")
	sf := fs.String("subfinder-path", "subfinder", "Subfinder executable")
	noSubs := fs.Bool("no-subdomains", false, "scan only the supplied host")
	tail := args[1:]
	target := ""
	if len(tail) > 0 && len(tail[0]) > 0 && tail[0][0] != '-' {
		target = tail[0]
		tail = tail[1:]
	}
	if err := fs.Parse(tail); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if target == "" && fs.NArg() == 1 {
		target = fs.Arg(0)
	} else if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "exactly one target required")
		return 2
	}
	if target == "" || *workers < 1 || *workers > 50 || math.IsNaN(*rps) || math.IsInf(*rps, 0) || *rps < 0.1 || *rps > 50 || *timeout < time.Second || *timeout > 60*time.Second || (*format != "json" && *format != "jsonl") {
		fmt.Fprintln(stderr, "invalid target or flag bounds; see scan --help")
		return 2
	}
	host, root, err := scope.Parse(target)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	fmt.Fprintf(stderr, "Authorized auditing only. Scope: %s (subdomain discovery: %t)\n", root, !*noSubs)
	hosts, err := subfinder.Enumerate(ctx, *sf, root, host, *noSubs)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	dest := stdout
	var outputFile *os.File
	if *output != "" {
		f, e := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			fmt.Fprintln(stderr, "cannot create output (existing files are not overwritten)")
			return 1
		}
		defer f.Close()
		outputFile = f
		dest = f
	}
	writer, err := report.New(dest, *format)
	if err != nil {
		return 1
	}
	client := httpcheck.New(root, *timeout, rate.NewLimiter(rate.Limit(*rps), 1))
	defer client.Close()
	jobs := make(chan string)
	results := make(chan []models.Finding, *workers)
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				var findings []models.Finding
				if e := exposure.ResolveHost(ctx, h, *timeout); e != nil {
					findings = []models.Finding{{Host: h, Classification: httpcheck.ErrorClass(e), Confidence: "LOW", Evidence: "DNS unresolved or address policy blocked; details omitted"}}
				} else {
					findings = exposure.ScanHost(ctx, client, h)
				}
				select {
				case results <- findings:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, h := range hosts {
			select {
			case jobs <- h:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	writeFailed := false
	for batch := range results {
		for _, finding := range batch {
			if !writeFailed {
				if e := writer.Write(finding); e != nil {
					writeFailed = true
					cancel()
				}
			}
		}
		if *verbose {
			fmt.Fprintf(stderr, "Completed host batch; %d structural results\n", len(batch))
		}
	}
	if err := writer.Close(); err != nil {
		writeFailed = true
	}
	if outputFile != nil {
		if err := outputFile.Close(); err != nil {
			writeFailed = true
		}
	}
	if writeFailed {
		fmt.Fprintln(stderr, "report write failed")
		return 1
	}
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "cancelled; report contains partial results")
		return 130
	}
	return 0
}

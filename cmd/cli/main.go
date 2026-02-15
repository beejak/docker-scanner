// CLI entrypoint for the Docker Container Scanner.
// Commands: scan, db update (optional), serve (optional).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/docker-scanner/scanner/pkg/policy"
	"github.com/docker-scanner/scanner/pkg/remediate"
	"github.com/docker-scanner/scanner/pkg/report"
	"github.com/docker-scanner/scanner/pkg/scanner"
)

func main() {
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	image := scanCmd.String("image", "", "Image to scan (e.g. alpine:latest or myregistry.io/app:v1)")
	dockerfile := scanCmd.String("dockerfile", "", "Optional Dockerfile path")
	severity := scanCmd.String("severity", "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN", "Comma-separated severities to include (default: all)")
	offline := scanCmd.Bool("offline", false, "Skip DB update and OSV; use cache and embedded rules only")
	cacheDir := scanCmd.String("cache-dir", "", "Cache directory for Trivy DB (default: system cache)")
	outputDir := scanCmd.String("output-dir", "./reports", "Output directory for reports")
	outputName := scanCmd.String("output-name", "report", "Base name for report files (e.g. report). Use with --timestamp for unique names.")
	timestamp := scanCmd.Bool("timestamp", false, "Append timestamp to report base name so each run writes unique files (e.g. report-20060102-150405.html).")
	format := scanCmd.String("format", "sarif,markdown", "Comma-separated formats: sarif, markdown, html, csv")
	failOnSeverity := scanCmd.String("fail-on-severity", "", "Exit with code 1 if any finding has this severity (e.g. CRITICAL,HIGH). Empty = do not fail.")
	failOnCount := scanCmd.String("fail-on-count", "", "Exit with code 1 if count for severity >= N (e.g. HIGH:5). One rule only.")

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: scanner scan --image <ref> [options]")
		fmt.Fprintln(os.Stderr, "       scanner db update [--cache-dir <dir>]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		_ = scanCmd.Parse(os.Args[2:])
		if *image == "" {
			fmt.Fprintln(os.Stderr, "Error: --image is required")
			os.Exit(1)
		}
		runScan(context.Background(), runScanOpts{
			image:           *image,
			dockerfile:      *dockerfile,
			severity:        splitTrim(*severity, ","),
			offline:         *offline,
			cacheDir:        *cacheDir,
			outputDir:       *outputDir,
			outputName:      *outputName,
			timestamp:       *timestamp,
			format:          splitTrim(*format, ","),
			failOnSeverity:  splitTrim(*failOnSeverity, ","),
			failOnCount:     *failOnCount,
		})
	case "db":
		if len(os.Args) > 2 && os.Args[2] == "update" {
			// TODO: run Trivy DB update
			fmt.Println("DB update not yet implemented; use Trivy directly or run without --offline.")
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "Usage: scanner db update [--cache-dir <dir>]")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

type runScanOpts struct {
	image          string
	dockerfile     string
	severity       []string
	offline        bool
	cacheDir       string
	outputDir      string
	outputName     string
	timestamp      bool
	format         []string
	failOnSeverity []string
	failOnCount    string
}

func runScan(ctx context.Context, opts runScanOpts) {
	scanOpts := scanner.ScanOptions{
		Image:      opts.image,
		Dockerfile: opts.dockerfile,
		Severity:   opts.severity,
		Offline:    opts.offline,
		CacheDir:   opts.cacheDir,
	}
	findings, err := scanner.Scan(ctx, scanOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}
	enriched := remediate.Enrich(findings, opts.offline)
	baseName := opts.outputName
	if baseName == "" {
		baseName = "report"
	}
	if opts.timestamp {
		baseName = baseName + "-" + time.Now().Format("20060102-150405")
	}
	reportOpts := report.Options{
		Formats:        opts.format,
		OutputDir:      opts.outputDir,
		ReportBaseName: baseName,
	}
	if err := report.Generate(enriched, reportOpts); err != nil {
		fmt.Fprintf(os.Stderr, "Report failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Scan complete: %d findings. Reports written to %s\n", len(enriched), opts.outputDir)

	// Fail-on policy: exit 1 if policy is violated so CI can gate the build
	if shouldFail, reason := policy.EvaluateFailPolicy(enriched, opts.failOnSeverity, opts.failOnCount); shouldFail {
		fmt.Fprintln(os.Stderr, reason)
		os.Exit(1)
	}
}

func splitTrim(s, sep string) []string {
	var out []string
	for _, v := range strings.Split(s, sep) {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}

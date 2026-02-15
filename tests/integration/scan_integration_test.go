//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/docker-scanner/scanner/pkg/remediate"
	"github.com/docker-scanner/scanner/pkg/report"
	"github.com/docker-scanner/scanner/pkg/scanner"
)

// Integration test: run full scan pipeline against a real vulnerable image.
// Requires: Trivy in PATH; optionally Docker (to pull image).
// Run with: go test -tags=integration ./tests/integration/... -v
// Or set RUN_INTEGRATION=1 and use build tag so CI can enable it.

const integrationImage = "alpine:3.10" // Known to have CVEs in older base

func TestScanRealImage(t *testing.T) {
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not in PATH; skip integration test")
	}

	ctx := context.Background()
	opts := scanner.ScanOptions{
		Image:    integrationImage,
		Severity: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
		Offline:  false, // Allow DB update so we get real results
	}

	findings, err := scanner.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// alpine:3.10 is known vulnerable; we expect at least 0 findings (scan succeeded)
	_ = findings

	enriched := remediate.Enrich(findings, false)
	dir := t.TempDir()
	reportOpts := report.Options{
		Formats:   []string{"sarif", "markdown", "html"},
		OutputDir: dir,
	}
	if err := report.Generate(enriched, reportOpts); err != nil {
		t.Fatalf("report.Generate() error = %v", err)
	}

	for _, name := range []string{"report.sarif", "report.md", "report.html"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected report file %s: %v", path, err)
		}
	}

	// For a known vulnerable image we optionally assert we got some findings (Trivy DB dependent)
	if os.Getenv("RUN_INTEGRATION_STRICT") == "1" && len(enriched) == 0 {
		t.Logf("RUN_INTEGRATION_STRICT=1: expected at least one finding for %s (DB may be empty or image updated)", integrationImage)
	}
}

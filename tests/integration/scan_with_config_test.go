//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker-scanner/scanner/pkg/config"
	"github.com/docker-scanner/scanner/pkg/remediate"
	"github.com/docker-scanner/scanner/pkg/report"
	"github.com/docker-scanner/scanner/pkg/scanner"
)

// Integration test: run full scan workflow with options loaded from a config file
// (emulates "scanner scan --image X" when scanner.yaml is present). Pulls image via Trivy.
// Run with: go test -tags=integration ./tests/integration/... -run TestScanWithConfig -v
func TestScanWithConfig(t *testing.T) {
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not in PATH; skip integration test")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "scanner.yaml")
	content := `severity: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN
format: markdown,html
output-dir: ` + dir + `
output-name: config-test-report
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load(): %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	severities := splitTrim(cfg.Severity, ",")
	if len(severities) == 0 {
		severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	}

	ctx := context.Background()
	opts := scanner.ScanOptions{
		Image:    integrationImage,
		Severity: severities,
		Offline:  false,
		CacheDir: cfg.CacheDir,
	}

	findings, err := scanner.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("Scan() with config options: %v", err)
	}

	enriched := remediate.Enrich(findings, false)
	reportOpts := report.Options{
		Formats:        splitTrim(cfg.Format, ","),
		OutputDir:      cfg.OutputDir,
		ReportBaseName: cfg.OutputName,
	}
	if len(reportOpts.Formats) == 0 {
		reportOpts.Formats = []string{"markdown", "html"}
	}
	if reportOpts.OutputDir == "" {
		reportOpts.OutputDir = dir
	}
	if reportOpts.ReportBaseName == "" {
		reportOpts.ReportBaseName = "report"
	}

	if err := report.Generate(enriched, reportOpts); err != nil {
		t.Fatalf("report.Generate(): %v", err)
	}

	// Assert reports written to config output-dir with config output-name
	for _, fmt := range reportOpts.Formats {
		var ext string
		switch strings.ToLower(fmt) {
		case "markdown":
			ext = ".md"
		case "html":
			ext = ".html"
		case "sarif":
			ext = ".sarif"
		case "csv":
			ext = ".csv"
		default:
			continue
		}
		path := filepath.Join(reportOpts.OutputDir, reportOpts.ReportBaseName+ext)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected report %s: %v", path, err)
		}
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

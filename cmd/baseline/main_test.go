package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker-scanner/scanner/pkg/report"
	"github.com/docker-scanner/scanner/pkg/scanner"
)

func TestLoadImages_basic(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "images*.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("alpine:latest\n# comment\n\nnginx:stable\n")
	f.Close()

	images, err := loadImages(f.Name())
	if err != nil {
		t.Fatalf("loadImages: %v", err)
	}
	if len(images) != 2 {
		t.Fatalf("len = %d; want 2", len(images))
	}
	if images[0] != "alpine:latest" || images[1] != "nginx:stable" {
		t.Errorf("images = %v; want [alpine:latest nginx:stable]", images)
	}
}

func TestLoadImages_notFound(t *testing.T) {
	_, err := loadImages("/nonexistent/path/images.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadImages_emptyFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "empty*.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	images, err := loadImages(f.Name())
	if err != nil {
		t.Fatalf("loadImages: %v", err)
	}
	if len(images) != 0 {
		t.Errorf("len = %d; want 0", len(images))
	}
}

func TestCsvEscape(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"with,comma", `"with,comma"`},
		{`with"quote`, `"with""quote"`},
		{"with\nnewline", "\"with\nnewline\""},
		{"with\rreturn", "\"with\rreturn\""},
		{"", ""},
	}
	for _, c := range cases {
		got := csvEscape(c.in)
		if got != c.want {
			t.Errorf("csvEscape(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestWriteFindingsMarkdown(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "findings.md")

	entries := []report.ImageFinding{
		{
			Image: "alpine:latest",
			Finding: scanner.Finding{
				CVEID:           "CVE-2021-36159",
				Title:           "libfetch integer overflow",
				Package:         "apk-tools",
				CurrentVersion:  "2.10.6-r0",
				Severity:        "CRITICAL",
				Exploitable:     "yes",
				WhySeverity:     "CISA KEV",
				ExploitInfo:     "actively exploited",
				RemediationText: "upgrade to 2.10.7-r0",
			},
		},
		{
			Image: "alpine:latest",
			Finding: scanner.Finding{
				CVEID:    "CVE-2020-28928",
				Package:  "musl",
				Severity: "MEDIUM",
			},
		},
	}

	if err := writeFindingsMarkdown(entries, outPath, "20260630-120000"); err != nil {
		t.Fatalf("writeFindingsMarkdown: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	content := string(data)

	// Must have a header and both CVEs.
	if !strings.Contains(content, "CVE-2021-36159") {
		t.Error("missing CVE-2021-36159")
	}
	if !strings.Contains(content, "CVE-2020-28928") {
		t.Error("missing CVE-2020-28928")
	}
	if !strings.Contains(content, "alpine:latest") {
		t.Error("missing image name")
	}
	if !strings.HasPrefix(content, "# Baseline findings") {
		t.Error("missing markdown header")
	}
}

func TestWriteFindingsMarkdown_empty(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "empty.md")
	if err := writeFindingsMarkdown(nil, outPath, "20260630"); err != nil {
		t.Fatalf("writeFindingsMarkdown(nil): %v", err)
	}
	data, _ := os.ReadFile(outPath)
	if !strings.Contains(string(data), "# Baseline findings") {
		t.Error("should write header even for empty findings")
	}
}

func TestWriteDashboardHTML(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "dashboard.html")

	results := []result{
		{Image: "alpine:latest", Findings: 3, Status: "OK"},
		{Image: "nginx:stable", Findings: 0, Status: "OK"},
	}
	entries := []report.ImageFinding{
		{Image: "alpine:latest", Finding: scanner.Finding{Severity: "CRITICAL", Exploitable: "yes"}},
	}

	if err := writeDashboardHTML(results, entries, outPath, "20260630-120000"); err != nil {
		t.Fatalf("writeDashboardHTML: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "<html") {
		t.Error("missing <html tag")
	}
	if !strings.Contains(content, "alpine:latest") {
		t.Error("missing image name in dashboard")
	}
}

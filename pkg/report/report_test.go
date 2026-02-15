package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker-scanner/scanner/pkg/scanner"
)

func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	findings := []scanner.Finding{
		{CVEID: "CVE-2020-1", Package: "pkg", CurrentVersion: "1.0", Severity: "HIGH", RemediationText: "Upgrade to 1.1"},
	}
	opts := Options{Formats: []string{"sarif", "markdown", "html"}, OutputDir: dir}
	if err := Generate(findings, opts); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	for _, name := range []string{"report.sarif", "report.md", "report.html"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected file %s: %v", path, err)
		}
	}
}

func TestGenerate_csvAndCustomBase(t *testing.T) {
	dir := t.TempDir()
	findings := []scanner.Finding{
		{CVEID: "CVE-X", Package: "pkg", Severity: "HIGH"},
	}
	opts := Options{Formats: []string{"csv"}, OutputDir: dir, ReportBaseName: "scan-20250101"}
	if err := Generate(findings, opts); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	csvPath := filepath.Join(dir, "scan-20250101.csv")
	if _, err := os.Stat(csvPath); err != nil {
		t.Errorf("expected file %s: %v", csvPath, err)
	}
	content, _ := os.ReadFile(csvPath)
	if !strings.Contains(string(content), "CVE") || !strings.Contains(string(content), "pkg") {
		t.Errorf("csv should contain CVE header and package data: %s", content)
	}
}

func TestGenerate_sarifLevels(t *testing.T) {
	dir := t.TempDir()
	findings := []scanner.Finding{
		{CVEID: "CVE-1", Package: "p", Severity: "CRITICAL"},
		{CVEID: "CVE-2", Package: "p", Severity: "HIGH"},
		{CVEID: "CVE-3", Package: "p", Severity: "MEDIUM"},
		{CVEID: "CVE-4", Package: "p", Severity: "LOW"},
		{CVEID: "CVE-5", Package: "p", Severity: "UNKNOWN"},
	}
	opts := Options{Formats: []string{"sarif"}, OutputDir: dir}
	if err := Generate(findings, opts); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "report.sarif"))
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse SARIF: %v", err)
	}
	levelByRule := make(map[string]string)
	for _, r := range doc.Runs[0].Results {
		levelByRule[r.RuleID] = r.Level
	}
	wantLevels := map[string]string{"CVE-1": "error", "CVE-2": "error", "CVE-3": "warning", "CVE-4": "note", "CVE-5": "note"}
	for id, want := range wantLevels {
		if got := levelByRule[id]; got != want {
			t.Errorf("rule %s level = %q, want %q", id, got, want)
		}
	}
}

func TestGenerate_markdownContent(t *testing.T) {
	dir := t.TempDir()
	findings := []scanner.Finding{
		{CVEID: "CVE-X", Package: "openssl", CurrentVersion: "1.0", Severity: "HIGH", RemediationText: "Upgrade"},
	}
	opts := Options{Formats: []string{"markdown"}, OutputDir: dir}
	if err := Generate(findings, opts); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	content, _ := os.ReadFile(filepath.Join(dir, "report.md"))
	s := string(content)
	if !strings.Contains(s, "CVE-X") || !strings.Contains(s, "openssl") || !strings.Contains(s, "HIGH") {
		t.Errorf("report.md missing expected content: %s", s)
	}
}

func TestGenerate_htmlEscaping(t *testing.T) {
	dir := t.TempDir()
	findings := []scanner.Finding{
		{CVEID: "CVE-1", Package: "p&q", Title: "<script>", Severity: "HIGH"},
	}
	opts := Options{Formats: []string{"html"}, OutputDir: dir}
	if err := Generate(findings, opts); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	content, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	s := string(content)
	if strings.Contains(s, "<script>") && !strings.Contains(s, "&lt;script&gt;") {
		t.Error("HTML should escape < and > in finding content")
	}
	if strings.Contains(s, "p&q") && !strings.Contains(s, "p&amp;q") {
		t.Error("HTML should escape & in finding content")
	}
}

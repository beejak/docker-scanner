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

// --- SARIF structural validation ---

// parseSARIF validates the minimal structure GitHub/Azure require to import SARIF.
func parseSARIF(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SARIF: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	return doc
}

func TestSARIF_requiredTopLevelFields(t *testing.T) {
	dir := t.TempDir()
	findings := []scanner.Finding{
		{CVEID: "CVE-2020-1", Package: "pkg", Severity: "HIGH", Title: "Test finding"},
	}
	if err := Generate(findings, Options{Formats: []string{"sarif"}, OutputDir: dir}); err != nil {
		t.Fatal(err)
	}
	doc := parseSARIF(t, filepath.Join(dir, "report.sarif"))

	// $schema must be present (required by GitHub SARIF viewer)
	if _, ok := doc["$schema"]; !ok {
		t.Error("SARIF missing required field: $schema")
	}
	if v, _ := doc["version"].(string); v != "2.1.0" {
		t.Errorf("SARIF version = %q; want 2.1.0", v)
	}
	runs, ok := doc["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("SARIF missing required field: runs (non-empty array)")
	}
}

func TestSARIF_toolDriverFields(t *testing.T) {
	dir := t.TempDir()
	findings := []scanner.Finding{
		{CVEID: "CVE-2020-1", Package: "p", Severity: "CRITICAL", Title: "T"},
	}
	if err := Generate(findings, Options{Formats: []string{"sarif"}, OutputDir: dir}); err != nil {
		t.Fatal(err)
	}
	doc := parseSARIF(t, filepath.Join(dir, "report.sarif"))
	runs := doc["runs"].([]interface{})
	run := runs[0].(map[string]interface{})

	tool, ok := run["tool"].(map[string]interface{})
	if !ok {
		t.Fatal("SARIF run missing required field: tool")
	}
	driver, ok := tool["driver"].(map[string]interface{})
	if !ok {
		t.Fatal("SARIF tool missing required field: driver")
	}
	if name, _ := driver["name"].(string); name == "" {
		t.Error("SARIF driver.name must not be empty")
	}
	if ver, _ := driver["version"].(string); ver == "" {
		t.Error("SARIF driver.version must not be empty")
	}
	if uri, _ := driver["informationUri"].(string); uri == "" {
		t.Error("SARIF driver.informationUri must not be empty")
	}
}

func TestSARIF_resultsHaveRequiredFields(t *testing.T) {
	dir := t.TempDir()
	findings := []scanner.Finding{
		{CVEID: "CVE-2021-1", Package: "pkg", CurrentVersion: "1.0", Severity: "CRITICAL", Title: "Test", FilePath: "/usr/lib/libfoo.so"},
		{CVEID: "CVE-2021-2", Package: "bar", CurrentVersion: "2.0", Severity: "MEDIUM", Title: "Medium issue"},
	}
	if err := Generate(findings, Options{Formats: []string{"sarif"}, OutputDir: dir}); err != nil {
		t.Fatal(err)
	}
	doc := parseSARIF(t, filepath.Join(dir, "report.sarif"))
	runs := doc["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results, ok := run["results"].([]interface{})
	if !ok || len(results) != 2 {
		t.Fatalf("expected 2 results, got %v", run["results"])
	}

	for i, raw := range results {
		r := raw.(map[string]interface{})
		if ruleID, _ := r["ruleId"].(string); ruleID == "" {
			t.Errorf("result[%d] missing ruleId", i)
		}
		if level, _ := r["level"].(string); level == "" {
			t.Errorf("result[%d] missing level", i)
		}
		msg, _ := r["message"].(map[string]interface{})
		if text, _ := msg["text"].(string); text == "" {
			t.Errorf("result[%d] message.text is empty", i)
		}
	}
}

func TestSARIF_locationIncludedWhenFilePath(t *testing.T) {
	dir := t.TempDir()
	findings := []scanner.Finding{
		{CVEID: "CVE-X", Package: "p", Severity: "HIGH", Title: "T", FilePath: "lib/libc.so.6"},
	}
	if err := Generate(findings, Options{Formats: []string{"sarif"}, OutputDir: dir}); err != nil {
		t.Fatal(err)
	}
	doc := parseSARIF(t, filepath.Join(dir, "report.sarif"))
	runs := doc["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	r := results[0].(map[string]interface{})

	locs, ok := r["locations"].([]interface{})
	if !ok || len(locs) == 0 {
		t.Fatal("expected locations when FilePath is set")
	}
	loc := locs[0].(map[string]interface{})
	pl := loc["physicalLocation"].(map[string]interface{})
	al := pl["artifactLocation"].(map[string]interface{})
	if uri, _ := al["uri"].(string); uri != "lib/libc.so.6" {
		t.Errorf("artifactLocation.uri = %q; want lib/libc.so.6", uri)
	}
}

func TestSARIF_noLocationWhenNoFilePath(t *testing.T) {
	dir := t.TempDir()
	findings := []scanner.Finding{
		{CVEID: "CVE-X", Package: "p", Severity: "HIGH", Title: "T"},
	}
	if err := Generate(findings, Options{Formats: []string{"sarif"}, OutputDir: dir}); err != nil {
		t.Fatal(err)
	}
	doc := parseSARIF(t, filepath.Join(dir, "report.sarif"))
	runs := doc["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	r := results[0].(map[string]interface{})

	if locs := r["locations"]; locs != nil {
		t.Errorf("expected no locations when FilePath is empty, got %v", locs)
	}
}

func TestSARIF_ruleDeduplication(t *testing.T) {
	dir := t.TempDir()
	// Two findings with the same CVE ID — rule should appear only once.
	findings := []scanner.Finding{
		{CVEID: "CVE-2020-1", Package: "pkgA", Severity: "HIGH", Title: "Test"},
		{CVEID: "CVE-2020-1", Package: "pkgB", Severity: "HIGH", Title: "Test"},
	}
	if err := Generate(findings, Options{Formats: []string{"sarif"}, OutputDir: dir}); err != nil {
		t.Fatal(err)
	}
	doc := parseSARIF(t, filepath.Join(dir, "report.sarif"))
	runs := doc["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	driver := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})
	if len(rules) != 1 {
		t.Errorf("expected 1 deduplicated rule, got %d", len(rules))
	}
	// But results must still have 2 entries (one per finding).
	results := run["results"].([]interface{})
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestSARIF_emptyFindings(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(nil, Options{Formats: []string{"sarif"}, OutputDir: dir}); err != nil {
		t.Fatal(err)
	}
	doc := parseSARIF(t, filepath.Join(dir, "report.sarif"))
	runs := doc["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	// results may be nil or empty — both are valid
	if results := run["results"]; results != nil {
		arr := results.([]interface{})
		if len(arr) != 0 {
			t.Errorf("expected 0 results for empty findings, got %d", len(arr))
		}
	}
}

// --- WriteFindingsCSVWithImage ---

func TestWriteFindingsCSVWithImage_basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.csv")

	entries := []ImageFinding{
		{Image: "alpine:3.10", Finding: scanner.Finding{CVEID: "CVE-2021-1", Package: "musl", CurrentVersion: "1.1.22", Severity: "CRITICAL"}},
		{Image: "nginx:1.21", Finding: scanner.Finding{CVEID: "CVE-2022-2", Package: "openssl", CurrentVersion: "1.1.1", Severity: "HIGH"}},
	}
	if err := WriteFindingsCSVWithImage(entries, path); err != nil {
		t.Fatalf("WriteFindingsCSVWithImage() error = %v", err)
	}
	b, _ := os.ReadFile(path)
	s := string(b)

	if !strings.Contains(s, "Image,CVE") {
		t.Error("CSV missing header row")
	}
	if !strings.Contains(s, "alpine:3.10") {
		t.Error("CSV missing first image")
	}
	if !strings.Contains(s, "nginx:1.21") {
		t.Error("CSV missing second image")
	}
	if !strings.Contains(s, "CVE-2021-1") || !strings.Contains(s, "CVE-2022-2") {
		t.Error("CSV missing CVE IDs")
	}
}

func TestWriteFindingsCSVWithImage_imageFirstColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.csv")
	entries := []ImageFinding{
		{Image: "myrepo/app:v1", Finding: scanner.Finding{CVEID: "CVE-X", Severity: "HIGH"}},
	}
	if err := WriteFindingsCSVWithImage(entries, path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines (header + data), got %d", len(lines))
	}
	// Data row: first CSV field must be the image reference.
	dataLine := lines[1]
	firstField := strings.SplitN(dataLine, ",", 2)[0]
	// csvEscape wraps all values in quotes.
	if firstField != `"myrepo/app:v1"` {
		t.Errorf("first CSV column = %q; want image reference", firstField)
	}
}

func TestWriteFindingsCSVWithImage_specialCharsEscaped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.csv")
	entries := []ImageFinding{
		{
			Image: "registry/app:1.0",
			Finding: scanner.Finding{
				CVEID:       "CVE-2024-1",
				Title:       `Title with "quotes" and, comma`,
				Description: "Multi\nline\ndescription",
				Severity:    "CRITICAL",
			},
		},
	}
	if err := WriteFindingsCSVWithImage(entries, path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	s := string(b)
	// Quotes inside a field must be doubled (RFC 4180).
	if !strings.Contains(s, `""quotes""`) {
		t.Error("double-quotes not properly escaped in CSV")
	}
}

func TestWriteFindingsCSVWithImage_empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.csv")
	if err := WriteFindingsCSVWithImage(nil, path); err != nil {
		t.Fatalf("WriteFindingsCSVWithImage(nil) error = %v", err)
	}
	b, _ := os.ReadFile(path)
	s := string(b)
	if !strings.Contains(s, "Image,CVE") {
		t.Error("empty CSV should still have header row")
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) != 1 {
		t.Errorf("expected only header row for empty input, got %d lines", len(lines))
	}
}

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// trivyJSON is a minimal Trivy JSON report with one CRITICAL finding.
// Inlined so the test has no dependency on external fixture files.
const trivyJSONCritical = `{
  "SchemaVersion": 2,
  "ArtifactName": "testimage:latest",
  "Results": [
    {
      "Target": "testimage:latest (alpine 3.10.9)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-36159",
          "PkgName": "apk-tools",
          "InstalledVersion": "2.10.6-r0",
          "FixedVersion": "2.10.7-r0",
          "Severity": "CRITICAL",
          "Title": "libfetch integer overflow",
          "Description": "libfetch before 2021-07-26 has an integer overflow.",
          "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2021-36159",
          "References": []
        }
      ]
    }
  ]
}`

// trivyJSONClean is a Trivy JSON report with no vulnerabilities.
const trivyJSONClean = `{
  "SchemaVersion": 2,
  "ArtifactName": "testimage:latest",
  "Results": []
}`

// setupFakeTrivy creates a temp directory with a fake trivy script that prints
// the given JSON body on stdout and exits 0. It prepends the dir to PATH.
// Returns cleanup func that restores PATH.
func setupFakeTrivy(t *testing.T, jsonBody string) func() {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake trivy test not supported on Windows")
	}
	dir := t.TempDir()
	// Write the fake trivy script.
	scriptPath := filepath.Join(dir, "trivy")
	// The script ignores all arguments and just prints the canned JSON.
	content := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\n", strings.ReplaceAll(jsonBody, "'", `'\''`))
	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		t.Fatalf("write fake trivy: %v", err)
	}
	origPATH := os.Getenv("PATH")
	os.Setenv("PATH", dir+string(os.PathListSeparator)+origPATH)
	return func() { os.Setenv("PATH", origPATH) }
}

func TestRunScan_policyViolation_exitCode1(t *testing.T) {
	cleanup := setupFakeTrivy(t, trivyJSONCritical)
	defer cleanup()

	dir := t.TempDir()
	opts := runScanOpts{
		image:          "testimage:latest",
		severity:       []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
		offline:        true, // skip KEV/OSV network calls
		outputDir:      dir,
		outputName:     "report",
		format:         []string{"sarif"},
		failOnSeverity: []string{"CRITICAL"},
	}

	code := runScan(context.Background(), opts)
	if code != 1 {
		t.Errorf("exit code = %d; want 1 (CRITICAL finding with fail-on-severity=CRITICAL)", code)
	}
}

func TestRunScan_clean_exitCode0(t *testing.T) {
	cleanup := setupFakeTrivy(t, trivyJSONClean)
	defer cleanup()

	dir := t.TempDir()
	opts := runScanOpts{
		image:          "testimage:latest",
		severity:       []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
		offline:        true,
		outputDir:      dir,
		outputName:     "report",
		format:         []string{"sarif"},
		failOnSeverity: []string{"CRITICAL"},
	}

	code := runScan(context.Background(), opts)
	if code != 0 {
		t.Errorf("exit code = %d; want 0 (no findings, policy should not trigger)", code)
	}
}

func TestRunScan_trivyError_exitCode1(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake trivy test not supported on Windows")
	}
	// Fake trivy that exits non-zero (simulates Trivy failure: image not found, etc.)
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "trivy")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho 'image not found' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatalf("write fake trivy: %v", err)
	}
	origPATH := os.Getenv("PATH")
	os.Setenv("PATH", dir+string(os.PathListSeparator)+origPATH)
	defer os.Setenv("PATH", origPATH)

	outDir := t.TempDir()
	opts := runScanOpts{
		image:     "nonexistent:latest",
		offline:   true,
		outputDir: outDir,
		format:    []string{"sarif"},
	}
	code := runScan(context.Background(), opts)
	if code != 1 {
		t.Errorf("exit code = %d; want 1 when trivy exits non-zero", code)
	}
}

func TestRunScan_failOnCount_exitCode1(t *testing.T) {
	// trivyJSONCritical has 1 CRITICAL finding; fail-on-count=CRITICAL:1 should trigger.
	cleanup := setupFakeTrivy(t, trivyJSONCritical)
	defer cleanup()

	dir := t.TempDir()
	opts := runScanOpts{
		image:       "testimage:latest",
		severity:    []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
		offline:     true,
		outputDir:   dir,
		outputName:  "report",
		format:      []string{"sarif"},
		failOnCount: "CRITICAL:1",
	}
	code := runScan(context.Background(), opts)
	if code != 1 {
		t.Errorf("exit code = %d; want 1 (fail-on-count=CRITICAL:1 with 1 CRITICAL finding)", code)
	}
}

func TestRunScan_failOnCount_belowThreshold_exitCode0(t *testing.T) {
	// trivyJSONCritical has 1 CRITICAL; fail-on-count=CRITICAL:5 should NOT trigger.
	cleanup := setupFakeTrivy(t, trivyJSONCritical)
	defer cleanup()

	dir := t.TempDir()
	opts := runScanOpts{
		image:       "testimage:latest",
		severity:    []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
		offline:     true,
		outputDir:   dir,
		outputName:  "report",
		format:      []string{"sarif"},
		failOnCount: "CRITICAL:5",
	}
	code := runScan(context.Background(), opts)
	if code != 0 {
		t.Errorf("exit code = %d; want 0 (1 CRITICAL, threshold 5 not reached)", code)
	}
}

func TestRunScan_reportsWritten(t *testing.T) {
	cleanup := setupFakeTrivy(t, trivyJSONCritical)
	defer cleanup()

	dir := t.TempDir()
	opts := runScanOpts{
		image:      "testimage:latest",
		severity:   []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
		offline:    true,
		outputDir:  dir,
		outputName: "report",
		format:     []string{"sarif", "markdown", "html"},
	}
	_ = runScan(context.Background(), opts)

	for _, name := range []string{"report.sarif", "report.md", "report.html"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected report file %s to exist: %v", name, err)
		}
	}
}

func TestValidLXCName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"mycontainer", true},
		{"my-container", true},
		{"my_container", true},
		{"Container123", true},
		{"", false},
		{"../../etc/passwd", false},
		{"name with spaces", false},
		{"name/slash", false},
		{"name;cmd", false},
	}
	for _, c := range cases {
		if got := validLXCName(c.name); got != c.want {
			t.Errorf("validLXCName(%q) = %v; want %v", c.name, got, c.want)
		}
	}
}

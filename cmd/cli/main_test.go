package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/docker-scanner/scanner/pkg/kev"
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

// trivyConfigJSON is a minimal Trivy config (Dockerfile misconfig) JSON report.
// DS002 = "Image user should not be 'root'".
const trivyConfigJSON = `{
  "SchemaVersion": 2,
  "ArtifactName": ".",
  "Results": [
    {
      "Target": "Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "Misconfigurations": [
        {
          "ID": "DS002",
          "Title": "Image user should not be 'root'",
          "Description": "Running containers as root can be dangerous.",
          "Resolution": "Add a non-root USER instruction.",
          "Severity": "HIGH",
          "Message": "Specify at least 1 USER command in Dockerfile",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
          "References": []
        }
      ]
    }
  ]
}`

// trivyCycloneDXJSON is a minimal CycloneDX JSON that trivy writes when --format cyclonedx is used.
const trivyCycloneDXJSON = `{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[]}`

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

// setupSmartFakeTrivy creates a fake trivy that dispatches on the first argument:
//   - "image" with "--format cyclonedx" → writes trivyCycloneDXJSON to --output file
//   - "config"                          → prints configJSON on stdout
//   - "image" (default)                 → prints imageJSON on stdout
func setupSmartFakeTrivy(t *testing.T, imageJSON, configJSON string) func() {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake trivy test not supported on Windows")
	}
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "trivy")

	imageEsc := strings.ReplaceAll(imageJSON, "'", `'\''`)
	configEsc := strings.ReplaceAll(configJSON, "'", `'\''`)
	cdxEsc := strings.ReplaceAll(trivyCycloneDXJSON, "'", `'\''`)

	// The script checks $1 (subcommand) and args for --format cyclonedx.
	script := fmt.Sprintf(`#!/bin/sh
SUBCMD="$1"
shift
if [ "$SUBCMD" = "config" ]; then
  printf '%%s' '%s'
  exit 0
fi
# image subcommand: check for cyclonedx
OUTPUT_FILE=""
IS_CDX=0
PREV=""
for arg in "$@"; do
  if [ "$PREV" = "--output" ]; then OUTPUT_FILE="$arg"; fi
  if [ "$arg" = "cyclonedx" ]; then IS_CDX=1; fi
  PREV="$arg"
done
if [ "$IS_CDX" = "1" ] && [ -n "$OUTPUT_FILE" ]; then
  printf '%%s' '%s' > "$OUTPUT_FILE"
  exit 0
fi
printf '%%s' '%s'
`, configEsc, cdxEsc, imageEsc)

	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
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

// TestRunScan_dockerfileFindingsMerged verifies that when --dockerfile is set,
// misconfigurations from trivy config are merged with image scan findings.
// Success: combined findings list contains DS002 (the Dockerfile misconfig).
// Failure: DS002 missing → dockerfile scan path silently dropped.
func TestRunScan_dockerfileFindingsMerged(t *testing.T) {
	cleanup := setupSmartFakeTrivy(t, trivyJSONClean, trivyConfigJSON)
	defer cleanup()

	dir := t.TempDir()
	// Create a real file at the dockerfile path — scanner stats the file before calling trivy.
	dfPath := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(dfPath, []byte("FROM alpine:latest\n"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := runScanOpts{
		image:      "testimage:latest",
		dockerfile: dfPath,
		severity:   []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
		offline:    true,
		outputDir:  dir,
		outputName: "report",
		format:     []string{"sarif", "markdown"},
	}
	code := runScan(context.Background(), opts)
	if code != 0 {
		t.Fatalf("unexpected exit code %d; want 0", code)
	}

	// The markdown report must mention DS002.
	data, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatalf("report.md missing: %v", err)
	}
	if !strings.Contains(string(data), "DS002") {
		t.Errorf("report.md does not contain DS002 — dockerfile scan findings were silently dropped\n%s", string(data)[:min(len(data), 500)])
	}
}

// TestRunScan_sbomWritten verifies that --sbom produces a CycloneDX JSON file.
// Success: <name>.cdx.json exists with bomFormat = "CycloneDX".
// Failure: file missing or malformed → SBOM output silently broken.
func TestRunScan_sbomWritten(t *testing.T) {
	cleanup := setupSmartFakeTrivy(t, trivyJSONClean, "")
	defer cleanup()

	dir := t.TempDir()
	opts := runScanOpts{
		image:      "testimage:latest",
		severity:   []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
		offline:    true,
		outputDir:  dir,
		outputName: "report",
		format:     []string{"sarif"},
		sbom:       true,
	}
	code := runScan(context.Background(), opts)
	if code != 0 {
		t.Fatalf("unexpected exit code %d; want 0", code)
	}

	sbomPath := filepath.Join(dir, "report.cdx.json")
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("report.cdx.json missing: %v", err)
	}
	if !strings.Contains(string(data), "CycloneDX") {
		t.Errorf("report.cdx.json does not contain 'CycloneDX' — SBOM output malformed")
	}
}

// TestRunScan_offlineSkipsKEV verifies that --offline prevents any HTTP call to the CISA KEV endpoint.
// Success: zero requests reach the mock server when offline=true.
// Failure: live KEV calls made in offline mode → undiscovered network dependency in air-gapped envs.
func TestRunScan_offlineSkipsKEV(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake trivy test not supported on Windows")
	}

	// Point KEV at a recording server; any request increments hits.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprintln(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	prevURL := kev.SetURLForTest(srv.URL)
	kev.ResetForTest()
	defer func() {
		kev.SetURLForTest(prevURL)
		kev.ResetForTest()
	}()

	cleanup := setupFakeTrivy(t, trivyJSONCritical)
	defer cleanup()

	dir := t.TempDir()
	opts := runScanOpts{
		image:      "testimage:latest",
		severity:   []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
		offline:    true,
		outputDir:  dir,
		outputName: "report",
		format:     []string{"sarif"},
	}
	if code := runScan(context.Background(), opts); code != 0 {
		t.Fatalf("unexpected exit code %d", code)
	}
	if hits > 0 {
		t.Errorf("KEV endpoint hit %d time(s) in offline mode — should be 0", hits)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

// MCP server for Docker Scanner: exposes scan_image, scan_rootfs, check_runtime,
// and db_update as MCP tools so IDEs and AI assistants (Cursor, Claude, Copilot)
// can run scans and get enriched findings.
//
// Run: go run ./cmd/mcp-server (stdio transport; IDE/agent spawns this process).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/docker-scanner/scanner/pkg/remediate"
	"github.com/docker-scanner/scanner/pkg/report"
	"github.com/docker-scanner/scanner/pkg/runc"
	"github.com/docker-scanner/scanner/pkg/scanner"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "docker-scanner",
		Version: "1.1.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: "scan_image",
		Description: "Scan a container image for vulnerabilities using Trivy, enriched with CISA KEV " +
			"(known exploited), OSV.dev CVE back-fill, and plain-English remediation. " +
			"Optionally scans a Dockerfile for misconfigurations, checks the host runc version " +
			"for container escape CVEs, and generates a CycloneDX SBOM. " +
			"Returns a structured summary and full findings list. Requires Trivy in PATH.",
	}, handleScanImage)

	mcp.AddTool(server, &mcp.Tool{
		Name: "scan_rootfs",
		Description: "Scan a root filesystem path for vulnerabilities (e.g. an LXC container rootfs " +
			"at /var/lib/lxc/<name>/rootfs, or any unpacked image layer). Same enrichment as scan_image. " +
			"Requires Trivy in PATH.",
	}, handleScanRootfs)

	mcp.AddTool(server, &mcp.Tool{
		Name: "check_runtime",
		Description: "Check the host runc version for known container escape CVEs " +
			"(CVE-2024-21626 LEAKY VESSELS, CVE-2025-31133, CVE-2025-52565, CVE-2025-52881). " +
			"These vulnerabilities are in the container runtime on the host — invisible to image scanners. " +
			"Returns advisory findings if the host runc is vulnerable.",
	}, handleCheckRuntime)

	mcp.AddTool(server, &mcp.Tool{
		Name: "db_update",
		Description: "Update the Trivy vulnerability database. Run once before offline scans " +
			"or to refresh the cache with the latest CVEs. Optional cache_dir.",
	}, handleDbUpdate)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

// ── scan_image ────────────────────────────────────────────────────────────────

type ScanImageInput struct {
	Image          string `json:"image"                    jsonschema:"required,description=Image reference (e.g. alpine:latest or myregistry.io/app:v1)"`
	Dockerfile     string `json:"dockerfile,omitempty"     jsonschema:"description=Optional Dockerfile path for misconfiguration scan"`
	Severity       string `json:"severity,omitempty"       jsonschema:"description=Comma-separated severities: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN (default: all)"`
	FailOnSeverity string `json:"fail_on_severity,omitempty" jsonschema:"description=Return error if any finding matches these severities (e.g. CRITICAL,HIGH)"`
	CheckRuntime   bool   `json:"check_runtime,omitempty"  jsonschema:"description=Also check host runc version for container escape CVEs"`
	SBOM           bool   `json:"sbom,omitempty"           jsonschema:"description=Generate a CycloneDX SBOM alongside the scan (written to reports/mcp-report.cdx.json)"`
	Offline        bool   `json:"offline,omitempty"        jsonschema:"description=Skip DB update and OSV enrichment; use cache only"`
	CacheDir       string `json:"cache_dir,omitempty"      jsonschema:"description=Trivy cache directory (empty = system default)"`
}

type ScanRootfsInput struct {
	Path           string `json:"path"                     jsonschema:"required,description=Absolute path to root filesystem (e.g. /var/lib/lxc/mycontainer/rootfs)"`
	Severity       string `json:"severity,omitempty"       jsonschema:"description=Comma-separated severities: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN (default: all)"`
	FailOnSeverity string `json:"fail_on_severity,omitempty" jsonschema:"description=Return error if any finding matches these severities"`
	Offline        bool   `json:"offline,omitempty"        jsonschema:"description=Skip DB update; use cache only"`
	CacheDir       string `json:"cache_dir,omitempty"      jsonschema:"description=Trivy cache directory (empty = system default)"`
}

type ScanResult struct {
	Ok          bool                  `json:"ok"`
	Target      string                `json:"target"`
	Count       int                   `json:"findings_count"`
	Summary     string                `json:"summary"`
	Exploitable int                   `json:"exploitable_count"`
	Findings    []scanFindingSummary  `json:"findings,omitempty"`
	ReportDir   string                `json:"report_dir,omitempty"`
	PolicyFail  bool                  `json:"policy_violated,omitempty"`
	Error       string                `json:"error,omitempty"`
}

type scanFindingSummary struct {
	CVEID       string `json:"cve_id,omitempty"`
	Package     string `json:"package"`
	Severity    string `json:"severity"`
	Exploitable string `json:"exploitable,omitempty"`
	FixedIn     string `json:"fixed_in,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

func handleScanImage(ctx context.Context, req *mcp.CallToolRequest, input ScanImageInput) (*mcp.CallToolResult, any, error) {
	severities := parseSeverities(input.Severity)
	opts := scanner.ScanOptions{
		Image:      input.Image,
		Dockerfile: input.Dockerfile,
		Severity:   severities,
		Offline:    input.Offline,
		CacheDir:   input.CacheDir,
	}

	findings, err := scanner.Scan(ctx, opts)
	if err != nil {
		return errorResult(ScanResult{Ok: false, Target: input.Image, Error: err.Error()})
	}

	// Prepend host runc advisory findings if requested.
	if input.CheckRuntime {
		if runcVer, err := runc.HostVersion(ctx); err == nil && runcVer != "" {
			runcFindings := runc.AdvisoryFindings(runcVer)
			findings = append(runcFindings, findings...)
		}
	}

	enriched := remediate.Enrich(findings, input.Offline)

	// Optional SBOM generation.
	if input.SBOM {
		sbomPath := "reports/mcp-report.cdx.json"
		_ = scanner.GenerateSBOM(ctx, opts, sbomPath) // best-effort; don't fail scan on SBOM error
	}

	result := buildScanResult(input.Image, enriched, input.FailOnSeverity)
	b, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}

func handleScanRootfs(ctx context.Context, req *mcp.CallToolRequest, input ScanRootfsInput) (*mcp.CallToolResult, any, error) {
	severities := parseSeverities(input.Severity)
	opts := scanner.ScanOptions{
		Rootfs:   input.Path,
		Severity: severities,
		Offline:  input.Offline,
		CacheDir: input.CacheDir,
	}
	findings, err := scanner.Scan(ctx, opts)
	if err != nil {
		return errorResult(ScanResult{Ok: false, Target: input.Path, Error: err.Error()})
	}
	enriched := remediate.Enrich(findings, input.Offline)
	result := buildScanResult(input.Path, enriched, input.FailOnSeverity)
	b, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}

// ── check_runtime ─────────────────────────────────────────────────────────────

type CheckRuntimeInput struct{}

type CheckRuntimeResult struct {
	Ok           bool                 `json:"ok"`
	RuncVersion  string               `json:"runc_version,omitempty"`
	Vulnerable   bool                 `json:"vulnerable"`
	FindingCount int                  `json:"finding_count"`
	Findings     []scanFindingSummary `json:"findings,omitempty"`
	Error        string               `json:"error,omitempty"`
}

func handleCheckRuntime(ctx context.Context, req *mcp.CallToolRequest, input CheckRuntimeInput) (*mcp.CallToolResult, any, error) {
	runcVer, err := runc.HostVersion(ctx)
	if err != nil {
		out := CheckRuntimeResult{Ok: false, Error: err.Error()}
		b, _ := json.MarshalIndent(out, "", "  ")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
	}

	findings := runc.AdvisoryFindings(runcVer)
	summaries := make([]scanFindingSummary, 0, len(findings))
	for _, f := range findings {
		summaries = append(summaries, scanFindingSummary{
			CVEID:       f.CVEID,
			Package:     "runc " + runcVer,
			Severity:    f.Severity,
			Exploitable: f.Exploitable,
			Remediation: f.RemediationText,
		})
	}

	out := CheckRuntimeResult{
		Ok:           true,
		RuncVersion:  runcVer,
		Vulnerable:   len(findings) > 0,
		FindingCount: len(findings),
		Findings:     summaries,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}

// ── db_update ─────────────────────────────────────────────────────────────────

type DbUpdateInput struct {
	CacheDir string `json:"cache_dir,omitempty" jsonschema:"description=Trivy cache directory (empty = system default)"`
}

type DbUpdateResult struct {
	Ok      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func handleDbUpdate(ctx context.Context, req *mcp.CallToolRequest, input DbUpdateInput) (*mcp.CallToolResult, any, error) {
	args := []string{"image", "--download-db-only"}
	if input.CacheDir != "" {
		args = append(args, "--cache-dir", input.CacheDir)
	}
	cmd := exec.CommandContext(ctx, "trivy", args...)
	out, err := cmd.CombinedOutput()
	var result DbUpdateResult
	if err != nil {
		result = DbUpdateResult{Ok: false, Error: strings.TrimSpace(string(out)) + ": " + err.Error()}
	} else {
		result = DbUpdateResult{Ok: true, Message: "Trivy DB updated successfully."}
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func parseSeverities(s string) []string {
	if s == "" {
		return []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(strings.ToUpper(p)); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func buildScanResult(target string, enriched []scanner.Finding, failOnSeverity string) ScanResult {
	reportDir := "reports"
	if err := report.Generate(enriched, report.Options{
		Formats:        []string{"sarif", "markdown", "html", "csv"},
		OutputDir:      reportDir,
		ReportBaseName: "mcp-report",
	}); err != nil {
		reportDir = "(report write failed: " + err.Error() + ")"
	}

	summaries := make([]scanFindingSummary, 0, len(enriched))
	exploitable := 0
	for _, f := range enriched {
		if strings.ToLower(f.Exploitable) == "yes" {
			exploitable++
		}
		summaries = append(summaries, scanFindingSummary{
			CVEID:       f.CVEID,
			Package:     fmt.Sprintf("%s %s", f.Package, f.CurrentVersion),
			Severity:    f.Severity,
			Exploitable: f.Exploitable,
			FixedIn:     f.FixedVersion,
			Remediation: f.RemediationText,
		})
	}

	// Policy check.
	policyFail := false
	if failOnSeverity != "" {
		failSet := make(map[string]bool)
		for _, s := range strings.Split(failOnSeverity, ",") {
			failSet[strings.TrimSpace(strings.ToUpper(s))] = true
		}
		for _, f := range enriched {
			if failSet[strings.ToUpper(f.Severity)] {
				policyFail = true
				break
			}
		}
	}

	return ScanResult{
		Ok:          true,
		Target:      target,
		Count:       len(enriched),
		Summary:     formatSummary(enriched),
		Exploitable: exploitable,
		Findings:    summaries,
		ReportDir:   reportDir,
		PolicyFail:  policyFail,
	}
}

func formatSummary(findings []scanner.Finding) string {
	if len(findings) == 0 {
		return "No findings."
	}
	bySev := make(map[string]int)
	exploitable := 0
	for _, f := range findings {
		s := strings.ToUpper(strings.TrimSpace(f.Severity))
		if s == "" {
			s = "UNKNOWN"
		}
		bySev[s]++
		if strings.ToLower(f.Exploitable) == "yes" {
			exploitable++
		}
	}
	var parts []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", sev, n))
		}
	}
	if exploitable > 0 {
		parts = append(parts, fmt.Sprintf("EXPLOITABLE:%d", exploitable))
	}
	return strings.Join(parts, " ")
}

func errorResult(r ScanResult) (*mcp.CallToolResult, any, error) {
	b, _ := json.MarshalIndent(r, "", "  ")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}

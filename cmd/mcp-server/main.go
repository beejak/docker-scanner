// MCP server for Docker Scanner: exposes scan_image and db_update as MCP tools
// so IDEs and AI assistants can run scans and get results.
// Run: go run ./cmd/mcp-server (stdio transport; Cursor/IDE spawns this).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/docker-scanner/scanner/pkg/remediate"
	"github.com/docker-scanner/scanner/pkg/report"
	"github.com/docker-scanner/scanner/pkg/scanner"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "docker-scanner",
		Version: "1.0.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_image",
		Description: "Scan a container image for vulnerabilities (and optionally a Dockerfile for misconfigurations). Returns a summary and enriched findings (CVE, severity, exploitable, remediation). Requires Trivy in PATH.",
	}, handleScanImage)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "db_update",
		Description: "Update the Trivy vulnerability database. Call when not using offline mode to refresh the cache. Optional cache_dir.",
	}, handleDbUpdate)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

type ScanImageInput struct {
	Image      string `json:"image" jsonschema:"required,description=Image reference (e.g. alpine:latest or myregistry.io/app:v1)"`
	Dockerfile string `json:"dockerfile,omitempty" jsonschema:"description=Optional path to Dockerfile for config/misconfiguration scan"`
	Severity   string `json:"severity,omitempty" jsonschema:"description=Comma-separated: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN (default all)"`
	Offline    bool   `json:"offline,omitempty" jsonschema:"description=Skip DB update; use cache only"`
	CacheDir   string `json:"cache_dir,omitempty" jsonschema:"description=Trivy cache directory (empty = default)"`
}

type ScanImageResult struct {
	Ok         bool   `json:"ok"`
	Image      string `json:"image"`
	Count      int    `json:"findings_count"`
	Summary    string `json:"summary"`
	Findings   []scanFindingSummary `json:"findings,omitempty"`
	ReportDir  string `json:"report_dir,omitempty"`
	Error      string `json:"error,omitempty"`
}

type scanFindingSummary struct {
	CVEID      string `json:"cve_id,omitempty"`
	Package    string `json:"package"`
	Severity   string `json:"severity"`
	Exploitable string `json:"exploitable,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

func handleScanImage(ctx context.Context, req *mcp.CallToolRequest, input ScanImageInput) (*mcp.CallToolResult, any, error) {
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	if input.Severity != "" {
		parts := strings.Split(input.Severity, ",")
		severities = nil
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				severities = append(severities, s)
			}
		}
	}
	opts := scanner.ScanOptions{
		Image:      input.Image,
		Dockerfile: input.Dockerfile,
		Severity:   severities,
		Offline:    input.Offline,
		CacheDir:   input.CacheDir,
	}
	findings, err := scanner.Scan(ctx, opts)
	if err != nil {
		out := ScanImageResult{Ok: false, Image: input.Image, Error: err.Error()}
		b, _ := json.MarshalIndent(out, "", "  ")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
		}, nil, nil
	}
	enriched := remediate.Enrich(findings, input.Offline)
	summaries := make([]scanFindingSummary, 0, len(enriched))
	for _, f := range enriched {
		summaries = append(summaries, scanFindingSummary{
			CVEID:       f.CVEID,
			Package:    f.Package + " " + f.CurrentVersion,
			Severity:    f.Severity,
			Exploitable: f.Exploitable,
			Remediation: f.RemediationText,
		})
	}
	reportDir := "./reports"
	baseName := "mcp-report"
	if err := report.Generate(enriched, report.Options{
		Formats:       []string{"markdown", "html"},
		OutputDir:     reportDir,
		ReportBaseName: baseName,
	}); err != nil {
		reportDir = "(report write failed: " + err.Error() + ")"
	}
	out := ScanImageResult{
		Ok:        true,
		Image:     input.Image,
		Count:     len(enriched),
		Summary:   formatSummary(enriched),
		Findings:  summaries,
		ReportDir: reportDir,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

func formatSummary(findings []scanner.Finding) string {
	if len(findings) == 0 {
		return "No findings."
	}
	bySev := make(map[string]int)
	for _, f := range findings {
		s := strings.ToUpper(strings.TrimSpace(f.Severity))
		if s == "" {
			s = "UNKNOWN"
		}
		bySev[s]++
	}
	var parts []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, sev+":"+fmt.Sprint(n))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

type DbUpdateInput struct {
	CacheDir string `json:"cache_dir,omitempty" jsonschema:"description=Trivy cache directory (empty = default)"`
}

type DbUpdateResult struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func handleDbUpdate(ctx context.Context, req *mcp.CallToolRequest, input DbUpdateInput) (*mcp.CallToolResult, any, error) {
	// CLI db update is not yet implemented; same here. Tell user to run trivy or scanner without --offline.
	out := DbUpdateResult{Ok: true}
	out.Error = "DB update not implemented in scanner; run scanner without --offline for first run, or update Trivy DB directly (trivy image --download-db-only)."
	b, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

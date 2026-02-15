package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker-scanner/scanner/pkg/scanner"
)

// Options holds output options (formats, output dir, report base name).
type Options struct {
	Formats       []string // "sarif", "markdown", "html", "csv"
	OutputDir     string
	ReportBaseName string   // Base name for report files (e.g. "report" or "report-20060102-150405"). Default "report".
}

// Generate writes SARIF, Markdown, HTML, and/or CSV from enriched findings to OutputDir.
func Generate(findings []scanner.Finding, opts Options) error {
	if err := os.MkdirAll(opts.OutputDir, 0755); err != nil {
		return err
	}
	base := opts.ReportBaseName
	if base == "" {
		base = "report"
	}
	for _, f := range opts.Formats {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "sarif":
			if err := writeSARIF(findings, filepath.Join(opts.OutputDir, base+".sarif")); err != nil {
				return err
			}
		case "markdown":
			if err := writeMarkdown(findings, filepath.Join(opts.OutputDir, base+".md")); err != nil {
				return err
			}
		case "html":
			if err := writeHTML(findings, filepath.Join(opts.OutputDir, base+".html")); err != nil {
				return err
			}
		case "csv":
			if err := writeCSV(findings, filepath.Join(opts.OutputDir, base+".csv")); err != nil {
				return err
			}
		}
	}
	return nil
}

// SARIF 2.1 minimal structure for Azure/GitHub Security tab.
type sarifDoc struct {
	Schema  string  `json:"$schema"`
	Version string  `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string       `json:"name"`
	Version         string       `json:"version"`
	InformationURI  string       `json:"informationUri"`
	Rules           []sarifRule  `json:"rules"`
}

type sarifRule struct {
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	ShortDescription sarifMessage  `json:"shortDescription"`
	Help             sarifHelp     `json:"help,omitempty"`
}

type sarifHelp struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level,omitempty"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func writeSARIF(findings []scanner.Finding, path string) error {
	ruleIDs := make(map[string]bool)
	var rules []sarifRule
	var results []sarifResult
	for _, f := range findings {
		ruleID := f.CVEID
		if ruleID == "" {
			ruleID = "vuln-" + f.Package + "-" + f.CurrentVersion
		}
		if !ruleIDs[ruleID] {
			ruleIDs[ruleID] = true
			helpText := f.RemediationText
			if len(f.RemediationLinks) > 0 {
				helpText += "\n\n" + strings.Join(f.RemediationLinks, "\n")
			}
			rules = append(rules, sarifRule{
				ID:   ruleID,
				Name: f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				Help: sarifHelp{Text: helpText},
			})
		}
		level := severityToSarifLevel(f.Severity)
		msg := fmt.Sprintf("%s in %s %s: %s", f.CVEID, f.Package, f.CurrentVersion, f.Title)
		if f.RemediationText != "" {
			msg += ". " + f.RemediationText
		}
		sr := sarifResult{
			RuleID:  ruleID,
			Level:   level,
			Message: sarifMessage{Text: msg},
		}
		if f.FilePath != "" {
			sr.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.FilePath},
				},
			}}
		}
		results = append(results, sr)
	}
	doc := sarifDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "Docker Container Scanner",
					Version:        "0.1.0",
					InformationURI: "https://github.com/docker-scanner/scanner",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func severityToSarifLevel(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "error"
	case "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "UNKNOWN":
		return "note"
	default:
		return "warning"
	}
}

func writeMarkdown(findings []scanner.Finding, path string) error {
	var b strings.Builder
	b.WriteString("# Container scan report\n\n")
	b.WriteString("Findings include severities: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN (default: all). Count depends on Trivy DB and image.\n\n")
	b.WriteString("| CVE | Package | Severity | Exploitable | Why severity | Exploit info | Path / location | Remediation |\n")
	b.WriteString("|-----|--------|----------|-------------|--------------|--------------|-----------------|-------------|\n")
	for _, f := range findings {
		cve := f.CVEID
		if cve == "" {
			cve = "-"
		}
		path := f.FilePath
		if path == "" {
			path = "-"
		}
		rem := f.RemediationText
		if len(f.RemediationLinks) > 0 {
			rem += " " + f.RemediationLinks[0]
		}
		exp := f.Exploitable
		if exp == "" {
			exp = "-"
		}
		why := f.WhySeverity
		if why == "" {
			why = "-"
		}
		info := f.ExploitInfo
		if info == "" {
			info = "-"
		}
		b.WriteString(fmt.Sprintf("| %s | %s %s | %s | %s | %s | %s | %s | %s |\n", cve, f.Package, f.CurrentVersion, f.Severity, exp, why, info, path, rem))
	}
	b.WriteString("\n## Remediation details\n\n")
	for _, f := range findings {
		b.WriteString(fmt.Sprintf("### %s - %s\n\n", f.CVEID, f.Package))
		b.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
		if f.Exploitable != "" {
			b.WriteString(fmt.Sprintf("- **Exploitable:** %s\n", f.Exploitable))
		}
		if f.WhySeverity != "" {
			b.WriteString(fmt.Sprintf("- **Why severity:** %s\n", f.WhySeverity))
		}
		if f.ExploitInfo != "" {
			b.WriteString(fmt.Sprintf("- **Exploit info:** %s\n", f.ExploitInfo))
		}
		if f.FilePath != "" {
			b.WriteString(fmt.Sprintf("- **Path / location:** %s\n", f.FilePath))
		}
		b.WriteString(fmt.Sprintf("- **Installed:** %s\n", f.CurrentVersion))
		if f.FixedVersion != "" {
			b.WriteString(fmt.Sprintf("- **Fixed in:** %s\n", f.FixedVersion))
		}
		b.WriteString(fmt.Sprintf("- **Remediation:** %s\n", f.RemediationText))
		for _, link := range f.RemediationLinks {
			b.WriteString(fmt.Sprintf("- %s\n", link))
		}
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func writeHTML(findings []scanner.Finding, outPath string) error {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"UTF-8\"><title>Scan report</title></head>\n<body>\n")
	b.WriteString("<h1>Container scan report</h1>\n<p>Findings include severities: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN (default: all). Count depends on Trivy DB and image.</p>\n<table border=\"1\"><thead><tr><th>CVE</th><th>Package</th><th>Severity</th><th>Exploitable</th><th>Why severity</th><th>Exploit info</th><th>Path / location</th><th>Remediation</th></tr></thead>\n<tbody>\n")
	for _, f := range findings {
		cve := f.CVEID
		if cve == "" {
			cve = "-"
		}
		loc := f.FilePath
		if loc == "" {
			loc = "-"
		}
		exp, why, info := f.Exploitable, f.WhySeverity, f.ExploitInfo
		if exp == "" {
			exp = "-"
		}
		if why == "" {
			why = "-"
		}
		if info == "" {
			info = "-"
		}
		rem := escapeHTML(f.RemediationText)
		if len(f.RemediationLinks) > 0 {
			rem += ` <a href="` + escapeHTML(f.RemediationLinks[0]) + `">Link</a>`
		}
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s %s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			escapeHTML(cve), escapeHTML(f.Package), escapeHTML(f.CurrentVersion), escapeHTML(f.Severity), escapeHTML(exp), escapeHTML(why), escapeHTML(info), escapeHTML(loc), rem))
	}
	b.WriteString("</tbody></table>\n</body>\n</html>")
	return os.WriteFile(outPath, []byte(b.String()), 0644)
}

func writeCSV(findings []scanner.Finding, outPath string) error {
	var b strings.Builder
	b.WriteString("CVE,Title,Description,Package,CurrentVersion,FixedVersion,Severity,Exploitable,WhySeverity,ExploitInfo,Path/Location,Remediation,RemediationLinks\n")
	for _, f := range findings {
		b.WriteString(csvEscape(f.CVEID) + ",")
		b.WriteString(csvEscape(f.Title) + ",")
		b.WriteString(csvEscape(f.Description) + ",")
		b.WriteString(csvEscape(f.Package) + ",")
		b.WriteString(csvEscape(f.CurrentVersion) + ",")
		b.WriteString(csvEscape(f.FixedVersion) + ",")
		b.WriteString(csvEscape(f.Severity) + ",")
		b.WriteString(csvEscape(f.Exploitable) + ",")
		b.WriteString(csvEscape(f.WhySeverity) + ",")
		b.WriteString(csvEscape(f.ExploitInfo) + ",")
		b.WriteString(csvEscape(f.FilePath) + ",")
		b.WriteString(csvEscape(f.RemediationText) + ",")
		if len(f.RemediationLinks) > 0 {
			b.WriteString(csvEscape(strings.Join(f.RemediationLinks, " ")))
		}
		b.WriteString("\n")
	}
	return os.WriteFile(outPath, []byte(b.String()), 0644)
}

// ImageFinding pairs an image reference with a finding (e.g. for baseline consolidated report).
type ImageFinding struct {
	Image   string
	Finding scanner.Finding
}

// WriteFindingsCSVWithImage writes a CSV with Image as first column, then CVE, Title, Description, Package, Severity, Exploitable, etc.
func WriteFindingsCSVWithImage(entries []ImageFinding, outPath string) error {
	var b strings.Builder
	b.WriteString("Image,CVE,Title,Description,Package,CurrentVersion,FixedVersion,Severity,Exploitable,WhySeverity,ExploitInfo,Path/Location,Remediation,RemediationLinks\n")
	for _, e := range entries {
		f := e.Finding
		b.WriteString(csvEscape(e.Image) + ",")
		b.WriteString(csvEscape(f.CVEID) + ",")
		b.WriteString(csvEscape(f.Title) + ",")
		b.WriteString(csvEscape(f.Description) + ",")
		b.WriteString(csvEscape(f.Package) + ",")
		b.WriteString(csvEscape(f.CurrentVersion) + ",")
		b.WriteString(csvEscape(f.FixedVersion) + ",")
		b.WriteString(csvEscape(f.Severity) + ",")
		b.WriteString(csvEscape(f.Exploitable) + ",")
		b.WriteString(csvEscape(f.WhySeverity) + ",")
		b.WriteString(csvEscape(f.ExploitInfo) + ",")
		b.WriteString(csvEscape(f.FilePath) + ",")
		b.WriteString(csvEscape(f.RemediationText) + ",")
		if len(f.RemediationLinks) > 0 {
			b.WriteString(csvEscape(strings.Join(f.RemediationLinks, " ")))
		}
		b.WriteString("\n")
	}
	return os.WriteFile(outPath, []byte(b.String()), 0644)
}

func csvEscape(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, ",\"\r\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return `"` + s + `"`
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

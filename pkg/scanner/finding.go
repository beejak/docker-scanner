package scanner

// Finding is the single finding model used by enricher and report generator.
// Do not duplicate; enricher adds remediation fields.
type Finding struct {
	CVEID           string   `json:"cve_id"`
	Package         string   `json:"package"`
	CurrentVersion  string   `json:"current_version"`
	FixedVersion    string   `json:"fixed_version,omitempty"`
	Severity        string   `json:"severity"`
	Title           string   `json:"title"`
	Description     string   `json:"description,omitempty"`
	RemediationText string   `json:"remediation_text,omitempty"`
	RemediationLinks []string `json:"remediation_links,omitempty"`
	// Location: path where the vulnerability was found (e.g. PkgPath from Trivy, or target file/layer).
	FilePath string `json:"file_path,omitempty"`
	// Enrichment: why this severity, exploit status, and ways to exploit (from CISA KEV and heuristics).
	WhySeverity string `json:"why_severity,omitempty"`
	Exploitable string `json:"exploitable,omitempty"` // "yes", "no", "unknown"
	ExploitInfo string `json:"exploit_info,omitempty"`
}

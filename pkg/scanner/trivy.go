package scanner

// Trivy JSON report shape (subset we need).
// See https://trivy.dev/docs/configuration/reporting/
type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string           `json:"Target"`
	Class           string           `json:"Class"`
	Type            string           `json:"Type"`
	Vulnerabilities []trivyVuln      `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	PkgPath          string   `json:"PkgPath"` // Path where the vulnerable package was found (file or layer path).
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
}

// trivyVulnToFinding converts one Trivy vulnerability to our Finding model.
// target is the result target (e.g. layer identifier or scanned path) for context when PkgPath is empty.
func trivyVulnToFinding(v trivyVuln, target string) Finding {
	f := Finding{
		CVEID:          v.VulnerabilityID,
		Package:        v.PkgName,
		CurrentVersion: v.InstalledVersion,
		FixedVersion:   v.FixedVersion,
		Severity:       v.Severity,
		Title:          v.Title,
		Description:    v.Description,
	}
	if v.PkgPath != "" {
		f.FilePath = v.PkgPath
	} else if target != "" {
		f.FilePath = target
	}
	if v.PrimaryURL != "" {
		f.RemediationLinks = append(f.RemediationLinks, v.PrimaryURL)
	}
	f.RemediationLinks = append(f.RemediationLinks, v.References...)
	return f
}

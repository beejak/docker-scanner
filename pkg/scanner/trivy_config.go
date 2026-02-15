package scanner

// Trivy config (misconfiguration) JSON report shape.
// See https://trivy.dev/docs/scanner/misconfiguration/
type trivyConfigReport struct {
	SchemaVersion int                 `json:"SchemaVersion"`
	ArtifactName  string              `json:"ArtifactName"`
	Results       []trivyConfigResult `json:"Results"`
}

type trivyConfigResult struct {
	Target          string              `json:"Target"`
	Class           string              `json:"Class"`
	Type            string              `json:"Type"`
	Misconfigurations []trivyMisconfig `json:"Misconfigurations"`
}

type trivyMisconfig struct {
	ID          string   `json:"ID"`
	Title       string   `json:"Title"`
	Description string   `json:"Description"`
	Resolution  string   `json:"Resolution"`
	Severity    string   `json:"Severity"`
	Message     string   `json:"Message"`
	PrimaryURL  string   `json:"PrimaryURL"`
	References  []string `json:"References"`
}

// trivyMisconfigToFinding converts one Trivy misconfiguration to our Finding model.
// CVEID holds the misconfig check ID (e.g. DS001); Package is the target file (e.g. Dockerfile).
func trivyMisconfigToFinding(m trivyMisconfig, target string) Finding {
	sev := m.Severity
	if sev == "" {
		sev = "UNKNOWN"
	}
	f := Finding{
		CVEID:           m.ID,
		Package:         target,
		CurrentVersion:  "",
		FixedVersion:    "",
		Severity:        sev,
		Title:           m.Title,
		Description:     m.Description,
		RemediationText: m.Resolution,
		FilePath:        target, // Misconfig location is the scanned file (e.g. Dockerfile).
	}
	if m.PrimaryURL != "" {
		f.RemediationLinks = append(f.RemediationLinks, m.PrimaryURL)
	}
	f.RemediationLinks = append(f.RemediationLinks, m.References...)
	return f
}

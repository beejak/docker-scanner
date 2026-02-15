package remediate

import (
	"fmt"
	"strings"

	"github.com/docker-scanner/scanner/pkg/kev"
	"github.com/docker-scanner/scanner/pkg/scanner"
)

// Enrich adds remediation text, links, exploit status (CISA KEV), why-severity text, and severity adjustment.
// In offline mode we skip KEV fetch and set Exploitable to "unknown".
func Enrich(findings []scanner.Finding, offline bool) []scanner.Finding {
	if !offline {
		_ = kev.Load()
	}
	out := make([]scanner.Finding, len(findings))
	for i, f := range findings {
		out[i] = f
		// Remediation text: keep if already set (e.g. Dockerfile misconfig Resolution); otherwise set from fixed version
		if f.RemediationText == "" {
			if f.FixedVersion != "" {
				out[i].RemediationText = fmt.Sprintf("Upgrade %s from %s to %s", f.Package, f.CurrentVersion, f.FixedVersion)
			} else if f.CurrentVersion != "" || f.Package != "" {
				out[i].RemediationText = fmt.Sprintf("Upgrade or patch %s (currently %s); no fixed version in DB", f.Package, f.CurrentVersion)
			}
		}
		// Ensure we have at least one link for vulns (CVE) or misconfig (AVD ID)
		if len(f.RemediationLinks) == 0 && f.CVEID != "" {
			if strings.HasPrefix(strings.ToUpper(f.CVEID), "CVE-") {
				out[i].RemediationLinks = []string{
					"https://nvd.nist.gov/vuln/detail/" + f.CVEID,
					"https://avd.aquasec.com/nvd/" + strings.ToLower(f.CVEID),
				}
			} else {
				out[i].RemediationLinks = []string{"https://avd.aquasec.com/misconfig/" + strings.ToLower(f.CVEID)}
			}
		}
		// Exploit and severity enrichment (CVE only)
		if strings.HasPrefix(strings.ToUpper(f.CVEID), "CVE-") {
			out[i].WhySeverity = whySeverityText(f.Severity)
			if offline {
				out[i].Exploitable = "unknown"
				out[i].ExploitInfo = "Offline mode; check NVD and vendor advisories for exploit status."
			} else if kev.IsKnownExploited(f.CVEID) {
				out[i].Exploitable = "yes"
				shortDesc, name, ransomware := kev.GetInfo(f.CVEID)
				out[i].ExploitInfo = "Listed in CISA Known Exploited Vulnerabilities catalog; active exploitation observed. Prioritize remediation."
				if shortDesc != "" {
					out[i].ExploitInfo = shortDesc
				}
				if name != "" {
					out[i].ExploitInfo += " (" + name + ")"
				}
				if strings.EqualFold(ransomware, "Known") {
					out[i].ExploitInfo += " Known ransomware campaign use."
				}
				// If exploitable, treat as CRITICAL for prioritization
				if out[i].Severity != "CRITICAL" {
					out[i].Severity = "CRITICAL"
				}
			} else {
				out[i].Exploitable = "no"
				out[i].ExploitInfo = "Not in CISA KEV; check NVD and vendor advisories for exploit availability."
			}
		} else {
			out[i].WhySeverity = whySeverityText(f.Severity)
			out[i].Exploitable = "unknown"
			out[i].ExploitInfo = "Non-CVE finding; see vendor/misconfig docs for impact."
		}
	}
	return out
}

func whySeverityText(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "Critical: often RCE, auth bypass, or severe impact; check NVD/CVSS for details."
	case "HIGH":
		return "High: significant impact; may allow privilege escalation or data exposure."
	case "MEDIUM":
		return "Medium: moderate impact; may require specific conditions to exploit."
	case "LOW":
		return "Low: limited impact or difficult to exploit."
	case "UNKNOWN":
		return "Severity from scanner; verify with NVD."
	default:
		return "Severity from scanner; verify with NVD."
	}
}

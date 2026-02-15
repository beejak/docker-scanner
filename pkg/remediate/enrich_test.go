package remediate

import (
	"reflect"
	"testing"

	"github.com/docker-scanner/scanner/pkg/scanner"
)

func TestEnrich(t *testing.T) {
	tests := []struct {
		name     string
		findings []scanner.Finding
		offline  bool
		want     []scanner.Finding
	}{
		{
			name:     "empty",
			findings: nil,
			offline:  false,
			want:     nil,
		},
		{
			name: "add remediation text from fixed version",
			findings: []scanner.Finding{
				{CVEID: "CVE-1", Package: "pkg", CurrentVersion: "1.0", FixedVersion: "1.1", Severity: "HIGH"},
			},
			offline: false,
			want: []scanner.Finding{
				{
					CVEID: "CVE-1", Package: "pkg", CurrentVersion: "1.0", FixedVersion: "1.1", Severity: "HIGH",
					RemediationText: "Upgrade pkg from 1.0 to 1.1",
				},
			},
		},
		{
			name: "keep existing remediation text (misconfig)",
			findings: []scanner.Finding{
				{CVEID: "DS001", Package: "Dockerfile", RemediationText: "Add USER directive", Severity: "HIGH"},
			},
			offline: false,
			want: []scanner.Finding{
				{CVEID: "DS001", Package: "Dockerfile", RemediationText: "Add USER directive", Severity: "HIGH"},
			},
		},
		{
			name: "add CVE links when none",
			findings: []scanner.Finding{
				{CVEID: "CVE-2020-1234", Package: "openssl", Severity: "HIGH"},
			},
			offline: false,
			want: []scanner.Finding{
				{
					CVEID: "CVE-2020-1234", Package: "openssl", Severity: "HIGH",
					RemediationText: "Upgrade or patch openssl (currently ); no fixed version in DB",
					RemediationLinks: []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-1234", "https://avd.aquasec.com/nvd/cve-2020-1234"},
				},
			},
		},
		{
			name: "add misconfig link for non-CVE ID",
			findings: []scanner.Finding{
				{CVEID: "DS002", Package: "Dockerfile", Severity: "MEDIUM"},
			},
			offline: false,
			want: []scanner.Finding{
				{
					CVEID: "DS002", Package: "Dockerfile", Severity: "MEDIUM",
					RemediationText: "Upgrade or patch Dockerfile (currently ); no fixed version in DB",
					RemediationLinks: []string{"https://avd.aquasec.com/misconfig/ds002"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Enrich(tt.findings, tt.offline)
			// Compare fields we care about (enricher may add RemediationText/Links; don't require exact clone of other fields)
			if len(got) != len(tt.want) {
				t.Fatalf("len(Enrich()) = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i].RemediationText != tt.want[i].RemediationText {
					t.Errorf("finding[%d].RemediationText = %q, want %q", i, got[i].RemediationText, tt.want[i].RemediationText)
				}
				if len(tt.want[i].RemediationLinks) > 0 && !reflect.DeepEqual(got[i].RemediationLinks, tt.want[i].RemediationLinks) {
					t.Errorf("finding[%d].RemediationLinks = %v, want %v", i, got[i].RemediationLinks, tt.want[i].RemediationLinks)
				}
			}
		})
	}
}

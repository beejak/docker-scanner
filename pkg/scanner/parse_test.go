package scanner

import (
	"encoding/json"
	"os"
	"testing"
)

// loadFixture reads testdata/trivy-fixture.json and returns the parsed report.
func loadFixture(t *testing.T) trivyReport {
	t.Helper()
	data, err := os.ReadFile("testdata/trivy-fixture.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var r trivyReport
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return r
}

func TestFixture_parsesCorrectly(t *testing.T) {
	r := loadFixture(t)
	if r.ArtifactName != "alpine:3.10" {
		t.Errorf("ArtifactName = %q; want alpine:3.10", r.ArtifactName)
	}
	if len(r.Results) != 1 {
		t.Fatalf("len(Results) = %d; want 1", len(r.Results))
	}
	if len(r.Results[0].Vulnerabilities) != 5 {
		t.Errorf("len(Vulnerabilities) = %d; want 5", len(r.Results[0].Vulnerabilities))
	}
}

func TestFixture_findingsConversion(t *testing.T) {
	r := loadFixture(t)
	target := r.Results[0].Target

	var findings []Finding
	for _, v := range r.Results[0].Vulnerabilities {
		findings = append(findings, trivyVulnToFinding(v, target))
	}

	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}

	// All findings must have required fields populated.
	for i, f := range findings {
		if f.CVEID == "" {
			t.Errorf("finding[%d] CVEID is empty", i)
		}
		if f.Package == "" {
			t.Errorf("finding[%d] Package is empty", i)
		}
		if f.Severity == "" {
			t.Errorf("finding[%d] Severity is empty", i)
		}
		if f.CurrentVersion == "" {
			t.Errorf("finding[%d] CurrentVersion is empty", i)
		}
	}
}

func TestFixture_severityDistribution(t *testing.T) {
	r := loadFixture(t)
	target := r.Results[0].Target

	bySeverity := map[string]int{}
	for _, v := range r.Results[0].Vulnerabilities {
		f := trivyVulnToFinding(v, target)
		bySeverity[f.Severity]++
	}

	// Fixture contains: 3 CRITICAL, 1 HIGH, 1 MEDIUM
	if bySeverity["CRITICAL"] != 3 {
		t.Errorf("CRITICAL count = %d; want 3", bySeverity["CRITICAL"])
	}
	if bySeverity["HIGH"] != 1 {
		t.Errorf("HIGH count = %d; want 1", bySeverity["HIGH"])
	}
	if bySeverity["MEDIUM"] != 1 {
		t.Errorf("MEDIUM count = %d; want 1", bySeverity["MEDIUM"])
	}
}

func TestFixture_pkgPathUsedAsFilePath(t *testing.T) {
	r := loadFixture(t)
	target := r.Results[0].Target

	// CVE-2019-14697 has PkgPath set; it should appear as FilePath.
	for _, v := range r.Results[0].Vulnerabilities {
		if v.VulnerabilityID == "CVE-2019-14697" {
			f := trivyVulnToFinding(v, target)
			if f.FilePath != "lib/libc.musl-x86_64.so.1" {
				t.Errorf("FilePath = %q; want lib/libc.musl-x86_64.so.1", f.FilePath)
			}
			return
		}
	}
	t.Fatal("CVE-2019-14697 not found in fixture")
}

func TestFixture_targetUsedWhenNoPkgPath(t *testing.T) {
	r := loadFixture(t)
	target := r.Results[0].Target

	// CVE-2021-36159 has no PkgPath; target should become FilePath.
	for _, v := range r.Results[0].Vulnerabilities {
		if v.VulnerabilityID == "CVE-2021-36159" {
			f := trivyVulnToFinding(v, target)
			if f.FilePath != target {
				t.Errorf("FilePath = %q; want %q (target)", f.FilePath, target)
			}
			return
		}
	}
	t.Fatal("CVE-2021-36159 not found in fixture")
}

func TestFixture_remediationLinksPopulated(t *testing.T) {
	r := loadFixture(t)
	target := r.Results[0].Target

	for _, v := range r.Results[0].Vulnerabilities {
		f := trivyVulnToFinding(v, target)
		if len(f.RemediationLinks) == 0 {
			t.Errorf("finding %s has no remediation links", f.CVEID)
		}
		// PrimaryURL must always be the first link when present.
		if v.PrimaryURL != "" && f.RemediationLinks[0] != v.PrimaryURL {
			t.Errorf("finding %s: first link = %q; want PrimaryURL %q", f.CVEID, f.RemediationLinks[0], v.PrimaryURL)
		}
	}
}

func TestFixture_severityFilter(t *testing.T) {
	r := loadFixture(t)
	severitySet := map[string]bool{"CRITICAL": true}

	var findings []Finding
	for _, res := range r.Results {
		target := res.Target
		for _, v := range res.Vulnerabilities {
			if severitySet[v.Severity] {
				findings = append(findings, trivyVulnToFinding(v, target))
			}
		}
	}

	if len(findings) != 3 {
		t.Errorf("CRITICAL-only filter: got %d findings; want 3", len(findings))
	}
	for _, f := range findings {
		if f.Severity != "CRITICAL" {
			t.Errorf("non-CRITICAL finding passed filter: %s %s", f.CVEID, f.Severity)
		}
	}
}

func TestScan_rootfsRejectsFile(t *testing.T) {
	// scanRootfs must reject a non-directory path.
	tmpFile, err := os.CreateTemp(t.TempDir(), "not-a-dir")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	_, err = Scan(t.Context(), ScanOptions{Rootfs: tmpFile.Name()})
	if err == nil {
		t.Error("expected error when rootfs path is a file, got nil")
	}
}

func TestScan_rootfsRejectsNonExistent(t *testing.T) {
	_, err := Scan(t.Context(), ScanOptions{Rootfs: "/nonexistent/path/that/does/not/exist"})
	if err == nil {
		t.Error("expected error for non-existent rootfs path, got nil")
	}
}

func TestGenerateSBOM_requiresImage(t *testing.T) {
	err := GenerateSBOM(t.Context(), ScanOptions{}, "/tmp/out.cdx.json")
	if err == nil {
		t.Error("expected error when Image is empty, got nil")
	}
}

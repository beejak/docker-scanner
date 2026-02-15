package scanner

import (
	"reflect"
	"testing"
)

func Test_trivyVulnToFinding(t *testing.T) {
	v := trivyVuln{
		VulnerabilityID:  "CVE-2020-1234",
		PkgName:          "openssl",
		InstalledVersion: "1.1.1a",
		FixedVersion:     "1.1.1b",
		Severity:         "HIGH",
		Title:            "OpenSSL issue",
		Description:      "Some description",
		PrimaryURL:       "https://example.com/cve",
		References:       []string{"https://ref1.com", "https://ref2.com"},
	}
	got := trivyVulnToFinding(v, "")
	want := Finding{
		CVEID:           "CVE-2020-1234",
		Package:         "openssl",
		CurrentVersion:  "1.1.1a",
		FixedVersion:    "1.1.1b",
		Severity:        "HIGH",
		Title:           "OpenSSL issue",
		Description:     "Some description",
		RemediationLinks: []string{"https://example.com/cve", "https://ref1.com", "https://ref2.com"},
	}
	if got.CVEID != want.CVEID || got.Package != want.Package || got.CurrentVersion != want.CurrentVersion ||
		got.FixedVersion != want.FixedVersion || got.Severity != want.Severity || got.Title != want.Title ||
		got.Description != want.Description {
		t.Errorf("trivyVulnToFinding() = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(got.RemediationLinks, want.RemediationLinks) {
		t.Errorf("trivyVulnToFinding() RemediationLinks = %v, want %v", got.RemediationLinks, want.RemediationLinks)
	}
}

func Test_trivyVulnToFinding_emptyPrimaryURL(t *testing.T) {
	v := trivyVuln{
		VulnerabilityID: "CVE-2020-5678",
		PkgName:         "curl",
		Severity:        "MEDIUM",
		References:      []string{"https://only-ref.com"},
	}
	got := trivyVulnToFinding(v, "")
	if len(got.RemediationLinks) != 1 || got.RemediationLinks[0] != "https://only-ref.com" {
		t.Errorf("RemediationLinks = %v, want [https://only-ref.com]", got.RemediationLinks)
	}
}

func Test_trivyVulnToFinding_withPkgPathAndTarget(t *testing.T) {
	v := trivyVuln{
		VulnerabilityID: "CVE-2020-1",
		PkgName:          "libfoo",
		PkgPath:          "/lib/libfoo.so.1",
		Severity:         "HIGH",
	}
	got := trivyVulnToFinding(v, "alpine 3.10")
	if got.FilePath != "/lib/libfoo.so.1" {
		t.Errorf("FilePath = %q, want /lib/libfoo.so.1", got.FilePath)
	}
	// When PkgPath is empty, target is used.
	got2 := trivyVulnToFinding(trivyVuln{VulnerabilityID: "CVE-2", PkgName: "p", Severity: "LOW"}, "alpine 3.10")
	if got2.FilePath != "alpine 3.10" {
		t.Errorf("FilePath (no PkgPath) = %q, want alpine 3.10", got2.FilePath)
	}
}

func Test_trivyMisconfigToFinding(t *testing.T) {
	m := trivyMisconfig{
		ID:          "DS001",
		Title:       "Run as non-root",
		Description: "Running as root is risky",
		Resolution:  "Add USER directive",
		Severity:    "HIGH",
		Message:     "Detected root",
		PrimaryURL:  "https://avd.aquasec.com/misconfig/ds001",
		References:  []string{"https://ref.com"},
	}
	got := trivyMisconfigToFinding(m, "Dockerfile")
	want := Finding{
		CVEID:           "DS001",
		Package:         "Dockerfile",
		CurrentVersion:  "",
		FixedVersion:    "",
		Severity:        "HIGH",
		Title:           "Run as non-root",
		Description:     "Running as root is risky",
		RemediationText: "Add USER directive",
		RemediationLinks: []string{"https://avd.aquasec.com/misconfig/ds001", "https://ref.com"},
	}
	if got.CVEID != want.CVEID || got.Package != want.Package || got.Severity != want.Severity ||
		got.Title != want.Title || got.RemediationText != want.RemediationText {
		t.Errorf("trivyMisconfigToFinding() = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(got.RemediationLinks, want.RemediationLinks) {
		t.Errorf("RemediationLinks = %v, want %v", got.RemediationLinks, want.RemediationLinks)
	}
}

func Test_trivyMisconfigToFinding_emptySeverity(t *testing.T) {
	m := trivyMisconfig{ID: "DS002", Severity: ""}
	got := trivyMisconfigToFinding(m, "Dockerfile")
	if got.Severity != "UNKNOWN" {
		t.Errorf("empty Severity should become UNKNOWN, got %q", got.Severity)
	}
}

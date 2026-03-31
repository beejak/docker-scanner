package runc

import (
	"testing"
)

// --- isVulnerable ---

func Test_isVulnerable(t *testing.T) {
	cases := []struct {
		name    string
		current [3]int
		fixed   [3]int
		want    bool
	}{
		{"patch below", [3]int{1, 1, 11}, [3]int{1, 1, 12}, true},
		{"patch equal", [3]int{1, 1, 12}, [3]int{1, 1, 12}, false},
		{"patch above", [3]int{1, 1, 13}, [3]int{1, 1, 12}, false},
		{"minor below", [3]int{1, 2, 7}, [3]int{1, 2, 8}, true},
		{"minor equal", [3]int{1, 2, 8}, [3]int{1, 2, 8}, false},
		{"minor above", [3]int{1, 2, 9}, [3]int{1, 2, 8}, false},
		{"major below", [3]int{1, 0, 0}, [3]int{2, 0, 0}, true},
		{"major above", [3]int{2, 0, 0}, [3]int{1, 9, 9}, false},
		{"zero version", [3]int{0, 0, 0}, [3]int{0, 0, 1}, true},
		{"all zeros", [3]int{0, 0, 0}, [3]int{0, 0, 0}, false},
		{"minor differs", [3]int{1, 1, 99}, [3]int{1, 2, 0}, true},
		{"major wins over minor", [3]int{2, 0, 0}, [3]int{1, 99, 99}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isVulnerable(c.current, c.fixed)
			if got != c.want {
				t.Errorf("isVulnerable(%v, %v) = %v; want %v", c.current, c.fixed, got, c.want)
			}
		})
	}
}

// --- AdvisoryFindings ---

func TestAdvisoryFindings_allVulnerable(t *testing.T) {
	// runc 1.1.11 is below both 1.1.12 and 1.2.8 thresholds.
	findings := AdvisoryFindings("1.1.11")
	if len(findings) != len(advisories) {
		t.Fatalf("expected %d findings for 1.1.11, got %d", len(advisories), len(findings))
	}
	for _, f := range findings {
		if f.Package != "runc" {
			t.Errorf("Package = %q; want runc", f.Package)
		}
		if f.FilePath != "host-runtime" {
			t.Errorf("FilePath = %q; want host-runtime", f.FilePath)
		}
		if f.CVEID == "" {
			t.Error("CVEID should not be empty")
		}
		if f.CurrentVersion != "1.1.11" {
			t.Errorf("CurrentVersion = %q; want 1.1.11", f.CurrentVersion)
		}
		if f.FixedVersion == "" {
			t.Error("FixedVersion should not be empty")
		}
		if f.Title == "" {
			t.Error("Title should not be empty")
		}
		if f.Severity != "CRITICAL" && f.Severity != "HIGH" {
			t.Errorf("unexpected Severity %q", f.Severity)
		}
		if len(f.RemediationLinks) < 2 {
			t.Errorf("expected at least 2 remediation links, got %d", len(f.RemediationLinks))
		}
	}
}

func TestAdvisoryFindings_safe(t *testing.T) {
	for _, ver := range []string{"1.2.8", "1.2.9", "1.3.0", "2.0.0"} {
		findings := AdvisoryFindings(ver)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for safe version %s, got %d", ver, len(findings))
		}
	}
}

func TestAdvisoryFindings_partialFix(t *testing.T) {
	// runc 1.1.12 fixes CVE-2024-21626 but not the 1.2.x CVEs.
	findings := AdvisoryFindings("1.1.12")
	cves := make(map[string]bool)
	for _, f := range findings {
		cves[f.CVEID] = true
	}
	if cves["CVE-2024-21626"] {
		t.Error("CVE-2024-21626 should NOT appear for 1.1.12 (fixed in 1.1.12)")
	}
	if !cves["CVE-2025-31133"] || !cves["CVE-2025-52565"] || !cves["CVE-2025-52881"] {
		t.Error("1.2.x CVEs should still appear for 1.1.12 (needs 1.2.8+)")
	}
}

func TestAdvisoryFindings_exactBoundary_1_2_7(t *testing.T) {
	// 1.2.7 is one below the 1.2.8 fix.
	findings := AdvisoryFindings("1.2.7")
	if len(findings) == 0 {
		t.Error("expected 1.2.x CVEs for 1.2.7")
	}
	for _, f := range findings {
		if f.CVEID == "CVE-2024-21626" {
			t.Error("CVE-2024-21626 should NOT appear for 1.2.7 (fixed in 1.1.12)")
		}
	}
}

func TestAdvisoryFindings_unparseable(t *testing.T) {
	for _, ver := range []string{"", "not-a-version", "abc.def.ghi", "v", "1.2"} {
		if findings := AdvisoryFindings(ver); findings != nil {
			t.Errorf("expected nil for unparseable version %q, got %d findings", ver, len(findings))
		}
	}
}

func TestAdvisoryFindings_prefixed(t *testing.T) {
	// Versions like "v1.1.11" or "1.1.11-rc2" should still parse the semver core.
	findings := AdvisoryFindings("v1.1.11")
	if len(findings) != len(advisories) {
		t.Errorf("expected %d findings for v1.1.11, got %d", len(advisories), len(findings))
	}
	findings = AdvisoryFindings("1.2.8-rc1")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 1.2.8-rc1, got %d", len(findings))
	}
}

func TestAdvisoryFindings_descriptionPresent(t *testing.T) {
	findings := AdvisoryFindings("1.0.0")
	for _, f := range findings {
		if f.Description == "" {
			t.Errorf("Description empty for %s", f.CVEID)
		}
	}
}

// --- Advisory table integrity ---

func TestAdvisoryTable_noEmptyFields(t *testing.T) {
	for i, a := range advisories {
		if a.CVEID == "" {
			t.Errorf("advisory[%d]: empty CVEID", i)
		}
		if a.Severity == "" {
			t.Errorf("advisory[%d]: empty Severity", i)
		}
		if a.FixedStr == "" {
			t.Errorf("advisory[%d]: empty FixedStr", i)
		}
		if a.Description == "" {
			t.Errorf("advisory[%d]: empty Description", i)
		}
	}
}

func TestAdvisoryTable_uniqueCVEIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, a := range advisories {
		if seen[a.CVEID] {
			t.Errorf("duplicate CVEID in advisory table: %s", a.CVEID)
		}
		seen[a.CVEID] = true
	}
}

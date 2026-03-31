package runc

import (
	"testing"
)

func Test_isVulnerable(t *testing.T) {
	cases := []struct {
		current [3]int
		fixed   [3]int
		want    bool
	}{
		{[3]int{1, 1, 11}, [3]int{1, 1, 12}, true},
		{[3]int{1, 1, 12}, [3]int{1, 1, 12}, false},
		{[3]int{1, 1, 13}, [3]int{1, 1, 12}, false},
		{[3]int{1, 2, 7}, [3]int{1, 2, 8}, true},
		{[3]int{1, 2, 8}, [3]int{1, 2, 8}, false},
		{[3]int{1, 2, 9}, [3]int{1, 2, 8}, false},
		{[3]int{1, 0, 0}, [3]int{2, 0, 0}, true},
		{[3]int{2, 0, 0}, [3]int{1, 9, 9}, false},
	}
	for _, c := range cases {
		got := isVulnerable(c.current, c.fixed)
		if got != c.want {
			t.Errorf("isVulnerable(%v, %v) = %v; want %v", c.current, c.fixed, got, c.want)
		}
	}
}

func TestAdvisoryFindings_vulnerable(t *testing.T) {
	// runc 1.1.11 is below both thresholds; should get all 4 advisories.
	findings := AdvisoryFindings("1.1.11")
	if len(findings) != len(advisories) {
		t.Fatalf("expected %d findings for 1.1.11, got %d", len(advisories), len(findings))
	}
	for _, f := range findings {
		if f.Package != "runc" {
			t.Errorf("expected Package=runc, got %q", f.Package)
		}
		if f.FilePath != "host-runtime" {
			t.Errorf("expected FilePath=host-runtime, got %q", f.FilePath)
		}
		if f.CVEID == "" {
			t.Error("expected non-empty CVEID")
		}
		if len(f.RemediationLinks) == 0 {
			t.Error("expected at least one remediation link")
		}
	}
}

func TestAdvisoryFindings_safe(t *testing.T) {
	// runc 1.2.8 meets all thresholds.
	findings := AdvisoryFindings("1.2.8")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 1.2.8, got %d", len(findings))
	}
}

func TestAdvisoryFindings_partial(t *testing.T) {
	// runc 1.1.12 fixes CVE-2024-21626 but not the 1.2.x CVEs.
	findings := AdvisoryFindings("1.1.12")
	for _, f := range findings {
		if f.CVEID == "CVE-2024-21626" {
			t.Errorf("CVE-2024-21626 should be fixed in 1.1.12, but was returned")
		}
	}
	if len(findings) == 0 {
		t.Error("expected findings for 1.1.12 (1.2.x CVEs should still match)")
	}
}

func TestAdvisoryFindings_unparseable(t *testing.T) {
	if AdvisoryFindings("") != nil {
		t.Error("expected nil for empty version")
	}
	if AdvisoryFindings("not-a-version") != nil {
		t.Error("expected nil for unparseable version")
	}
}

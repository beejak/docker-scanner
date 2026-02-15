package policy

import (
	"testing"

	"github.com/docker-scanner/scanner/pkg/scanner"
)

func TestParseFailOnCount(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantSev   string
		wantN     int
		wantError bool
	}{
		{"valid HIGH:5", "HIGH:5", "HIGH", 5, false},
		{"valid CRITICAL:1", "CRITICAL:1", "CRITICAL", 1, false},
		{"valid with spaces", " HIGH : 10 ", "HIGH", 10, false},
		{"empty", "", "", 0, true},
		{"no colon", "HIGH5", "", 0, true},
		{"colon only", ":", "", 0, true},
		{"severity only", "HIGH:", "", 0, true},
		{"negative N", "HIGH:-1", "HIGH", -1, true},
		{"non-numeric N", "HIGH:abc", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sev, n, err := ParseFailOnCount(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ParseFailOnCount() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if !tt.wantError && (sev != tt.wantSev || n != tt.wantN) {
				t.Errorf("ParseFailOnCount() = %q, %d; want %q, %d", sev, n, tt.wantSev, tt.wantN)
			}
		})
	}
}

func TestEvaluateFailPolicy(t *testing.T) {
	crit := []scanner.Finding{{Severity: "CRITICAL", CVEID: "CVE-1"}}
	high := []scanner.Finding{{Severity: "HIGH", CVEID: "CVE-2"}}
	threeHigh := []scanner.Finding{
		{Severity: "HIGH", CVEID: "1"},
		{Severity: "HIGH", CVEID: "2"},
		{Severity: "HIGH", CVEID: "3"},
	}

	tests := []struct {
		name             string
		findings         []scanner.Finding
		failOnSeverity   []string
		failOnCount      string
		wantFail         bool
		wantReasonPrefix string
	}{
		{"no policy, no findings", nil, nil, "", false, ""},
		{"no policy, some findings", high, nil, "", false, ""},
		{"fail-on-severity CRITICAL, has CRITICAL", crit, []string{"CRITICAL"}, "", true, "Policy violated"},
		{"fail-on-severity CRITICAL, only HIGH", high, []string{"CRITICAL"}, "", false, ""},
		{"fail-on-severity HIGH, has HIGH", high, []string{"HIGH"}, "", true, "Policy violated"},
		{"fail-on-count HIGH:1, has 1 HIGH", high, nil, "HIGH:1", true, "Policy violated"},
		{"fail-on-count HIGH:5, has 1 HIGH", high, nil, "HIGH:5", false, ""},
		{"fail-on-count HIGH:3, has 3 HIGH", threeHigh, nil, "HIGH:3", true, "Policy violated"},
		{"fail-on-count HIGH:4, has 3 HIGH", threeHigh, nil, "HIGH:4", false, ""},
		{"invalid fail-on-count", high, nil, "INVALID", true, "Invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldFail, reason := EvaluateFailPolicy(tt.findings, tt.failOnSeverity, tt.failOnCount)
			if shouldFail != tt.wantFail {
				t.Errorf("EvaluateFailPolicy() shouldFail = %v, want %v", shouldFail, tt.wantFail)
			}
			if tt.wantReasonPrefix != "" && (reason == "" || len(reason) < len(tt.wantReasonPrefix) || reason[:len(tt.wantReasonPrefix)] != tt.wantReasonPrefix) {
				t.Errorf("EvaluateFailPolicy() reason = %q, want prefix %q", reason, tt.wantReasonPrefix)
			}
		})
	}
}

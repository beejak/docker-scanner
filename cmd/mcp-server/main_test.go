package main

import (
	"strings"
	"testing"

	"github.com/docker-scanner/scanner/pkg/scanner"
)

func TestParseSeverities_empty(t *testing.T) {
	got := parseSeverities("")
	want := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	if len(got) != len(want) {
		t.Fatalf("len = %d; want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("[%d] = %q; want %q", i, got[i], w)
		}
	}
}

func TestParseSeverities_custom(t *testing.T) {
	got := parseSeverities("critical,high")
	if len(got) != 2 || got[0] != "CRITICAL" || got[1] != "HIGH" {
		t.Errorf("got %v; want [CRITICAL HIGH]", got)
	}
}

func TestParseSeverities_normalizes(t *testing.T) {
	got := parseSeverities("medium , LOW")
	if len(got) != 2 || got[0] != "MEDIUM" || got[1] != "LOW" {
		t.Errorf("got %v; want [MEDIUM LOW]", got)
	}
}

func TestFormatSummary_empty(t *testing.T) {
	got := formatSummary(nil)
	if got != "No findings." {
		t.Errorf("got %q; want 'No findings.'", got)
	}
}

func TestFormatSummary_counts(t *testing.T) {
	findings := []scanner.Finding{
		{Severity: "CRITICAL", Exploitable: "yes"},
		{Severity: "CRITICAL"},
		{Severity: "HIGH", Exploitable: "yes"},
		{Severity: "MEDIUM"},
		{Severity: "LOW"},
	}
	got := formatSummary(findings)
	if !strings.Contains(got, "CRITICAL:2") {
		t.Errorf("missing CRITICAL:2 in %q", got)
	}
	if !strings.Contains(got, "HIGH:1") {
		t.Errorf("missing HIGH:1 in %q", got)
	}
	if !strings.Contains(got, "EXPLOITABLE:2") {
		t.Errorf("missing EXPLOITABLE:2 in %q", got)
	}
}

func TestFormatSummary_order(t *testing.T) {
	findings := []scanner.Finding{
		{Severity: "LOW"},
		{Severity: "CRITICAL"},
		{Severity: "HIGH"},
	}
	got := formatSummary(findings)
	// CRITICAL should appear before HIGH which should appear before LOW.
	critIdx := strings.Index(got, "CRITICAL")
	highIdx := strings.Index(got, "HIGH")
	lowIdx := strings.Index(got, "LOW")
	if critIdx > highIdx || highIdx > lowIdx {
		t.Errorf("severity order wrong in %q", got)
	}
}

func TestFormatSummary_emptyAndUnknownSeverity(t *testing.T) {
	findings := []scanner.Finding{
		{Severity: ""},
		{Severity: "UNKNOWN"},
	}
	got := formatSummary(findings)
	if !strings.Contains(got, "UNKNOWN:2") {
		t.Errorf("missing UNKNOWN:2 in %q", got)
	}
}

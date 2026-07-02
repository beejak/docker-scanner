package remediate

// Integration tests for the Enrich() KEV hot path.
// These tests wire together the real Enrich() function with a mocked KEV HTTP
// server so we can verify the exploit-flagging and severity-upgrade logic without
// hitting the live CISA endpoint.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/docker-scanner/scanner/pkg/kev"
	"github.com/docker-scanner/scanner/pkg/policy"
	"github.com/docker-scanner/scanner/pkg/scanner"
)

// mockKEVServer starts a fake CISA KEV endpoint and returns the server + a cleanup
// func that restores the original KEV URL.
func mockKEVServer(t *testing.T, cveIDs []string) (cleanup func()) {
	t.Helper()
	type vuln struct {
		CveID             string `json:"cveID"`
		ShortDescription  string `json:"shortDescription"`
		VulnerabilityName string `json:"vulnerabilityName"`
		KnownRansomware   string `json:"knownRansomwareCampaignUse"`
	}
	type catalog struct {
		Vulnerabilities []vuln `json:"vulnerabilities"`
	}
	var c catalog
	for _, id := range cveIDs {
		c.Vulnerabilities = append(c.Vulnerabilities, vuln{
			CveID:             id,
			ShortDescription:  "Mock exploit description for " + id,
			VulnerabilityName: "MockVuln-" + id,
			KnownRansomware:   "Unknown",
		})
	}
	payload, _ := json.Marshal(c)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))

	// Reach into pkg/kev to point it at our mock and clear cache.
	origURL := kev.SetURLForTest(ts.URL)
	kev.ResetForTest()

	return func() {
		ts.Close()
		kev.SetURLForTest(origURL)
		kev.ResetForTest()
	}
}

// TestEnrich_kevHitMarksExploitable verifies that a CVE present in the KEV catalog
// gets Exploitable="yes" and ExploitInfo populated.
func TestEnrich_kevHitMarksExploitable(t *testing.T) {
	cleanup := mockKEVServer(t, []string{"CVE-2021-44228"})
	defer cleanup()

	findings := []scanner.Finding{
		{CVEID: "CVE-2021-44228", Package: "log4j", CurrentVersion: "2.14.1", FixedVersion: "2.15.0", Severity: "HIGH"},
	}
	enriched := Enrich(findings, false)

	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched finding, got %d", len(enriched))
	}
	f := enriched[0]

	if f.Exploitable != "yes" {
		t.Errorf("Exploitable = %q; want yes (CVE in KEV catalog)", f.Exploitable)
	}
	if f.ExploitInfo == "" {
		t.Error("ExploitInfo should be populated for KEV hit")
	}
	if !strings.Contains(strings.ToLower(f.ExploitInfo), "mock exploit description") {
		t.Errorf("ExploitInfo = %q; want text from KEV shortDescription", f.ExploitInfo)
	}
}

// TestEnrich_kevHitUpgradesToCritical verifies that a HIGH finding in the KEV catalog
// is upgraded to CRITICAL severity for prioritisation.
func TestEnrich_kevHitUpgradesToCritical(t *testing.T) {
	cleanup := mockKEVServer(t, []string{"CVE-2021-44228"})
	defer cleanup()

	findings := []scanner.Finding{
		{CVEID: "CVE-2021-44228", Package: "log4j", CurrentVersion: "2.14.1", Severity: "HIGH"},
	}
	enriched := Enrich(findings, false)

	if enriched[0].Severity != "CRITICAL" {
		t.Errorf("Severity = %q; want CRITICAL (exploitable finding upgraded)", enriched[0].Severity)
	}
}

// TestEnrich_kevMissMarksNotExploitable verifies a CVE absent from KEV gets "no".
func TestEnrich_kevMissMarksNotExploitable(t *testing.T) {
	cleanup := mockKEVServer(t, []string{"CVE-2021-44228"}) // only Log4Shell in catalog
	defer cleanup()

	findings := []scanner.Finding{
		{CVEID: "CVE-2022-99999", Package: "pkg", CurrentVersion: "1.0", Severity: "HIGH"},
	}
	enriched := Enrich(findings, false)

	if enriched[0].Exploitable != "no" {
		t.Errorf("Exploitable = %q; want no (CVE not in KEV)", enriched[0].Exploitable)
	}
}

// TestEnrich_ransomwareMentionedInExploitInfo verifies ransomware flag flows through.
func TestEnrich_ransomwareMentionedInExploitInfo(t *testing.T) {
	type vuln struct {
		CveID            string `json:"cveID"`
		ShortDescription string `json:"shortDescription"`
		KnownRansomware  string `json:"knownRansomwareCampaignUse"`
	}
	type catalog struct {
		Vulnerabilities []vuln `json:"vulnerabilities"`
	}
	payload, _ := json.Marshal(catalog{Vulnerabilities: []vuln{
		{CveID: "CVE-2023-9999", ShortDescription: "Ransom vuln", KnownRansomware: "Known"},
	}})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	origURL := kev.SetURLForTest(ts.URL)
	kev.ResetForTest()
	defer func() {
		ts.Close()
		kev.SetURLForTest(origURL)
		kev.ResetForTest()
	}()

	findings := []scanner.Finding{
		{CVEID: "CVE-2023-9999", Package: "pkg", CurrentVersion: "1.0", Severity: "CRITICAL"},
	}
	enriched := Enrich(findings, false)

	if !strings.Contains(enriched[0].ExploitInfo, "ransomware") {
		t.Errorf("ExploitInfo = %q; want ransomware mention for Known ransomware campaign", enriched[0].ExploitInfo)
	}
}

// TestEnrich_offlineSetsUnknown verifies offline mode never calls KEV and sets "unknown".
func TestEnrich_offlineSetsUnknown(t *testing.T) {
	// No mock server — if KEV is called in offline mode the test process would hang or fail.
	findings := []scanner.Finding{
		{CVEID: "CVE-2021-44228", Package: "log4j", CurrentVersion: "2.14.1", Severity: "CRITICAL"},
	}
	enriched := Enrich(findings, true) // offline=true

	if enriched[0].Exploitable != "unknown" {
		t.Errorf("Exploitable = %q; want unknown in offline mode", enriched[0].Exploitable)
	}
}

// --- Policy + Enrichment pipeline ---

// TestPolicyPipeline_criticalFindingsTriggerFailure is the end-to-end contract:
// oracle-fixture-level findings → Enrich → EvaluateFailPolicy → shouldFail=true.
// This is what the CLI exercises when --fail-on-severity=CRITICAL is set.
func TestPolicyPipeline_criticalFindingsTriggerFailure(t *testing.T) {
	cleanup := mockKEVServer(t, []string{}) // empty catalog — no KEV hits
	defer cleanup()

	// Findings that mirror the oracle fixture (alpine:3.10 has CRITICAL findings).
	findings := []scanner.Finding{
		{CVEID: "CVE-2021-36159", Package: "apk-tools", CurrentVersion: "2.10.6-r0", FixedVersion: "2.10.7-r0", Severity: "CRITICAL"},
		{CVEID: "CVE-2021-3520", Package: "lz4", CurrentVersion: "1.9.1-r0", FixedVersion: "1.9.3-r0", Severity: "CRITICAL"},
		{CVEID: "CVE-2020-28928", Package: "musl", CurrentVersion: "1.1.22-r3", FixedVersion: "1.1.24-r3", Severity: "MEDIUM"},
	}

	enriched := Enrich(findings, false)

	shouldFail, reason := policy.EvaluateFailPolicy(enriched, []string{"CRITICAL"}, "")
	if !shouldFail {
		t.Error("expected policy to fail when CRITICAL findings exist with fail-on-severity=CRITICAL")
	}
	if reason == "" {
		t.Error("expected non-empty reason when policy fails")
	}
}

// TestPolicyPipeline_noViolationWhenClean verifies no false positive — clean image passes.
func TestPolicyPipeline_noViolationWhenClean(t *testing.T) {
	// No findings = scan passed; policy must not trigger.
	enriched := Enrich([]scanner.Finding{}, false)
	shouldFail, _ := policy.EvaluateFailPolicy(enriched, []string{"CRITICAL"}, "")
	if shouldFail {
		t.Error("expected no policy failure when there are zero findings")
	}
}

// TestPolicyPipeline_countThreshold verifies fail-on-count triggers at threshold.
func TestPolicyPipeline_countThreshold(t *testing.T) {
	cleanup := mockKEVServer(t, []string{})
	defer cleanup()

	// 5 HIGH findings; fail-on-count=HIGH:3 should trigger.
	var findings []scanner.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, scanner.Finding{
			CVEID:    "CVE-2020-" + string(rune('A'+i)),
			Package:  "pkg",
			Severity: "HIGH",
		})
	}
	enriched := Enrich(findings, false)

	shouldFail, _ := policy.EvaluateFailPolicy(enriched, nil, "HIGH:3")
	if !shouldFail {
		t.Error("expected fail-on-count=HIGH:3 to trigger with 5 HIGH findings")
	}

	// fail-on-count=HIGH:10 must NOT trigger with only 5.
	shouldFail2, _ := policy.EvaluateFailPolicy(enriched, nil, "HIGH:10")
	if shouldFail2 {
		t.Error("expected fail-on-count=HIGH:10 NOT to trigger with only 5 HIGH findings")
	}
}

// TestPolicyPipeline_bothPolicies verifies severity + count applied together.
func TestPolicyPipeline_bothPolicies(t *testing.T) {
	cleanup := mockKEVServer(t, []string{})
	defer cleanup()

	findings := []scanner.Finding{
		{CVEID: "CVE-X", Package: "p", Severity: "HIGH"},
	}
	enriched := Enrich(findings, false)

	// fail-on-severity=CRITICAL should NOT trigger (only HIGH present).
	shouldFail, _ := policy.EvaluateFailPolicy(enriched, []string{"CRITICAL"}, "HIGH:5")
	if shouldFail {
		t.Error("neither severity nor count policy should trigger here")
	}

	// fail-on-severity=HIGH should trigger.
	shouldFail2, _ := policy.EvaluateFailPolicy(enriched, []string{"HIGH"}, "")
	if !shouldFail2 {
		t.Error("fail-on-severity=HIGH should trigger when HIGH finding is present")
	}
}

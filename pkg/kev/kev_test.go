package kev

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// resetCache clears package-level cache state between tests.
func resetCache() {
	mu.Lock()
	defer mu.Unlock()
	knownExploited = nil
	kevInfo = nil
	lastFetch = time.Time{}
}

// mockCatalog builds a minimal KEV JSON response for tests.
func mockCatalog(entries []struct{ ID, Desc, Name, Ransomware string }) []byte {
	type vuln struct {
		CveID             string `json:"cveID"`
		ShortDescription  string `json:"shortDescription"`
		VulnerabilityName string `json:"vulnerabilityName"`
		KnownRansomware   string `json:"knownRansomwareCampaignUse"`
	}
	type cat struct {
		Vulnerabilities []vuln `json:"vulnerabilities"`
	}
	var c cat
	for _, e := range entries {
		c.Vulnerabilities = append(c.Vulnerabilities, vuln{
			CveID:             e.ID,
			ShortDescription:  e.Desc,
			VulnerabilityName: e.Name,
			KnownRansomware:   e.Ransomware,
		})
	}
	b, _ := json.Marshal(c)
	return b
}

func TestLoad_fetchesAndPopulatesCache(t *testing.T) {
	payload := mockCatalog([]struct{ ID, Desc, Name, Ransomware string }{
		{"CVE-2021-44228", "Log4Shell RCE", "Log4Shell", "Known"},
		{"CVE-2022-0001", "Some issue", "SomeVuln", "Unknown"},
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer ts.Close()
	resetCache()
	origURL := cisaKEVURL
	cisaKEVURL = ts.URL
	defer func() { cisaKEVURL = origURL }()

	if err := Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !IsKnownExploited("CVE-2021-44228") {
		t.Error("expected CVE-2021-44228 to be known exploited")
	}
	if IsKnownExploited("CVE-9999-9999") {
		t.Error("expected unknown CVE to not be exploited")
	}
}

func TestLoad_cacheHitSkipsHTTP(t *testing.T) {
	callCount := 0
	payload := mockCatalog([]struct{ ID, Desc, Name, Ransomware string }{
		{"CVE-2021-44228", "Log4Shell", "Log4Shell", "Known"},
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write(payload)
	}))
	defer ts.Close()
	resetCache()
	origURL := cisaKEVURL
	cisaKEVURL = ts.URL
	defer func() { cisaKEVURL = origURL }()

	_ = Load()
	_ = Load() // should use cache; no second HTTP call
	_ = Load()

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call (cached), got %d", callCount)
	}
}

func TestLoad_cacheExpires(t *testing.T) {
	callCount := 0
	payload := mockCatalog([]struct{ ID, Desc, Name, Ransomware string }{
		{"CVE-2021-44228", "d", "n", "Unknown"},
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write(payload)
	}))
	defer ts.Close()
	resetCache()
	origURL := cisaKEVURL
	origTTL := cacheTTL
	cisaKEVURL = ts.URL
	cacheTTL = 0 // expire immediately so second Load re-fetches
	defer func() {
		cisaKEVURL = origURL
		cacheTTL = origTTL
	}()

	_ = Load()
	_ = Load() // TTL=0 means cache is always stale → second HTTP call

	if callCount < 2 {
		t.Errorf("expected ≥2 HTTP calls with TTL=0, got %d", callCount)
	}
}

func TestLoad_httpError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	resetCache()
	origURL := cisaKEVURL
	cisaKEVURL = ts.URL
	defer func() { cisaKEVURL = origURL }()

	// HTTP 500 body is still valid (empty JSON may decode), so test that catalog stays empty.
	// The current impl uses json.Decoder which may or may not error on a 500 with no body.
	// Either way: Load must not panic, and unknown CVE must not be reported as exploited.
	_ = Load()
	if IsKnownExploited("CVE-2021-44228") {
		t.Error("expected no exploits after failed fetch")
	}
}

func TestLoad_malformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json at all"))
	}))
	defer ts.Close()
	resetCache()
	origURL := cisaKEVURL
	cisaKEVURL = ts.URL
	defer func() { cisaKEVURL = origURL }()

	err := Load()
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestLoad_concurrentSafe(t *testing.T) {
	payload := mockCatalog([]struct{ ID, Desc, Name, Ransomware string }{
		{"CVE-2021-44228", "Log4Shell", "Log4Shell", "Known"},
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer ts.Close()
	resetCache()
	origURL := cisaKEVURL
	cisaKEVURL = ts.URL
	defer func() { cisaKEVURL = origURL }()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = Load()
			_ = IsKnownExploited("CVE-2021-44228")
		}()
	}
	wg.Wait()
	// If go test -race detects a data race this test will fail.
}

func TestIsKnownExploited_caseNormalized(t *testing.T) {
	payload := mockCatalog([]struct{ ID, Desc, Name, Ransomware string }{
		{"CVE-2021-44228", "d", "n", "Unknown"},
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer ts.Close()
	resetCache()
	origURL := cisaKEVURL
	cisaKEVURL = ts.URL
	defer func() { cisaKEVURL = origURL }()
	_ = Load()

	// Input casing should not matter — IsKnownExploited uppercases internally.
	cases := []string{"CVE-2021-44228", "cve-2021-44228", "Cve-2021-44228"}
	for _, c := range cases {
		if !IsKnownExploited(c) {
			t.Errorf("IsKnownExploited(%q) = false; want true", c)
		}
	}
}

func TestIsKnownExploited_emptyInput(t *testing.T) {
	resetCache()
	if IsKnownExploited("") {
		t.Error("IsKnownExploited(\"\") should return false")
	}
	if IsKnownExploited("   ") {
		t.Error("IsKnownExploited(whitespace) should return false")
	}
}

func TestIsKnownExploited_beforeLoad(t *testing.T) {
	resetCache()
	// Calling IsKnownExploited with empty catalog must not panic.
	got := IsKnownExploited("CVE-2021-44228")
	if got {
		t.Error("expected false when catalog not loaded")
	}
}

func TestGetInfo_found(t *testing.T) {
	payload := mockCatalog([]struct{ ID, Desc, Name, Ransomware string }{
		{"CVE-2021-44228", "Apache Log4j RCE", "Log4Shell", "Known"},
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer ts.Close()
	resetCache()
	origURL := cisaKEVURL
	cisaKEVURL = ts.URL
	defer func() { cisaKEVURL = origURL }()
	_ = Load()

	desc, name, ransomware := GetInfo("CVE-2021-44228")
	if desc != "Apache Log4j RCE" {
		t.Errorf("GetInfo desc = %q; want Apache Log4j RCE", desc)
	}
	if name != "Log4Shell" {
		t.Errorf("GetInfo name = %q; want Log4Shell", name)
	}
	if ransomware != "Known" {
		t.Errorf("GetInfo ransomware = %q; want Known", ransomware)
	}
}

func TestGetInfo_notFound(t *testing.T) {
	resetCache()
	desc, name, ransomware := GetInfo("CVE-9999-0000")
	if desc != "" || name != "" || ransomware != "" {
		t.Errorf("GetInfo on unknown CVE returned non-empty: %q %q %q", desc, name, ransomware)
	}
}

func TestGetInfo_emptyIDsSkipped(t *testing.T) {
	// Catalog entries with empty cveID should be silently skipped.
	type vuln struct {
		CveID string `json:"cveID"`
	}
	type cat struct {
		Vulnerabilities []vuln `json:"vulnerabilities"`
	}
	payload, _ := json.Marshal(cat{Vulnerabilities: []vuln{{CveID: ""}, {CveID: "CVE-2023-0001"}}})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer ts.Close()
	resetCache()
	origURL := cisaKEVURL
	cisaKEVURL = ts.URL
	defer func() { cisaKEVURL = origURL }()
	if err := Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if IsKnownExploited("") {
		t.Error("empty ID should not be marked exploited")
	}
	if !IsKnownExploited("CVE-2023-0001") {
		t.Error("CVE-2023-0001 should be marked exploited")
	}
}

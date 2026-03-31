package osv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestEcosystemFor(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		// OS families
		{"alpine", "Alpine"},
		{"Alpine Linux", "Alpine"},
		{"debian 11", "Debian"},
		{"ubuntu:22.04", "Debian"},
		{"rhel 8", "Red Hat"},
		{"centos:7", "Red Hat"},
		{"fedora 39", "Red Hat"},
		{"amazon linux 2", "Red Hat"},

		// Language ecosystems
		{"go.sum", "Go"},
		{"go.mod", "Go"},
		{"golang.org/x/net", "Go"},
		{"package-lock.json", "npm"},
		{"node_modules", "npm"},
		{"yarn.lock", "npm"},
		{"requirements.txt (python)", "PyPI"},
		{"pip freeze output", "PyPI"},
		{"Cargo.lock", "crates.io"},
		{"rust toolchain", "crates.io"},
		{"pom.xml (maven)", "Maven"},
		{"build.gradle", "Maven"},
		{"packages.config (nuget)", "NuGet"},
		{"NuGet Gallery", "NuGet"},
		{"composer.json", "Packagist"},
		{"Gemfile.lock", "RubyGems"},
		{"ruby 3.2", "RubyGems"},

		// Unmapped
		{"unknown-os", ""},
		{"", ""},
		{"windows", ""},
	}
	for _, c := range cases {
		got := EcosystemFor(c.target)
		if got != c.want {
			t.Errorf("EcosystemFor(%q) = %q; want %q", c.target, got, c.want)
		}
	}
}

func TestEcosystemFor_cargoBeforeGo(t *testing.T) {
	// "cargo" contains "go" as a substring; must resolve to crates.io, not Go.
	got := EcosystemFor("Cargo.lock")
	if got != "crates.io" {
		t.Errorf("EcosystemFor(%q) = %q; want %q — cargo matched after go?", "Cargo.lock", got, "crates.io")
	}
}

func TestEcosystemFor_caseInsensitive(t *testing.T) {
	got := EcosystemFor("ALPINE 3.19")
	if got != "Alpine" {
		t.Errorf("EcosystemFor(%q) = %q; want %q", "ALPINE 3.19", got, "Alpine")
	}
}

func TestQuery_emptyInputs(t *testing.T) {
	r, err := Query("", "1.0", "Alpine")
	if err != nil || r != nil {
		t.Errorf("Query(empty pkg) = %v, %v; want nil, nil", r, err)
	}
	r, err = Query("curl", "", "Alpine")
	if err != nil || r != nil {
		t.Errorf("Query(empty version) = %v, %v; want nil, nil", r, err)
	}
	r, err = Query("curl", "1.0", "")
	if err != nil || r != nil {
		t.Errorf("Query(empty ecosystem) = %v, %v; want nil, nil", r, err)
	}
}

func TestQuery_mockServer(t *testing.T) {
	// Mock OSV API server returning one vuln with a CVE alias.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		// Decode request to verify shape.
		var req osvQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Package.Name != "curl" || req.Package.Ecosystem != "Alpine" || req.Version != "7.88.1-r1" {
			t.Errorf("unexpected request: %+v", req)
		}

		resp := osvQueryResponse{
			Vulns: []osvVuln{
				{
					ID:      "GHSA-xxxx-yyyy-zzzz",
					Aliases: []string{"CVE-2024-99999"},
					Summary: "curl buffer overflow",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	// Override the URL and clear cache for test isolation.
	origURL := osvURL
	setOSVQueryURL(ts.URL)
	defer setOSVQueryURL(origURL)
	clearCache()

	results, err := Query("curl", "7.88.1-r1", "Alpine")
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	// Should prefer CVE alias over GHSA ID.
	if r.CVEID != "CVE-2024-99999" {
		t.Errorf("CVEID = %q; want CVE-2024-99999", r.CVEID)
	}
	if r.Summary != "curl buffer overflow" {
		t.Errorf("Summary = %q; want 'curl buffer overflow'", r.Summary)
	}
	if !strings.Contains(r.AdvisoryURL, "osv.dev") {
		t.Errorf("AdvisoryURL = %q; want URL containing osv.dev", r.AdvisoryURL)
	}
}

func TestQuery_noVulns(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(osvQueryResponse{})
	}))
	defer ts.Close()

	origURL := osvURL
	setOSVQueryURL(ts.URL)
	defer setOSVQueryURL(origURL)
	clearCache()

	results, err := Query("safe-pkg", "1.0.0", "Alpine")
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestQuery_noCVEAlias(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := osvQueryResponse{
			Vulns: []osvVuln{{ID: "GHSA-only-1234", Summary: "Some vuln"}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	origURL := osvURL
	setOSVQueryURL(ts.URL)
	defer setOSVQueryURL(origURL)
	clearCache()

	results, err := Query("pkg", "1.0", "Go")
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// When no CVE alias, keep the raw OSV ID.
	if results[0].CVEID != "GHSA-only-1234" {
		t.Errorf("CVEID = %q; want GHSA-only-1234", results[0].CVEID)
	}
}

func TestQuery_caching(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(osvQueryResponse{})
	}))
	defer ts.Close()

	origURL := osvURL
	setOSVQueryURL(ts.URL)
	defer setOSVQueryURL(origURL)
	clearCache()

	// First call hits server.
	_, _ = Query("cached-pkg", "2.0", "npm")
	// Second call should use cache.
	_, _ = Query("cached-pkg", "2.0", "npm")

	if callCount != 1 {
		t.Errorf("expected 1 API call (cached), got %d", callCount)
	}
}

func TestQuery_serverError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	origURL := osvURL
	setOSVQueryURL(ts.URL)
	defer setOSVQueryURL(origURL)
	clearCache()

	_, err := Query("fail-pkg", "1.0", "Alpine")
	if err == nil {
		t.Error("expected error for 500 status, got nil")
	}
}

func TestQuery_malformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer ts.Close()

	origURL := osvURL
	setOSVQueryURL(ts.URL)
	defer setOSVQueryURL(origURL)
	clearCache()

	_, err := Query("bad-pkg", "1.0", "Alpine")
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestQuery_multipleVulns(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := osvQueryResponse{
			Vulns: []osvVuln{
				{ID: "GHSA-1111", Aliases: []string{"CVE-2024-1111"}, Summary: "First"},
				{ID: "GHSA-2222", Aliases: []string{"CVE-2024-2222"}, Summary: "Second"},
				{ID: "GHSA-3333", Summary: "Third (no CVE alias)"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	origURL := osvURL
	setOSVQueryURL(ts.URL)
	defer setOSVQueryURL(origURL)
	clearCache()

	results, err := Query("multi-pkg", "1.0", "PyPI")
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].CVEID != "CVE-2024-1111" {
		t.Errorf("results[0].CVEID = %q; want CVE-2024-1111", results[0].CVEID)
	}
	if results[2].CVEID != "GHSA-3333" {
		t.Errorf("results[2].CVEID = %q; want GHSA-3333 (no alias)", results[2].CVEID)
	}
}

// Test helpers — need matching exports in osv.go.

func setOSVQueryURL(url string) {
	osvURL = url
}

func clearCache() {
	cache = sync.Map{}
}

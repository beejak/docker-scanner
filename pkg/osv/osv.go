// Package osv queries the OSV.dev API to back-fill CVE/GHSA IDs for findings
// that Trivy returned without an identifier (e.g. unlisted Go stdlib CVEs).
// Results are cached in-process; the caller must skip this package in offline mode.
package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var osvURL = "https://api.osv.dev/v1/query"

// ecosystemRule maps a lowercase substring to an OSV ecosystem name.
// Evaluated in order; first match wins. More specific prefixes must come before
// shorter ones that are substrings of them (e.g. "cargo" before "go").
type ecosystemRule struct {
	substr    string
	ecosystem string
}

var ecosystemRules = []ecosystemRule{
	// OS families
	{"alpine", "Alpine"},
	{"debian", "Debian"},
	{"ubuntu", "Debian"}, // OSV uses "Debian" for Ubuntu too
	{"rhel", "Red Hat"},
	{"centos", "Red Hat"},
	{"fedora", "Red Hat"},
	{"amazon linux", "Red Hat"},
	// Language ecosystems — more specific substrings first
	{"cargo", "crates.io"}, // must precede "go" (cargo contains "go" as substring)
	{"rust", "crates.io"},
	{"go.sum", "Go"},
	{"go.mod", "Go"},
	{"golang", "Go"},
	{"package-lock", "npm"}, // must precede bare "npm"
	{"node_modules", "npm"},
	{"npm", "npm"},
	{"yarn", "npm"},
	{"pip", "PyPI"},
	{"python", "PyPI"},
	{"requirements", "PyPI"},
	{"maven", "Maven"},
	{"gradle", "Maven"},
	{"pom.xml", "Maven"},
	{"nuget", "NuGet"},
	{"packages.config", "NuGet"},
	{"composer", "Packagist"},
	{"gemfile", "RubyGems"},
	{"gem", "RubyGems"},
	{"ruby", "RubyGems"},
}

// EcosystemFor returns the OSV ecosystem name for a given Trivy target/class string.
// Returns "" if unmapped (caller should skip OSV query in that case).
func EcosystemFor(trivyTarget string) string {
	lower := strings.ToLower(trivyTarget)
	for _, r := range ecosystemRules {
		if strings.Contains(lower, r.substr) {
			return r.ecosystem
		}
	}
	return ""
}

type osvQueryRequest struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases"`
	Summary  string     `json:"summary"`
	Severity []osvSev   `json:"severity"`
}

type osvSev struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Result holds OSV findings for a package@version.
type Result struct {
	// CVEID is the first CVE-* alias found, or the OSV ID itself if no CVE alias exists.
	CVEID   string
	Summary string
	// AdvisoryURL is the canonical OSV advisory page.
	AdvisoryURL string
}

var (
	cache   sync.Map // key: "pkg@version@ecosystem" → []Result
	hclient = &http.Client{Timeout: 10 * time.Second}
)

// Query calls OSV for a package/version/ecosystem and returns any matched advisories.
// Results are cached per unique (pkg, version, ecosystem) tuple.
// Returns nil slice (not an error) when no vulnerabilities are found.
func Query(pkg, version, ecosystem string) ([]Result, error) {
	if pkg == "" || version == "" || ecosystem == "" {
		return nil, nil
	}
	key := pkg + "@" + version + "@" + ecosystem
	if cached, ok := cache.Load(key); ok {
		return cached.([]Result), nil
	}

	body, err := json.Marshal(osvQueryRequest{
		Package: osvPackage{Name: pkg, Ecosystem: ecosystem},
		Version: version,
	})
	if err != nil {
		return nil, err
	}

	resp, err := hclient.Post(osvURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv api: status %d", resp.StatusCode)
	}

	var result osvQueryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1*1024*1024)).Decode(&result); err != nil {
		return nil, err
	}

	var out []Result
	for _, v := range result.Vulns {
		r := Result{
			CVEID:       v.ID,
			Summary:     v.Summary,
			AdvisoryURL: "https://osv.dev/vulnerability/" + v.ID,
		}
		// Prefer a CVE alias over the raw OSV/GHSA ID.
		for _, alias := range v.Aliases {
			if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
				r.CVEID = alias
				break
			}
		}
		out = append(out, r)
	}

	cache.Store(key, out)
	return out, nil
}

// Package runc detects the host runc version and emits advisory findings for
// known container escape / breakout CVEs. runc is the container runtime on the
// host — it never appears as a package inside a scanned image, so Trivy cannot
// detect it. This package fills that gap with a host-side check.
package runc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/docker-scanner/scanner/pkg/scanner"
)

// advisory pairs a CVE with the first safe runc semver and a plain-text description.
type advisory struct {
	CVEID       string
	Severity    string
	FixedSemver [3]int // major, minor, patch — first version NOT affected
	FixedStr    string // human-readable minimum safe version
	Description string
}

// advisories is the table of known runc CVEs. Update as new CVEs are published.
var advisories = []advisory{
	{
		CVEID:       "CVE-2025-31133",
		Severity:    "CRITICAL",
		FixedSemver: [3]int{1, 2, 8},
		FixedStr:    "1.2.8",
		Description: "maskedPaths bypass: attacker replaces /dev/null with a symlink during container creation, allowing writes to arbitrary host paths (e.g. /proc/sys/kernel/core_pattern). Full container breakout possible.",
	},
	{
		CVEID:       "CVE-2025-52565",
		Severity:    "CRITICAL",
		FixedSemver: [3]int{1, 2, 8},
		FixedStr:    "1.2.8",
		Description: "/dev/console bind-mount escape: insufficient validation during /dev/pts/$n → /dev/console mount allows redirecting mounts before LSM protections activate, granting write access to sensitive procfs files.",
	},
	{
		CVEID:       "CVE-2025-52881",
		Severity:    "CRITICAL",
		FixedSemver: [3]int{1, 2, 8},
		FixedStr:    "1.2.8",
		Description: "LSM bypass via shared mounts: race condition with shared mounts redirects runc writes to /proc files, bypassing Linux Security Module checks. Can crash host (/proc/sysrq-trigger) or achieve full breakout (/proc/sys/kernel/core_pattern).",
	},
	{
		CVEID:       "CVE-2024-21626",
		Severity:    "HIGH",
		FixedSemver: [3]int{1, 1, 12},
		FixedStr:    "1.1.12",
		Description: "LEAKY VESSELS: working directory escape via leaked file descriptor. Container process can access host filesystem paths outside the container root.",
	},
}

var semverRE = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// dockerVersionJSON is a minimal subset of `docker version --format json` output.
type dockerVersionJSON struct {
	Components []struct {
		Name    string            `json:"Name"`
		Details map[string]string `json:"Details"`
	} `json:"Components"`
	Server *struct {
		Components []struct {
			Name    string            `json:"Name"`
			Details map[string]string `json:"Details"`
		} `json:"Components"`
	} `json:"Server"`
}

// HostVersion returns the runc version string from the host.
// It tries `docker version --format json` first, then `runc --version`.
// Returns ("", nil) when neither is available (non-Docker environment).
func HostVersion(ctx context.Context) (string, error) {
	// Try docker version first.
	out, err := runCmd(ctx, "docker", "version", "--format", "json")
	if err == nil {
		var dv dockerVersionJSON
		if jsonErr := json.Unmarshal([]byte(out), &dv); jsonErr == nil {
			// Docker 20+ puts components under Server.Components
			var components []struct {
				Name    string            `json:"Name"`
				Details map[string]string `json:"Details"`
			}
			if dv.Server != nil {
				components = dv.Server.Components
			} else {
				components = dv.Components
			}
			for _, c := range components {
				if strings.EqualFold(c.Name, "runc") {
					if v, ok := c.Details["Version"]; ok && v != "" {
						return v, nil
					}
				}
			}
		}
	}

	// Fallback: runc --version
	out, err = runCmd(ctx, "runc", "--version")
	if err != nil {
		return "", nil // not available; caller treats as skip
	}
	// Output: "runc version 1.1.12\ncommit: ..."
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "runc version") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[2], nil
			}
		}
	}
	return "", nil
}

// AdvisoryFindings returns scanner.Finding entries for each advisory that applies
// to the given runc version string. Returns nil if version is empty or unparseable.
func AdvisoryFindings(version string) []scanner.Finding {
	v := semverRE.FindStringSubmatch(version)
	if len(v) < 4 {
		return nil
	}
	var major, minor, patch int
	fmt.Sscanf(v[1], "%d", &major)
	fmt.Sscanf(v[2], "%d", &minor)
	fmt.Sscanf(v[3], "%d", &patch)

	var findings []scanner.Finding
	for _, a := range advisories {
		if isVulnerable([3]int{major, minor, patch}, a.FixedSemver) {
			findings = append(findings, scanner.Finding{
				CVEID:          a.CVEID,
				Package:        "runc",
				CurrentVersion: version,
				FixedVersion:   a.FixedStr,
				Severity:       a.Severity,
				Title:          a.CVEID + " — runc container escape (" + a.FixedStr + "+ required)",
				Description:    a.Description,
				FilePath:       "host-runtime",
				RemediationLinks: []string{
					"https://nvd.nist.gov/vuln/detail/" + a.CVEID,
					"https://github.com/opencontainers/runc/releases",
				},
			})
		}
	}
	return findings
}

// isVulnerable returns true when current < fixed.
func isVulnerable(current, fixed [3]int) bool {
	if current[0] != fixed[0] {
		return current[0] < fixed[0]
	}
	if current[1] != fixed[1] {
		return current[1] < fixed[1]
	}
	return current[2] < fixed[2]
}

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

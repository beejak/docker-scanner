package policy

import (
	"fmt"
	"strings"

	"github.com/docker-scanner/scanner/pkg/scanner"
)

// EvaluateFailPolicy returns true if the scan should fail (exit 1) based on fail-on-severity and fail-on-count.
func EvaluateFailPolicy(findings []scanner.Finding, failOnSeverity []string, failOnCount string) (shouldFail bool, reason string) {
	countBySev := make(map[string]int)
	for _, f := range findings {
		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		countBySev[sev]++
	}

	if len(failOnSeverity) > 0 {
		for _, sev := range failOnSeverity {
			sev = strings.ToUpper(strings.TrimSpace(sev))
			if countBySev[sev] > 0 {
				return true, fmt.Sprintf("Policy violated: found %d %s finding(s). Fix these or adjust --fail-on-severity. See report in output-dir.", countBySev[sev], sev)
			}
		}
	}

	if failOnCount != "" {
		sev, n, err := ParseFailOnCount(failOnCount)
		if err != nil {
			return true, fmt.Sprintf("Invalid --fail-on-count %q: %v. Use SEVERITY:N (e.g. HIGH:5).", failOnCount, err)
		}
		count := countBySev[strings.ToUpper(sev)]
		if count >= n {
			return true, fmt.Sprintf("Policy violated: %d %s finding(s) (threshold: %d). Fix these or adjust --fail-on-count. See report in output-dir.", count, sev, n)
		}
	}

	return false, ""
}

// ParseFailOnCount parses "SEVERITY:N" (e.g. HIGH:5) and returns severity, N, and error.
func ParseFailOnCount(s string) (severity string, n int, err error) {
	idx := strings.LastIndex(s, ":")
	if idx <= 0 || idx == len(s)-1 {
		return "", 0, fmt.Errorf("expected SEVERITY:N")
	}
	severity = strings.TrimSpace(s[:idx])
	var num int
	_, err = fmt.Sscanf(s[idx+1:], "%d", &num)
	if err != nil || num < 0 {
		return "", 0, fmt.Errorf("expected non-negative integer N in SEVERITY:N")
	}
	return severity, num, nil
}

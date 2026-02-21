package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ScanOptions configures a scan (image, rootfs, optional Dockerfile, severity filter, offline, cache).
type ScanOptions struct {
	Image      string   // Image reference (e.g. alpine:latest) — use when scanning Docker/Podman image
	Dockerfile string   // Optional path to Dockerfile (only with Image)
	Rootfs     string   // Path to root filesystem to scan (e.g. LXC container rootfs) — use instead of Image for filesystem/LXC
	Severity   []string // Severities to include (e.g. CRITICAL,HIGH,MEDIUM,LOW)
	Offline    bool     // Skip DB/policy update
	CacheDir   string   // Trivy cache directory (empty = default)
}

// Scan runs the scanner engine (Trivy) on the given image or rootfs, and optional Dockerfile (image only).
// Returns raw findings; caller should pass to enricher then report generator.
// Use Rootfs for LXC or any unpacked root filesystem; use Image for Docker/Podman/containerd images.
func Scan(ctx context.Context, opts ScanOptions) ([]Finding, error) {
	if opts.Rootfs != "" {
		return scanRootfs(ctx, opts)
	}
	// 1. Scan image
	imageFindings, err := scanImage(ctx, opts)
	if err != nil {
		return nil, err
	}
	// 2. Optionally scan Dockerfile and merge
	if opts.Dockerfile != "" {
		configFindings, err := scanDockerfile(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("dockerfile scan: %w", err)
		}
		imageFindings = append(imageFindings, configFindings...)
	}
	return imageFindings, nil
}

// scanRootfs runs trivy rootfs on a path (e.g. LXC container rootfs) and returns findings. Same JSON shape as image.
func scanRootfs(ctx context.Context, opts ScanOptions) ([]Finding, error) {
	path := opts.Rootfs
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("rootfs path: %w", err)
	}
	if info, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("rootfs not found %q: %w", path, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("rootfs path is not a directory: %s", path)
	}
	args := []string{"rootfs", "--format", "json"}
	if opts.CacheDir != "" {
		args = append(args, "--cache-dir", opts.CacheDir)
	}
	if opts.Offline {
		args = append(args, "--skip-db-update")
	}
	if len(opts.Severity) > 0 {
		args = append(args, "--severity", strings.Join(opts.Severity, ","))
	}
	args = append(args, abs)
	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy rootfs: %w (stderr: %s)", err, stderr.String())
	}
	var report trivyReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("parse trivy rootfs json: %w", err)
	}
	severitySet := make(map[string]bool)
	for _, s := range opts.Severity {
		severitySet[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	var findings []Finding
	for _, res := range report.Results {
		target := strings.TrimSpace(res.Target)
		for _, v := range res.Vulnerabilities {
			sev := strings.ToUpper(v.Severity)
			if len(severitySet) > 0 && !severitySet[sev] {
				continue
			}
			findings = append(findings, trivyVulnToFinding(v, target))
		}
	}
	return findings, nil
}

func scanImage(ctx context.Context, opts ScanOptions) ([]Finding, error) {
	args := []string{"image", "--format", "json"}
	if opts.CacheDir != "" {
		args = append(args, "--cache-dir", opts.CacheDir)
	}
	if opts.Offline {
		args = append(args, "--skip-db-update")
	}
	if len(opts.Severity) > 0 {
		args = append(args, "--severity", strings.Join(opts.Severity, ","))
	}
	args = append(args, opts.Image)

	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy image: %w (stderr: %s)", err, stderr.String())
	}

	var report trivyReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("parse trivy image json: %w", err)
	}

	severitySet := make(map[string]bool)
	for _, s := range opts.Severity {
		severitySet[strings.ToUpper(strings.TrimSpace(s))] = true
	}

	var findings []Finding
	for _, res := range report.Results {
		target := strings.TrimSpace(res.Target)
		for _, v := range res.Vulnerabilities {
			sev := strings.ToUpper(v.Severity)
			if len(severitySet) > 0 && !severitySet[sev] {
				continue
			}
			findings = append(findings, trivyVulnToFinding(v, target))
		}
	}
	return findings, nil
}

// scanDockerfile runs trivy config on the Dockerfile path and returns findings (misconfigurations) mapped to our Finding model.
func scanDockerfile(ctx context.Context, opts ScanOptions) ([]Finding, error) {
	path := opts.Dockerfile
	if path == "" {
		return nil, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("dockerfile path: %w", err)
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("dockerfile not found %q: %w", path, err)
	}
	// Trivy config expects a directory or file; we pass the directory containing the Dockerfile so Trivy detects it
	dir := filepath.Dir(abs)
	args := []string{"config", "--format", "json"}
	if opts.CacheDir != "" {
		args = append(args, "--cache-dir", opts.CacheDir)
	}
	if opts.Offline {
		args = append(args, "--skip-policy-update")
	}
	if len(opts.Severity) > 0 {
		args = append(args, "--severity", strings.Join(opts.Severity, ","))
	}
	args = append(args, dir)

	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy config: %w (stderr: %s)", err, stderr.String())
	}

	var report trivyConfigReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("parse trivy config json: %w", err)
	}

	severitySet := make(map[string]bool)
	for _, s := range opts.Severity {
		severitySet[strings.ToUpper(strings.TrimSpace(s))] = true
	}

	var findings []Finding
	for _, res := range report.Results {
		target := filepath.Base(res.Target)
		for _, m := range res.Misconfigurations {
			sev := strings.ToUpper(m.Severity)
			if sev == "" {
				sev = "UNKNOWN"
			}
			if len(severitySet) > 0 && !severitySet[sev] {
				continue
			}
			findings = append(findings, trivyMisconfigToFinding(m, target))
		}
	}
	return findings, nil
}

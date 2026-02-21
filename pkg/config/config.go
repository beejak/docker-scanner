// Package config loads scanner.yaml or .scanner.yaml for default scan options.
// CLI flags override config values.
package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Config holds default values for scan (severity, format, output-dir, etc.).
// Empty values mean "use CLI default". No secrets; use for paths and options only.
type Config struct {
	Severity        string `yaml:"severity"`         // Comma-separated: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN
	Format          string `yaml:"format"`          // Comma-separated: sarif, markdown, html, csv
	OutputDir       string `yaml:"output-dir"`       // Report output directory
	OutputName      string `yaml:"output-name"`      // Base name for report files
	CacheDir        string `yaml:"cache-dir"`        // Trivy cache directory
	FailOnSeverity  string `yaml:"fail-on-severity"` // Comma-separated severities that cause exit 1
	FailOnCount    string `yaml:"fail-on-count"`    // SEVERITY:N (e.g. HIGH:5)
}

// Find looks for scanner.yaml or .scanner.yaml in dir. Returns the path if found, else "".
func Find(dir string) string {
	if dir == "" {
		return ""
	}
	for _, name := range []string{"scanner.yaml", ".scanner.yaml"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Load reads a config file and returns the config. Missing file or empty file returns nil, nil.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var c Config
	if err := parseYAML(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// parseYAML is a minimal YAML parser for our flat struct (key: value per line).
// Avoids adding a YAML dependency for a few keys. Supports only simple string values.
func parseYAML(data []byte, c *Config) error {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, "\"'")
		switch key {
		case "severity":
			c.Severity = val
		case "format":
			c.Format = val
		case "output-dir":
			c.OutputDir = val
		case "output-name":
			c.OutputName = val
		case "cache-dir":
			c.CacheDir = val
		case "fail-on-severity":
			c.FailOnSeverity = val
		case "fail-on-count":
			c.FailOnCount = val
		}
	}
	return nil
}

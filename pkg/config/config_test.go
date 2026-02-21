package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanner.yaml")
	content := `# comment
severity: CRITICAL,HIGH
format: markdown,html
output-dir: ./out
output-name: scan
fail-on-severity: CRITICAL
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Severity != "CRITICAL,HIGH" {
		t.Errorf("Severity = %q", cfg.Severity)
	}
	if cfg.Format != "markdown,html" {
		t.Errorf("Format = %q", cfg.Format)
	}
	if cfg.OutputDir != "./out" {
		t.Errorf("OutputDir = %q", cfg.OutputDir)
	}
	if cfg.OutputName != "scan" {
		t.Errorf("OutputName = %q", cfg.OutputName)
	}
	if cfg.FailOnSeverity != "CRITICAL" {
		t.Errorf("FailOnSeverity = %q", cfg.FailOnSeverity)
	}
}

func TestLoad_missing(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Errorf("expected nil config for missing file")
	}
}

func TestFind(t *testing.T) {
	dir := t.TempDir()
	if p := Find(dir); p != "" {
		t.Errorf("Find(empty dir) = %q, want \"\"", p)
	}
	path := filepath.Join(dir, "scanner.yaml")
	if err := os.WriteFile(path, []byte("severity: HIGH\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if p := Find(dir); p != path {
		t.Errorf("Find() = %q, want %q", p, path)
	}
}

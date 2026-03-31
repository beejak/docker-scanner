package osv

import (
	"testing"
)

func TestEcosystemFor(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"alpine", "Alpine"},
		{"Alpine Linux", "Alpine"},
		{"debian 11", "Debian"},
		{"ubuntu:22.04", "Debian"},
		{"go.sum", "Go"},
		{"package-lock.json", "npm"},
		{"requirements.txt (python)", "PyPI"},
		{"Cargo.lock", "crates.io"},
		{"pom.xml (maven)", "Maven"},
		{"packages.config (nuget)", "NuGet"},
		{"unknown-os", ""},
	}
	for _, c := range cases {
		got := EcosystemFor(c.target)
		if got != c.want {
			t.Errorf("EcosystemFor(%q) = %q; want %q", c.target, got, c.want)
		}
	}
}

package namesquat

import (
	"testing"

	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/report"
)

func TestNormalizePackageName(t *testing.T) {
	if got := NormalizePackageName("pypi", "My_Pkg.Name"); got != "my-pkg-name" {
		t.Fatalf("PyPI normalized name = %q, want my-pkg-name", got)
	}
	if got := NormalizePackageName("npm", "@TanStack/React-Query"); got != "@tanstack/react-query" {
		t.Fatalf("npm normalized name = %q, want @tanstack/react-query", got)
	}
}

func TestProtectedPackageExactMatchCreatesNoFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "PyPI", Name: "requests"}, config.PolicyConfig{
		ProtectedPackages: map[string][]string{
			"pypi": {"requests"},
		},
	})

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestProtectedPackageTypoCreatesMediumFinding(t *testing.T) {
	cases := []struct {
		name             string
		packageName      string
		protectedPackage string
	}{
		{name: "transposition", packageName: "reqeusts", protectedPackage: "requests"},
		{name: "deletion", packageName: "lodas", protectedPackage: "lodash"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := Check(report.PackageReport{Ecosystem: "PyPI", Name: tc.packageName}, config.PolicyConfig{
				ProtectedPackages: map[string][]string{
					"pypi": {tc.protectedPackage},
				},
			})

			if len(findings) != 1 {
				t.Fatalf("findings = %+v, want 1 finding", findings)
			}
			if findings[0].Severity != "MEDIUM" {
				t.Fatalf("severity = %q, want MEDIUM", findings[0].Severity)
			}
		})
	}
}

func TestProtectedPackageUnrelatedNameCreatesNoFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "npm", Name: "chalk"}, config.PolicyConfig{
		ProtectedPackages: map[string][]string{
			"npm": {"react"},
		},
	})

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestProtectedTokenBoundaryCreatesMediumFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "npm", Name: "tanstack-query-utils"}, config.PolicyConfig{
		ProtectedTokens: map[string][]string{
			"npm": {"tanstack"},
		},
	})

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", findings)
	}
	if findings[0].Severity != "MEDIUM" {
		t.Fatalf("severity = %q, want MEDIUM", findings[0].Severity)
	}
}

func TestProtectedTokenInsideWordCreatesNoFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "npm", Name: "mytanstackhelper"}, config.PolicyConfig{
		ProtectedTokens: map[string][]string{
			"npm": {"tanstack"},
		},
	})

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestProtectedTokenExactProtectedPackageCreatesNoFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "npm", Name: "@tanstack/react-query"}, config.PolicyConfig{
		ProtectedPackages: map[string][]string{
			"npm": {"@tanstack/react-query"},
		},
		ProtectedTokens: map[string][]string{
			"npm": {"tanstack"},
		},
	})

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestProtectedTokenScopedUnknownPackageCreatesMediumFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "npm", Name: "@tanstack/unknown"}, config.PolicyConfig{
		ProtectedPackages: map[string][]string{
			"npm": {"@tanstack/react-query"},
		},
		ProtectedTokens: map[string][]string{
			"npm": {"tanstack"},
		},
	})

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", findings)
	}
	if findings[0].Severity != "MEDIUM" {
		t.Fatalf("severity = %q, want MEDIUM", findings[0].Severity)
	}
}

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
	findings := Check(report.PackageReport{Ecosystem: "PyPI", Name: "requests"}, config.PolicyTierConfig{
		ProtectedPackages: map[string][]string{
			"pypi": {"requests"},
		},
	})

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestProtectedPackageTypoCreatesFinding(t *testing.T) {
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
			findings := Check(report.PackageReport{Ecosystem: "PyPI", Name: tc.packageName}, config.PolicyTierConfig{
				ProtectedPackages: map[string][]string{
					"pypi": {tc.protectedPackage},
				},
			})

			if len(findings) != 1 {
				t.Fatalf("findings = %+v, want 1 finding", findings)
			}
			if findings[0].Severity != "" {
				t.Fatalf("severity = %q, want empty severity", findings[0].Severity)
			}
		})
	}
}

func TestProtectedPackageUnrelatedNameCreatesNoFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "npm", Name: "chalk"}, config.PolicyTierConfig{
		ProtectedPackages: map[string][]string{
			"npm": {"react"},
		},
	})

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestProtectedTokenBoundaryCreatesFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "npm", Name: "tanstack-query-utils"}, config.PolicyTierConfig{
		ProtectedTokens: map[string][]string{
			"npm": {"tanstack"},
		},
	})

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", findings)
	}
	if findings[0].Severity != "" {
		t.Fatalf("severity = %q, want empty severity", findings[0].Severity)
	}
}

func TestProtectedTokenInsideWordCreatesNoFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "npm", Name: "mytanstackhelper"}, config.PolicyTierConfig{
		ProtectedTokens: map[string][]string{
			"npm": {"tanstack"},
		},
	})

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestProtectedTokenExactProtectedPackageCreatesNoFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "npm", Name: "@tanstack/react-query"}, config.PolicyTierConfig{
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

func TestProtectedTokenScopedUnknownPackageCreatesFinding(t *testing.T) {
	findings := Check(report.PackageReport{Ecosystem: "npm", Name: "@tanstack/unknown"}, config.PolicyTierConfig{
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
	if findings[0].Severity != "" {
		t.Fatalf("severity = %q, want empty severity", findings[0].Severity)
	}
}

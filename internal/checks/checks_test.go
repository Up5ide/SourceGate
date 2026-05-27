package checks

import (
	"testing"
	"time"

	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/report"
)

func TestEvaluateBlocksFreshLatestRelease(t *testing.T) {
	pkg := report.PackageReport{
		LatestPublishedAt: "2026-05-26T12:00:00Z",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			MinimumDaysSinceLatestRelease: 3,
		},
	}
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

	Evaluate(&pkg, config, now)

	if pkg.Decision != report.DecisionBlock {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionBlock)
	}
}

func TestEvaluateBlocksDormantRelease(t *testing.T) {
	pkg := report.PackageReport{
		LatestPublishedAt:   "2026-05-27T12:00:00Z",
		PreviousPublishedAt: "2025-05-27T12:00:00Z",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			DormantReleaseThresholdDays: 180,
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionBlock {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionBlock)
	}
}

func TestEvaluateAllowsProtectedNameAlerts(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "PyPI",
		Name:      "reqeusts",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			ProtectedPackages: map[string][]string{
				"pypi": {"requests"},
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Severity != "MEDIUM" {
		t.Fatalf("unexpected findings: %+v", pkg.Findings)
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

package sourcegate

import (
	"testing"
	"time"
)

func TestEvaluatePolicyBlocksFreshLatestRelease(t *testing.T) {
	report := PackageReport{
		LatestPublishedAt: "2026-05-26T12:00:00Z",
	}
	config := Config{
		Policy: PolicyConfig{
			MinimumDaysSinceLatestRelease: 3,
		},
	}
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

	EvaluatePolicy(&report, config, now)

	if report.Decision != DecisionBlock {
		t.Fatalf("decision = %q, want %q", report.Decision, DecisionBlock)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}
}

func TestEvaluatePolicyAllowsOlderLatestRelease(t *testing.T) {
	report := PackageReport{
		LatestPublishedAt: "2026-05-20T12:00:00Z",
	}
	config := Config{
		Policy: PolicyConfig{
			MinimumDaysSinceLatestRelease: 3,
		},
	}
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

	EvaluatePolicy(&report, config, now)

	if report.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want %q", report.Decision, DecisionAllow)
	}
}

func TestEvaluatePolicyBlocksDormantRelease(t *testing.T) {
	report := PackageReport{
		LatestPublishedAt:   "2026-05-27T12:00:00Z",
		PreviousPublishedAt: "2025-05-27T12:00:00Z",
	}
	config := Config{
		Policy: PolicyConfig{
			DormantReleaseThresholdDays: 180,
		},
	}

	EvaluatePolicy(&report, config, time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

	if report.Decision != DecisionBlock {
		t.Fatalf("decision = %q, want %q", report.Decision, DecisionBlock)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}
}

func TestEvaluatePolicyAllowsNonDormantRelease(t *testing.T) {
	report := PackageReport{
		LatestPublishedAt:   "2026-05-27T12:00:00Z",
		PreviousPublishedAt: "2026-04-27T12:00:00Z",
	}
	config := Config{
		Policy: PolicyConfig{
			DormantReleaseThresholdDays: 180,
		},
	}

	EvaluatePolicy(&report, config, time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

	if report.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want %q", report.Decision, DecisionAllow)
	}
}

func TestEvaluatePolicySkipsDormantCheckForFirstRelease(t *testing.T) {
	report := PackageReport{
		LatestPublishedAt: "2026-05-27T12:00:00Z",
	}
	config := Config{
		Policy: PolicyConfig{
			DormantReleaseThresholdDays: 180,
		},
	}

	EvaluatePolicy(&report, config, time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

	if report.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want %q", report.Decision, DecisionAllow)
	}
	if len(report.Findings) != 1 || report.Findings[0].Severity != "INFO" {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
}

func TestEvaluatePolicyLeavesInspectOnlyWhenDisabled(t *testing.T) {
	report := PackageReport{
		LatestPublishedAt: "2026-05-27T12:00:00Z",
	}

	EvaluatePolicy(&report, Config{}, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if report.Decision != DecisionInspectOnly {
		t.Fatalf("decision = %q, want %q", report.Decision, DecisionInspectOnly)
	}
}

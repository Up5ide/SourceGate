package checks

import (
	"fmt"
	"time"

	"github.com/sourcegate/sourcegate/internal/checks/dormant"
	"github.com/sourcegate/sourcegate/internal/checks/namesquat"
	"github.com/sourcegate/sourcegate/internal/checks/releaseage"
	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/report"
)

func Evaluate(pkg *report.PackageReport, cfg config.Config, now time.Time) {
	pkg.Decision = report.DecisionInspectOnly

	policiesEnabled := cfg.Policy.MinimumDaysSinceLatestRelease > 0 ||
		cfg.Policy.DormantReleaseThresholdDays > 0 ||
		hasProtectedNamePolicy(cfg)
	if !policiesEnabled {
		return
	}

	var policySummaries []string
	if cfg.Policy.MinimumDaysSinceLatestRelease > 0 {
		policySummaries = append(
			policySummaries,
			fmt.Sprintf("latest release must be at least %d day(s) old", cfg.Policy.MinimumDaysSinceLatestRelease),
		)
	}
	if cfg.Policy.DormantReleaseThresholdDays > 0 {
		policySummaries = append(
			policySummaries,
			fmt.Sprintf("release inactivity gap must be below %d day(s)", cfg.Policy.DormantReleaseThresholdDays),
		)
	}
	if hasProtectedNamePolicy(cfg) {
		policySummaries = append(policySummaries, "protected package and token alerts enabled")
	}
	pkg.PolicySummary = joinPolicySummaries(policySummaries)

	if cfg.Policy.MinimumDaysSinceLatestRelease > 0 {
		pkg.Findings = append(pkg.Findings, releaseage.Check(*pkg, cfg.Policy.MinimumDaysSinceLatestRelease, now)...)
	}
	if cfg.Policy.DormantReleaseThresholdDays > 0 {
		pkg.Findings = append(pkg.Findings, dormant.Check(*pkg, cfg.Policy.DormantReleaseThresholdDays)...)
	}
	if hasProtectedNamePolicy(cfg) {
		pkg.Findings = append(pkg.Findings, namesquat.Check(*pkg, cfg.Policy)...)
	}

	if hasHighSeverityFinding(pkg.Findings) {
		pkg.Decision = report.DecisionBlock
		return
	}
	pkg.Decision = report.DecisionAllow
}

func hasProtectedNamePolicy(cfg config.Config) bool {
	return len(cfg.Policy.ProtectedPackages) > 0 || len(cfg.Policy.ProtectedTokens) > 0
}

func hasHighSeverityFinding(findings []report.Finding) bool {
	for _, finding := range findings {
		if finding.Severity == "HIGH" {
			return true
		}
	}
	return false
}

func joinPolicySummaries(values []string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += "; " + value
	}
	return result
}

package sourcegate

import (
	"fmt"
	"time"
)

type Decision string

const (
	DecisionInspectOnly Decision = "INSPECT_ONLY"
	DecisionAllow       Decision = "ALLOW"
	DecisionBlock       Decision = "BLOCK"
)

type Finding struct {
	Severity string
	Message  string
}

func EvaluatePolicy(report *PackageReport, config Config, now time.Time) {
	report.Decision = DecisionInspectOnly

	policiesEnabled := config.Policy.MinimumDaysSinceLatestRelease > 0 ||
		config.Policy.DormantReleaseThresholdDays > 0
	if !policiesEnabled {
		return
	}

	var policySummaries []string
	if config.Policy.MinimumDaysSinceLatestRelease > 0 {
		policySummaries = append(
			policySummaries,
			fmt.Sprintf("latest release must be at least %d day(s) old", config.Policy.MinimumDaysSinceLatestRelease),
		)
	}
	if config.Policy.DormantReleaseThresholdDays > 0 {
		policySummaries = append(
			policySummaries,
			fmt.Sprintf("release inactivity gap must be below %d day(s)", config.Policy.DormantReleaseThresholdDays),
		)
	}
	report.PolicySummary = joinPolicySummaries(policySummaries)

	if config.Policy.MinimumDaysSinceLatestRelease > 0 {
		evaluateLatestReleaseAge(report, config.Policy.MinimumDaysSinceLatestRelease, now)
	}
	if config.Policy.DormantReleaseThresholdDays > 0 {
		evaluateDormantRelease(report, config.Policy.DormantReleaseThresholdDays)
	}

	if hasHighSeverityFinding(report.Findings) {
		report.Decision = DecisionBlock
		return
	}
	report.Decision = DecisionAllow
}

func evaluateLatestReleaseAge(report *PackageReport, minDays int, now time.Time) {
	latestPublishedAt, err := parseRegistryTime(report.LatestPublishedAt)
	if err != nil {
		report.Findings = append(report.Findings, Finding{
			Severity: "HIGH",
			Message:  "latest release publish time is unavailable or invalid",
		})
		return
	}

	age := now.UTC().Sub(latestPublishedAt.UTC())
	requiredAge := time.Duration(minDays) * 24 * time.Hour
	if age < requiredAge {
		report.Findings = append(report.Findings, Finding{
			Severity: "HIGH",
			Message: fmt.Sprintf(
				"latest release was published %s ago, below configured minimum of %d day(s)",
				formatAge(age),
				minDays,
			),
		})
		return
	}

	report.Findings = append(report.Findings, Finding{
		Severity: "INFO",
		Message:  fmt.Sprintf("latest release age satisfies configured minimum of %d day(s)", minDays),
	})
}

func evaluateDormantRelease(report *PackageReport, thresholdDays int) {
	latestPublishedAt, err := parseRegistryTime(report.LatestPublishedAt)
	if err != nil {
		report.Findings = append(report.Findings, Finding{
			Severity: "HIGH",
			Message:  "latest release publish time is unavailable or invalid",
		})
		return
	}

	previousPublishedAt, err := parseRegistryTime(report.PreviousPublishedAt)
	if err != nil {
		report.Findings = append(report.Findings, Finding{
			Severity: "INFO",
			Message:  "previous release publish time is unavailable; dormant release check skipped",
		})
		return
	}

	inactivity := latestPublishedAt.UTC().Sub(previousPublishedAt.UTC())
	threshold := time.Duration(thresholdDays) * 24 * time.Hour
	if inactivity >= threshold {
		report.Findings = append(report.Findings, Finding{
			Severity: "HIGH",
			Message: fmt.Sprintf(
				"latest release follows %d day(s) of package inactivity, meeting or exceeding configured threshold of %d day(s)",
				int(inactivity.Hours()/24),
				thresholdDays,
			),
		})
		return
	}

	report.Findings = append(report.Findings, Finding{
		Severity: "INFO",
		Message:  fmt.Sprintf("release inactivity gap is below configured threshold of %d day(s)", thresholdDays),
	})
}

func hasHighSeverityFinding(findings []Finding) bool {
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

func parseRegistryTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	return time.Parse(time.RFC3339, value)
}

func formatAge(age time.Duration) string {
	if age < 0 {
		return "0 hours"
	}
	hours := int(age.Hours())
	if hours < 48 {
		return fmt.Sprintf("%d hour(s)", hours)
	}
	return fmt.Sprintf("%d day(s)", hours/24)
}

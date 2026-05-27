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

	minDays := config.Policy.MinimumDaysSinceLatestRelease
	if minDays == 0 {
		return
	}

	report.PolicySummary = fmt.Sprintf("latest release must be at least %d day(s) old", minDays)

	latestPublishedAt, err := parseRegistryTime(report.LatestPublishedAt)
	if err != nil {
		report.Decision = DecisionBlock
		report.Findings = append(report.Findings, Finding{
			Severity: "HIGH",
			Message:  "latest release publish time is unavailable or invalid",
		})
		return
	}

	age := now.UTC().Sub(latestPublishedAt.UTC())
	requiredAge := time.Duration(minDays) * 24 * time.Hour
	if age < requiredAge {
		report.Decision = DecisionBlock
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

	report.Decision = DecisionAllow
	report.Findings = append(report.Findings, Finding{
		Severity: "INFO",
		Message:  fmt.Sprintf("latest release age satisfies configured minimum of %d day(s)", minDays),
	})
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

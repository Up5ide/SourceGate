package dormant

import (
	"fmt"
	"time"

	"github.com/sourcegate/sourcegate/internal/report"
)

func Check(pkg report.PackageReport, thresholdDays int) []report.Finding {
	latestPublishedAt, err := parseRegistryTime(pkg.LatestPublishedAt)
	if err != nil {
		return []report.Finding{{
			Severity: "HIGH",
			Message:  "latest release publish time is unavailable or invalid",
		}}
	}

	previousPublishedAt, err := parseRegistryTime(pkg.PreviousPublishedAt)
	if err != nil {
		return []report.Finding{{
			Severity: "INFO",
			Message:  "previous release publish time is unavailable; dormant release check skipped",
		}}
	}

	inactivity := latestPublishedAt.UTC().Sub(previousPublishedAt.UTC())
	threshold := time.Duration(thresholdDays) * 24 * time.Hour
	if inactivity >= threshold {
		return []report.Finding{{
			Severity: "HIGH",
			Message: fmt.Sprintf(
				"latest release follows %d day(s) of package inactivity, meeting or exceeding configured threshold of %d day(s)",
				int(inactivity.Hours()/24),
				thresholdDays,
			),
		}}
	}

	return []report.Finding{{
		Severity: "INFO",
		Message:  fmt.Sprintf("release inactivity gap is below configured threshold of %d day(s)", thresholdDays),
	}}
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

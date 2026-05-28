package releaseage

import (
	"fmt"
	"time"

	"github.com/sourcegate/sourcegate/internal/report"
)

func Check(pkg report.PackageReport, minDays int, now time.Time) []report.Finding {
	latestPublishedAt, err := parseRegistryTime(pkg.LatestPublishedAt)
	if err != nil {
		return []report.Finding{{
			Message: "latest release publish time is unavailable or invalid",
		}}
	}

	age := now.UTC().Sub(latestPublishedAt.UTC())
	requiredAge := time.Duration(minDays) * 24 * time.Hour
	if age < requiredAge {
		return []report.Finding{{
			Message: fmt.Sprintf(
				"latest release was published %s ago, below configured minimum of %d day(s)",
				formatAge(age),
				minDays,
			),
		}}
	}

	return nil
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

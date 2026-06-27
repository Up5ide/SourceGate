package dormant

import (
	"fmt"
	"time"

	"github.com/sourcegate/sourcegate/internal/report"
)

func Check(pkg report.PackageReport, thresholdDays int) []report.Finding {
	selectedPublishedAt, err := parseRegistryTime(pkg.SelectedPublishedAt)
	if err != nil {
		return []report.Finding{{
			Message: "selected release publish time is unavailable or invalid",
		}}
	}

	previousPublishedAt, err := parseRegistryTime(pkg.PreviousPublishedAt)
	if err != nil {
		return nil
	}

	inactivity := selectedPublishedAt.UTC().Sub(previousPublishedAt.UTC())
	inactivityDays := int64(inactivity / (24 * time.Hour))
	if inactivity >= 0 && inactivityDays >= int64(thresholdDays) {
		return []report.Finding{{
			Message: fmt.Sprintf(
				"selected release follows %d day(s) of package inactivity, meeting or exceeding configured threshold of %d day(s)",
				inactivityDays,
				thresholdDays,
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

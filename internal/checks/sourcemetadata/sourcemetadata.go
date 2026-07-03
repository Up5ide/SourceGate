package sourcemetadata

import (
	"fmt"
	"strings"
	"time"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
)

func CheckGitHeadMissing(pkg report.PackageReport) []report.Finding {
	if !isNPM(pkg) || strings.TrimSpace(pkg.NPMSource.SelectedGitHead) != "" {
		return nil
	}
	return []report.Finding{{Message: "npm registry metadata for selected version is missing gitHead"}}
}

func CheckRepositoryMissing(pkg report.PackageReport) []report.Finding {
	if !isNPM(pkg) || strings.TrimSpace(pkg.NPMSource.RepositoryURL) != "" {
		return nil
	}
	return []report.Finding{{Message: "npm registry metadata is missing repository URL"}}
}

func CheckGitHeadChangedAfterDormancy(pkg report.PackageReport, thresholdDays int) []report.Finding {
	if !isNPM(pkg) || thresholdDays <= 0 {
		return nil
	}
	selectedGitHead := strings.TrimSpace(pkg.NPMSource.SelectedGitHead)
	previousGitHead := strings.TrimSpace(pkg.NPMSource.PreviousGitHead)
	if selectedGitHead == "" || previousGitHead == "" || selectedGitHead == previousGitHead {
		return nil
	}
	days, dormant := dormantReleaseGap(pkg, thresholdDays)
	if !dormant {
		return nil
	}
	return []report.Finding{{
		Message: fmt.Sprintf("npm registry gitHead changed after %d day(s) of package inactivity", days),
	}}
}

func CheckRepositoryChanged(pkg report.PackageReport) []report.Finding {
	if !isNPM(pkg) {
		return nil
	}
	selectedRepository := normalizedURL(pkg.NPMSource.RepositoryURL)
	previousRepository := normalizedURL(pkg.NPMSource.PreviousRepositoryURL)
	if selectedRepository == "" || previousRepository == "" || selectedRepository == previousRepository {
		return nil
	}
	return []report.Finding{{
		Message: fmt.Sprintf("npm registry repository URL changed from %s to %s", pkg.NPMSource.PreviousRepositoryURL, pkg.NPMSource.RepositoryURL),
	}}
}

func CheckPublisherChanged(pkg report.PackageReport) []report.Finding {
	if !isNPM(pkg) {
		return nil
	}
	selectedPublisher := strings.TrimSpace(pkg.NPMSource.SelectedPublisher)
	previousPublisher := strings.TrimSpace(pkg.NPMSource.PreviousPublisher)
	if selectedPublisher == "" || previousPublisher == "" || selectedPublisher == previousPublisher {
		return nil
	}
	return []report.Finding{{
		Message: fmt.Sprintf("npm publisher metadata changed from %s to %s", previousPublisher, selectedPublisher),
	}}
}

func CheckReleaseBurst(pkg report.PackageReport, count int, windowHours int) []report.Finding {
	if !isNPM(pkg) || count <= 0 || windowHours <= 0 {
		return nil
	}
	recentCount, ok := recentReleaseCount(pkg, time.Duration(windowHours)*time.Hour)
	if !ok || recentCount < count {
		return nil
	}
	return []report.Finding{{
		Message: fmt.Sprintf("npm registry metadata shows %d release(s) within %d hour(s) ending at the selected version", recentCount, windowHours),
	}}
}

func Evidence(pkg report.PackageReport, burstWindowHours int) []string {
	evidence := []string{
		"repository URL: " + valueOrUnavailable(pkg.NPMSource.RepositoryURL),
		"previous repository URL: " + valueOrUnavailable(pkg.NPMSource.PreviousRepositoryURL),
		"selected gitHead: " + valueOrUnavailable(pkg.NPMSource.SelectedGitHead),
		"previous gitHead: " + valueOrUnavailable(pkg.NPMSource.PreviousGitHead),
		"selected publisher: " + valueOrUnavailable(pkg.NPMSource.SelectedPublisher),
		"previous publisher: " + valueOrUnavailable(pkg.NPMSource.PreviousPublisher),
	}
	if burstWindowHours > 0 {
		count, ok := recentReleaseCount(pkg, time.Duration(burstWindowHours)*time.Hour)
		if ok {
			evidence = append(evidence, fmt.Sprintf("release burst count in %d hour(s): %d", burstWindowHours, count))
		} else {
			evidence = append(evidence, fmt.Sprintf("release burst count in %d hour(s): unavailable", burstWindowHours))
		}
	}
	return evidence
}

func recentReleaseCount(pkg report.PackageReport, window time.Duration) (int, bool) {
	selected, err := parseRegistryTime(pkg.SelectedPublishedAt)
	if err != nil {
		return 0, false
	}
	count := 1
	for _, entry := range pkg.LifecycleHistory {
		published, err := parseRegistryTime(entry.PublishedAt)
		if err != nil {
			continue
		}
		if published.After(selected) {
			continue
		}
		if selected.Sub(published) <= window {
			count++
		}
	}
	return count, true
}

func dormantReleaseGap(pkg report.PackageReport, thresholdDays int) (int, bool) {
	selectedPublishedAt, err := parseRegistryTime(pkg.SelectedPublishedAt)
	if err != nil {
		return 0, false
	}
	previousPublishedAt, err := parseRegistryTime(pkg.PreviousPublishedAt)
	if err != nil {
		return 0, false
	}
	inactivity := selectedPublishedAt.UTC().Sub(previousPublishedAt.UTC())
	inactivityDays := int64(inactivity / (24 * time.Hour))
	if inactivity < 0 || inactivityDays < int64(thresholdDays) {
		return 0, false
	}
	return int(inactivityDays), true
}

func parseRegistryTime(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	return time.Parse(time.RFC3339, value)
}

func normalizedURL(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "git+")
	value = strings.TrimSuffix(value, ".git")
	return value
}

func valueOrUnavailable(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unavailable"
	}
	return value
}

func isNPM(pkg report.PackageReport) bool {
	return strings.EqualFold(strings.TrimSpace(pkg.Ecosystem), string(ecosystem.NPM))
}

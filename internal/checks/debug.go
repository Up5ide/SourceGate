package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/sourcegate/sourcegate/internal/checks/namesquat"
	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
)

func releaseAgeEvidence(pkg report.PackageReport, now time.Time) []string {
	evidence := []string{"selected published: " + valueOrUnavailable(pkg.SelectedPublishedAt)}
	selected, err := parseRegistryTime(pkg.SelectedPublishedAt)
	if err != nil {
		return append(evidence, "release age: unavailable")
	}
	return append(evidence, "release age: "+formatDuration(now.UTC().Sub(selected.UTC())))
}

func dormantReleaseEvidence(pkg report.PackageReport) []string {
	evidence := []string{
		"selected published: " + valueOrUnavailable(pkg.SelectedPublishedAt),
		"previous published: " + valueOrUnavailable(pkg.PreviousPublishedAt),
	}
	diagnostics := pkg.PyPIHistory
	if isNPM(pkg) {
		diagnostics = pkg.NPMHistory
	}
	evidence = append(evidence,
		fmt.Sprintf("selected comparison versions: %s", valuesOrNone(diagnostics.SelectedVersions)),
		fmt.Sprintf("skipped later versions: %d", diagnostics.SkippedLaterVersions),
		fmt.Sprintf("skipped prerelease versions: %d", diagnostics.SkippedPrereleaseVersions),
		fmt.Sprintf("skipped malformed versions: %s", valuesOrNone(diagnostics.SkippedMalformedVersions)),
		fmt.Sprintf("skipped malformed publish times: %s", valuesOrNone(diagnostics.SkippedMalformedTimes)),
	)
	if diagnostics.IndeterminateReason != "" {
		evidence = append(evidence, "history reliability: indeterminate: "+diagnostics.IndeterminateReason)
	}
	selected, selectedErr := parseRegistryTime(pkg.SelectedPublishedAt)
	previous, previousErr := parseRegistryTime(pkg.PreviousPublishedAt)
	if selectedErr != nil || previousErr != nil {
		return append(evidence, "inactivity gap: unavailable")
	}
	return append(evidence, "inactivity gap: "+formatDuration(selected.UTC().Sub(previous.UTC())))
}

func valuesOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	const limit = 5
	if len(values) > limit {
		return fmt.Sprintf("%s, and %d more", strings.Join(values[:limit], ", "), len(values)-limit)
	}
	return strings.Join(values, ", ")
}

func firstReleaseEvidence(pkg report.PackageReport) []string {
	return []string{fmt.Sprintf("published versions: %d", pkg.VersionCount)}
}

func protectedNameEvidence(pkg report.PackageReport, label string, tiers []policyTier, values func(config.PolicyTierConfig) map[string][]string) []string {
	ecosystemKey := strings.ToLower(strings.TrimSpace(pkg.Ecosystem))
	return []string{
		"normalized package name: " + namesquat.NormalizePackageName(ecosystemKey, pkg.Name),
		fmt.Sprintf("%s: block=%d, alert=%d, inform=%d", label,
			len(values(tiers[0].policy)[ecosystemKey]),
			len(values(tiers[1].policy)[ecosystemKey]),
			len(values(tiers[2].policy)[ecosystemKey]),
		),
	}
}

func integerThresholdEvidence(label string, tiers []policyTier, value func(config.PolicyTierConfig) int) string {
	return fmt.Sprintf("%s: block=%s, alert=%s, inform=%s", label,
		formatIntegerThreshold(value(tiers[0].policy)),
		formatIntegerThreshold(value(tiers[1].policy)),
		formatIntegerThreshold(value(tiers[2].policy)),
	)
}

func booleanThresholdEvidence(label string, tiers []policyTier, value func(config.PolicyTierConfig) bool) string {
	return fmt.Sprintf("%s: block=%s, alert=%s, inform=%s", label,
		formatEnabled(value(tiers[0].policy)),
		formatEnabled(value(tiers[1].policy)),
		formatEnabled(value(tiers[2].policy)),
	)
}

func maxTierInteger(tiers []policyTier, value func(config.PolicyTierConfig) int) int {
	max := 0
	for _, tier := range tiers {
		if current := value(tier.policy); current > max {
			max = current
		}
	}
	return max
}

func anyTier(tiers []policyTier, enabled func(config.PolicyTierConfig) bool) bool {
	for _, tier := range tiers {
		if enabled(tier.policy) {
			return true
		}
	}
	return false
}

func isNPM(pkg report.PackageReport) bool {
	return strings.EqualFold(strings.TrimSpace(pkg.Ecosystem), string(ecosystem.NPM))
}

func isPyPI(pkg report.PackageReport) bool {
	return strings.EqualFold(strings.TrimSpace(pkg.Ecosystem), string(ecosystem.PyPI))
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

func formatDuration(value time.Duration) string {
	hours := int(value.Hours())
	if hours < 0 {
		hours = 0
	}
	if hours < 48 {
		return fmt.Sprintf("%d hour(s)", hours)
	}
	return fmt.Sprintf("%d day(s)", hours/24)
}

func formatIntegerThreshold(value int) string {
	if value <= 0 {
		return "disabled"
	}
	return fmt.Sprintf("%d", value)
}

func formatEnabled(value bool) string {
	if value {
		return "enabled"
	}
	return "disabled"
}

func valueOrUnavailable(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unavailable"
	}
	return value
}

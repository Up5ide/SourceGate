package installlifecycle

import (
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

func DeclaredScriptsEvidence(pkg report.PackageReport) []string {
	names := installScriptNames(pkg.LifecycleScripts)
	if len(names) == 0 {
		return []string{"install-relevant lifecycle scripts: none"}
	}

	evidence := make([]string, 0, len(names))
	for _, name := range names {
		evidence = append(evidence, fmt.Sprintf("lifecycle script %s: %s", name, pkg.LifecycleScripts[name]))
	}
	return evidence
}

func SuspiciousCommandsEvidence(pkg report.PackageReport) []string {
	var evidence []string
	for _, name := range installScriptNames(pkg.LifecycleScripts) {
		reasons := suspiciousCommandReasons(pkg.LifecycleScripts[name])
		if len(reasons) == 0 {
			continue
		}
		evidence = append(evidence, fmt.Sprintf("lifecycle script %s suspicious patterns: %s", name, strings.Join(reasons, ", ")))
	}
	if len(evidence) == 0 {
		return []string{"suspicious lifecycle command patterns: none"}
	}
	return evidence
}

func HistoryEvidence(pkg report.PackageReport, historyVersions int) []string {
	evidence := []string{
		fmt.Sprintf("fetched lifecycle history versions: %d", len(pkg.LifecycleHistory)),
		fmt.Sprintf("comparison limit: %d", historyVersions),
		fmt.Sprintf("selected comparison versions: %s", displayValues(pkg.NPMHistory.SelectedVersions)),
		fmt.Sprintf("skipped later versions: %d", pkg.NPMHistory.SkippedLaterVersions),
		fmt.Sprintf("skipped prerelease versions: %d", pkg.NPMHistory.SkippedPrereleaseVersions),
		fmt.Sprintf("skipped malformed versions: %s", displayValues(pkg.NPMHistory.SkippedMalformedVersions)),
		fmt.Sprintf("skipped malformed publish times: %s", displayValues(pkg.NPMHistory.SkippedMalformedTimes)),
	}
	if pkg.NPMHistory.IndeterminateReason != "" {
		evidence = append(evidence, "history reliability: indeterminate: "+pkg.NPMHistory.IndeterminateReason)
	}
	names := installScriptNames(pkg.LifecycleScripts)
	if len(names) == 0 {
		return append(evidence, "install-relevant lifecycle scripts: none")
	}

	for _, name := range names {
		result := compareImmediateScript(pkg, name, historyVersions)
		switch {
		case !result.hasPrevious:
			evidence = append(evidence, fmt.Sprintf("lifecycle script %s has no previous release to compare", name))
		case !result.previousKnown:
			evidence = append(evidence, fmt.Sprintf("lifecycle script %s immediate previous release metadata is unknown", name))
		case result.previousHasScript:
			evidence = append(evidence, fmt.Sprintf("lifecycle script %s present in immediate previous version %s", name, result.previousVersion))
		case result.olderHasScript:
			evidence = append(evidence, fmt.Sprintf("lifecycle script %s absent from immediate previous version %s and present in older version %s", name, result.previousVersion, result.olderVersion))
		default:
			evidence = append(evidence, fmt.Sprintf("lifecycle script %s absent from immediate previous version %s and older compared history", name, result.previousVersion))
		}
	}
	return evidence
}

func displayValues(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	const limit = 5
	if len(values) > limit {
		return fmt.Sprintf("%s, and %d more", strings.Join(values[:limit], ", "), len(values)-limit)
	}
	return strings.Join(values, ", ")
}

func DormantAddedEvidence(pkg report.PackageReport, historyVersions int, thresholdDays int) []string {
	evidence := []string{
		fmt.Sprintf("comparison limit: %d", historyVersions),
		fmt.Sprintf("dormancy threshold: %d day(s)", thresholdDays),
	}
	inactivityDays, dormant := dormantReleaseGap(pkg, thresholdDays)
	if !dormant {
		return append(evidence, "dormant release gap: no")
	}
	return append(evidence, fmt.Sprintf("dormant release gap: yes (%d day(s))", inactivityDays))
}

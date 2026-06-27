package pypiartifacts

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

func ArtifactHistoryEvidence(pkg report.PackageReport, historyVersions int) []string {
	evidence := []string{
		fmt.Sprintf("configured history versions: %d", historyVersions),
		fmt.Sprintf("fetched artifact history versions: %d", len(pkg.PyPIReleaseHistory)),
	}
	return append(evidence, historyDiagnosticsEvidence(pkg.PyPIHistory)...)
}

func ArtifactShapeEvidence(pkg report.PackageReport, historyVersions int) []string {
	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	return []string{
		fmt.Sprintf("selected release files: %d", len(pkg.PyPISelectedRelease.Files)),
		fmt.Sprintf("compared artifact history versions: %d", len(history)),
	}
}

func FileSizeEvidence(pkg report.PackageReport, historyVersions int) []string {
	latestTotal, latestLargest, historicalMedianTotal, historicalMedianLargest, known := fileSizeStats(pkg, historyVersions)
	if !known {
		return []string{"file-size comparison metadata: unavailable or invalid"}
	}
	return []string{
		fmt.Sprintf("latest total file size: %d bytes", latestTotal),
		fmt.Sprintf("historical median total file size: %d bytes", historicalMedianTotal),
		fmt.Sprintf("latest largest file size: %d bytes", latestLargest),
		fmt.Sprintf("historical median largest file size: %d bytes", historicalMedianLargest),
	}
}

func DependencyEvidence(pkg report.PackageReport, historyVersions int, includeOptional bool) []string {
	comparison := compareDependencies(pkg, historyVersions, includeOptional)
	if !comparison.latestKnown {
		return []string{"latest dependency metadata: unavailable or dynamic"}
	}
	if !comparison.previousKnown {
		return []string{"previous dependency metadata: unavailable"}
	}
	return []string{
		fmt.Sprintf("compared against version: %s", comparison.previousVersion),
		fmt.Sprintf("added dependencies: %s", displaySet(comparison.added)),
		fmt.Sprintf("removed dependencies: %s", displaySet(comparison.removed)),
		fmt.Sprintf("added required dependencies: %s", displaySet(comparison.requiredAdded)),
		fmt.Sprintf("removed required dependencies: %s", displaySet(comparison.requiredRemoved)),
		fmt.Sprintf("added optional dependencies: %s", displaySet(comparison.optionalAdded)),
		fmt.Sprintf("removed optional dependencies: %s", displaySet(comparison.optionalRemoved)),
		fmt.Sprintf("required-to-optional dependencies: %s", displaySet(comparison.requiredToOptional)),
		fmt.Sprintf("optional-to-required dependencies: %s", displaySet(comparison.optionalToRequired)),
		fmt.Sprintf("optional dependency comparison: %s", enabledLabel(includeOptional)),
	}
}

func ProvenanceEvidence(pkg report.PackageReport) []string {
	summary := pkg.PyPIProvenance
	evidence := []string{
		fmt.Sprintf("requested scopes: %s", displaySet(summary.RequestedScopes)),
		fmt.Sprintf("python executable: %s", valueOrUnavailable(summary.PythonExecutable)),
		fmt.Sprintf("target platform: %s", valueOrUnavailable(summary.TargetPlatform)),
		fmt.Sprintf("target python version: %s", valueOrUnavailable(summary.PythonVersion)),
		fmt.Sprintf("target implementation: %s", valueOrUnavailable(summary.Implementation)),
		fmt.Sprintf("target ABIs: %s", displaySet(summary.ABIs)),
		fmt.Sprintf("compatible tags: %d", summary.CompatibleTagCount),
		fmt.Sprintf("checked compatible files: %d", summary.CheckedCompatibleFiles),
		fmt.Sprintf("skipped non-target files: %d", summary.SkippedNonTargetFiles),
	}
	if summary.UsedFallback {
		evidence = append(evidence, "target compatibility fallback: "+summary.FallbackReason)
	}
	if summary.CompatibilityError != "" {
		evidence = append(evidence, "target compatibility error: "+summary.CompatibilityError)
	}
	for _, scope := range summary.RequestedScopes {
		evidence = append(evidence, provenanceScopeEvidence(pkg, scope)...)
	}
	return evidence
}

func ReleaseFileCountEvidence(pkg report.PackageReport, historyVersions int) []string {
	latest, historicalMedian := releaseFileCountStats(pkg, historyVersions)
	return []string{
		fmt.Sprintf("selected release file count: %d", latest),
		fmt.Sprintf("historical median file count: %d", historicalMedian),
	}
}

func provenanceScopeEvidence(pkg report.PackageReport, scope string) []string {
	total := 0
	checked := 0
	available := 0
	var missing []string
	var errors []string
	for _, file := range pkg.PyPISelectedRelease.Files {
		if !provenanceFileInScope(file, scope) {
			continue
		}
		total++
		if file.ProvenanceChecked {
			checked++
		}
		if file.ProvenanceAvailable {
			available++
		}
		switch {
		case !file.ProvenanceChecked:
			errors = append(errors, file.Filename+": not checked")
		case file.ProvenanceError != "":
			errors = append(errors, file.Filename+": "+file.ProvenanceError)
		case !file.ProvenanceAvailable:
			missing = append(missing, file.Filename)
		}
	}
	sort.Strings(missing)
	sort.Strings(errors)
	return []string{
		fmt.Sprintf("scope %s release files: %d", scope, total),
		fmt.Sprintf("scope %s provenance checked: %d", scope, checked),
		fmt.Sprintf("scope %s provenance available: %d", scope, available),
		fmt.Sprintf("scope %s missing provenance files: %s", scope, displayBounded(missing)),
		fmt.Sprintf("scope %s provenance errors: %s", scope, displayBounded(errors)),
	}
}

func historyDiagnosticsEvidence(diagnostics report.HistoryDiagnostics) []string {
	evidence := []string{
		fmt.Sprintf("selected comparison versions: %s", displayBounded(diagnostics.SelectedVersions)),
		fmt.Sprintf("skipped later versions: %d", diagnostics.SkippedLaterVersions),
		fmt.Sprintf("skipped prerelease versions: %d", diagnostics.SkippedPrereleaseVersions),
		fmt.Sprintf("skipped malformed versions: %s", displayBounded(diagnostics.SkippedMalformedVersions)),
		fmt.Sprintf("skipped malformed publish times: %s", displayBounded(diagnostics.SkippedMalformedTimes)),
	}
	if diagnostics.IndeterminateReason != "" {
		evidence = append(evidence, "history reliability: indeterminate: "+diagnostics.IndeterminateReason)
	}
	return evidence
}

func displayBounded(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	const limit = 5
	if len(values) <= limit {
		return strings.Join(values, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(values[:limit], "; "), len(values)-limit)
}

func enabledLabel(enabled bool) string {
	if enabled {
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

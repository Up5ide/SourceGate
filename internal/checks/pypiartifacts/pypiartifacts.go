package pypiartifacts

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
)

func CheckArtifactShapeChange(pkg report.PackageReport, historyVersions int) []report.Finding {
	if !isPyPI(pkg) || historyVersions <= 0 || len(pkg.PyPILatestRelease.Files) == 0 {
		return nil
	}

	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	if len(history) == 0 {
		return nil
	}

	latest := releaseShape(pkg.PyPILatestRelease)
	previous := releaseShape(history[0])
	historical := historicalShape(history)

	var findings []report.Finding
	if latest.hasSdist && !latest.hasWheel && historical.hasWheel {
		findings = append(findings, report.Finding{Message: "latest PyPI release is source-only after prior release history included wheels"})
	}
	if !latest.hasWheel && previous.hasWheel {
		findings = append(findings, report.Finding{Message: "latest PyPI release removes wheel artifacts present in the previous release"})
	}
	if latest.hasSdist && !previous.hasSdist {
		findings = append(findings, report.Finding{Message: "latest PyPI release adds a source distribution artifact not present in the previous release"})
	}
	if !latest.hasSdist && previous.hasSdist {
		findings = append(findings, report.Finding{Message: "latest PyPI release removes source distribution artifacts present in the previous release"})
	}

	newWheelTags := sortedDifference(latest.wheelTags, historical.wheelTags)
	if len(newWheelTags) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("latest PyPI release adds new wheel platform tag(s): %s", strings.Join(newWheelTags, ", ")),
		})
	}

	newPackageTypes := sortedDifference(latest.packageTypes, previous.packageTypes)
	removedPackageTypes := sortedDifference(previous.packageTypes, latest.packageTypes)
	if len(newPackageTypes) > 0 || len(removedPackageTypes) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf(
				"latest PyPI release artifact package types changed; added: %s; removed: %s",
				displaySet(newPackageTypes),
				displaySet(removedPackageTypes),
			),
		})
	}

	return findings
}

func CheckFileSizeJump(pkg report.PackageReport, historyVersions int, jumpPercent int) []report.Finding {
	if !isPyPI(pkg) || historyVersions <= 0 || jumpPercent <= 0 || len(pkg.PyPILatestRelease.Files) == 0 {
		return nil
	}

	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	if len(history) == 0 {
		return nil
	}

	latestTotal, latestLargest, historicalMedianTotal, historicalMedianLargest := fileSizeStats(pkg, historyVersions)
	var findings []report.Finding
	if historicalMedianTotal > 0 && latestTotal*100 >= historicalMedianTotal*int64(100+jumpPercent) {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("latest PyPI release total file size is %d bytes, increased by at least %d%% over historical median %d bytes", latestTotal, jumpPercent, historicalMedianTotal),
		})
	}
	if historicalMedianLargest > 0 && latestLargest*100 >= historicalMedianLargest*int64(100+jumpPercent) {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("latest PyPI release largest file is %d bytes, increased by at least %d%% over historical median largest file %d bytes", latestLargest, jumpPercent, historicalMedianLargest),
		})
	}
	return findings
}

func fileSizeStats(pkg report.PackageReport, historyVersions int) (int64, int64, int64, int64) {
	latestTotal := totalSize(pkg.PyPILatestRelease.Files)
	latestLargest := largestSize(pkg.PyPILatestRelease.Files)
	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	historyTotals := make([]int64, 0, len(history))
	historyLargest := make([]int64, 0, len(history))
	for _, release := range history {
		if len(release.Files) == 0 {
			continue
		}
		historyTotals = append(historyTotals, totalSize(release.Files))
		historyLargest = append(historyLargest, largestSize(release.Files))
	}
	return latestTotal, latestLargest, medianInt64(historyTotals), medianInt64(historyLargest)
}

func CheckDependencyChange(pkg report.PackageReport, historyVersions int, includeOptional bool) []report.Finding {
	if !isPyPI(pkg) || historyVersions <= 0 {
		return nil
	}

	comparison := compareDependencies(pkg, historyVersions, includeOptional)
	if !comparison.latestKnown {
		return []report.Finding{{Message: "latest PyPI dependency metadata is unavailable or dynamic; dependency changes cannot be confirmed"}}
	}
	if !comparison.previousKnown {
		return []report.Finding{{Message: "previous PyPI dependency metadata is unavailable; dependency changes cannot be confirmed"}}
	}

	var findings []report.Finding
	if len(comparison.added) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("latest PyPI release adds declared dependency name(s): %s", strings.Join(comparison.added, ", ")),
		})
	}
	if len(comparison.removed) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("latest PyPI release removes declared dependency name(s): %s", strings.Join(comparison.removed, ", ")),
		})
	}
	return findings
}

type dependencyComparison struct {
	latestKnown     bool
	previousKnown   bool
	previousVersion string
	added           []string
	removed         []string
	requiredAdded   []string
	requiredRemoved []string
	optionalAdded   []string
	optionalRemoved []string
}

func compareDependencies(pkg report.PackageReport, historyVersions int, includeOptional bool) dependencyComparison {
	comparison := dependencyComparison{latestKnown: pkg.PyPILatestRelease.DependenciesKnown}
	if !comparison.latestKnown {
		return comparison
	}

	var previous report.PyPIReleaseInfo
	for _, release := range limitedHistory(pkg.PyPIReleaseHistory, historyVersions) {
		if release.DependenciesKnown {
			previous = release
			comparison.previousKnown = true
			comparison.previousVersion = release.Version
			break
		}
	}
	if !comparison.previousKnown {
		return comparison
	}

	latestDeps := stringSet(pkg.PyPILatestRelease.Dependencies)
	previousDeps := stringSet(previous.Dependencies)
	comparison.requiredAdded = sortedDifference(latestDeps, previousDeps)
	comparison.requiredRemoved = sortedDifference(previousDeps, latestDeps)
	comparison.added = append([]string(nil), comparison.requiredAdded...)
	comparison.removed = append([]string(nil), comparison.requiredRemoved...)
	if includeOptional {
		latestOptional := stringSet(pkg.PyPILatestRelease.OptionalDependencies)
		previousOptional := stringSet(previous.OptionalDependencies)
		comparison.optionalAdded = sortedDifference(latestOptional, previousOptional)
		comparison.optionalRemoved = sortedDifference(previousOptional, latestOptional)
		comparison.added = sortedUniqueStrings(append(comparison.added, comparison.optionalAdded...))
		comparison.removed = sortedUniqueStrings(append(comparison.removed, comparison.optionalRemoved...))
	}
	return comparison
}

func CheckProvenanceRequired(pkg report.PackageReport, scope string) []report.Finding {
	if !isPyPI(pkg) {
		return nil
	}

	eligible := 0
	missing := 0
	unknown := 0
	for _, file := range pkg.PyPILatestRelease.Files {
		if !provenanceFileInScope(file, scope) {
			continue
		}
		eligible++
		switch {
		case !file.ProvenanceChecked:
			unknown++
		case file.ProvenanceError != "":
			unknown++
		case !file.ProvenanceAvailable:
			missing++
		}
	}
	var findings []report.Finding
	if eligible == 0 {
		return []report.Finding{{Message: fmt.Sprintf("PyPI provenance scope %q selected no latest-release files", scope)}}
	}
	if missing > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("%d PyPI release file(s) in provenance scope %q have no provenance available", missing, scope),
		})
	}
	if unknown > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("PyPI provenance availability is unknown for %d release file(s) in provenance scope %q", unknown, scope),
		})
	}
	return findings
}

func CheckReleaseFileCountChange(pkg report.PackageReport, historyVersions int) []report.Finding {
	if !isPyPI(pkg) || historyVersions <= 0 || len(pkg.PyPILatestRelease.Files) == 0 {
		return nil
	}

	latestCount, historicalMedian := releaseFileCountStats(pkg, historyVersions)
	if historicalMedian == 0 || latestCount == historicalMedian {
		return nil
	}

	return []report.Finding{{
		Message: fmt.Sprintf("latest PyPI release has %d file(s), different from historical median of %d file(s)", latestCount, historicalMedian),
	}}
}

func releaseFileCountStats(pkg report.PackageReport, historyVersions int) (int, int) {
	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	counts := make([]int, 0, len(history))
	for _, release := range history {
		if len(release.Files) > 0 {
			counts = append(counts, len(release.Files))
		}
	}
	return len(pkg.PyPILatestRelease.Files), medianInt(counts)
}

type artifactShape struct {
	hasSdist     bool
	hasWheel     bool
	packageTypes map[string]struct{}
	wheelTags    map[string]struct{}
}

func releaseShape(release report.PyPIReleaseInfo) artifactShape {
	shape := artifactShape{
		packageTypes: make(map[string]struct{}),
		wheelTags:    make(map[string]struct{}),
	}
	for _, file := range release.Files {
		packageType := strings.TrimSpace(file.PackageType)
		if packageType != "" {
			shape.packageTypes[packageType] = struct{}{}
		}
		switch packageType {
		case "sdist":
			shape.hasSdist = true
		case "bdist_wheel":
			shape.hasWheel = true
			if tag := wheelTag(file.Filename); tag != "" {
				shape.wheelTags[tag] = struct{}{}
			}
		}
	}
	return shape
}

func historicalShape(history []report.PyPIReleaseInfo) artifactShape {
	shape := artifactShape{
		packageTypes: make(map[string]struct{}),
		wheelTags:    make(map[string]struct{}),
	}
	for _, release := range history {
		current := releaseShape(release)
		shape.hasSdist = shape.hasSdist || current.hasSdist
		shape.hasWheel = shape.hasWheel || current.hasWheel
		for value := range current.packageTypes {
			shape.packageTypes[value] = struct{}{}
		}
		for value := range current.wheelTags {
			shape.wheelTags[value] = struct{}{}
		}
	}
	return shape
}

func wheelTag(filename string) string {
	if !strings.HasSuffix(filename, ".whl") {
		return ""
	}
	stem := strings.TrimSuffix(filename, ".whl")
	parts := strings.Split(stem, "-")
	if len(parts) < 5 {
		return ""
	}
	tagParts := parts[len(parts)-3:]
	return strings.Join(tagParts, "-")
}

func totalSize(files []report.PyPIReleaseFile) int64 {
	var total int64
	for _, file := range files {
		total += file.Size
	}
	return total
}

func largestSize(files []report.PyPIReleaseFile) int64 {
	var largest int64
	for _, file := range files {
		if file.Size > largest {
			largest = file.Size
		}
	}
	return largest
}

func limitedHistory(history []report.PyPIReleaseInfo, historyVersions int) []report.PyPIReleaseInfo {
	if historyVersions <= 0 || len(history) == 0 {
		return nil
	}
	if len(history) > historyVersions {
		return history[:historyVersions]
	}
	return history
}

func medianInt64(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func medianInt(values []int) int {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result[value] = struct{}{}
		}
	}
	return result
}

func sortedDifference(left map[string]struct{}, right map[string]struct{}) []string {
	var result []string
	for value := range left {
		if _, ok := right[value]; !ok {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func displaySet(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func provenanceFileInScope(file report.PyPIReleaseFile, scope string) bool {
	if scope == "" {
		return true
	}
	for _, fileScope := range file.ProvenanceScopes {
		if fileScope == scope {
			return true
		}
	}
	return false
}

func sortedUniqueStrings(values []string) []string {
	set := stringSet(values)
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func isPyPI(pkg report.PackageReport) bool {
	return strings.EqualFold(strings.TrimSpace(pkg.Ecosystem), string(ecosystem.PyPI))
}

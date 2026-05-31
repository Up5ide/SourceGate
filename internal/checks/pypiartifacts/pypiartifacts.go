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

	latestTotal := totalSize(pkg.PyPILatestRelease.Files)
	latestLargest := largestSize(pkg.PyPILatestRelease.Files)
	historyTotals := make([]int64, 0, len(history))
	historyLargest := make([]int64, 0, len(history))
	for _, release := range history {
		if len(release.Files) == 0 {
			continue
		}
		historyTotals = append(historyTotals, totalSize(release.Files))
		historyLargest = append(historyLargest, largestSize(release.Files))
	}

	var findings []report.Finding
	if median := medianInt64(historyTotals); median > 0 && latestTotal*100 >= median*int64(jumpPercent) {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("latest PyPI release total file size is %d bytes, at least %d%% of historical median %d bytes", latestTotal, jumpPercent, median),
		})
	}
	if median := medianInt64(historyLargest); median > 0 && latestLargest*100 >= median*int64(jumpPercent) {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("latest PyPI release largest file is %d bytes, at least %d%% of historical median largest file %d bytes", latestLargest, jumpPercent, median),
		})
	}
	return findings
}

func CheckDependencyChange(pkg report.PackageReport, historyVersions int) []report.Finding {
	if !isPyPI(pkg) || historyVersions <= 0 {
		return nil
	}

	if !pkg.PyPILatestRelease.DependenciesKnown {
		return []report.Finding{{Message: "latest PyPI dependency metadata is unavailable or dynamic; dependency changes cannot be confirmed"}}
	}

	var previous report.PyPIReleaseInfo
	foundPrevious := false
	for _, release := range limitedHistory(pkg.PyPIReleaseHistory, historyVersions) {
		if release.DependenciesKnown {
			previous = release
			foundPrevious = true
			break
		}
	}
	if !foundPrevious {
		return []report.Finding{{Message: "previous PyPI dependency metadata is unavailable; dependency changes cannot be confirmed"}}
	}

	latestDeps := stringSet(pkg.PyPILatestRelease.Dependencies)
	previousDeps := stringSet(previous.Dependencies)
	added := sortedDifference(latestDeps, previousDeps)
	removed := sortedDifference(previousDeps, latestDeps)

	var findings []report.Finding
	if len(added) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("latest PyPI release adds declared dependency name(s): %s", strings.Join(added, ", ")),
		})
	}
	if len(removed) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("latest PyPI release removes declared dependency name(s): %s", strings.Join(removed, ", ")),
		})
	}
	return findings
}

func CheckProvenanceRequired(pkg report.PackageReport) []report.Finding {
	if !isPyPI(pkg) {
		return nil
	}

	var findings []report.Finding
	for _, file := range pkg.PyPILatestRelease.Files {
		switch {
		case !file.ProvenanceChecked:
			findings = append(findings, report.Finding{
				Message: fmt.Sprintf("PyPI provenance availability was not checked for release file %q", file.Filename),
			})
		case file.ProvenanceError != "":
			findings = append(findings, report.Finding{
				Message: fmt.Sprintf("PyPI provenance availability is unknown for release file %q: %s", file.Filename, file.ProvenanceError),
			})
		case !file.ProvenanceAvailable:
			findings = append(findings, report.Finding{
				Message: fmt.Sprintf("PyPI release file %q has no provenance available", file.Filename),
			})
		}
	}
	return findings
}

func CheckReleaseFileCountChange(pkg report.PackageReport, historyVersions int) []report.Finding {
	if !isPyPI(pkg) || historyVersions <= 0 || len(pkg.PyPILatestRelease.Files) == 0 {
		return nil
	}

	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	counts := make([]int, 0, len(history))
	for _, release := range history {
		if len(release.Files) > 0 {
			counts = append(counts, len(release.Files))
		}
	}
	median := medianInt(counts)
	if median == 0 || len(pkg.PyPILatestRelease.Files) == median {
		return nil
	}

	return []report.Finding{{
		Message: fmt.Sprintf("latest PyPI release has %d file(s), different from historical median of %d file(s)", len(pkg.PyPILatestRelease.Files), median),
	}}
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

func isPyPI(pkg report.PackageReport) bool {
	return strings.EqualFold(strings.TrimSpace(pkg.Ecosystem), string(ecosystem.PyPI))
}

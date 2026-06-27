package pypiartifacts

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
)

func CheckArtifactShapeChange(pkg report.PackageReport, historyVersions int) []report.Finding {
	if !isPyPI(pkg) || historyVersions <= 0 {
		return nil
	}
	if reason := ArtifactShapeIndeterminateReason(pkg, historyVersions); reason != "" {
		return []report.Finding{{Message: reason}}
	}

	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	if len(history) == 0 {
		return nil
	}

	latest := releaseShape(pkg.PyPISelectedRelease)
	previous := releaseShape(history[0])
	historical := historicalShape(history)

	var findings []report.Finding
	if latest.hasSdist && !latest.hasWheel && historical.hasWheel {
		findings = append(findings, report.Finding{Message: "selected PyPI release is source-only after prior release history included wheels"})
	}
	if !latest.hasWheel && previous.hasWheel {
		findings = append(findings, report.Finding{Message: "selected PyPI release removes wheel artifacts present in the previous release"})
	}
	if latest.hasSdist && !previous.hasSdist {
		findings = append(findings, report.Finding{Message: "selected PyPI release adds a source distribution artifact not present in the previous release"})
	}
	if !latest.hasSdist && previous.hasSdist {
		findings = append(findings, report.Finding{Message: "selected PyPI release removes source distribution artifacts present in the previous release"})
	}

	newWheelPlatforms := sortedDifference(latest.wheelPlatforms, historical.wheelPlatforms)
	if len(newWheelPlatforms) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("selected PyPI release adds new wheel platform tag(s): %s", strings.Join(newWheelPlatforms, ", ")),
		})
	}

	newPackageTypes := sortedDifference(latest.packageTypes, previous.packageTypes)
	removedPackageTypes := sortedDifference(previous.packageTypes, latest.packageTypes)
	if len(newPackageTypes) > 0 || len(removedPackageTypes) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf(
				"selected PyPI release artifact package types changed; added: %s; removed: %s",
				displaySet(newPackageTypes),
				displaySet(removedPackageTypes),
			),
		})
	}

	return findings
}

func ArtifactShapeIndeterminateReason(pkg report.PackageReport, historyVersions int) string {
	if !isPyPI(pkg) || historyVersions <= 0 {
		return ""
	}
	if len(pkg.PyPISelectedRelease.Files) == 0 {
		return "selected PyPI release artifact metadata is unavailable"
	}
	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	if reason := missingHistoryFilesReason(history, "artifact"); reason != "" {
		return reason
	}
	return ""
}

func CheckFileSizeJump(pkg report.PackageReport, historyVersions int, jumpPercent int) []report.Finding {
	if !isPyPI(pkg) || historyVersions <= 0 || jumpPercent <= 0 {
		return nil
	}
	if reason := FileSizeIndeterminateReason(pkg, historyVersions); reason != "" {
		return []report.Finding{{Message: reason}}
	}

	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	if len(history) == 0 {
		return nil
	}

	latestTotal, latestLargest, historicalMedianTotal, historicalMedianLargest, _ := fileSizeStats(pkg, historyVersions)
	var findings []report.Finding
	if increaseAtLeastPercent(latestTotal, historicalMedianTotal, jumpPercent) {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("selected PyPI release total file size is %d bytes, increased by at least %d%% over historical median %d bytes", latestTotal, jumpPercent, historicalMedianTotal),
		})
	}
	if increaseAtLeastPercent(latestLargest, historicalMedianLargest, jumpPercent) {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("selected PyPI release largest file is %d bytes, increased by at least %d%% over historical median largest file %d bytes", latestLargest, jumpPercent, historicalMedianLargest),
		})
	}
	return findings
}

func FileSizeIndeterminateReason(pkg report.PackageReport, historyVersions int) string {
	if !isPyPI(pkg) || historyVersions <= 0 {
		return ""
	}
	if len(pkg.PyPISelectedRelease.Files) == 0 {
		return "selected PyPI release file-size metadata is unavailable"
	}
	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	if len(history) == 0 {
		return ""
	}
	if reason := missingHistoryFilesReason(history, "file-size"); reason != "" {
		return reason
	}
	_, _, _, _, known := fileSizeStats(pkg, historyVersions)
	if !known {
		return "PyPI release file-size metadata is invalid or exceeds supported numeric range"
	}
	return ""
}

func fileSizeStats(pkg report.PackageReport, historyVersions int) (int64, int64, int64, int64, bool) {
	latestTotal, latestKnown := totalSize(pkg.PyPISelectedRelease.Files)
	latestLargest := largestSize(pkg.PyPISelectedRelease.Files)
	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	historyTotals := make([]int64, 0, len(history))
	historyLargest := make([]int64, 0, len(history))
	for _, release := range history {
		if len(release.Files) == 0 {
			return 0, 0, 0, 0, false
		}
		total, known := totalSize(release.Files)
		if !known {
			return 0, 0, 0, 0, false
		}
		historyTotals = append(historyTotals, total)
		historyLargest = append(historyLargest, largestSize(release.Files))
	}
	return latestTotal, latestLargest, medianInt64(historyTotals), medianInt64(historyLargest), latestKnown && len(historyTotals) > 0
}

func CheckDependencyChange(pkg report.PackageReport, historyVersions int, includeOptional bool) []report.Finding {
	if !isPyPI(pkg) || historyVersions <= 0 {
		return nil
	}

	comparison := compareDependencies(pkg, historyVersions, includeOptional)
	if !comparison.latestKnown {
		return []report.Finding{{Message: "selected PyPI dependency metadata is unavailable or dynamic; dependency changes cannot be confirmed"}}
	}
	if !comparison.previousKnown {
		if len(limitedHistory(pkg.PyPIReleaseHistory, historyVersions)) == 0 {
			return nil
		}
		return []report.Finding{{Message: "immediate previous PyPI dependency metadata is unavailable or dynamic; dependency changes cannot be confirmed"}}
	}

	var findings []report.Finding
	if len(comparison.added) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("selected PyPI release adds declared dependency name(s): %s", strings.Join(comparison.added, ", ")),
		})
	}
	if len(comparison.removed) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("selected PyPI release removes declared dependency name(s): %s", strings.Join(comparison.removed, ", ")),
		})
	}
	if len(comparison.requiredToOptional) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("selected PyPI release moves dependency name(s) from required to optional: %s", strings.Join(comparison.requiredToOptional, ", ")),
		})
	}
	if len(comparison.optionalToRequired) > 0 {
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf("selected PyPI release moves dependency name(s) from optional to required: %s", strings.Join(comparison.optionalToRequired, ", ")),
		})
	}
	return findings
}

func DependencyIndeterminateReason(pkg report.PackageReport, historyVersions int) string {
	if !isPyPI(pkg) || historyVersions <= 0 {
		return ""
	}
	if !pkg.PyPISelectedRelease.DependenciesKnown {
		return "selected PyPI dependency metadata is unavailable or dynamic"
	}
	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	if len(history) > 0 && !history[0].DependenciesKnown {
		return "immediate previous PyPI dependency metadata is unavailable or dynamic"
	}
	return ""
}

type dependencyComparison struct {
	latestKnown        bool
	previousKnown      bool
	previousVersion    string
	added              []string
	removed            []string
	requiredAdded      []string
	requiredRemoved    []string
	optionalAdded      []string
	optionalRemoved    []string
	requiredToOptional []string
	optionalToRequired []string
}

func compareDependencies(pkg report.PackageReport, historyVersions int, includeOptional bool) dependencyComparison {
	comparison := dependencyComparison{latestKnown: pkg.PyPISelectedRelease.DependenciesKnown}
	if !comparison.latestKnown {
		return comparison
	}

	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	if len(history) == 0 {
		return comparison
	}
	previous := history[0]
	comparison.previousKnown = previous.DependenciesKnown
	comparison.previousVersion = previous.Version
	if !comparison.previousKnown {
		return comparison
	}

	latestDeps := stringSet(pkg.PyPISelectedRelease.Dependencies)
	previousDeps := stringSet(previous.Dependencies)
	comparison.requiredAdded = sortedDifference(latestDeps, previousDeps)
	comparison.requiredRemoved = sortedDifference(previousDeps, latestDeps)
	comparison.added = append([]string(nil), comparison.requiredAdded...)
	comparison.removed = append([]string(nil), comparison.requiredRemoved...)
	if includeOptional {
		latestOptional := stringSet(pkg.PyPISelectedRelease.OptionalDependencies)
		previousOptional := stringSet(previous.OptionalDependencies)
		comparison.optionalAdded = sortedDifference(latestOptional, previousOptional)
		comparison.optionalRemoved = sortedDifference(previousOptional, latestOptional)
		comparison.requiredToOptional = sortedIntersection(previousDeps, latestOptional)
		comparison.optionalToRequired = sortedIntersection(previousOptional, latestDeps)
		latestAll := unionSets(latestDeps, latestOptional)
		previousAll := unionSets(previousDeps, previousOptional)
		comparison.added = sortedDifference(latestAll, previousAll)
		comparison.removed = sortedDifference(previousAll, latestAll)
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
	for _, file := range pkg.PyPISelectedRelease.Files {
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
		return []report.Finding{{Message: fmt.Sprintf("PyPI provenance scope %q selected no selected-release files", scope)}}
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

func ProvenanceIndeterminateReason(pkg report.PackageReport, scope string) string {
	if !isPyPI(pkg) || scope != "install-target" || pkg.PyPIProvenance.CompatibilityError == "" {
		return ""
	}
	return "PyPI install-target wheel compatibility could not be resolved: " + pkg.PyPIProvenance.CompatibilityError
}

func CheckReleaseFileCountChange(pkg report.PackageReport, historyVersions int) []report.Finding {
	if !isPyPI(pkg) || historyVersions <= 0 {
		return nil
	}
	if reason := ReleaseFileCountIndeterminateReason(pkg, historyVersions); reason != "" {
		return []report.Finding{{Message: reason}}
	}

	latestCount, historicalMedian := releaseFileCountStats(pkg, historyVersions)
	if historicalMedian == 0 || latestCount == historicalMedian {
		return nil
	}

	return []report.Finding{{
		Message: fmt.Sprintf("selected PyPI release has %d file(s), different from historical median of %d file(s)", latestCount, historicalMedian),
	}}
}

func ReleaseFileCountIndeterminateReason(pkg report.PackageReport, historyVersions int) string {
	if !isPyPI(pkg) || historyVersions <= 0 {
		return ""
	}
	if len(pkg.PyPISelectedRelease.Files) == 0 {
		return "selected PyPI release file-count metadata is unavailable"
	}
	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	if reason := missingHistoryFilesReason(history, "file-count"); reason != "" {
		return reason
	}
	return ""
}

func releaseFileCountStats(pkg report.PackageReport, historyVersions int) (int, int) {
	history := limitedHistory(pkg.PyPIReleaseHistory, historyVersions)
	counts := make([]int, 0, len(history))
	for _, release := range history {
		if len(release.Files) == 0 {
			return len(pkg.PyPISelectedRelease.Files), 0
		}
		counts = append(counts, len(release.Files))
	}
	return len(pkg.PyPISelectedRelease.Files), medianInt(counts)
}

func missingHistoryFilesReason(history []report.PyPIReleaseInfo, metadata string) string {
	for index, release := range history {
		if len(release.Files) > 0 {
			continue
		}
		if index == 0 {
			return fmt.Sprintf("immediate previous PyPI release %s metadata is unavailable", metadata)
		}
		if release.Version != "" {
			return fmt.Sprintf("PyPI release %s metadata is unavailable for historical version %s", metadata, release.Version)
		}
		return fmt.Sprintf("PyPI release %s metadata is unavailable within the configured history window", metadata)
	}
	return ""
}

type artifactShape struct {
	hasSdist       bool
	hasWheel       bool
	packageTypes   map[string]struct{}
	wheelPlatforms map[string]struct{}
}

func releaseShape(release report.PyPIReleaseInfo) artifactShape {
	shape := artifactShape{
		packageTypes:   make(map[string]struct{}),
		wheelPlatforms: make(map[string]struct{}),
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
			for _, platform := range wheelPlatforms(file.Filename) {
				shape.wheelPlatforms[platform] = struct{}{}
			}
		}
	}
	return shape
}

func historicalShape(history []report.PyPIReleaseInfo) artifactShape {
	shape := artifactShape{
		packageTypes:   make(map[string]struct{}),
		wheelPlatforms: make(map[string]struct{}),
	}
	for _, release := range history {
		current := releaseShape(release)
		shape.hasSdist = shape.hasSdist || current.hasSdist
		shape.hasWheel = shape.hasWheel || current.hasWheel
		for value := range current.packageTypes {
			shape.packageTypes[value] = struct{}{}
		}
		for value := range current.wheelPlatforms {
			shape.wheelPlatforms[value] = struct{}{}
		}
	}
	return shape
}

func wheelPlatforms(filename string) []string {
	if !strings.HasSuffix(filename, ".whl") {
		return nil
	}
	stem := strings.TrimSuffix(filename, ".whl")
	parts := strings.Split(stem, "-")
	if len(parts) < 5 {
		return nil
	}
	return sortedUniqueStrings(strings.Split(parts[len(parts)-1], "."))
}

func totalSize(files []report.PyPIReleaseFile) (int64, bool) {
	var total int64
	for _, file := range files {
		if file.Size <= 0 || total > math.MaxInt64-file.Size {
			return 0, false
		}
		total += file.Size
	}
	return total, len(files) > 0
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
	return sorted[mid-1] + (sorted[mid]-sorted[mid-1])/2
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
	return sorted[mid-1] + (sorted[mid]-sorted[mid-1])/2
}

func increaseAtLeastPercent(current, baseline int64, percent int) bool {
	if current <= 0 || baseline <= 0 || current < baseline || percent <= 0 {
		return false
	}
	left := new(big.Int).Mul(big.NewInt(current-baseline), big.NewInt(100))
	right := new(big.Int).Mul(big.NewInt(baseline), new(big.Int).SetInt64(int64(percent)))
	return left.Cmp(right) >= 0
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

func sortedIntersection(left map[string]struct{}, right map[string]struct{}) []string {
	var result []string
	for value := range left {
		if _, ok := right[value]; ok {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func unionSets(left map[string]struct{}, right map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(left)+len(right))
	for value := range left {
		result[value] = struct{}{}
	}
	for value := range right {
		result[value] = struct{}{}
	}
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

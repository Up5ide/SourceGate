package artifactdelta

import (
	"sort"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

const (
	StatusCompared    = "COMPARED"
	StatusUnavailable = "UNAVAILABLE"
)

const maxExamples = 12

func Compare(selected report.ArtifactInspectionSummary, previous report.ArtifactInspectionSummary, previousCandidate report.ArtifactCandidate, previousDownload report.ArtifactDownloadSummary) report.ArtifactDeltaSummary {
	delta := report.ArtifactDeltaSummary{
		Status:                          StatusCompared,
		PreviousFilename:                previousCandidate.Filename,
		PreviousPackageType:             previousCandidate.PackageType,
		PreviousFileCount:               previous.FileCount,
		PreviousTotalUncompressedBytes:  previous.TotalUncompressedBytes,
		SelectedTotalUncompressedBytes:  selected.TotalUncompressedBytes,
		PreviousArtifactDownloadStatus:  previousDownload.Status,
		PreviousArtifactDigestVerified:  previousDownload.DigestVerified,
		PreviousArtifactDownloadedSize:  previousDownload.DownloadedSize,
		PreviousArtifactDigestAlgorithm: previousDownload.DigestAlgorithm,
	}

	added, removed := pathDiff(selected.Paths, previous.Paths)
	delta.AddedPathCount = len(added)
	delta.AddedPathExamples = cappedStrings(added)
	delta.RemovedPathCount = len(removed)
	delta.RemovedPathExamples = cappedStrings(removed)

	newSurfaces := newExecutionSurfaces(selected.ExecutionSurfaceExamples, previous.ExecutionSurfaceExamples)
	delta.NewExecutionSurfaceCount = len(newSurfaces)
	delta.NewExecutionSurfaceExamples = cappedExecutionSurfaces(newSurfaces)

	newFileTypes := newSuspiciousFileTypes(selected.SuspiciousFileTypeExamples, previous.SuspiciousFileTypeExamples)
	delta.NewSuspiciousFileTypeCount = len(newFileTypes)
	delta.NewSuspiciousFileTypeExamples = cappedSuspiciousFileTypes(newFileTypes)

	delta.FileCountDelta = selected.FileCount - previous.FileCount
	delta.UncompressedSizeDeltaBytes = selected.TotalUncompressedBytes - previous.TotalUncompressedBytes
	if previous.TotalUncompressedBytes > 0 {
		delta.UncompressedSizeDeltaPercentKnown = true
		delta.UncompressedSizeDeltaPercent = int((delta.UncompressedSizeDeltaBytes * 100) / previous.TotalUncompressedBytes)
	}
	return delta
}

func Unavailable(candidate report.ArtifactCandidate, message string) report.ArtifactDeltaSummary {
	return report.ArtifactDeltaSummary{
		Status:                             StatusUnavailable,
		PreviousFilename:                   candidate.Filename,
		PreviousPackageType:                candidate.PackageType,
		PreviousArtifactSelectionError:     candidate.SelectionError,
		PreviousArtifactUnavailableMessage: message,
	}
}

func pathDiff(selected, previous []string) ([]string, []string) {
	selectedSet := stringSet(selected)
	previousSet := stringSet(previous)
	var added []string
	for _, value := range selected {
		if _, ok := previousSet[value]; !ok {
			added = append(added, value)
		}
	}
	var removed []string
	for _, value := range previous {
		if _, ok := selectedSet[value]; !ok {
			removed = append(removed, value)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func newExecutionSurfaces(selected, previous []report.ArtifactExecutionSurface) []report.ArtifactExecutionSurface {
	previousSet := make(map[string]struct{}, len(previous))
	for _, surface := range previous {
		previousSet[executionSurfaceKey(surface)] = struct{}{}
	}
	var result []report.ArtifactExecutionSurface
	for _, surface := range selected {
		if _, ok := previousSet[executionSurfaceKey(surface)]; !ok {
			result = append(result, surface)
		}
	}
	return result
}

func newSuspiciousFileTypes(selected, previous []report.ArtifactSuspiciousFileType) []report.ArtifactSuspiciousFileType {
	previousSet := make(map[string]struct{}, len(previous))
	for _, fileType := range previous {
		previousSet[suspiciousFileTypeKey(fileType)] = struct{}{}
	}
	var result []report.ArtifactSuspiciousFileType
	for _, fileType := range selected {
		if _, ok := previousSet[suspiciousFileTypeKey(fileType)]; !ok {
			result = append(result, fileType)
		}
	}
	return result
}

func executionSurfaceKey(surface report.ArtifactExecutionSurface) string {
	return strings.Join([]string{surface.Type, surface.Path, surface.Name, surface.Detail}, "\x00")
}

func suspiciousFileTypeKey(fileType report.ArtifactSuspiciousFileType) string {
	return strings.Join([]string{fileType.Type, fileType.Path, fileType.Reason, fileType.Detail}, "\x00")
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func cappedStrings(values []string) []string {
	if len(values) <= maxExamples {
		return append([]string(nil), values...)
	}
	return append([]string(nil), values[:maxExamples]...)
}

func cappedExecutionSurfaces(values []report.ArtifactExecutionSurface) []report.ArtifactExecutionSurface {
	if len(values) <= maxExamples {
		return append([]report.ArtifactExecutionSurface(nil), values...)
	}
	return append([]report.ArtifactExecutionSurface(nil), values[:maxExamples]...)
}

func cappedSuspiciousFileTypes(values []report.ArtifactSuspiciousFileType) []report.ArtifactSuspiciousFileType {
	if len(values) <= maxExamples {
		return append([]report.ArtifactSuspiciousFileType(nil), values...)
	}
	return append([]report.ArtifactSuspiciousFileType(nil), values[:maxExamples]...)
}

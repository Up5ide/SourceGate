package artifactdelta

import (
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

func CheckFileListChange(pkg report.PackageReport) []report.Finding {
	if pkg.ArtifactDelta == nil {
		return nil
	}
	if pkg.ArtifactDelta.AddedPathCount == 0 && pkg.ArtifactDelta.RemovedPathCount == 0 {
		return nil
	}
	message := fmt.Sprintf("artifact file list changed: %d added, %d removed", pkg.ArtifactDelta.AddedPathCount, pkg.ArtifactDelta.RemovedPathCount)
	if len(pkg.ArtifactDelta.AddedPathExamples) > 0 {
		message += "; added examples: " + strings.Join(pkg.ArtifactDelta.AddedPathExamples, ", ")
	}
	if len(pkg.ArtifactDelta.RemovedPathExamples) > 0 {
		message += "; removed examples: " + strings.Join(pkg.ArtifactDelta.RemovedPathExamples, ", ")
	}
	return []report.Finding{{Message: message}}
}

func CheckNewExecutionSurfaces(pkg report.PackageReport) []report.Finding {
	if pkg.ArtifactDelta == nil || pkg.ArtifactDelta.NewExecutionSurfaceCount == 0 {
		return nil
	}
	message := fmt.Sprintf("artifact added %d install/build execution surface(s)", pkg.ArtifactDelta.NewExecutionSurfaceCount)
	if len(pkg.ArtifactDelta.NewExecutionSurfaceExamples) > 0 {
		message += ": " + strings.Join(surfaceExamples(pkg.ArtifactDelta.NewExecutionSurfaceExamples), "; ")
	}
	return []report.Finding{{Message: message}}
}

func CheckNewSuspiciousFileTypes(pkg report.PackageReport) []report.Finding {
	if pkg.ArtifactDelta == nil || pkg.ArtifactDelta.NewSuspiciousFileTypeCount == 0 {
		return nil
	}
	message := fmt.Sprintf("artifact added %d suspicious native/executable file type(s)", pkg.ArtifactDelta.NewSuspiciousFileTypeCount)
	if len(pkg.ArtifactDelta.NewSuspiciousFileTypeExamples) > 0 {
		message += ": " + strings.Join(fileTypeExamples(pkg.ArtifactDelta.NewSuspiciousFileTypeExamples), "; ")
	}
	return []report.Finding{{Message: message}}
}

func CheckSizeDelta(pkg report.PackageReport) []report.Finding {
	if pkg.ArtifactDelta == nil {
		return nil
	}
	if pkg.ArtifactDelta.FileCountDelta == 0 && pkg.ArtifactDelta.UncompressedSizeDeltaBytes == 0 {
		return nil
	}
	message := fmt.Sprintf(
		"artifact size metadata changed: file count delta %+d, uncompressed size delta %+d bytes",
		pkg.ArtifactDelta.FileCountDelta,
		pkg.ArtifactDelta.UncompressedSizeDeltaBytes,
	)
	if pkg.ArtifactDelta.UncompressedSizeDeltaPercentKnown {
		message += fmt.Sprintf(" (%+d%%)", pkg.ArtifactDelta.UncompressedSizeDeltaPercent)
	}
	return []report.Finding{{Message: message}}
}

func Evidence(pkg report.PackageReport) []string {
	if pkg.ArtifactDelta == nil {
		return []string{"artifact delta unavailable"}
	}
	evidence := []string{
		"artifact delta status: " + valueOrUnavailable(pkg.ArtifactDelta.Status),
		"previous artifact filename: " + valueOrUnavailable(pkg.ArtifactDelta.PreviousFilename),
		fmt.Sprintf("added paths: %d", pkg.ArtifactDelta.AddedPathCount),
		fmt.Sprintf("removed paths: %d", pkg.ArtifactDelta.RemovedPathCount),
		fmt.Sprintf("new execution surfaces: %d", pkg.ArtifactDelta.NewExecutionSurfaceCount),
		fmt.Sprintf("new suspicious file types: %d", pkg.ArtifactDelta.NewSuspiciousFileTypeCount),
		fmt.Sprintf("file count delta: %+d", pkg.ArtifactDelta.FileCountDelta),
		fmt.Sprintf("uncompressed size delta bytes: %+d", pkg.ArtifactDelta.UncompressedSizeDeltaBytes),
	}
	if pkg.ArtifactDelta.PreviousArtifactUnavailableMessage != "" {
		evidence = append(evidence, "previous artifact unavailable: "+pkg.ArtifactDelta.PreviousArtifactUnavailableMessage)
	}
	if pkg.ArtifactDelta.PreviousArtifactInspectionError != "" {
		evidence = append(evidence, "previous artifact inspection error: "+pkg.ArtifactDelta.PreviousArtifactInspectionError)
	}
	return evidence
}

func DeltaIndeterminateReason(pkg report.PackageReport) string {
	if pkg.ArtifactDelta == nil {
		return "artifact delta comparison did not run"
	}
	if pkg.ArtifactDelta.Status == "COMPARED" {
		return ""
	}
	if pkg.ArtifactDelta.PreviousArtifactUnavailableMessage != "" {
		return pkg.ArtifactDelta.PreviousArtifactUnavailableMessage
	}
	if pkg.ArtifactDelta.PreviousArtifactInspectionError != "" {
		return pkg.ArtifactDelta.PreviousArtifactInspectionError
	}
	if pkg.ArtifactDelta.PreviousArtifactSelectionError != "" {
		return pkg.ArtifactDelta.PreviousArtifactSelectionError
	}
	return "artifact delta comparison is unavailable"
}

func surfaceExamples(surfaces []report.ArtifactExecutionSurface) []string {
	result := make([]string, 0, len(surfaces))
	for _, surface := range surfaces {
		parts := []string{surface.Type, surface.Path}
		if strings.TrimSpace(surface.Name) != "" {
			parts = append(parts, surface.Name)
		}
		if strings.TrimSpace(surface.Detail) != "" {
			parts = append(parts, surface.Detail)
		}
		result = append(result, strings.Join(parts, " "))
	}
	return result
}

func fileTypeExamples(fileTypes []report.ArtifactSuspiciousFileType) []string {
	result := make([]string, 0, len(fileTypes))
	for _, fileType := range fileTypes {
		parts := []string{fileType.Type, fileType.Path, fileType.Reason}
		if strings.TrimSpace(fileType.Detail) != "" {
			parts = append(parts, fileType.Detail)
		}
		result = append(result, strings.Join(parts, " "))
	}
	return result
}

func valueOrUnavailable(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unavailable"
	}
	return value
}

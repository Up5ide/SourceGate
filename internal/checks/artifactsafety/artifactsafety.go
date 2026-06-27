package artifactsafety

import (
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

func CheckUnsafePaths(pkg report.PackageReport) []report.Finding {
	if pkg.ArtifactInspection == nil || pkg.ArtifactInspection.UnsafePathCount == 0 {
		return nil
	}
	message := fmt.Sprintf("artifact archive contains %d unsafe path(s)", pkg.ArtifactInspection.UnsafePathCount)
	if len(pkg.ArtifactInspection.UnsafePathExamples) > 0 {
		message += ": " + strings.Join(pkg.ArtifactInspection.UnsafePathExamples, "; ")
	}
	return []report.Finding{{Message: message}}
}

func CheckFileCount(pkg report.PackageReport, maxFiles int) []report.Finding {
	if pkg.ArtifactInspection == nil || maxFiles <= 0 || pkg.ArtifactInspection.FileCount <= maxFiles {
		return nil
	}
	return []report.Finding{{Message: fmt.Sprintf("artifact archive file count %d exceeds configured limit %d", pkg.ArtifactInspection.FileCount, maxFiles)}}
}

func CheckUncompressedSize(pkg report.PackageReport, maxSizeMB int) []report.Finding {
	if pkg.ArtifactInspection == nil || maxSizeMB <= 0 {
		return nil
	}
	maxBytes := int64(maxSizeMB) * 1024 * 1024
	if pkg.ArtifactInspection.TotalUncompressedBytes <= maxBytes {
		return nil
	}
	return []report.Finding{{Message: fmt.Sprintf("artifact archive uncompressed size %d bytes exceeds configured limit %d MiB", pkg.ArtifactInspection.TotalUncompressedBytes, maxSizeMB)}}
}

func CheckExpansionRatio(pkg report.PackageReport, maxRatio int) []report.Finding {
	if pkg.ArtifactInspection == nil || maxRatio <= 0 || !pkg.ArtifactInspection.ExpansionRatioApplicable {
		return nil
	}
	if pkg.ArtifactInspection.ExpansionRatio <= float64(maxRatio) {
		return nil
	}
	return []report.Finding{{Message: fmt.Sprintf("artifact archive expansion ratio %.2f exceeds configured limit %d", pkg.ArtifactInspection.ExpansionRatio, maxRatio)}}
}

func Evidence(pkg report.PackageReport) []string {
	if pkg.ArtifactInspection == nil {
		return []string{"artifact inspection unavailable"}
	}
	summary := pkg.ArtifactInspection
	evidence := []string{
		"archive format: " + valueOrUnavailable(summary.ArchiveFormat),
		fmt.Sprintf("files: %d", summary.FileCount),
		fmt.Sprintf("directories: %d", summary.DirectoryCount),
		fmt.Sprintf("symlinks: %d", summary.SymlinkCount),
		fmt.Sprintf("hardlinks: %d", summary.HardlinkCount),
		fmt.Sprintf("total uncompressed bytes: %d", summary.TotalUncompressedBytes),
		fmt.Sprintf("compressed bytes: %d", summary.CompressedBytes),
		fmt.Sprintf("max path depth: %d", summary.MaxPathDepth),
		fmt.Sprintf("duplicate paths: %d", summary.DuplicatePathCount),
		fmt.Sprintf("nested archives: %d", summary.NestedArchiveCount),
		fmt.Sprintf("unsafe paths: %d", summary.UnsafePathCount),
	}
	if summary.ExpansionRatioApplicable {
		evidence = append(evidence, fmt.Sprintf("expansion ratio: %.2f", summary.ExpansionRatio))
	} else {
		evidence = append(evidence, "expansion ratio: not evaluated")
	}
	for _, example := range summary.UnsafePathExamples {
		evidence = append(evidence, "unsafe path: "+example)
	}
	return evidence
}

func valueOrUnavailable(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unavailable"
	}
	return value
}

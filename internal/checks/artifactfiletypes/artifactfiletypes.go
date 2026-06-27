package artifactfiletypes

import (
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

func CheckSuspiciousFileTypes(pkg report.PackageReport) []report.Finding {
	if pkg.ArtifactInspection == nil || pkg.ArtifactInspection.SuspiciousFileTypeCount == 0 {
		return nil
	}
	message := fmt.Sprintf("artifact archive contains %d suspicious native/executable file type(s)", pkg.ArtifactInspection.SuspiciousFileTypeCount)
	if len(pkg.ArtifactInspection.SuspiciousFileTypeExamples) > 0 {
		message += ": " + strings.Join(fileTypeExamples(pkg.ArtifactInspection.SuspiciousFileTypeExamples), "; ")
	}
	return []report.Finding{{Message: message}}
}

func Evidence(pkg report.PackageReport) []string {
	if pkg.ArtifactInspection == nil {
		return []string{"artifact inspection unavailable"}
	}
	evidence := []string{fmt.Sprintf("suspicious file types: %d", pkg.ArtifactInspection.SuspiciousFileTypeCount)}
	for _, fileType := range pkg.ArtifactInspection.SuspiciousFileTypeExamples {
		evidence = append(evidence, "suspicious file type: "+fileTypeExample(fileType))
	}
	return evidence
}

func fileTypeExamples(fileTypes []report.ArtifactSuspiciousFileType) []string {
	result := make([]string, 0, len(fileTypes))
	for _, fileType := range fileTypes {
		result = append(result, fileTypeExample(fileType))
	}
	return result
}

func fileTypeExample(fileType report.ArtifactSuspiciousFileType) string {
	parts := []string{fileType.Type, fileType.Path, fileType.Reason}
	if strings.TrimSpace(fileType.Detail) != "" {
		parts = append(parts, fileType.Detail)
	}
	return strings.Join(parts, " ")
}

package artifactexecution

import (
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

func CheckExecutionSurfaces(pkg report.PackageReport) []report.Finding {
	if pkg.ArtifactInspection == nil || pkg.ArtifactInspection.ExecutionSurfaceCount == 0 {
		return nil
	}
	message := fmt.Sprintf("artifact archive exposes %d install/build execution surface(s)", pkg.ArtifactInspection.ExecutionSurfaceCount)
	if len(pkg.ArtifactInspection.ExecutionSurfaceExamples) > 0 {
		message += ": " + strings.Join(surfaceExamples(pkg.ArtifactInspection.ExecutionSurfaceExamples), "; ")
	}
	return []report.Finding{{Message: message}}
}

func Evidence(pkg report.PackageReport) []string {
	if pkg.ArtifactInspection == nil {
		return []string{"artifact inspection unavailable"}
	}
	evidence := []string{fmt.Sprintf("execution surfaces: %d", pkg.ArtifactInspection.ExecutionSurfaceCount)}
	for _, surface := range pkg.ArtifactInspection.ExecutionSurfaceExamples {
		evidence = append(evidence, "execution surface: "+surfaceExample(surface))
	}
	return evidence
}

func surfaceExamples(surfaces []report.ArtifactExecutionSurface) []string {
	result := make([]string, 0, len(surfaces))
	for _, surface := range surfaces {
		result = append(result, surfaceExample(surface))
	}
	return result
}

func surfaceExample(surface report.ArtifactExecutionSurface) string {
	parts := []string{surface.Type, surface.Path}
	if strings.TrimSpace(surface.Name) != "" {
		parts = append(parts, surface.Name)
	}
	if strings.TrimSpace(surface.Detail) != "" {
		parts = append(parts, surface.Detail)
	}
	return strings.Join(parts, " ")
}

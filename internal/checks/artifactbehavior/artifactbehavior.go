package artifactbehavior

import (
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

func CheckBehaviorIndicators(pkg report.PackageReport) []report.Finding {
	if pkg.ArtifactInspection == nil || pkg.ArtifactInspection.BehaviorIndicatorCount == 0 {
		return nil
	}
	message := fmt.Sprintf("artifact archive contains %d suspicious behavior indicator(s)", pkg.ArtifactInspection.BehaviorIndicatorCount)
	if len(pkg.ArtifactInspection.BehaviorIndicatorExamples) > 0 {
		message += ": " + strings.Join(indicatorExamples(pkg.ArtifactInspection.BehaviorIndicatorExamples), "; ")
	}
	return []report.Finding{{Message: message}}
}

func Evidence(pkg report.PackageReport) []string {
	if pkg.ArtifactInspection == nil {
		return []string{"artifact inspection unavailable"}
	}
	evidence := []string{fmt.Sprintf("behavior indicators: %d", pkg.ArtifactInspection.BehaviorIndicatorCount)}
	for _, indicator := range pkg.ArtifactInspection.BehaviorIndicatorExamples {
		evidence = append(evidence, "behavior indicator: "+indicatorExample(indicator))
	}
	return evidence
}

func indicatorExamples(indicators []report.ArtifactBehaviorIndicator) []string {
	result := make([]string, 0, len(indicators))
	for _, indicator := range indicators {
		result = append(result, indicatorExample(indicator))
	}
	return result
}

func indicatorExample(indicator report.ArtifactBehaviorIndicator) string {
	parts := []string{indicator.Type, indicator.Path, indicator.Reason}
	if strings.TrimSpace(indicator.Detail) != "" {
		parts = append(parts, indicator.Detail)
	}
	return strings.Join(parts, " ")
}

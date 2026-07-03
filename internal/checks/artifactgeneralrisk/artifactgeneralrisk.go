package artifactgeneralrisk

import (
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

func CheckGeneralRiskSignals(pkg report.PackageReport) []report.Finding {
	if pkg.ArtifactInspection == nil || pkg.ArtifactInspection.GeneralRiskSignalCount == 0 {
		return nil
	}
	message := fmt.Sprintf("artifact archive contains %d general metadata/path risk signal(s)", pkg.ArtifactInspection.GeneralRiskSignalCount)
	if len(pkg.ArtifactInspection.GeneralRiskSignalExamples) > 0 {
		message += ": " + strings.Join(signalExamples(pkg.ArtifactInspection.GeneralRiskSignalExamples), "; ")
	}
	return []report.Finding{{Message: message}}
}

func Evidence(pkg report.PackageReport) []string {
	if pkg.ArtifactInspection == nil {
		return []string{"artifact inspection unavailable"}
	}
	evidence := []string{fmt.Sprintf("general risk signals: %d", pkg.ArtifactInspection.GeneralRiskSignalCount)}
	for _, signal := range pkg.ArtifactInspection.GeneralRiskSignalExamples {
		evidence = append(evidence, "general risk signal: "+signalExample(signal))
	}
	return evidence
}

func signalExamples(signals []report.ArtifactGeneralRiskSignal) []string {
	result := make([]string, 0, len(signals))
	for _, signal := range signals {
		result = append(result, signalExample(signal))
	}
	return result
}

func signalExample(signal report.ArtifactGeneralRiskSignal) string {
	parts := []string{signal.Type}
	if strings.TrimSpace(signal.Path) != "" {
		parts = append(parts, signal.Path)
	}
	parts = append(parts, signal.Reason)
	if strings.TrimSpace(signal.Detail) != "" {
		parts = append(parts, signal.Detail)
	}
	return strings.Join(parts, " ")
}

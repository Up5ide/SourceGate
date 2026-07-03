package artifactgeneralrisk

import (
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCheckGeneralRiskSignals(t *testing.T) {
	findings := CheckGeneralRiskSignals(report.PackageReport{
		ArtifactInspection: &report.ArtifactInspectionSummary{
			GeneralRiskSignalCount: 1,
			GeneralRiskSignalExamples: []report.ArtifactGeneralRiskSignal{{
				Type:   "sensitive_config_file",
				Path:   "package/.npmrc",
				Reason: "sensitive configuration filename",
			}},
		},
	})

	if len(findings) != 1 || !strings.Contains(findings[0].Message, ".npmrc") {
		t.Fatalf("findings = %+v, want general risk signal finding", findings)
	}
}

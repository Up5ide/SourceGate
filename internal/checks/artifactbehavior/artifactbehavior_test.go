package artifactbehavior

import (
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCheckBehaviorIndicators(t *testing.T) {
	empty := report.PackageReport{ArtifactInspection: &report.ArtifactInspectionSummary{}}
	if findings := CheckBehaviorIndicators(empty); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}

	pkg := report.PackageReport{
		ArtifactInspection: &report.ArtifactInspectionSummary{
			BehaviorIndicatorCount: 1,
			BehaviorIndicatorExamples: []report.ArtifactBehaviorIndicator{
				{Type: "download_execute", Path: "package/install.sh", Reason: "pattern", Detail: "curl or wget piped to shell"},
			},
		},
	}

	findings := CheckBehaviorIndicators(pkg)
	if len(findings) != 1 || !strings.Contains(findings[0].Message, "install.sh") {
		t.Fatalf("findings = %+v, want behavior indicator finding with example", findings)
	}
	if evidence := strings.Join(Evidence(pkg), "\n"); !strings.Contains(evidence, "download_execute") {
		t.Fatalf("evidence = %q, want indicator detail", evidence)
	}
}

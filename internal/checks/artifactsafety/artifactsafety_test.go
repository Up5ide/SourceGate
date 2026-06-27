package artifactsafety

import (
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestArtifactSafetyChecks(t *testing.T) {
	pkg := report.PackageReport{
		ArtifactInspection: &report.ArtifactInspectionSummary{
			FileCount:                11,
			TotalUncompressedBytes:   3 * 1024 * 1024,
			ExpansionRatio:           101,
			ExpansionRatioApplicable: true,
			UnsafePathCount:          1,
			UnsafePathExamples:       []string{"path traversal: ../evil.js"},
		},
	}

	if findings := CheckUnsafePaths(pkg); len(findings) != 1 {
		t.Fatalf("unsafe path findings = %+v, want one", findings)
	}
	if findings := CheckFileCount(pkg, 10); len(findings) != 1 {
		t.Fatalf("file count findings = %+v, want one", findings)
	}
	if findings := CheckUncompressedSize(pkg, 2); len(findings) != 1 {
		t.Fatalf("size findings = %+v, want one", findings)
	}
	if findings := CheckExpansionRatio(pkg, 100); len(findings) != 1 {
		t.Fatalf("ratio findings = %+v, want one", findings)
	}
}

func TestExpansionRatioCheckSkipsInapplicableSmallArchives(t *testing.T) {
	pkg := report.PackageReport{
		ArtifactInspection: &report.ArtifactInspectionSummary{
			ExpansionRatio:           1000,
			ExpansionRatioApplicable: false,
		},
	}

	if findings := CheckExpansionRatio(pkg, 100); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

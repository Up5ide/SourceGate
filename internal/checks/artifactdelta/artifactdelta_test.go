package artifactdelta

import (
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestArtifactDeltaChecks(t *testing.T) {
	pkg := report.PackageReport{
		ArtifactDelta: &report.ArtifactDeltaSummary{
			Status:                            "COMPARED",
			AddedPathCount:                    1,
			AddedPathExamples:                 []string{"package/new.js"},
			RemovedPathCount:                  1,
			RemovedPathExamples:               []string{"package/old.js"},
			NewExecutionSurfaceCount:          1,
			NewExecutionSurfaceExamples:       []report.ArtifactExecutionSurface{{Type: "script_file", Path: "package/install.sh"}},
			NewSuspiciousFileTypeCount:        1,
			NewSuspiciousFileTypeExamples:     []report.ArtifactSuspiciousFileType{{Type: "windows_executable", Path: "package/tool.exe", Reason: "extension"}},
			FileCountDelta:                    1,
			UncompressedSizeDeltaBytes:        1024,
			UncompressedSizeDeltaPercent:      50,
			UncompressedSizeDeltaPercentKnown: true,
		},
	}

	checks := [][]report.Finding{
		CheckFileListChange(pkg),
		CheckNewExecutionSurfaces(pkg),
		CheckNewSuspiciousFileTypes(pkg),
		CheckSizeDelta(pkg),
	}
	for _, findings := range checks {
		if len(findings) != 1 {
			t.Fatalf("findings = %+v, want one artifact delta finding", findings)
		}
	}
}

func TestDeltaIndeterminateReason(t *testing.T) {
	reason := DeltaIndeterminateReason(report.PackageReport{
		ArtifactDelta: &report.ArtifactDeltaSummary{
			Status:                             "UNAVAILABLE",
			PreviousArtifactUnavailableMessage: "immediate previous comparable artifact is unavailable",
		},
	})
	if !strings.Contains(reason, "unavailable") {
		t.Fatalf("reason = %q, want unavailable previous artifact reason", reason)
	}
}

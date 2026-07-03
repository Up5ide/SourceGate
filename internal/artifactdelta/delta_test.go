package artifactdelta

import (
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCompareSummarizesPathSurfaceTypeAndSizeDeltas(t *testing.T) {
	delta := Compare(
		report.ArtifactInspectionSummary{
			FileCount:              2,
			TotalUncompressedBytes: 300,
			Paths:                  []string{"package/index.js", "package/install.sh"},
			ExecutionSurfaceExamples: []report.ArtifactExecutionSurface{
				{Type: "script_file", Path: "package/install.sh"},
			},
			SuspiciousFileTypeExamples: []report.ArtifactSuspiciousFileType{
				{Type: "windows_executable", Path: "package/tool.exe", Reason: "extension"},
			},
		},
		report.ArtifactInspectionSummary{
			FileCount:              1,
			TotalUncompressedBytes: 100,
			Paths:                  []string{"package/index.js", "package/old.js"},
		},
		report.ArtifactCandidate{Filename: "pkg-0.9.0.tgz", PackageType: "npm-tarball"},
		report.ArtifactDownloadSummary{Status: report.ArtifactDownloadStatusVerified, DigestVerified: true},
	)

	if delta.Status != StatusCompared || delta.AddedPathCount != 1 || delta.RemovedPathCount != 1 || delta.NewExecutionSurfaceCount != 1 || delta.NewSuspiciousFileTypeCount != 1 {
		t.Fatalf("delta = %+v, want path, surface, and file type changes", delta)
	}
	if delta.FileCountDelta != 1 || delta.UncompressedSizeDeltaBytes != 200 || !delta.UncompressedSizeDeltaPercentKnown || delta.UncompressedSizeDeltaPercent != 200 {
		t.Fatalf("size delta = %+v, want file and uncompressed size delta", delta)
	}
}

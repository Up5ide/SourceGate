package sourcemetadata

import (
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestSourceMetadataChecks(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem:           "npm",
		SelectedPublishedAt: "2026-06-01T00:00:00Z",
		PreviousPublishedAt: "2025-01-01T00:00:00Z",
		NPMSource: report.NPMSourceMetadata{
			RepositoryURL:         "https://example.com/new.git",
			PreviousRepositoryURL: "https://example.com/old.git",
			SelectedGitHead:       "newhead",
			PreviousGitHead:       "oldhead",
			SelectedPublisher:     "new publisher",
			PreviousPublisher:     "old publisher",
		},
		LifecycleHistory: []report.VersionLifecycleScripts{
			{Version: "0.9.0", PublishedAt: "2026-05-31T23:30:00Z"},
			{Version: "0.8.0", PublishedAt: "2026-05-31T23:00:00Z"},
		},
	}

	cases := map[string][]report.Finding{
		"git head dormancy": CheckGitHeadChangedAfterDormancy(pkg, 180),
		"repository change": CheckRepositoryChanged(pkg),
		"publisher change":  CheckPublisherChanged(pkg),
		"release burst":     CheckReleaseBurst(pkg, 3, 2),
	}
	for name, findings := range cases {
		t.Run(name, func(t *testing.T) {
			if len(findings) != 1 {
				t.Fatalf("findings = %+v, want one source metadata finding", findings)
			}
		})
	}
}

func TestSourceMetadataMissingChecks(t *testing.T) {
	pkg := report.PackageReport{Ecosystem: "npm"}
	if findings := CheckGitHeadMissing(pkg); len(findings) != 1 || !strings.Contains(findings[0].Message, "gitHead") {
		t.Fatalf("gitHead findings = %+v, want missing gitHead", findings)
	}
	if findings := CheckRepositoryMissing(pkg); len(findings) != 1 || !strings.Contains(findings[0].Message, "repository") {
		t.Fatalf("repository findings = %+v, want missing repository", findings)
	}
}

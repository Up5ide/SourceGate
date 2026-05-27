package releaseage

import (
	"testing"
	"time"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCheckBlocksFreshLatestRelease(t *testing.T) {
	findings := Check(report.PackageReport{
		LatestPublishedAt: "2026-05-26T12:00:00Z",
	}, 3, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if len(findings) != 1 || findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestCheckAllowsOlderLatestRelease(t *testing.T) {
	findings := Check(report.PackageReport{
		LatestPublishedAt: "2026-05-20T12:00:00Z",
	}, 3, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if len(findings) != 1 || findings[0].Severity != "INFO" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

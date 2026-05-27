package dormant

import (
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCheckBlocksDormantRelease(t *testing.T) {
	findings := Check(report.PackageReport{
		LatestPublishedAt:   "2026-05-27T12:00:00Z",
		PreviousPublishedAt: "2025-05-27T12:00:00Z",
	}, 180)

	if len(findings) != 1 || findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestCheckAllowsNonDormantRelease(t *testing.T) {
	findings := Check(report.PackageReport{
		LatestPublishedAt:   "2026-05-27T12:00:00Z",
		PreviousPublishedAt: "2026-04-27T12:00:00Z",
	}, 180)

	if len(findings) != 1 || findings[0].Severity != "INFO" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestCheckSkipsDormantCheckForFirstRelease(t *testing.T) {
	findings := Check(report.PackageReport{
		LatestPublishedAt: "2026-05-27T12:00:00Z",
	}, 180)

	if len(findings) != 1 || findings[0].Severity != "INFO" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

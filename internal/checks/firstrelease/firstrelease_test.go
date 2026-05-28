package firstrelease

import (
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCheckAlertsOnFirstRelease(t *testing.T) {
	findings := Check(report.PackageReport{VersionCount: 1})

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", findings)
	}
	if findings[0].Severity != "" {
		t.Fatalf("severity = %q, want empty severity", findings[0].Severity)
	}
}

func TestCheckIgnoresPackagesWithMultipleVersions(t *testing.T) {
	findings := Check(report.PackageReport{VersionCount: 2})

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

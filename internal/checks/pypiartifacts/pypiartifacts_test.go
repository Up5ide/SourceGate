package pypiartifacts

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCheckArtifactShapeChangeReportsSourceOnlyShift(t *testing.T) {
	findings := CheckArtifactShapeChange(report.PackageReport{
		Ecosystem: "PyPI",
		PyPILatestRelease: report.PyPIReleaseInfo{
			Files: []report.PyPIReleaseFile{{Filename: "pkg-2.0.0.tar.gz", PackageType: "sdist"}},
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{{
			Version: "1.0.0",
			Files:   []report.PyPIReleaseFile{{Filename: "pkg-1.0.0-py3-none-any.whl", PackageType: "bdist_wheel"}},
		}},
	}, 5)

	if !hasMessageContaining(findings, "source-only") {
		t.Fatalf("findings = %+v, want source-only finding", findings)
	}
	if !hasMessageContaining(findings, "removes wheel") {
		t.Fatalf("findings = %+v, want wheel removal finding", findings)
	}
}

func TestCheckArtifactShapeChangeReportsNewWheelPlatformTag(t *testing.T) {
	findings := CheckArtifactShapeChange(report.PackageReport{
		Ecosystem: "PyPI",
		PyPILatestRelease: report.PyPIReleaseInfo{
			Files: []report.PyPIReleaseFile{{Filename: "pkg-2.0.0-cp311-cp311-win_amd64.whl", PackageType: "bdist_wheel"}},
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{{
			Version: "1.0.0",
			Files:   []report.PyPIReleaseFile{{Filename: "pkg-1.0.0-py3-none-any.whl", PackageType: "bdist_wheel"}},
		}},
	}, 5)

	if !hasMessageContaining(findings, "new wheel platform tag") {
		t.Fatalf("findings = %+v, want new wheel platform finding", findings)
	}
}

func TestCheckFileSizeJumpReportsTotalAndLargestFileIncrease(t *testing.T) {
	findings := CheckFileSizeJump(report.PackageReport{
		Ecosystem: "PyPI",
		PyPILatestRelease: report.PyPIReleaseInfo{
			Files: []report.PyPIReleaseFile{
				{Filename: "pkg-2.0.0-py3-none-any.whl", Size: 5000},
				{Filename: "pkg-2.0.0.tar.gz", Size: 3000},
			},
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{{
			Version: "1.0.0",
			Files: []report.PyPIReleaseFile{
				{Filename: "pkg-1.0.0-py3-none-any.whl", Size: 1000},
				{Filename: "pkg-1.0.0.tar.gz", Size: 1000},
			},
		}},
	}, 5, 300)

	if !hasMessageContaining(findings, "total file size") {
		t.Fatalf("findings = %+v, want total file size finding", findings)
	}
	if !hasMessageContaining(findings, "largest file") {
		t.Fatalf("findings = %+v, want largest file finding", findings)
	}
}

func TestCheckFileSizeJumpUsesIncreaseOverBaseline(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "PyPI",
		PyPILatestRelease: report.PyPIReleaseInfo{
			Files: []report.PyPIReleaseFile{{Filename: "pkg-2.0.0.tar.gz", Size: 3999}},
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{{
			Version: "1.0.0",
			Files:   []report.PyPIReleaseFile{{Filename: "pkg-1.0.0.tar.gz", Size: 1000}},
		}},
	}

	if findings := CheckFileSizeJump(pkg, 5, 300); len(findings) != 0 {
		t.Fatalf("findings = %+v, want no match below 400%% of baseline", findings)
	}
	pkg.PyPILatestRelease.Files[0].Size = 4000
	if findings := CheckFileSizeJump(pkg, 5, 300); len(findings) == 0 {
		t.Fatalf("findings = %+v, want match at 300%% increase", findings)
	}
}

func TestCheckDependencyChangeReportsAddedAndRemovedDependencies(t *testing.T) {
	findings := CheckDependencyChange(report.PackageReport{
		Ecosystem: "PyPI",
		PyPILatestRelease: report.PyPIReleaseInfo{
			DependenciesKnown: true,
			Dependencies:      []string{"requests", "urllib3"},
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{{
			Version:           "1.0.0",
			DependenciesKnown: true,
			Dependencies:      []string{"certifi", "requests"},
		}},
	}, 5, false)

	if !hasMessageContaining(findings, "adds declared dependency name(s): urllib3") {
		t.Fatalf("findings = %+v, want added dependency finding", findings)
	}
	if !hasMessageContaining(findings, "removes declared dependency name(s): certifi") {
		t.Fatalf("findings = %+v, want removed dependency finding", findings)
	}
}

func TestCheckDependencyChangeReportsUnknownLatestDependencies(t *testing.T) {
	findings := CheckDependencyChange(report.PackageReport{
		Ecosystem: "PyPI",
		PyPILatestRelease: report.PyPIReleaseInfo{
			DependenciesKnown: false,
		},
	}, 5, false)

	if !hasMessageContaining(findings, "unavailable or dynamic") {
		t.Fatalf("findings = %+v, want unknown dependency finding", findings)
	}
}

func TestCheckDependencyChangeIncludesOptionalDependenciesOnlyWhenEnabled(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "PyPI",
		PyPILatestRelease: report.PyPIReleaseInfo{
			DependenciesKnown:    true,
			OptionalDependencies: []string{"socks"},
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{{
			Version:           "1.0.0",
			DependenciesKnown: true,
		}},
	}

	if findings := CheckDependencyChange(pkg, 5, false); len(findings) != 0 {
		t.Fatalf("findings = %+v, want optional changes ignored", findings)
	}
	if findings := CheckDependencyChange(pkg, 5, true); !hasMessageContaining(findings, "socks") {
		t.Fatalf("findings = %+v, want optional dependency change", findings)
	}
}

func TestProvenanceEvidenceBoundsMissingFiles(t *testing.T) {
	var files []report.PyPIReleaseFile
	for i := range 7 {
		files = append(files, report.PyPIReleaseFile{
			Filename:          fmt.Sprintf("pkg-%d.whl", i),
			ProvenanceChecked: true,
			ProvenanceScopes:  []string{"install-target"},
		})
	}
	evidence := ProvenanceEvidence(report.PackageReport{
		PyPILatestRelease: report.PyPIReleaseInfo{Files: files},
		PyPIProvenance:    report.PyPIProvenanceSummary{RequestedScopes: []string{"install-target"}},
	})

	if !strings.Contains(strings.Join(evidence, "\n"), "and 2 more") {
		t.Fatalf("evidence = %v, want bounded filename list", evidence)
	}
}

func TestCheckProvenanceRequiredReportsMissingAndUnknownProvenance(t *testing.T) {
	findings := CheckProvenanceRequired(report.PackageReport{
		Ecosystem: "PyPI",
		PyPILatestRelease: report.PyPIReleaseInfo{
			Files: []report.PyPIReleaseFile{
				{Filename: "pkg-1.0.0-py3-none-any.whl", ProvenanceChecked: true, ProvenanceAvailable: false},
				{Filename: "pkg-1.0.0.tar.gz", ProvenanceChecked: true, ProvenanceError: "PyPI Integrity API returned status 403"},
				{Filename: "pkg-1.0.0.zip", ProvenanceChecked: false},
			},
		},
	}, "")

	if !hasMessageContaining(findings, "have no provenance available") {
		t.Fatalf("findings = %+v, want missing provenance finding", findings)
	}
	if !hasMessageContaining(findings, "provenance availability is unknown") {
		t.Fatalf("findings = %+v, want unknown provenance finding", findings)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want one missing and one unknown summary", findings)
	}
}

func TestCheckReleaseFileCountChangeReportsDifferentCount(t *testing.T) {
	findings := CheckReleaseFileCountChange(report.PackageReport{
		Ecosystem: "PyPI",
		PyPILatestRelease: report.PyPIReleaseInfo{
			Files: []report.PyPIReleaseFile{{Filename: "a"}, {Filename: "b"}, {Filename: "c"}},
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{
			{Version: "1.0.0", Files: []report.PyPIReleaseFile{{Filename: "a"}}},
			{Version: "1.1.0", Files: []report.PyPIReleaseFile{{Filename: "a"}}},
		},
	}, 5)

	if !hasMessageContaining(findings, "different from historical median") {
		t.Fatalf("findings = %+v, want file count finding", findings)
	}
}

func TestChecksIgnoreNonPyPIReports(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "npm",
		PyPILatestRelease: report.PyPIReleaseInfo{
			Files: []report.PyPIReleaseFile{{Filename: "pkg-1.0.0.tar.gz", PackageType: "sdist"}},
		},
	}

	if len(CheckArtifactShapeChange(pkg, 5)) != 0 {
		t.Fatalf("shape check returned finding for non-pypi")
	}
	if len(CheckFileSizeJump(pkg, 5, 300)) != 0 {
		t.Fatalf("size check returned finding for non-pypi")
	}
	if len(CheckDependencyChange(pkg, 5, false)) != 0 {
		t.Fatalf("dependency check returned finding for non-pypi")
	}
	if len(CheckProvenanceRequired(pkg, "")) != 0 {
		t.Fatalf("provenance check returned finding for non-pypi")
	}
	if len(CheckReleaseFileCountChange(pkg, 5)) != 0 {
		t.Fatalf("file count check returned finding for non-pypi")
	}
}

func hasMessageContaining(findings []report.Finding, value string) bool {
	for _, finding := range findings {
		if strings.Contains(finding.Message, value) {
			return true
		}
	}
	return false
}

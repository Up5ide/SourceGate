package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestRenderHumanStatesDecisionAndFindings(t *testing.T) {
	var buf bytes.Buffer
	RenderHuman(&buf, report.PackageReport{
		Ecosystem:       "npm",
		Registry:        "npm registry",
		Name:            "lodash",
		SelectedVersion: "4.17.21",
		Decision:        report.DecisionAllow,
		Findings: []report.Finding{
			{Severity: "ALERT", Message: "selected release was published 1 day(s) ago"},
		},
		VersionCount: 2,
	})

	output := buf.String()
	for _, want := range []string{
		"Ecosystem: npm",
		"Package: lodash",
		"Selected Version: 4.17.21",
		"Selected Published: unknown",
		"Previous Published: unknown",
		"Decision: ALLOW",
		"[ALERT] selected release was published 1 day(s) ago",
		"Install executed: no",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestRenderHumanAppendsDebugEvaluationTrace(t *testing.T) {
	var buf bytes.Buffer
	RenderHuman(&buf, report.PackageReport{
		Name:     "requests",
		Decision: report.DecisionAllow,
		DebugTrace: []report.DebugTraceEntry{
			{CheckID: "release_age", Status: report.DebugTraceNoMatch, Evidence: []string{"release age: 17 day(s)"}},
			{CheckID: "first_release", Status: report.DebugTraceDisabled},
			{CheckID: "npm_lifecycle_scripts", Status: report.DebugTraceNotApplicable},
			{CheckID: "pypi_dependency_change", Status: report.DebugTraceMatch, Severity: "ALERT", Evidence: []string{"added dependencies: urllib3"}},
		},
	})

	output := buf.String()
	for _, want := range []string{
		"Install executed: no\n\nDebug Evaluation Trace:",
		"[release_age] NO MATCH",
		"release age: 17 day(s)",
		"[first_release] DISABLED",
		"[npm_lifecycle_scripts] NOT APPLICABLE",
		"[pypi_dependency_change] MATCH severity=ALERT",
		"added dependencies: urllib3",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestRenderHumanOmitsDebugTraceWhenNotCollected(t *testing.T) {
	var buf bytes.Buffer
	RenderHuman(&buf, report.PackageReport{Name: "lodash"})
	if strings.Contains(buf.String(), "Debug Evaluation Trace") {
		t.Fatalf("unexpected debug trace:\n%s", buf.String())
	}
}

func TestRenderHumanIncludesNonPolicyWarnings(t *testing.T) {
	var buf bytes.Buffer
	RenderHuman(&buf, report.PackageReport{
		Name:     "cryptography",
		Decision: report.DecisionAllow,
		Warnings: []string{"PyPI install-target compatibility inspection failed; using fallback platform \"win_amd64\": python unavailable"},
	})

	output := buf.String()
	if !strings.Contains(output, "Warnings:\n  - PyPI install-target compatibility inspection failed") {
		t.Fatalf("output missing warning:\n%s", output)
	}
	if !strings.Contains(output, "Decision: ALLOW") {
		t.Fatalf("output missing unchanged decision:\n%s", output)
	}
}

func TestRenderHumanIncludesArtifactDownloadSummary(t *testing.T) {
	var buf bytes.Buffer
	RenderHuman(&buf, report.PackageReport{
		Name: "pkg",
		ArtifactDownload: &report.ArtifactDownloadSummary{
			Status:          report.ArtifactDownloadStatusVerified,
			Filename:        "pkg.tgz",
			PackageType:     "npm-tarball",
			DownloadedSize:  42,
			DigestAlgorithm: "sha512",
			DigestVerified:  true,
		},
	})
	for _, want := range []string{"Artifact Download:", "Status: DOWNLOADED_VERIFIED", "Filename: pkg.tgz", "Digest: sha512 verified=true"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, buf.String())
		}
	}
}

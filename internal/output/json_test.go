package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestRenderJSONEmitsFullReportEnvelope(t *testing.T) {
	var buf bytes.Buffer
	err := RenderJSON(&buf, report.PackageReport{
		Ecosystem:           "npm",
		Registry:            "npm registry",
		Name:                "lodash",
		SelectedVersion:     "4.17.21",
		SelectedPublishedAt: "2021-02-20T15:42:16.891Z",
		Warnings:            []string{"warning"},
		Decision:            report.DecisionAllow,
		Findings: []report.Finding{
			{Severity: "ALERT", Message: "finding"},
		},
	})
	if err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON did not decode: %v\n%s", err, buf.String())
	}
	if decoded["schema_version"] != JSONSchemaVersion {
		t.Fatalf("schema_version = %v, want %s", decoded["schema_version"], JSONSchemaVersion)
	}
	if decoded["sourcegate_version"] == "" {
		t.Fatalf("sourcegate_version missing: %v", decoded)
	}
	if decoded["install_executed"] != false {
		t.Fatalf("install_executed = %v, want false", decoded["install_executed"])
	}

	reportValue := decoded["report"].(map[string]any)
	if reportValue["selected_version"] != "4.17.21" || reportValue["decision"] != string(report.DecisionAllow) {
		t.Fatalf("report = %+v, want selected version and decision", reportValue)
	}
	if _, ok := reportValue["debug_trace"]; ok {
		t.Fatalf("debug_trace present without collected trace: %+v", reportValue["debug_trace"])
	}
	if !strings.Contains(buf.String(), "\n  \"report\": {") {
		t.Fatalf("JSON is not pretty-printed:\n%s", buf.String())
	}
}

func TestRenderJSONIncludesDebugTraceWhenCollected(t *testing.T) {
	var buf bytes.Buffer
	err := RenderJSON(&buf, report.PackageReport{
		Name:     "requests",
		Decision: report.DecisionAllow,
		DebugTrace: []report.DebugTraceEntry{
			{CheckID: "release_age", Status: report.DebugTraceNoMatch, Evidence: []string{"release age: 17 day(s)"}},
		},
	})
	if err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "\"debug_trace\"") || !strings.Contains(buf.String(), "\"check_id\": \"release_age\"") {
		t.Fatalf("JSON missing debug trace:\n%s", buf.String())
	}
}

func TestRenderJSONIncludesArtifactSummaryButNotInternalCandidate(t *testing.T) {
	var buf bytes.Buffer
	err := RenderJSON(&buf, report.PackageReport{
		ArtifactCandidate: report.ArtifactCandidate{URL: "https://secret.example/artifact"},
		ArtifactDownload:  &report.ArtifactDownloadSummary{Status: report.ArtifactDownloadStatusSkippedBlocked},
		ArtifactInspection: &report.ArtifactInspectionSummary{
			Status:                report.ArtifactInspectionStatusInspected,
			ArchiveFormat:         "zip",
			FileCount:             1,
			ExecutionSurfaceCount: 1,
			ExecutionSurfaceExamples: []report.ArtifactExecutionSurface{
				{Type: "pypi_build_file", Path: "pkg/setup.py", Name: "setup.py"},
			},
		},
	})
	if err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "\"artifact_download\"") ||
		!strings.Contains(buf.String(), "\"artifact_inspection\"") ||
		!strings.Contains(buf.String(), "\"execution_surface_examples\"") ||
		!strings.Contains(buf.String(), "\"pypi_build_file\"") ||
		strings.Contains(buf.String(), "secret.example") ||
		strings.Contains(buf.String(), "artifact_candidate") {
		t.Fatalf("JSON artifact fields incorrect:\n%s", buf.String())
	}
}

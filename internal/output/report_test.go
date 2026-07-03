package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/configsource"
	"github.com/sourcegate/sourcegate/internal/report"
	"github.com/sourcegate/sourcegate/internal/version"
)

func TestRenderReportEmitsCompactDecisionReport(t *testing.T) {
	var buf bytes.Buffer
	err := RenderReport(&buf, report.PackageReport{
		EvaluationMode:      "metadata",
		Ecosystem:           "npm",
		Registry:            "npm registry",
		Name:                "lodash",
		SelectedVersion:     "4.17.21",
		SelectedPublishedAt: "2021-02-20T15:42:16.891Z",
		Description:         "untrusted package text",
		Maintainers:         []string{"maintainer"},
		ProjectURLs:         []string{"https://example.invalid"},
		Decision:            report.DecisionAllow,
		Findings: []report.Finding{
			{Severity: "ALERT", Message: "finding"},
		},
		DebugTrace: []report.DebugTraceEntry{
			{CheckID: "release_age", Status: report.DebugTraceMatch},
		},
	}, ReportOptions{
		Argv:     []string{"sourcegate", "--format", "report", "npm", "install", "lodash"},
		Manager:  "npm",
		Command:  "install",
		ExitCode: 20,
	})
	if err != nil {
		t.Fatalf("RenderReport returned error: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("report JSON did not decode: %v\n%s", err, buf.String())
	}
	header := decoded["sourcegate_report"].(map[string]any)
	if header["schema_version"] != version.Current+"-report" || header["sourcegate_version"] != version.Current {
		t.Fatalf("header = %+v, want report schema and sourcegate version", header)
	}
	command := decoded["command"].(map[string]any)
	if command["manager"] != "npm" || command["mode"] != "metadata" {
		t.Fatalf("command = %+v, want npm metadata command", command)
	}
	pkg := decoded["package"].(map[string]any)
	if pkg["name"] != "lodash" || pkg["selected_version"] != "4.17.21" {
		t.Fatalf("package = %+v, want lodash identity", pkg)
	}
	finalDecision := decoded["final_decision"].(map[string]any)
	if finalDecision["decision"] != string(report.DecisionAllow) || finalDecision["highest_severity"] != "ALERT" || finalDecision["exit_code"] != float64(20) {
		t.Fatalf("final_decision = %+v, want alert allow decision", finalDecision)
	}
	if _, ok := decoded["configuration"]; ok {
		t.Fatalf("configuration present without verbose report: %+v", decoded["configuration"])
	}
	for _, disallowed := range []string{"untrusted package text", "maintainer", "example.invalid", "debug_trace", "release_age", "recommended"} {
		if strings.Contains(buf.String(), disallowed) {
			t.Fatalf("report output contains %q unexpectedly:\n%s", disallowed, buf.String())
		}
	}
	if !strings.Contains(buf.String(), "\n  \"sourcegate_report\": {") {
		t.Fatalf("report JSON is not pretty-printed:\n%s", buf.String())
	}
}

func TestRenderReportVerboseIncludesEffectiveConfig(t *testing.T) {
	cfg := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{InstallLifecycleScripts: true},
		},
	}
	var buf bytes.Buffer
	err := RenderReport(&buf, report.PackageReport{
		Ecosystem:       "npm",
		Registry:        "npm registry",
		Name:            "pkg",
		SelectedVersion: "1.0.0",
	}, ReportOptions{
		Argv:     []string{"sourcegate", "--format", "report", "-v", "npm", "install", "pkg"},
		Manager:  "npm",
		Command:  "install",
		ExitCode: 0,
		ConfigStatus: &configsource.Status{
			ConfigMode:            configsource.ModeFile,
			AcceptsExternalConfig: true,
			ConfigPath:            "sourcegate.config.json",
			DefaultPath:           true,
			Exists:                true,
			Valid:                 true,
			SHA256:                "abc123",
			Config:                &cfg,
		},
	})
	if err != nil {
		t.Fatalf("RenderReport returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "\"configuration\"") ||
		!strings.Contains(buf.String(), "\"effective_config\"") ||
		!strings.Contains(buf.String(), "\"install_lifecycle_scripts\": true") ||
		!strings.Contains(buf.String(), "\"sha256\": \"abc123\"") {
		t.Fatalf("verbose report missing configuration:\n%s", buf.String())
	}
}

func TestRenderReportHighestSeverityNone(t *testing.T) {
	var buf bytes.Buffer
	err := RenderReport(&buf, report.PackageReport{}, ReportOptions{})
	if err != nil {
		t.Fatalf("RenderReport returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "\"highest_severity\": \"NONE\"") ||
		!strings.Contains(buf.String(), "\"decision\": \"INSPECT_ONLY\"") {
		t.Fatalf("report missing empty finding decision defaults:\n%s", buf.String())
	}
}

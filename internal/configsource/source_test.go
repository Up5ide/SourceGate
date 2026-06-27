package configsource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedConfigFixtureMatchesRootDefault(t *testing.T) {
	fixture, err := os.ReadFile("sourcegate.config.json")
	if err != nil {
		t.Fatalf("read embedded fixture: %v", err)
	}
	root, err := os.ReadFile(filepath.Join("..", "..", "sourcegate.config.json"))
	if err != nil {
		t.Fatalf("read root config: %v", err)
	}
	if string(fixture) != string(root) {
		t.Fatalf("embedded config fixture differs from root sourcegate.config.json")
	}
}

func TestFileModePrintStatusForMissingDefaultConfig(t *testing.T) {
	if Mode() != ModeFile {
		t.Skip("file-mode status test only applies to relaxed builds")
	}
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWorkingDirectory); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})

	status := PrintStatus("")
	if status.ConfigMode != ModeFile || !status.AcceptsExternalConfig || !status.DefaultPath {
		t.Fatalf("status = %+v, want file default status", status)
	}
	if status.Exists || !status.Valid || status.Config == nil {
		t.Fatalf("status = %+v, want missing default to be valid disabled config", status)
	}
}

func TestFileModePrintStatusForMissingExplicitConfig(t *testing.T) {
	if Mode() != ModeFile {
		t.Skip("file-mode status test only applies to relaxed builds")
	}
	status := PrintStatus(filepath.Join(t.TempDir(), "missing.json"))
	if status.Exists || status.Valid || !strings.Contains(status.Error, "not found") {
		t.Fatalf("status = %+v, want missing explicit config to be invalid", status)
	}
}

func TestEmbeddedModeRejectsExternalConfig(t *testing.T) {
	if Mode() != ModeEmbedded {
		t.Skip("embedded-mode status test only applies to embedded builds")
	}
	if _, err := Load("custom.json"); err == nil {
		t.Fatalf("Load returned nil error for external config in embedded mode")
	}
	status := PrintStatus("custom.json")
	if status.Valid || !strings.Contains(status.Error, "does not accept --config") {
		t.Fatalf("status = %+v, want embedded external config rejection", status)
	}
}

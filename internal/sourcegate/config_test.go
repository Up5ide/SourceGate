package sourcegate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sourcegate.config.json")
	if err := os.WriteFile(path, []byte(`{"policy":{"minimum_days_since_latest_release":5,"dormant_release_threshold_days":180}}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if config.Policy.MinimumDaysSinceLatestRelease != 5 {
		t.Fatalf("minimum days = %d, want 5", config.Policy.MinimumDaysSinceLatestRelease)
	}
	if config.Policy.DormantReleaseThresholdDays != 180 {
		t.Fatalf("dormant threshold days = %d, want 180", config.Policy.DormantReleaseThresholdDays)
	}
}

func TestLoadConfigMissingFileReturnsDefaultConfig(t *testing.T) {
	config, err := LoadConfig(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if config.Policy.MinimumDaysSinceLatestRelease != 0 {
		t.Fatalf("minimum days = %d, want 0", config.Policy.MinimumDaysSinceLatestRelease)
	}
}

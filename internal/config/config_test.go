package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sourcegate.config.json")
	if err := os.WriteFile(path, []byte(`{
		"policy": {
			"minimum_days_since_latest_release": 5,
			"dormant_release_threshold_days": 180,
			"protected_packages": {
				"npm": ["react", "lodash"],
				"pypi": ["requests", "django"]
			},
			"protected_tokens": {
				"npm": ["tanstack"],
				"pypi": ["pytest"]
			}
		}
	}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if config.Policy.MinimumDaysSinceLatestRelease != 5 {
		t.Fatalf("minimum days = %d, want 5", config.Policy.MinimumDaysSinceLatestRelease)
	}
	if config.Policy.DormantReleaseThresholdDays != 180 {
		t.Fatalf("dormant threshold days = %d, want 180", config.Policy.DormantReleaseThresholdDays)
	}
	if len(config.Policy.ProtectedPackages["npm"]) != 2 {
		t.Fatalf("npm protected packages = %v, want 2 entries", config.Policy.ProtectedPackages["npm"])
	}
	if len(config.Policy.ProtectedTokens["pypi"]) != 1 {
		t.Fatalf("pypi protected tokens = %v, want 1 entry", config.Policy.ProtectedTokens["pypi"])
	}
}

func TestLoadMissingFileReturnsDefaultConfig(t *testing.T) {
	config, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if config.Policy.MinimumDaysSinceLatestRelease != 0 {
		t.Fatalf("minimum days = %d, want 0", config.Policy.MinimumDaysSinceLatestRelease)
	}
}

func TestLoadRejectsInvalidProtectedNameConfig(t *testing.T) {
	cases := map[string]string{
		"unsupported package ecosystem": `{"policy":{"protected_packages":{"cargo":["serde"]}}}`,
		"unsupported token ecosystem":   `{"policy":{"protected_tokens":{"cargo":["serde"]}}}`,
		"empty package":                 `{"policy":{"protected_packages":{"npm":[" "]}}}`,
		"empty token":                   `{"policy":{"protected_tokens":{"pypi":[""]}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sourcegate.config.json")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			if _, err := Load(path); err == nil {
				t.Fatalf("Load returned nil error")
			}
		})
	}
}

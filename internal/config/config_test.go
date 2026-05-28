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
			"inform": {
				"minimum_days_since_latest_release": 1,
				"dormant_release_threshold_days": 90,
				"alert_on_first_release": true,
				"install_lifecycle_scripts": false,
				"install_lifecycle_history_versions": 0,
				"suspicious_install_script_commands": false,
				"install_script_added_after_dormancy": false,
				"protected_packages": {},
				"protected_tokens": {}
			},
			"alert": {
				"minimum_days_since_latest_release": 5,
				"dormant_release_threshold_days": 180,
				"alert_on_first_release": true,
				"install_lifecycle_scripts": true,
				"install_lifecycle_history_versions": 5,
				"suspicious_install_script_commands": false,
				"install_script_added_after_dormancy": true,
				"protected_packages": {
					"npm": ["react", "lodash"],
					"pypi": ["requests", "django"]
				},
				"protected_tokens": {
					"npm": ["tanstack"],
					"pypi": ["pytest"]
				}
			},
			"block": {
				"minimum_days_since_latest_release": 7,
				"dormant_release_threshold_days": 365,
				"alert_on_first_release": false,
				"install_lifecycle_scripts": false,
				"install_lifecycle_history_versions": 0,
				"suspicious_install_script_commands": true,
				"install_script_added_after_dormancy": false,
				"protected_packages": {},
				"protected_tokens": {}
			}
		}
	}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if config.Policy.Inform.MinimumDaysSinceLatestRelease != 1 {
		t.Fatalf("inform minimum days = %d, want 1", config.Policy.Inform.MinimumDaysSinceLatestRelease)
	}
	if config.Policy.Alert.MinimumDaysSinceLatestRelease != 5 {
		t.Fatalf("alert minimum days = %d, want 5", config.Policy.Alert.MinimumDaysSinceLatestRelease)
	}
	if config.Policy.Alert.DormantReleaseThresholdDays != 180 {
		t.Fatalf("alert dormant threshold days = %d, want 180", config.Policy.Alert.DormantReleaseThresholdDays)
	}
	if !config.Policy.Alert.AlertOnFirstRelease {
		t.Fatalf("alert on first release = false, want true")
	}
	if !config.Policy.Alert.InstallLifecycleScripts {
		t.Fatalf("alert install lifecycle scripts = false, want true")
	}
	if config.Policy.Alert.InstallLifecycleHistoryVersions != 5 {
		t.Fatalf("alert install lifecycle history versions = %d, want 5", config.Policy.Alert.InstallLifecycleHistoryVersions)
	}
	if !config.Policy.Alert.InstallScriptAddedAfterDormancy {
		t.Fatalf("alert install script added after dormancy = false, want true")
	}
	if config.Policy.Block.DormantReleaseThresholdDays != 365 {
		t.Fatalf("block dormant threshold days = %d, want 365", config.Policy.Block.DormantReleaseThresholdDays)
	}
	if !config.Policy.Block.SuspiciousInstallScriptCommands {
		t.Fatalf("block suspicious install script commands = false, want true")
	}
	if len(config.Policy.Alert.ProtectedPackages["npm"]) != 2 {
		t.Fatalf("npm protected packages = %v, want 2 entries", config.Policy.Alert.ProtectedPackages["npm"])
	}
	if len(config.Policy.Alert.ProtectedTokens["pypi"]) != 1 {
		t.Fatalf("pypi protected tokens = %v, want 1 entry", config.Policy.Alert.ProtectedTokens["pypi"])
	}
}

func TestLoadMissingFileReturnsDefaultConfig(t *testing.T) {
	config, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if config.Policy.Alert.MinimumDaysSinceLatestRelease != 0 {
		t.Fatalf("alert minimum days = %d, want 0", config.Policy.Alert.MinimumDaysSinceLatestRelease)
	}
}

func TestLoadRejectsInvalidProtectedNameConfig(t *testing.T) {
	cases := map[string]string{
		"unsupported package ecosystem": `{"policy":{"alert":{"protected_packages":{"cargo":["serde"]}}}}`,
		"unsupported token ecosystem":   `{"policy":{"block":{"protected_tokens":{"cargo":["serde"]}}}}`,
		"empty package":                 `{"policy":{"inform":{"protected_packages":{"npm":[" "]}}}}`,
		"empty token":                   `{"policy":{"alert":{"protected_tokens":{"pypi":[""]}}}}`,
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

func TestLoadRejectsNegativeTierThresholds(t *testing.T) {
	cases := map[string]string{
		"negative release age":                `{"policy":{"alert":{"minimum_days_since_latest_release":-1}}}`,
		"negative dormant":                    `{"policy":{"block":{"dormant_release_threshold_days":-1}}}`,
		"negative lifecycle history versions": `{"policy":{"inform":{"install_lifecycle_history_versions":-1}}}`,
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

func TestLoadRejectsOldFlatPolicyShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sourcegate.config.json")
	if err := os.WriteFile(path, []byte(`{
		"policy": {
			"minimum_days_since_latest_release": 3
		}
	}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatalf("Load returned nil error")
	}
}

package config

import (
	"encoding/json"
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
				"pypi_artifact_history_versions": 0,
				"pypi_artifact_shape_change": false,
				"pypi_file_size_jump_percent": 0,
				"pypi_dependency_change": false,
				"pypi_provenance_required": false,
				"pypi_provenance_scope": false,
				"pypi_include_optional_dependencies": false,
				"pypi_release_file_count_change": false,
				"artifact_unsafe_paths": false,
				"artifact_max_file_count": false,
				"artifact_max_uncompressed_size_mb": false,
				"artifact_max_expansion_ratio": false,
				"artifact_execution_surfaces": false,
				"artifact_suspicious_file_types": false,
				"artifact_behavior_indicators": false,
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
				"pypi_artifact_history_versions": 5,
				"pypi_artifact_shape_change": true,
				"pypi_file_size_jump_percent": 300,
				"pypi_dependency_change": true,
				"pypi_provenance_required": true,
				"pypi_provenance_scope": "install-target",
				"pypi_include_optional_dependencies": true,
				"pypi_release_file_count_change": true,
				"artifact_unsafe_paths": true,
				"artifact_max_file_count": 1000,
				"artifact_max_uncompressed_size_mb": 256,
				"artifact_max_expansion_ratio": 50,
				"artifact_execution_surfaces": true,
				"artifact_suspicious_file_types": true,
				"artifact_behavior_indicators": true,
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
				"pypi_artifact_history_versions": 0,
				"pypi_artifact_shape_change": false,
				"pypi_file_size_jump_percent": 0,
				"pypi_dependency_change": false,
				"pypi_provenance_required": false,
				"pypi_provenance_scope": false,
				"pypi_include_optional_dependencies": false,
				"pypi_release_file_count_change": false,
				"artifact_unsafe_paths": true,
				"artifact_max_file_count": 20000,
				"artifact_max_uncompressed_size_mb": 1024,
				"artifact_max_expansion_ratio": 100,
				"artifact_execution_surfaces": false,
				"artifact_suspicious_file_types": false,
				"artifact_behavior_indicators": false,
				"protected_packages": {},
				"protected_tokens": {}
			}
		},
		"pypi_runtime": {
			"target_platform": "linux_x86_64",
			"python_version": "3.12",
			"implementation": "cp",
			"abis": ["cp312"]
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
	if config.Policy.Alert.PyPIArtifactHistoryVersions != 5 {
		t.Fatalf("alert pypi artifact history versions = %d, want 5", config.Policy.Alert.PyPIArtifactHistoryVersions)
	}
	if !config.Policy.Alert.PyPIArtifactShapeChange {
		t.Fatalf("alert pypi artifact shape change = false, want true")
	}
	if config.Policy.Alert.PyPIFileSizeJumpPercent != 300 {
		t.Fatalf("alert pypi file size jump percent = %d, want 300", config.Policy.Alert.PyPIFileSizeJumpPercent)
	}
	if !config.Policy.Alert.PyPIDependencyChange {
		t.Fatalf("alert pypi dependency change = false, want true")
	}
	if !config.Policy.Alert.PyPIProvenanceRequired {
		t.Fatalf("alert pypi provenance required = false, want true")
	}
	if config.Policy.Alert.PyPIProvenanceScope != "install-target" {
		t.Fatalf("alert pypi provenance scope = %q, want install-target", config.Policy.Alert.PyPIProvenanceScope)
	}
	if !config.Policy.Alert.PyPIIncludeOptionalDependencies {
		t.Fatalf("alert pypi include optional dependencies = false, want true")
	}
	if !config.Policy.Alert.PyPIReleaseFileCountChange {
		t.Fatalf("alert pypi release file count change = false, want true")
	}
	if !config.Policy.Alert.ArtifactUnsafePaths {
		t.Fatalf("alert artifact unsafe paths = false, want true")
	}
	if config.Policy.Alert.ArtifactMaxFileCount != 1000 {
		t.Fatalf("alert artifact max file count = %d, want 1000", config.Policy.Alert.ArtifactMaxFileCount)
	}
	if config.Policy.Alert.ArtifactMaxUncompressedSizeMB != 256 {
		t.Fatalf("alert artifact max uncompressed size MB = %d, want 256", config.Policy.Alert.ArtifactMaxUncompressedSizeMB)
	}
	if config.Policy.Alert.ArtifactMaxExpansionRatio != 50 {
		t.Fatalf("alert artifact max expansion ratio = %d, want 50", config.Policy.Alert.ArtifactMaxExpansionRatio)
	}
	if !config.Policy.Alert.ArtifactExecutionSurfaces {
		t.Fatalf("alert artifact execution surfaces = false, want true")
	}
	if !config.Policy.Alert.ArtifactSuspiciousFileTypes {
		t.Fatalf("alert artifact suspicious file types = false, want true")
	}
	if !config.Policy.Alert.ArtifactBehaviorIndicators {
		t.Fatalf("alert artifact behavior indicators = false, want true")
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
	if config.PyPIRuntime.TargetPlatform != "linux_x86_64" || config.PyPIRuntime.PythonVersion != "3.12" || config.PyPIRuntime.Implementation != "cp" {
		t.Fatalf("pypi runtime = %+v, want configured target defaults", config.PyPIRuntime)
	}
	if len(config.PyPIRuntime.ABIs) != 1 || config.PyPIRuntime.ABIs[0] != "cp312" {
		t.Fatalf("pypi runtime ABIs = %v, want cp312", config.PyPIRuntime.ABIs)
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

func TestLoadAcceptsFalseForIntegerAndMapOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sourcegate.config.json")
	if err := os.WriteFile(path, completeConfigJSON(t, `{
		"policy": {
			"alert": {
				"minimum_days_since_latest_release": false,
				"dormant_release_threshold_days": false,
				"install_lifecycle_history_versions": false,
				"pypi_artifact_history_versions": false,
				"pypi_file_size_jump_percent": false,
				"artifact_max_file_count": false,
				"artifact_max_uncompressed_size_mb": false,
				"artifact_max_expansion_ratio": false,
				"protected_packages": false,
				"protected_tokens": false
			}
		}
	}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if config.Policy.Alert.MinimumDaysSinceLatestRelease != 0 {
		t.Fatalf("minimum days = %d, want 0", config.Policy.Alert.MinimumDaysSinceLatestRelease)
	}
	if config.Policy.Alert.DormantReleaseThresholdDays != 0 {
		t.Fatalf("dormant days = %d, want 0", config.Policy.Alert.DormantReleaseThresholdDays)
	}
	if config.Policy.Alert.InstallLifecycleHistoryVersions != 0 {
		t.Fatalf("lifecycle history versions = %d, want 0", config.Policy.Alert.InstallLifecycleHistoryVersions)
	}
	if config.Policy.Alert.PyPIArtifactHistoryVersions != 0 {
		t.Fatalf("pypi artifact history versions = %d, want 0", config.Policy.Alert.PyPIArtifactHistoryVersions)
	}
	if config.Policy.Alert.PyPIFileSizeJumpPercent != 0 {
		t.Fatalf("pypi file size jump percent = %d, want 0", config.Policy.Alert.PyPIFileSizeJumpPercent)
	}
	if config.Policy.Alert.ArtifactMaxFileCount != 0 {
		t.Fatalf("artifact max file count = %d, want 0", config.Policy.Alert.ArtifactMaxFileCount)
	}
	if config.Policy.Alert.ArtifactMaxUncompressedSizeMB != 0 {
		t.Fatalf("artifact max uncompressed size MB = %d, want 0", config.Policy.Alert.ArtifactMaxUncompressedSizeMB)
	}
	if config.Policy.Alert.ArtifactMaxExpansionRatio != 0 {
		t.Fatalf("artifact max expansion ratio = %d, want 0", config.Policy.Alert.ArtifactMaxExpansionRatio)
	}
	if len(config.Policy.Alert.ProtectedPackages) != 0 {
		t.Fatalf("protected packages = %v, want empty map", config.Policy.Alert.ProtectedPackages)
	}
	if len(config.Policy.Alert.ProtectedTokens) != 0 {
		t.Fatalf("protected tokens = %v, want empty map", config.Policy.Alert.ProtectedTokens)
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
			if err := os.WriteFile(path, completeConfigJSON(t, content), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			if _, err := Load(path); err == nil {
				t.Fatalf("Load returned nil error")
			}
		})
	}
}

func TestLoadRejectsInvalidFlexiblePolicyValueTypes(t *testing.T) {
	cases := map[string]string{
		"string integer":   `{"policy":{"alert":{"minimum_days_since_latest_release":"3"}}}`,
		"true integer":     `{"policy":{"alert":{"pypi_file_size_jump_percent":true}}}`,
		"array map":        `{"policy":{"alert":{"protected_packages":[]}}}`,
		"string map":       `{"policy":{"alert":{"protected_tokens":"npm"}}}`,
		"number bool":      `{"policy":{"alert":{"pypi_dependency_change":1}}}`,
		"number optional":  `{"policy":{"alert":{"pypi_include_optional_dependencies":1}}}`,
		"number artifact":  `{"policy":{"alert":{"artifact_unsafe_paths":1}}}`,
		"number execution": `{"policy":{"alert":{"artifact_execution_surfaces":1}}}`,
		"number filetype":  `{"policy":{"alert":{"artifact_suspicious_file_types":1}}}`,
		"number behavior":  `{"policy":{"alert":{"artifact_behavior_indicators":1}}}`,
		"array scope":      `{"policy":{"alert":{"pypi_provenance_scope":[]}}}`,
		"unknown field":    `{"policy":{"alert":{"does_not_exist":false}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sourcegate.config.json")
			if err := os.WriteFile(path, completeConfigJSON(t, content), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			if _, err := Load(path); err == nil {
				t.Fatalf("Load returned nil error")
			}
		})
	}
}

func TestLoadRejectsContradictoryPyPIProvenanceScope(t *testing.T) {
	cases := map[string]string{
		"required without scope": `{"policy":{"alert":{"pypi_provenance_required":true,"pypi_provenance_scope":false}}}`,
		"scope without required": `{"policy":{"alert":{"pypi_provenance_required":false,"pypi_provenance_scope":"install-target"}}}`,
		"unsupported scope":      `{"policy":{"alert":{"pypi_provenance_required":true,"pypi_provenance_scope":"wheels-only"}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sourcegate.config.json")
			if err := os.WriteFile(path, completeConfigJSON(t, content), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("Load returned nil error")
			}
		})
	}
}

func TestLoadRejectsInvalidPyPIRuntime(t *testing.T) {
	cases := map[string]string{
		"unknown field": `{"pypi_runtime":{"python_executable":"python"}}`,
		"blank abi":     `{"pypi_runtime":{"abis":[" "]}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sourcegate.config.json")
			if err := os.WriteFile(path, completeConfigJSON(t, content), 0600); err != nil {
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
		"negative pypi history versions":      `{"policy":{"alert":{"pypi_artifact_history_versions":-1}}}`,
		"negative pypi size jump percent":     `{"policy":{"block":{"pypi_file_size_jump_percent":-1}}}`,
		"negative artifact file count":        `{"policy":{"alert":{"artifact_max_file_count":-1}}}`,
		"negative artifact size":              `{"policy":{"block":{"artifact_max_uncompressed_size_mb":-1}}}`,
		"negative artifact expansion":         `{"policy":{"inform":{"artifact_max_expansion_ratio":-1}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sourcegate.config.json")
			if err := os.WriteFile(path, completeConfigJSON(t, content), 0600); err != nil {
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

func TestLoadRequiresCompletePolicyConfig(t *testing.T) {
	cases := map[string]string{
		"missing policy": `{"pypi_runtime":{}}`,
		"missing tier":   `{"policy":{"inform":{},"alert":{}}}`,
		"missing key":    `{"policy":{"inform":{},"alert":{},"block":{}}}`,
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

func TestLoadAcceptsUTF8BOMAndRejectsTrailingJSON(t *testing.T) {
	valid := completeConfigJSON(t, `{}`)
	path := filepath.Join(t.TempDir(), "sourcegate.config.json")
	if err := os.WriteFile(path, append([]byte{0xEF, 0xBB, 0xBF}, valid...), 0600); err != nil {
		t.Fatalf("write BOM config: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load BOM config returned error: %v", err)
	}

	if err := os.WriteFile(path, append(valid, []byte(` {"extra":true}`)...), 0600); err != nil {
		t.Fatalf("write trailing config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("Load trailing config returned nil error")
	}
}

func TestLoadRejectsMissingSameTierCompanionOptions(t *testing.T) {
	cases := map[string]string{
		"dormant script history":          `{"policy":{"alert":{"install_script_added_after_dormancy":true,"dormant_release_threshold_days":180,"install_lifecycle_history_versions":false}}}`,
		"dormant script threshold":        `{"policy":{"alert":{"install_script_added_after_dormancy":true,"dormant_release_threshold_days":false,"install_lifecycle_history_versions":5}}}`,
		"PyPI shape history":              `{"policy":{"alert":{"pypi_artifact_shape_change":true,"pypi_artifact_history_versions":false}}}`,
		"PyPI optional dependency parent": `{"policy":{"alert":{"pypi_include_optional_dependencies":true,"pypi_dependency_change":false}}}`,
		"orphan PyPI history":             `{"policy":{"alert":{"pypi_artifact_history_versions":5}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sourcegate.config.json")
			if err := os.WriteFile(path, completeConfigJSON(t, content), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("Load returned nil error")
			}
		})
	}
}

func completeConfigJSON(t *testing.T, override string) []byte {
	t.Helper()
	base, err := json.Marshal(Config{Policy: PolicyConfig{}})
	if err != nil {
		t.Fatalf("marshal base config: %v", err)
	}
	var baseValue map[string]any
	var overrideValue map[string]any
	if err := json.Unmarshal(base, &baseValue); err != nil {
		t.Fatalf("decode base config: %v", err)
	}
	if err := json.Unmarshal([]byte(override), &overrideValue); err != nil {
		t.Fatalf("decode override config: %v", err)
	}
	mergeJSONMaps(baseValue, overrideValue)
	result, err := json.Marshal(baseValue)
	if err != nil {
		t.Fatalf("marshal complete config: %v", err)
	}
	return result
}

func mergeJSONMaps(target, override map[string]any) {
	for key, value := range override {
		overrideMap, overrideOK := value.(map[string]any)
		targetMap, targetOK := target[key].(map[string]any)
		if overrideOK && targetOK {
			mergeJSONMaps(targetMap, overrideMap)
			continue
		}
		target[key] = value
	}
}

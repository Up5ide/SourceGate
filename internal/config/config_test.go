package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadGroupedConfigNormalizesDefaultsAndOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sourcegate.config.json")
	if err := os.WriteFile(path, completeConfigJSON(t, `{
		"policy": {
			"inform": {
				"groups": {
					"release_metadata": true
				}
			},
			"alert": {
				"groups": {
					"release_metadata": true,
					"name_protection": true,
					"npm_lifecycle": true,
					"npm_dependencies": true,
					"pypi_artifacts": true,
					"source_metadata": true,
					"artifact_behavior": true
				},
				"checks": {
					"minimum_days_since_latest_release": 5,
					"pypi_include_optional_dependencies": true,
					"artifact_unsafe_paths": true,
					"artifact_max_file_count": 1000,
					"artifact_max_uncompressed_size_mb": 256,
					"artifact_max_expansion_ratio": 50,
					"protected_packages": {
						"npm": ["react", "lodash"],
						"pypi": ["requests", "django"]
					},
					"protected_tokens": {
						"npm": ["tanstack"],
						"pypi": ["pytest"]
					},
					"private_packages": {
						"npm": ["@internal/core"],
						"pypi": ["internal-core"]
					}
				}
			},
			"block": {
				"groups": {
					"release_metadata": true,
					"npm_lifecycle": true,
					"artifact_safety": true
				},
				"checks": {
					"minimum_days_since_latest_release": 7,
					"dormant_release_threshold_days": 365
				}
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
	if !config.Policy.Alert.InstallLifecycleScripts || config.Policy.Alert.InstallLifecycleHistoryVersions != 5 || !config.Policy.Alert.InstallScriptAddedAfterDormancy {
		t.Fatalf("alert npm lifecycle policy = %+v, want group defaults", config.Policy.Alert)
	}
	if config.Policy.Alert.NPMDependencyHistoryVersions != 5 || !config.Policy.Alert.NPMDependencyChange || !config.Policy.Alert.NPMDirectDependencyLifecycleScripts || !config.Policy.Alert.NPMDirectDependencySuspiciousInstallCommands || config.Policy.Alert.NPMMaxDirectDependencies != 25 {
		t.Fatalf("alert npm dependency policy = %+v, want group defaults", config.Policy.Alert)
	}
	if !config.Policy.Block.SuspiciousInstallScriptCommands {
		t.Fatalf("block suspicious install script commands = false, want true")
	}
	if config.Policy.Alert.PyPIArtifactHistoryVersions != 5 || !config.Policy.Alert.PyPIArtifactShapeChange || config.Policy.Alert.PyPIFileSizeJumpPercent != 300 || !config.Policy.Alert.PyPIDependencyChange || !config.Policy.Alert.PyPIProvenanceRequired || config.Policy.Alert.PyPIProvenanceScope != "install-target" || !config.Policy.Alert.PyPIReleaseFileCountChange {
		t.Fatalf("alert PyPI policy = %+v, want group defaults", config.Policy.Alert)
	}
	if !config.Policy.Alert.PyPIIncludeOptionalDependencies {
		t.Fatalf("alert pypi include optional dependencies = false, want true")
	}
	if !config.Policy.Alert.ArtifactUnsafePaths || config.Policy.Alert.ArtifactMaxFileCount != 1000 || config.Policy.Alert.ArtifactMaxUncompressedSizeMB != 256 || config.Policy.Alert.ArtifactMaxExpansionRatio != 50 {
		t.Fatalf("alert artifact safety overrides = %+v, want configured values", config.Policy.Alert)
	}
	if !config.Policy.Alert.ArtifactExecutionSurfaces || !config.Policy.Alert.ArtifactSuspiciousFileTypes || !config.Policy.Alert.ArtifactBehaviorIndicators {
		t.Fatalf("alert artifact behavior policy = %+v, want group defaults", config.Policy.Alert)
	}
	if !config.Policy.Alert.ArtifactGeneralRiskSignals || !config.Policy.Alert.ArtifactFileListChange || !config.Policy.Alert.ArtifactNewExecutionSurfaces || !config.Policy.Alert.ArtifactNewSuspiciousFileTypes || !config.Policy.Alert.ArtifactSizeDelta {
		t.Fatalf("alert artifact metadata/delta policy = %+v, want group defaults", config.Policy.Alert)
	}
	if !config.Policy.Alert.NPMGitHeadMissing || !config.Policy.Alert.NPMRepositoryMissing || !config.Policy.Alert.NPMGitHeadChangedAfterDormancy || !config.Policy.Alert.NPMRepositoryChanged || !config.Policy.Alert.NPMPublisherChanged || config.Policy.Alert.NPMReleaseBurstCount != 3 || config.Policy.Alert.NPMReleaseBurstWindowHours != 2 {
		t.Fatalf("alert source metadata policy = %+v, want group defaults", config.Policy.Alert)
	}
	if config.Policy.Block.DormantReleaseThresholdDays != 365 || config.Policy.Block.ArtifactMaxFileCount != 20000 || config.Policy.Block.ArtifactMaxUncompressedSizeMB != 1024 || config.Policy.Block.ArtifactMaxExpansionRatio != 100 {
		t.Fatalf("block policy = %+v, want defaults plus overrides", config.Policy.Block)
	}
	if len(config.Policy.Alert.ProtectedPackages["npm"]) != 2 {
		t.Fatalf("npm protected packages = %v, want 2 entries", config.Policy.Alert.ProtectedPackages["npm"])
	}
	if len(config.Policy.Alert.ProtectedTokens["pypi"]) != 1 {
		t.Fatalf("pypi protected tokens = %v, want 1 entry", config.Policy.Alert.ProtectedTokens["pypi"])
	}
	if len(config.Policy.Alert.PrivatePackages["npm"]) != 1 {
		t.Fatalf("npm private packages = %v, want 1 entry", config.Policy.Alert.PrivatePackages["npm"])
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

func TestLoadRequiredRejectsMissingFile(t *testing.T) {
	if _, err := LoadRequired(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatalf("LoadRequired returned nil error")
	}
}

func TestLoadAcceptsOmittedChecks(t *testing.T) {
	config, err := LoadBytes(completeConfigJSON(t, `{
		"policy": {
			"alert": {
				"checks": {}
			}
		}
	}`))
	if err != nil {
		t.Fatalf("LoadBytes returned error: %v", err)
	}
	if config.Policy.Alert.MinimumDaysSinceLatestRelease != 0 {
		t.Fatalf("alert minimum days = %d, want disabled policy", config.Policy.Alert.MinimumDaysSinceLatestRelease)
	}
}

func TestGroupFalseDisablesDefaults(t *testing.T) {
	config, err := LoadBytes(completeConfigJSON(t, `{
		"policy": {
			"alert": {
				"groups": {
					"release_metadata": false,
					"npm_lifecycle": false,
					"npm_dependencies": false,
					"pypi_artifacts": false,
					"source_metadata": false,
					"artifact_behavior": false
				}
			}
		}
	}`))
	if err != nil {
		t.Fatalf("LoadBytes returned error: %v", err)
	}
	if config.Policy.Alert.AlertOnFirstRelease || config.Policy.Alert.InstallLifecycleScripts || config.Policy.Alert.NPMDependencyChange || config.Policy.Alert.PyPIDependencyChange || config.Policy.Alert.NPMGitHeadMissing || config.Policy.Alert.ArtifactBehaviorIndicators {
		t.Fatalf("alert policy = %+v, want disabled group defaults", config.Policy.Alert)
	}
}

func TestExplicitOverrideDisablesGroupEnabledCheck(t *testing.T) {
	config, err := LoadBytes(completeConfigJSON(t, `{
		"policy": {
			"alert": {
				"groups": {
					"release_metadata": true
				},
				"checks": {
					"minimum_days_since_latest_release": false,
					"alert_on_first_release": false
				}
			}
		}
	}`))
	if err != nil {
		t.Fatalf("LoadBytes returned error: %v", err)
	}
	if config.Policy.Alert.MinimumDaysSinceLatestRelease != 0 || config.Policy.Alert.DormantReleaseThresholdDays != 180 || config.Policy.Alert.AlertOnFirstRelease {
		t.Fatalf("alert policy = %+v, want explicit overrides to win", config.Policy.Alert)
	}
}

func TestExplicitOverrideEnablesCheckInsideDisabledGroup(t *testing.T) {
	config, err := LoadBytes(completeConfigJSON(t, `{
		"policy": {
			"alert": {
				"groups": {
					"release_metadata": false
				},
				"checks": {
					"minimum_days_since_latest_release": 4
				}
			}
		}
	}`))
	if err != nil {
		t.Fatalf("LoadBytes returned error: %v", err)
	}
	if config.Policy.Alert.MinimumDaysSinceLatestRelease != 4 || config.Policy.Alert.DormantReleaseThresholdDays != 0 {
		t.Fatalf("alert policy = %+v, want explicit check enabled inside disabled group", config.Policy.Alert)
	}
}

func TestLoadAcceptsFalseForIntegerStringAndMapOptions(t *testing.T) {
	config, err := LoadBytes(completeConfigJSON(t, `{
		"policy": {
			"alert": {
				"groups": {
					"release_metadata": true,
					"npm_lifecycle": true,
					"npm_dependencies": true,
					"pypi_artifacts": true,
					"source_metadata": true,
					"artifact_safety": true
				},
				"checks": {
					"minimum_days_since_latest_release": false,
					"dormant_release_threshold_days": false,
					"install_lifecycle_history_versions": false,
					"install_script_added_after_dormancy": false,
					"npm_dependency_history_versions": false,
					"npm_dependency_change": false,
					"npm_direct_dependency_lifecycle_scripts": false,
					"npm_direct_dependency_suspicious_install_commands": false,
					"npm_max_direct_dependencies": false,
					"pypi_artifact_history_versions": false,
					"pypi_artifact_shape_change": false,
					"pypi_file_size_jump_percent": false,
					"pypi_dependency_change": false,
					"pypi_provenance_required": false,
					"pypi_provenance_scope": false,
					"pypi_release_file_count_change": false,
					"artifact_max_file_count": false,
					"artifact_max_uncompressed_size_mb": false,
					"artifact_max_expansion_ratio": false,
					"protected_packages": false,
					"protected_tokens": false,
					"private_packages": false,
					"npm_git_head_missing": false,
					"npm_repository_missing": false,
					"npm_git_head_changed_after_dormancy": false,
					"npm_repository_changed": false,
					"npm_publisher_changed": false,
					"npm_release_burst_count": false,
					"npm_release_burst_window_hours": false
				}
			}
		}
	}`))
	if err != nil {
		t.Fatalf("LoadBytes returned error: %v", err)
	}

	if config.Policy.Alert.MinimumDaysSinceLatestRelease != 0 || config.Policy.Alert.DormantReleaseThresholdDays != 0 || config.Policy.Alert.InstallLifecycleHistoryVersions != 0 || config.Policy.Alert.NPMDependencyHistoryVersions != 0 || config.Policy.Alert.NPMMaxDirectDependencies != 0 || config.Policy.Alert.PyPIArtifactHistoryVersions != 0 || config.Policy.Alert.PyPIFileSizeJumpPercent != 0 || config.Policy.Alert.PyPIProvenanceScope != "" || config.Policy.Alert.ArtifactMaxFileCount != 0 || config.Policy.Alert.ArtifactMaxUncompressedSizeMB != 0 || config.Policy.Alert.ArtifactMaxExpansionRatio != 0 || config.Policy.Alert.NPMReleaseBurstCount != 0 || config.Policy.Alert.NPMReleaseBurstWindowHours != 0 {
		t.Fatalf("alert policy = %+v, want neutral false values", config.Policy.Alert)
	}
	if len(config.Policy.Alert.ProtectedPackages) != 0 || len(config.Policy.Alert.ProtectedTokens) != 0 || len(config.Policy.Alert.PrivatePackages) != 0 {
		t.Fatalf("protected names = %v/%v, want empty maps", config.Policy.Alert.ProtectedPackages, config.Policy.Alert.ProtectedTokens)
	}
}

func TestLoadRejectsInvalidProtectedNameConfig(t *testing.T) {
	cases := map[string]string{
		"unsupported package ecosystem": `{"policy":{"alert":{"checks":{"protected_packages":{"cargo":["serde"]}}}}}`,
		"unsupported token ecosystem":   `{"policy":{"block":{"checks":{"protected_tokens":{"cargo":["serde"]}}}}}`,
		"unsupported private ecosystem": `{"policy":{"block":{"checks":{"private_packages":{"cargo":["serde"]}}}}}`,
		"empty package":                 `{"policy":{"inform":{"checks":{"protected_packages":{"npm":[" "]}}}}}`,
		"empty token":                   `{"policy":{"alert":{"checks":{"protected_tokens":{"pypi":[""]}}}}}`,
		"empty private package":         `{"policy":{"alert":{"checks":{"private_packages":{"npm":[""]}}}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes(completeConfigJSON(t, content)); err == nil {
				t.Fatalf("LoadBytes returned nil error")
			}
		})
	}
}

func TestLoadRejectsInvalidFlexiblePolicyValueTypes(t *testing.T) {
	cases := map[string]string{
		"string integer":   `{"policy":{"alert":{"checks":{"minimum_days_since_latest_release":"3"}}}}`,
		"true integer":     `{"policy":{"alert":{"checks":{"pypi_file_size_jump_percent":true}}}}`,
		"array map":        `{"policy":{"alert":{"checks":{"protected_packages":[]}}}}`,
		"string map":       `{"policy":{"alert":{"checks":{"protected_tokens":"npm"}}}}`,
		"number bool":      `{"policy":{"alert":{"checks":{"pypi_dependency_change":1}}}}`,
		"number optional":  `{"policy":{"alert":{"checks":{"pypi_include_optional_dependencies":1}}}}`,
		"number artifact":  `{"policy":{"alert":{"checks":{"artifact_unsafe_paths":1}}}}`,
		"number execution": `{"policy":{"alert":{"checks":{"artifact_execution_surfaces":1}}}}`,
		"number filetype":  `{"policy":{"alert":{"checks":{"artifact_suspicious_file_types":1}}}}`,
		"number behavior":  `{"policy":{"alert":{"checks":{"artifact_behavior_indicators":1}}}}`,
		"array scope":      `{"policy":{"alert":{"checks":{"pypi_provenance_scope":[]}}}}`,
		"unknown check":    `{"policy":{"alert":{"checks":{"does_not_exist":false}}}}`,
		"unknown group":    `{"policy":{"alert":{"groups":{"unknown":true}}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes(completeConfigJSON(t, content)); err == nil {
				t.Fatalf("LoadBytes returned nil error")
			}
		})
	}
}

func TestLoadRejectsContradictoryPyPIProvenanceScope(t *testing.T) {
	cases := map[string]string{
		"required without scope": `{"policy":{"alert":{"checks":{"pypi_provenance_required":true,"pypi_provenance_scope":false}}}}`,
		"scope without required": `{"policy":{"alert":{"checks":{"pypi_provenance_required":false,"pypi_provenance_scope":"install-target"}}}}`,
		"unsupported scope":      `{"policy":{"alert":{"checks":{"pypi_provenance_required":true,"pypi_provenance_scope":"wheels-only"}}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes(completeConfigJSON(t, content)); err == nil {
				t.Fatalf("LoadBytes returned nil error")
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
			if _, err := LoadBytes(completeConfigJSON(t, content)); err == nil {
				t.Fatalf("LoadBytes returned nil error")
			}
		})
	}
}

func TestLoadRejectsNegativeTierThresholds(t *testing.T) {
	cases := map[string]string{
		"negative release age":                `{"policy":{"alert":{"checks":{"minimum_days_since_latest_release":-1}}}}`,
		"negative dormant":                    `{"policy":{"block":{"checks":{"dormant_release_threshold_days":-1}}}}`,
		"negative lifecycle history versions": `{"policy":{"inform":{"checks":{"install_lifecycle_history_versions":-1}}}}`,
		"negative npm dependency history":     `{"policy":{"inform":{"checks":{"npm_dependency_history_versions":-1}}}}`,
		"negative npm dependency limit":       `{"policy":{"inform":{"checks":{"npm_max_direct_dependencies":-1}}}}`,
		"negative pypi history versions":      `{"policy":{"alert":{"checks":{"pypi_artifact_history_versions":-1}}}}`,
		"negative pypi size jump percent":     `{"policy":{"block":{"checks":{"pypi_file_size_jump_percent":-1}}}}`,
		"negative artifact file count":        `{"policy":{"alert":{"checks":{"artifact_max_file_count":-1}}}}`,
		"negative artifact size":              `{"policy":{"block":{"checks":{"artifact_max_uncompressed_size_mb":-1}}}}`,
		"negative artifact expansion":         `{"policy":{"inform":{"checks":{"artifact_max_expansion_ratio":-1}}}}`,
		"negative npm release burst count":    `{"policy":{"inform":{"checks":{"npm_release_burst_count":-1}}}}`,
		"negative npm release burst window":   `{"policy":{"inform":{"checks":{"npm_release_burst_window_hours":-1}}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes(completeConfigJSON(t, content)); err == nil {
				t.Fatalf("LoadBytes returned nil error")
			}
		})
	}
}

func TestLoadRejectsOldFlatPolicyShape(t *testing.T) {
	cases := map[string]string{
		"flat root policy": `{
			"policy": {
				"minimum_days_since_latest_release": 3
			}
		}`,
		"flat tier policy": `{
			"policy": {
				"inform": {"groups": {"release_metadata": false, "name_protection": false, "npm_lifecycle": false, "pypi_artifacts": false, "artifact_safety": false, "artifact_behavior": false}},
				"alert": {
					"groups": {"release_metadata": false, "name_protection": false, "npm_lifecycle": false, "pypi_artifacts": false, "artifact_safety": false, "artifact_behavior": false},
					"minimum_days_since_latest_release": 3
				},
				"block": {"groups": {"release_metadata": false, "name_protection": false, "npm_lifecycle": false, "pypi_artifacts": false, "artifact_safety": false, "artifact_behavior": false}}
			}
		}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(content)); err == nil {
				t.Fatalf("LoadBytes returned nil error")
			}
		})
	}
}

func TestLoadRequiresCompletePolicyConfig(t *testing.T) {
	cases := map[string]string{
		"missing policy":       `{"pypi_runtime":{}}`,
		"missing tier":         `{"policy":{"inform":{"groups":{}},"alert":{"groups":{}}}}`,
		"missing groups":       `{"policy":{"inform":{},"alert":{},"block":{}}}`,
		"missing group member": `{"policy":{"inform":{"groups":{"release_metadata":false}},"alert":{"groups":{}},"block":{"groups":{}}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(content)); err == nil {
				t.Fatalf("LoadBytes returned nil error")
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
		"dormant script history":           `{"policy":{"alert":{"checks":{"install_script_added_after_dormancy":true,"dormant_release_threshold_days":180,"install_lifecycle_history_versions":false}}}}`,
		"dormant script threshold":         `{"policy":{"alert":{"checks":{"install_script_added_after_dormancy":true,"dormant_release_threshold_days":false,"install_lifecycle_history_versions":5}}}}`,
		"npm dependency history":           `{"policy":{"alert":{"checks":{"npm_dependency_change":true,"npm_dependency_history_versions":false}}}}`,
		"orphan npm dependency history":    `{"policy":{"alert":{"checks":{"npm_dependency_history_versions":5}}}}`,
		"npm direct dependency limit":      `{"policy":{"alert":{"checks":{"npm_direct_dependency_lifecycle_scripts":true,"npm_max_direct_dependencies":false}}}}`,
		"orphan npm direct dependency max": `{"policy":{"alert":{"checks":{"npm_max_direct_dependencies":5}}}}`,
		"npm gitHead dormancy threshold":   `{"policy":{"alert":{"checks":{"npm_git_head_changed_after_dormancy":true,"dormant_release_threshold_days":false}}}}`,
		"npm release burst count":          `{"policy":{"alert":{"checks":{"npm_release_burst_count":3,"npm_release_burst_window_hours":false}}}}`,
		"npm release burst window":         `{"policy":{"alert":{"checks":{"npm_release_burst_count":false,"npm_release_burst_window_hours":2}}}}`,
		"PyPI shape history":               `{"policy":{"alert":{"checks":{"pypi_artifact_shape_change":true,"pypi_artifact_history_versions":false}}}}`,
		"PyPI optional dependency parent":  `{"policy":{"alert":{"checks":{"pypi_include_optional_dependencies":true,"pypi_dependency_change":false}}}}`,
		"orphan PyPI history":              `{"policy":{"alert":{"checks":{"pypi_artifact_history_versions":5}}}}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadBytes(completeConfigJSON(t, content)); err == nil {
				t.Fatalf("LoadBytes returned nil error")
			}
		})
	}
}

func completeConfigJSON(t *testing.T, override string) []byte {
	t.Helper()
	baseValue := map[string]any{
		"policy": map[string]any{
			"inform": baseTierConfig(),
			"alert":  baseTierConfig(),
			"block":  baseTierConfig(),
		},
	}
	var overrideValue map[string]any
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

func baseTierConfig() map[string]any {
	return map[string]any{
		"groups": map[string]any{
			"release_metadata":  false,
			"name_protection":   false,
			"npm_lifecycle":     false,
			"npm_dependencies":  false,
			"pypi_artifacts":    false,
			"source_metadata":   false,
			"artifact_safety":   false,
			"artifact_behavior": false,
		},
		"checks": map[string]any{},
	}
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

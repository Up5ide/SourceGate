package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
)

const DefaultPath = "sourcegate.config.json"

const (
	GroupReleaseMetadata  = "release_metadata"
	GroupNameProtection   = "name_protection"
	GroupNPMLifecycle     = "npm_lifecycle"
	GroupNPMDependencies  = "npm_dependencies"
	GroupPyPIArtifacts    = "pypi_artifacts"
	GroupSourceMetadata   = "source_metadata"
	GroupArtifactSafety   = "artifact_safety"
	GroupArtifactBehavior = "artifact_behavior"
)

var supportedPolicyGroups = []string{
	GroupReleaseMetadata,
	GroupNameProtection,
	GroupNPMLifecycle,
	GroupNPMDependencies,
	GroupPyPIArtifacts,
	GroupSourceMetadata,
	GroupArtifactSafety,
	GroupArtifactBehavior,
}

type Config struct {
	Policy      PolicyConfig      `json:"policy"`
	PyPIRuntime PyPIRuntimeConfig `json:"pypi_runtime,omitempty"`
}

type PyPIRuntimeConfig struct {
	TargetPlatform string   `json:"target_platform,omitempty"`
	PythonVersion  string   `json:"python_version,omitempty"`
	Implementation string   `json:"implementation,omitempty"`
	ABIs           []string `json:"abis,omitempty"`
}

type PolicyConfig struct {
	Inform PolicyTierConfig `json:"inform"`
	Alert  PolicyTierConfig `json:"alert"`
	Block  PolicyTierConfig `json:"block"`
}

type PolicyTierConfig struct {
	MinimumDaysSinceLatestRelease                int                 `json:"minimum_days_since_latest_release"`
	DormantReleaseThresholdDays                  int                 `json:"dormant_release_threshold_days"`
	AlertOnFirstRelease                          bool                `json:"alert_on_first_release"`
	InstallLifecycleScripts                      bool                `json:"install_lifecycle_scripts"`
	InstallLifecycleHistoryVersions              int                 `json:"install_lifecycle_history_versions"`
	SuspiciousInstallScriptCommands              bool                `json:"suspicious_install_script_commands"`
	InstallScriptAddedAfterDormancy              bool                `json:"install_script_added_after_dormancy"`
	NPMDependencyHistoryVersions                 int                 `json:"npm_dependency_history_versions"`
	NPMDependencyChange                          bool                `json:"npm_dependency_change"`
	NPMDirectDependencyLifecycleScripts          bool                `json:"npm_direct_dependency_lifecycle_scripts"`
	NPMDirectDependencySuspiciousInstallCommands bool                `json:"npm_direct_dependency_suspicious_install_commands"`
	NPMMaxDirectDependencies                     int                 `json:"npm_max_direct_dependencies"`
	PyPIArtifactHistoryVersions                  int                 `json:"pypi_artifact_history_versions"`
	PyPIArtifactShapeChange                      bool                `json:"pypi_artifact_shape_change"`
	PyPIFileSizeJumpPercent                      int                 `json:"pypi_file_size_jump_percent"`
	PyPIDependencyChange                         bool                `json:"pypi_dependency_change"`
	PyPIProvenanceRequired                       bool                `json:"pypi_provenance_required"`
	PyPIProvenanceScope                          string              `json:"pypi_provenance_scope"`
	PyPIIncludeOptionalDependencies              bool                `json:"pypi_include_optional_dependencies"`
	PyPIReleaseFileCountChange                   bool                `json:"pypi_release_file_count_change"`
	ArtifactUnsafePaths                          bool                `json:"artifact_unsafe_paths"`
	ArtifactMaxFileCount                         int                 `json:"artifact_max_file_count"`
	ArtifactMaxUncompressedSizeMB                int                 `json:"artifact_max_uncompressed_size_mb"`
	ArtifactMaxExpansionRatio                    int                 `json:"artifact_max_expansion_ratio"`
	ArtifactExecutionSurfaces                    bool                `json:"artifact_execution_surfaces"`
	ArtifactSuspiciousFileTypes                  bool                `json:"artifact_suspicious_file_types"`
	ArtifactBehaviorIndicators                   bool                `json:"artifact_behavior_indicators"`
	ArtifactGeneralRiskSignals                   bool                `json:"artifact_general_risk_signals"`
	ArtifactFileListChange                       bool                `json:"artifact_file_list_change"`
	ArtifactNewExecutionSurfaces                 bool                `json:"artifact_new_execution_surfaces"`
	ArtifactNewSuspiciousFileTypes               bool                `json:"artifact_new_suspicious_file_types"`
	ArtifactSizeDelta                            bool                `json:"artifact_size_delta"`
	ProtectedPackages                            map[string][]string `json:"protected_packages"`
	ProtectedTokens                              map[string][]string `json:"protected_tokens"`
	PrivatePackages                              map[string][]string `json:"private_packages"`
	NPMGitHeadMissing                            bool                `json:"npm_git_head_missing"`
	NPMRepositoryMissing                         bool                `json:"npm_repository_missing"`
	NPMGitHeadChangedAfterDormancy               bool                `json:"npm_git_head_changed_after_dormancy"`
	NPMRepositoryChanged                         bool                `json:"npm_repository_changed"`
	NPMPublisherChanged                          bool                `json:"npm_publisher_changed"`
	NPMReleaseBurstCount                         int                 `json:"npm_release_burst_count"`
	NPMReleaseBurstWindowHours                   int                 `json:"npm_release_burst_window_hours"`
}

type rawConfig struct {
	Policy      rawPolicyConfig   `json:"policy"`
	PyPIRuntime PyPIRuntimeConfig `json:"pypi_runtime,omitempty"`
}

type rawPolicyConfig struct {
	Inform rawPolicyTierConfig `json:"inform"`
	Alert  rawPolicyTierConfig `json:"alert"`
	Block  rawPolicyTierConfig `json:"block"`
}

type rawPolicyTierConfig struct {
	Groups map[string]bool            `json:"groups"`
	Checks map[string]json.RawMessage `json:"checks,omitempty"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	config, err := LoadBytes(data)
	if err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	return config, nil
}

func LoadRequired(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	config, err := LoadBytes(data)
	if err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	return config, nil
}

func LoadBytes(data []byte) (Config, error) {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	var raw rawConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Config{}, err
	}

	config, err := normalizeRawConfig(raw)
	if err != nil {
		return Config{}, err
	}
	if err := validatePyPIRuntime(config.PyPIRuntime); err != nil {
		return Config{}, err
	}
	for _, tier := range []struct {
		name   string
		policy PolicyTierConfig
	}{
		{name: "inform", policy: config.Policy.Inform},
		{name: "alert", policy: config.Policy.Alert},
		{name: "block", policy: config.Policy.Block},
	} {
		if err := validatePolicyTier(tier.name, tier.policy); err != nil {
			return Config{}, err
		}
	}

	return config, nil
}

func normalizeRawConfig(raw rawConfig) (Config, error) {
	inform, err := normalizeRawPolicyTier("inform", raw.Policy.Inform)
	if err != nil {
		return Config{}, err
	}
	alert, err := normalizeRawPolicyTier("alert", raw.Policy.Alert)
	if err != nil {
		return Config{}, err
	}
	block, err := normalizeRawPolicyTier("block", raw.Policy.Block)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Policy: PolicyConfig{
			Inform: inform,
			Alert:  alert,
			Block:  block,
		},
		PyPIRuntime: raw.PyPIRuntime,
	}, nil
}

func normalizeRawPolicyTier(tier string, raw rawPolicyTierConfig) (PolicyTierConfig, error) {
	if err := validateGroupMap(tier, raw.Groups); err != nil {
		return PolicyTierConfig{}, err
	}

	policy := PolicyTierConfig{}
	for _, group := range supportedPolicyGroups {
		if raw.Groups[group] {
			applyGroupDefaults(tier, group, &policy)
		}
	}

	for _, check := range sortedRawKeys(raw.Checks) {
		if err := applyCheckOverride(tier, check, raw.Checks[check], &policy); err != nil {
			return PolicyTierConfig{}, err
		}
	}
	return policy, nil
}

func validateGroupMap(tier string, groups map[string]bool) error {
	if groups == nil {
		return fmt.Errorf("policy.%s.groups is required", tier)
	}
	var missing []string
	for _, group := range supportedPolicyGroups {
		if _, ok := groups[group]; !ok {
			missing = append(missing, "policy."+tier+".groups."+group)
		}
	}
	for group := range groups {
		if !supportedGroup(group) {
			return fmt.Errorf("policy.%s.groups contains unsupported group %q", tier, group)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("missing required field(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

func supportedGroup(group string) bool {
	for _, supported := range supportedPolicyGroups {
		if group == supported {
			return true
		}
	}
	return false
}

func applyGroupDefaults(tier, group string, policy *PolicyTierConfig) {
	switch group {
	case GroupReleaseMetadata:
		switch tier {
		case "inform":
			policy.MinimumDaysSinceLatestRelease = 1
			policy.DormantReleaseThresholdDays = 90
			policy.AlertOnFirstRelease = true
		case "alert":
			policy.MinimumDaysSinceLatestRelease = 3
			policy.DormantReleaseThresholdDays = 180
			policy.AlertOnFirstRelease = true
		}
	case GroupNPMLifecycle:
		switch tier {
		case "alert":
			policy.InstallLifecycleScripts = true
			policy.InstallLifecycleHistoryVersions = 5
			policy.InstallScriptAddedAfterDormancy = true
		case "block":
			policy.SuspiciousInstallScriptCommands = true
		}
	case GroupNPMDependencies:
		if tier == "alert" {
			policy.NPMDependencyHistoryVersions = 5
			policy.NPMDependencyChange = true
			policy.NPMDirectDependencyLifecycleScripts = true
			policy.NPMDirectDependencySuspiciousInstallCommands = true
			policy.NPMMaxDirectDependencies = 25
		}
	case GroupPyPIArtifacts:
		if tier == "alert" {
			policy.PyPIArtifactHistoryVersions = 5
			policy.PyPIArtifactShapeChange = true
			policy.PyPIFileSizeJumpPercent = 300
			policy.PyPIDependencyChange = true
			policy.PyPIProvenanceRequired = true
			policy.PyPIProvenanceScope = "install-target"
			policy.PyPIReleaseFileCountChange = true
		}
	case GroupSourceMetadata:
		if tier == "alert" {
			policy.NPMGitHeadMissing = true
			policy.NPMRepositoryMissing = true
			policy.NPMGitHeadChangedAfterDormancy = policy.DormantReleaseThresholdDays > 0
			policy.NPMRepositoryChanged = true
			policy.NPMPublisherChanged = true
			policy.NPMReleaseBurstCount = 3
			policy.NPMReleaseBurstWindowHours = 2
		}
	case GroupArtifactSafety:
		if tier == "block" {
			policy.ArtifactUnsafePaths = true
			policy.ArtifactMaxFileCount = 20000
			policy.ArtifactMaxUncompressedSizeMB = 1024
			policy.ArtifactMaxExpansionRatio = 100
		}
	case GroupArtifactBehavior:
		if tier == "alert" {
			policy.ArtifactExecutionSurfaces = true
			policy.ArtifactSuspiciousFileTypes = true
			policy.ArtifactBehaviorIndicators = true
			policy.ArtifactGeneralRiskSignals = true
			policy.ArtifactFileListChange = true
			policy.ArtifactNewExecutionSurfaces = true
			policy.ArtifactNewSuspiciousFileTypes = true
			policy.ArtifactSizeDelta = true
		}
	}
}

func sortedRawKeys(values map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func applyCheckOverride(tier, check string, raw json.RawMessage, policy *PolicyTierConfig) error {
	var err error
	field := "policy." + tier + ".checks." + check
	switch check {
	case "minimum_days_since_latest_release":
		policy.MinimumDaysSinceLatestRelease, err = intOrFalse(field, raw)
	case "dormant_release_threshold_days":
		policy.DormantReleaseThresholdDays, err = intOrFalse(field, raw)
	case "alert_on_first_release":
		policy.AlertOnFirstRelease, err = boolValue(field, raw)
	case "install_lifecycle_scripts":
		policy.InstallLifecycleScripts, err = boolValue(field, raw)
	case "install_lifecycle_history_versions":
		policy.InstallLifecycleHistoryVersions, err = intOrFalse(field, raw)
	case "suspicious_install_script_commands":
		policy.SuspiciousInstallScriptCommands, err = boolValue(field, raw)
	case "install_script_added_after_dormancy":
		policy.InstallScriptAddedAfterDormancy, err = boolValue(field, raw)
	case "npm_dependency_history_versions":
		policy.NPMDependencyHistoryVersions, err = intOrFalse(field, raw)
	case "npm_dependency_change":
		policy.NPMDependencyChange, err = boolValue(field, raw)
	case "npm_direct_dependency_lifecycle_scripts":
		policy.NPMDirectDependencyLifecycleScripts, err = boolValue(field, raw)
	case "npm_direct_dependency_suspicious_install_commands":
		policy.NPMDirectDependencySuspiciousInstallCommands, err = boolValue(field, raw)
	case "npm_max_direct_dependencies":
		policy.NPMMaxDirectDependencies, err = intOrFalse(field, raw)
	case "pypi_artifact_history_versions":
		policy.PyPIArtifactHistoryVersions, err = intOrFalse(field, raw)
	case "pypi_artifact_shape_change":
		policy.PyPIArtifactShapeChange, err = boolValue(field, raw)
	case "pypi_file_size_jump_percent":
		policy.PyPIFileSizeJumpPercent, err = intOrFalse(field, raw)
	case "pypi_dependency_change":
		policy.PyPIDependencyChange, err = boolValue(field, raw)
	case "pypi_provenance_required":
		policy.PyPIProvenanceRequired, err = boolValue(field, raw)
	case "pypi_provenance_scope":
		policy.PyPIProvenanceScope, err = stringOrFalse(field, raw)
	case "pypi_include_optional_dependencies":
		policy.PyPIIncludeOptionalDependencies, err = boolValue(field, raw)
	case "pypi_release_file_count_change":
		policy.PyPIReleaseFileCountChange, err = boolValue(field, raw)
	case "artifact_unsafe_paths":
		policy.ArtifactUnsafePaths, err = boolValue(field, raw)
	case "artifact_max_file_count":
		policy.ArtifactMaxFileCount, err = intOrFalse(field, raw)
	case "artifact_max_uncompressed_size_mb":
		policy.ArtifactMaxUncompressedSizeMB, err = intOrFalse(field, raw)
	case "artifact_max_expansion_ratio":
		policy.ArtifactMaxExpansionRatio, err = intOrFalse(field, raw)
	case "artifact_execution_surfaces":
		policy.ArtifactExecutionSurfaces, err = boolValue(field, raw)
	case "artifact_suspicious_file_types":
		policy.ArtifactSuspiciousFileTypes, err = boolValue(field, raw)
	case "artifact_behavior_indicators":
		policy.ArtifactBehaviorIndicators, err = boolValue(field, raw)
	case "artifact_general_risk_signals":
		policy.ArtifactGeneralRiskSignals, err = boolValue(field, raw)
	case "artifact_file_list_change":
		policy.ArtifactFileListChange, err = boolValue(field, raw)
	case "artifact_new_execution_surfaces":
		policy.ArtifactNewExecutionSurfaces, err = boolValue(field, raw)
	case "artifact_new_suspicious_file_types":
		policy.ArtifactNewSuspiciousFileTypes, err = boolValue(field, raw)
	case "artifact_size_delta":
		policy.ArtifactSizeDelta, err = boolValue(field, raw)
	case "protected_packages":
		policy.ProtectedPackages, err = ecosystemListMapOrFalse(field, raw)
	case "protected_tokens":
		policy.ProtectedTokens, err = ecosystemListMapOrFalse(field, raw)
	case "private_packages":
		policy.PrivatePackages, err = ecosystemListMapOrFalse(field, raw)
	case "npm_git_head_missing":
		policy.NPMGitHeadMissing, err = boolValue(field, raw)
	case "npm_repository_missing":
		policy.NPMRepositoryMissing, err = boolValue(field, raw)
	case "npm_git_head_changed_after_dormancy":
		policy.NPMGitHeadChangedAfterDormancy, err = boolValue(field, raw)
	case "npm_repository_changed":
		policy.NPMRepositoryChanged, err = boolValue(field, raw)
	case "npm_publisher_changed":
		policy.NPMPublisherChanged, err = boolValue(field, raw)
	case "npm_release_burst_count":
		policy.NPMReleaseBurstCount, err = intOrFalse(field, raw)
	case "npm_release_burst_window_hours":
		policy.NPMReleaseBurstWindowHours, err = intOrFalse(field, raw)
	default:
		return fmt.Errorf("policy.%s.checks contains unsupported check %q", tier, check)
	}
	return err
}

func intOrFalse(field string, raw json.RawMessage) (int, error) {
	if isJSONFalse(raw) {
		return 0, nil
	}

	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, fmt.Errorf("%s must be an integer or false", field)
	}
	return value, nil
}

func boolValue(field string, raw json.RawMessage) (bool, error) {
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, fmt.Errorf("%s must be a boolean", field)
	}
	return value, nil
}

func stringOrFalse(field string, raw json.RawMessage) (string, error) {
	if isJSONFalse(raw) {
		return "", nil
	}

	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s must be a string or false", field)
	}
	return strings.TrimSpace(value), nil
}

func ecosystemListMapOrFalse(field string, raw json.RawMessage) (map[string][]string, error) {
	if isJSONFalse(raw) {
		return map[string][]string{}, nil
	}

	var values map[string][]string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("%s must be a map or false", field)
	}
	if values == nil {
		return map[string][]string{}, nil
	}
	return values, nil
}

func isJSONFalse(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("false"))
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("configuration must contain exactly one JSON value")
}

func validatePolicyTier(tier string, policy PolicyTierConfig) error {
	if policy.MinimumDaysSinceLatestRelease < 0 {
		return fmt.Errorf("policy.%s.minimum_days_since_latest_release cannot be negative", tier)
	}
	if policy.DormantReleaseThresholdDays < 0 {
		return fmt.Errorf("policy.%s.dormant_release_threshold_days cannot be negative", tier)
	}
	if policy.InstallLifecycleHistoryVersions < 0 {
		return fmt.Errorf("policy.%s.install_lifecycle_history_versions cannot be negative", tier)
	}
	if policy.NPMDependencyHistoryVersions < 0 {
		return fmt.Errorf("policy.%s.npm_dependency_history_versions cannot be negative", tier)
	}
	if policy.NPMMaxDirectDependencies < 0 {
		return fmt.Errorf("policy.%s.npm_max_direct_dependencies cannot be negative", tier)
	}
	if policy.PyPIArtifactHistoryVersions < 0 {
		return fmt.Errorf("policy.%s.pypi_artifact_history_versions cannot be negative", tier)
	}
	if policy.PyPIFileSizeJumpPercent < 0 {
		return fmt.Errorf("policy.%s.pypi_file_size_jump_percent cannot be negative", tier)
	}
	if policy.ArtifactMaxFileCount < 0 {
		return fmt.Errorf("policy.%s.artifact_max_file_count cannot be negative", tier)
	}
	if policy.ArtifactMaxUncompressedSizeMB < 0 {
		return fmt.Errorf("policy.%s.artifact_max_uncompressed_size_mb cannot be negative", tier)
	}
	if policy.ArtifactMaxExpansionRatio < 0 {
		return fmt.Errorf("policy.%s.artifact_max_expansion_ratio cannot be negative", tier)
	}
	if policy.NPMReleaseBurstCount < 0 {
		return fmt.Errorf("policy.%s.npm_release_burst_count cannot be negative", tier)
	}
	if policy.NPMReleaseBurstWindowHours < 0 {
		return fmt.Errorf("policy.%s.npm_release_burst_window_hours cannot be negative", tier)
	}
	if policy.InstallScriptAddedAfterDormancy {
		if policy.InstallLifecycleHistoryVersions <= 0 {
			return fmt.Errorf("policy.%s.install_lifecycle_history_versions must be configured when install_script_added_after_dormancy is true", tier)
		}
		if policy.DormantReleaseThresholdDays <= 0 {
			return fmt.Errorf("policy.%s.dormant_release_threshold_days must be configured when install_script_added_after_dormancy is true", tier)
		}
	}
	npmDependencyHistoryEnabled := policy.NPMDependencyChange
	if npmDependencyHistoryEnabled && policy.NPMDependencyHistoryVersions <= 0 {
		return fmt.Errorf("policy.%s.npm_dependency_history_versions must be configured when npm_dependency_change is true", tier)
	}
	if policy.NPMDependencyHistoryVersions > 0 && !npmDependencyHistoryEnabled {
		return fmt.Errorf("policy.%s.npm_dependency_history_versions must be disabled when no history-dependent npm dependency check is enabled", tier)
	}
	npmDirectDependencyEnabled := policy.NPMDirectDependencyLifecycleScripts || policy.NPMDirectDependencySuspiciousInstallCommands
	if npmDirectDependencyEnabled && policy.NPMMaxDirectDependencies <= 0 {
		return fmt.Errorf("policy.%s.npm_max_direct_dependencies must be configured when direct npm dependency inspection is enabled", tier)
	}
	if policy.NPMMaxDirectDependencies > 0 && !npmDirectDependencyEnabled {
		return fmt.Errorf("policy.%s.npm_max_direct_dependencies must be disabled when direct npm dependency inspection is disabled", tier)
	}
	if policy.PyPIIncludeOptionalDependencies && !policy.PyPIDependencyChange {
		return fmt.Errorf("policy.%s.pypi_dependency_change must be true when pypi_include_optional_dependencies is true", tier)
	}
	historyDependentPyPIEnabled := policy.PyPIArtifactShapeChange ||
		policy.PyPIFileSizeJumpPercent > 0 ||
		policy.PyPIDependencyChange ||
		policy.PyPIReleaseFileCountChange
	if historyDependentPyPIEnabled && policy.PyPIArtifactHistoryVersions <= 0 {
		return fmt.Errorf("policy.%s.pypi_artifact_history_versions must be configured when a history-dependent PyPI check is enabled", tier)
	}
	if policy.PyPIArtifactHistoryVersions > 0 && !historyDependentPyPIEnabled {
		return fmt.Errorf("policy.%s.pypi_artifact_history_versions must be disabled when no history-dependent PyPI check is enabled", tier)
	}
	if err := validatePyPIProvenanceScope(tier, policy); err != nil {
		return err
	}
	if err := validateEcosystemListMap("policy."+tier+".protected_packages", policy.ProtectedPackages); err != nil {
		return err
	}
	if err := validateEcosystemListMap("policy."+tier+".protected_tokens", policy.ProtectedTokens); err != nil {
		return err
	}
	if err := validateEcosystemListMap("policy."+tier+".private_packages", policy.PrivatePackages); err != nil {
		return err
	}
	if policy.NPMGitHeadChangedAfterDormancy && policy.DormantReleaseThresholdDays <= 0 {
		return fmt.Errorf("policy.%s.dormant_release_threshold_days must be configured when npm_git_head_changed_after_dormancy is true", tier)
	}
	releaseBurstEnabled := policy.NPMReleaseBurstCount > 0 || policy.NPMReleaseBurstWindowHours > 0
	if releaseBurstEnabled && (policy.NPMReleaseBurstCount <= 0 || policy.NPMReleaseBurstWindowHours <= 0) {
		return fmt.Errorf("policy.%s.npm_release_burst_count and npm_release_burst_window_hours must both be configured for release burst checks", tier)
	}
	return nil
}

func validatePyPIRuntime(runtime PyPIRuntimeConfig) error {
	for field, value := range map[string]string{
		"target_platform": runtime.TargetPlatform,
		"python_version":  runtime.PythonVersion,
		"implementation":  runtime.Implementation,
	} {
		if value != "" && strings.TrimSpace(value) == "" {
			return fmt.Errorf("pypi_runtime.%s cannot be empty", field)
		}
	}
	for _, abi := range runtime.ABIs {
		if strings.TrimSpace(abi) == "" {
			return fmt.Errorf("pypi_runtime.abis contains an empty value")
		}
	}
	return nil
}

func validatePyPIProvenanceScope(tier string, policy PolicyTierConfig) error {
	switch policy.PyPIProvenanceScope {
	case "", "install-target", "all-artifacts", "sdist-only":
	default:
		return fmt.Errorf("policy.%s.pypi_provenance_scope must be false, install-target, all-artifacts, or sdist-only", tier)
	}
	if policy.PyPIProvenanceRequired && policy.PyPIProvenanceScope == "" {
		return fmt.Errorf("policy.%s.pypi_provenance_scope must be configured when pypi_provenance_required is true", tier)
	}
	if !policy.PyPIProvenanceRequired && policy.PyPIProvenanceScope != "" {
		return fmt.Errorf("policy.%s.pypi_provenance_scope must be false when pypi_provenance_required is false", tier)
	}
	return nil
}

func validateEcosystemListMap(field string, values map[string][]string) error {
	for ecosystemKey, entries := range values {
		if ecosystemKey != string(ecosystem.NPM) && ecosystemKey != string(ecosystem.PyPI) {
			return fmt.Errorf("%s contains unsupported ecosystem %q", field, ecosystemKey)
		}
		for _, entry := range entries {
			if strings.TrimSpace(entry) == "" {
				return fmt.Errorf("%s.%s contains an empty value", field, ecosystemKey)
			}
		}
	}
	return nil
}

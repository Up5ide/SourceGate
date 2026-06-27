package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
)

const DefaultPath = "sourcegate.config.json"

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
	MinimumDaysSinceLatestRelease   int                 `json:"minimum_days_since_latest_release"`
	DormantReleaseThresholdDays     int                 `json:"dormant_release_threshold_days"`
	AlertOnFirstRelease             bool                `json:"alert_on_first_release"`
	InstallLifecycleScripts         bool                `json:"install_lifecycle_scripts"`
	InstallLifecycleHistoryVersions int                 `json:"install_lifecycle_history_versions"`
	SuspiciousInstallScriptCommands bool                `json:"suspicious_install_script_commands"`
	InstallScriptAddedAfterDormancy bool                `json:"install_script_added_after_dormancy"`
	PyPIArtifactHistoryVersions     int                 `json:"pypi_artifact_history_versions"`
	PyPIArtifactShapeChange         bool                `json:"pypi_artifact_shape_change"`
	PyPIFileSizeJumpPercent         int                 `json:"pypi_file_size_jump_percent"`
	PyPIDependencyChange            bool                `json:"pypi_dependency_change"`
	PyPIProvenanceRequired          bool                `json:"pypi_provenance_required"`
	PyPIProvenanceScope             string              `json:"pypi_provenance_scope"`
	PyPIIncludeOptionalDependencies bool                `json:"pypi_include_optional_dependencies"`
	PyPIReleaseFileCountChange      bool                `json:"pypi_release_file_count_change"`
	ArtifactUnsafePaths             bool                `json:"artifact_unsafe_paths"`
	ArtifactMaxFileCount            int                 `json:"artifact_max_file_count"`
	ArtifactMaxUncompressedSizeMB   int                 `json:"artifact_max_uncompressed_size_mb"`
	ArtifactMaxExpansionRatio       int                 `json:"artifact_max_expansion_ratio"`
	ArtifactExecutionSurfaces       bool                `json:"artifact_execution_surfaces"`
	ArtifactSuspiciousFileTypes     bool                `json:"artifact_suspicious_file_types"`
	ArtifactBehaviorIndicators      bool                `json:"artifact_behavior_indicators"`
	ProtectedPackages               map[string][]string `json:"protected_packages"`
	ProtectedTokens                 map[string][]string `json:"protected_tokens"`
}

var policyTierFields = requiredJSONFields(reflect.TypeOf(PolicyTierConfig{}))

func requiredJSONFields(valueType reflect.Type) []string {
	fields := make([]string, 0, valueType.NumField())
	for index := 0; index < valueType.NumField(); index++ {
		name := strings.Split(valueType.Field(index).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	return fields
}

func (policy *PolicyTierConfig) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("policy tier must be an object: %w", err)
	}

	for field, raw := range fields {
		var err error
		switch field {
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
		case "protected_packages":
			policy.ProtectedPackages, err = ecosystemListMapOrFalse(field, raw)
		case "protected_tokens":
			policy.ProtectedTokens, err = ecosystemListMapOrFalse(field, raw)
		default:
			return fmt.Errorf("unknown policy tier field %q", field)
		}
		if err != nil {
			return err
		}
	}
	return nil
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

	if err := validateConfigCompleteness(data); err != nil {
		return Config{}, err
	}

	var config Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
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

func validateConfigCompleteness(data []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}

	var missing []string
	policyRaw, ok := root["policy"]
	if !ok {
		return fmt.Errorf("missing required field policy")
	}

	var policy map[string]json.RawMessage
	if err := json.Unmarshal(policyRaw, &policy); err != nil {
		return fmt.Errorf("policy must be an object: %w", err)
	}
	for _, tierName := range []string{"inform", "alert", "block"} {
		tierRaw, ok := policy[tierName]
		if !ok {
			missing = append(missing, "policy."+tierName)
			continue
		}
		var tier map[string]json.RawMessage
		if err := json.Unmarshal(tierRaw, &tier); err != nil {
			return fmt.Errorf("policy.%s must be an object: %w", tierName, err)
		}
		for _, field := range policyTierFields {
			if _, ok := tier[field]; !ok {
				missing = append(missing, "policy."+tierName+"."+field)
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("missing required field(s): %s", strings.Join(missing, ", "))
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
	if policy.InstallScriptAddedAfterDormancy {
		if policy.InstallLifecycleHistoryVersions <= 0 {
			return fmt.Errorf("policy.%s.install_lifecycle_history_versions must be configured when install_script_added_after_dormancy is true", tier)
		}
		if policy.DormantReleaseThresholdDays <= 0 {
			return fmt.Errorf("policy.%s.dormant_release_threshold_days must be configured when install_script_added_after_dormancy is true", tier)
		}
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

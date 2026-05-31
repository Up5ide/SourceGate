package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
)

const DefaultPath = "sourcegate.config.json"

type Config struct {
	Policy PolicyConfig `json:"policy"`
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
	PyPIReleaseFileCountChange      bool                `json:"pypi_release_file_count_change"`
	ProtectedPackages               map[string][]string `json:"protected_packages"`
	ProtectedTokens                 map[string][]string `json:"protected_tokens"`
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
		case "pypi_release_file_count_change":
			policy.PyPIReleaseFileCountChange, err = boolValue(field, raw)
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

	var config Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
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
	if err := validateEcosystemListMap("policy."+tier+".protected_packages", policy.ProtectedPackages); err != nil {
		return err
	}
	if err := validateEcosystemListMap("policy."+tier+".protected_tokens", policy.ProtectedTokens); err != nil {
		return err
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

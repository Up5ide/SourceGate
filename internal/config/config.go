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
	ProtectedPackages               map[string][]string `json:"protected_packages"`
	ProtectedTokens                 map[string][]string `json:"protected_tokens"`
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

package config

import (
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
	MinimumDaysSinceLatestRelease int                 `json:"minimum_days_since_latest_release"`
	DormantReleaseThresholdDays   int                 `json:"dormant_release_threshold_days"`
	ProtectedPackages             map[string][]string `json:"protected_packages"`
	ProtectedTokens               map[string][]string `json:"protected_tokens"`
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
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if config.Policy.MinimumDaysSinceLatestRelease < 0 {
		return Config{}, fmt.Errorf("minimum_days_since_latest_release cannot be negative")
	}
	if config.Policy.DormantReleaseThresholdDays < 0 {
		return Config{}, fmt.Errorf("dormant_release_threshold_days cannot be negative")
	}
	if err := validateEcosystemListMap("protected_packages", config.Policy.ProtectedPackages); err != nil {
		return Config{}, err
	}
	if err := validateEcosystemListMap("protected_tokens", config.Policy.ProtectedTokens); err != nil {
		return Config{}, err
	}

	return config, nil
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

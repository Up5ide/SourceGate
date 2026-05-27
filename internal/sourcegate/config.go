package sourcegate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const defaultConfigPath = "sourcegate.config.json"

type Config struct {
	Policy PolicyConfig `json:"policy"`
}

type PolicyConfig struct {
	MinimumDaysSinceLatestRelease int `json:"minimum_days_since_latest_release"`
}

func LoadConfig(path string) (Config, error) {
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

	return config, nil
}

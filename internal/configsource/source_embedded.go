//go:build embedded_config

package configsource

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/config"
)

//go:embed sourcegate.config.json
var embeddedConfigData []byte

func Mode() string {
	return ModeEmbedded
}

func AcceptsExternalConfig() bool {
	return false
}

func AcceptedInputs() string {
	return "embedded config only; external config files are rejected"
}

func Load(path string) (config.Config, error) {
	if strings.TrimSpace(path) != "" {
		return config.Config{}, fmt.Errorf("embedded config build does not accept --config")
	}
	cfg, err := config.LoadBytes(embeddedConfigData)
	if err != nil {
		return config.Config{}, fmt.Errorf("parse embedded config: %w", err)
	}
	return cfg, nil
}

func PrintStatus(path string) Status {
	status := Status{
		ConfigMode:            Mode(),
		AcceptsExternalConfig: AcceptsExternalConfig(),
		Exists:                true,
	}
	sum := sha256.Sum256(embeddedConfigData)
	status.SHA256 = hex.EncodeToString(sum[:])

	if strings.TrimSpace(path) != "" {
		status.Valid = false
		status.Error = "embedded config build does not accept --config"
		return status
	}

	cfg, err := config.LoadBytes(embeddedConfigData)
	if err != nil {
		status.Valid = false
		status.Error = err.Error()
		return status
	}
	status.Valid = true
	status.Config = &cfg
	return status
}

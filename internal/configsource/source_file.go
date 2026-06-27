//go:build !embedded_config

package configsource

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"github.com/sourcegate/sourcegate/internal/config"
)

func Mode() string {
	return ModeFile
}

func AcceptsExternalConfig() bool {
	return true
}

func AcceptedInputs() string {
	return config.DefaultPath + " from the current working directory, or --config <path>"
}

func Load(path string) (config.Config, error) {
	if strings.TrimSpace(path) == "" {
		return config.Load(config.DefaultPath)
	}
	return config.LoadRequired(path)
}

func PrintStatus(path string) Status {
	effectivePath := strings.TrimSpace(path)
	defaultPath := effectivePath == ""
	if defaultPath {
		effectivePath = config.DefaultPath
	}
	status := Status{
		ConfigMode:            Mode(),
		AcceptsExternalConfig: AcceptsExternalConfig(),
		ConfigPath:            effectivePath,
		DefaultPath:           defaultPath,
	}

	data, err := os.ReadFile(effectivePath)
	if errors.Is(err, os.ErrNotExist) {
		status.Exists = false
		if defaultPath {
			cfg := config.Config{}
			status.Valid = true
			status.Config = &cfg
		} else {
			status.Valid = false
			status.Error = "config file not found"
		}
		return status
	}
	if err != nil {
		status.Exists = false
		status.Valid = false
		status.Error = err.Error()
		return status
	}

	status.Exists = true
	sum := sha256.Sum256(data)
	status.SHA256 = hex.EncodeToString(sum[:])
	cfg, err := config.LoadBytes(data)
	if err != nil {
		status.Valid = false
		status.Error = err.Error()
		return status
	}
	status.Valid = true
	status.Config = &cfg
	return status
}

package configsource

import "github.com/sourcegate/sourcegate/internal/config"

const (
	ModeFile     = "file"
	ModeEmbedded = "embedded"
)

type Status struct {
	ConfigMode            string         `json:"config_mode"`
	AcceptsExternalConfig bool           `json:"accepts_external_config"`
	ConfigPath            string         `json:"config_path,omitempty"`
	DefaultPath           bool           `json:"default_path,omitempty"`
	Preset                string         `json:"preset,omitempty"`
	Exists                bool           `json:"exists"`
	Valid                 bool           `json:"valid"`
	Error                 string         `json:"error,omitempty"`
	SHA256                string         `json:"sha256,omitempty"`
	Config                *config.Config `json:"config,omitempty"`
}

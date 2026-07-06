package config

import (
	"encoding/json"
	"fmt"
	"sort"
)

const (
	PresetMinimal  = "minimal"
	PresetBalanced = "balanced"
	PresetStrict   = "strict"

	PresetFormatCompact = "compact"
	PresetFormatFull    = "full"
)

var presetInputs = map[string]string{
	PresetMinimal: `{
  "policy": {
    "inform": {
      "groups": {
        "release_metadata": true
      }
    }
  }
}`,
	PresetBalanced: `{
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
        "protected_packages": {
          "npm": ["react", "lodash", "@tanstack/react-query"],
          "pypi": ["requests", "django"]
        }
      }
    },
    "block": {
      "groups": {
        "npm_lifecycle": true,
        "artifact_safety": true
      }
    }
  }
}`,
	PresetStrict: `{
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
      }
    },
    "block": {
      "groups": {
        "npm_lifecycle": true,
        "artifact_safety": true
      },
      "checks": {
        "artifact_behavior_indicators": true,
        "artifact_suspicious_file_types": true
      }
    }
  }
}`,
}

func PresetNames() []string {
	names := make([]string, 0, len(presetInputs))
	for name := range presetInputs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func LoadPreset(name string) (Config, error) {
	input, ok := presetInputs[name]
	if !ok {
		return Config{}, fmt.Errorf("unsupported preset %q: supported presets are minimal, balanced, and strict", name)
	}
	cfg, err := LoadBytes([]byte(input))
	if err != nil {
		return Config{}, fmt.Errorf("parse preset %s: %w", name, err)
	}
	return cfg, nil
}

func PresetJSON(name, format string) ([]byte, error) {
	input, ok := presetInputs[name]
	if !ok {
		return nil, fmt.Errorf("unsupported preset %q: supported presets are minimal, balanced, and strict", name)
	}
	switch format {
	case "", PresetFormatCompact:
		return []byte(input + "\n"), nil
	case PresetFormatFull:
		cfg, err := LoadPreset(name)
		if err != nil {
			return nil, err
		}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	default:
		return nil, fmt.Errorf("unsupported preset format %q: supported formats are compact and full", format)
	}
}

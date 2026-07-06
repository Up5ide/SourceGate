# SourceGate Configuration

SourceGate config is intentionally explicit: if a group or check is not present in the active config, it is disabled. Presets are available as starting points, but they are not hidden inheritance.

## Quick Start

Use a preset directly for one run:

```bash
sourcegate --preset balanced npm install lodash
sourcegate --preset strict --mode artifact pip install requests
```

Generate a config from a preset:

```bash
sourcegate config preset balanced > sourcegate.config.json
sourcegate config preset strict --format full > strict.full.json
```

Validate and inspect config without registry access:

```bash
sourcegate config test
sourcegate config test --config ./strict.json
sourcegate config explain
sourcegate --print-config
```

`config explain` prints a short human summary. `--print-config` prints JSON status and the normalized policy that SourceGate evaluates.

## Mental Model

Configuration has three layers:

- Presets choose a starting point when explicitly used.
- Groups enable broad behavior for a tier.
- Checks tune exact behavior inside a tier.

Policy has three tiers:

- `inform`: low-noise visibility.
- `alert`: warning-level findings.
- `block`: block-level findings, decision `BLOCK`, and exit code `30`.

Checks evaluate from strongest to weakest: `block`, then `alert`, then `inform`. If the same check matches multiple tiers, only the strongest finding is reported. This lets one rule appear in multiple tiers with different thresholds.

## Override-Only Config

Config files may omit `policy`, tiers, `groups`, group keys, and `checks`. Omitted values are disabled.

This is a valid disabled config:

```json
{}
```

This enables only alert-level npm lifecycle defaults:

```json
{
  "policy": {
    "alert": {
      "groups": {
        "npm_lifecycle": true
      }
    }
  }
}
```

This enables a single advanced check without enabling the whole group:

```json
{
  "policy": {
    "block": {
      "checks": {
        "suspicious_install_script_commands": true
      }
    }
  }
}
```

Complete grouped configs from earlier versions are still accepted. Unknown fields, unknown groups, unknown checks, invalid value types, and invalid companion settings are rejected.

## Supported Groups

| Group | Purpose |
| --- | --- |
| `release_metadata` | Release age, dormant release, and first-release checks. |
| `name_protection` | Protected package, protected token, and private/internal package public-registry checks. |
| `npm_lifecycle` | npm lifecycle script, suspicious command, history, and dormant-addition checks. |
| `npm_dependencies` | npm dependency name history and bounded direct dependency lifecycle metadata checks. |
| `pypi_artifacts` | PyPI artifact history, shape, size, dependency, provenance, and file-count checks. |
| `source_metadata` | npm registry source, publisher, and release-burst metadata checks. |
| `artifact_safety` | Artifact unsafe path, file-count, uncompressed-size, and expansion-ratio checks. |
| `artifact_behavior` | Artifact execution-surface, suspicious file-type, behavior-indicator, general risk, and artifact-delta checks. |

Artifact groups only produce findings when the command runs with `--mode artifact` or `--mode install`.

## Checked-In Balanced Config

```json
{
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
}
```

## Presets

`minimal` is a low-noise local-development baseline:

```json
{
  "policy": {
    "inform": {
      "groups": {
        "release_metadata": true
      }
    }
  }
}
```

`balanced` is the recommended default and matches the checked-in config.

`strict` is a CI-oriented baseline with more block-level high-confidence artifact behavior:

```json
{
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
}
```

## Common Changes

Add protected public packages:

```json
{
  "policy": {
    "alert": {
      "checks": {
        "protected_packages": {
          "npm": ["react", "lodash"],
          "pypi": ["requests", "django"]
        }
      }
    }
  }
}
```

Block public-registry resolution of private package names:

```json
{
  "policy": {
    "block": {
      "checks": {
        "private_packages": {
          "npm": ["@company/internal-core"],
          "pypi": ["company-internal-core"]
        }
      }
    }
  }
}
```

Disable noisy PyPI provenance alerts while keeping other PyPI artifact checks:

```json
{
  "policy": {
    "alert": {
      "groups": {
        "pypi_artifacts": true
      },
      "checks": {
        "pypi_provenance_required": false,
        "pypi_provenance_scope": false
      }
    }
  }
}
```

Use different thresholds for the same rule:

```json
{
  "policy": {
    "alert": {
      "checks": {
        "artifact_max_file_count": 10000
      }
    },
    "block": {
      "checks": {
        "artifact_max_file_count": 20000
      }
    }
  }
}
```

Enable artifact behavior alerts:

```json
{
  "policy": {
    "alert": {
      "groups": {
        "artifact_behavior": true
      }
    }
  }
}
```

Run artifact policy with:

```bash
sourcegate --mode artifact npm install lodash
```

## Check Overrides

`checks` uses detailed check names. Boolean checks accept `true` or `false`. Numeric threshold checks accept a non-negative integer or `false`. Map checks accept a map or `false`. `pypi_provenance_scope` accepts `install-target`, `all-artifacts`, `sdist-only`, or `false`.

Common override names include:

| Check | Value type |
| --- | --- |
| `minimum_days_since_latest_release` | integer or `false` |
| `dormant_release_threshold_days` | integer or `false` |
| `alert_on_first_release` | boolean |
| `install_lifecycle_scripts` | boolean |
| `install_lifecycle_history_versions` | integer or `false` |
| `suspicious_install_script_commands` | boolean |
| `install_script_added_after_dormancy` | boolean |
| `npm_dependency_history_versions` | integer or `false` |
| `npm_dependency_change` | boolean |
| `npm_direct_dependency_lifecycle_scripts` | boolean |
| `npm_direct_dependency_suspicious_install_commands` | boolean |
| `npm_max_direct_dependencies` | integer or `false` |
| `pypi_artifact_history_versions` | integer or `false` |
| `pypi_artifact_shape_change` | boolean |
| `pypi_file_size_jump_percent` | integer or `false` |
| `pypi_dependency_change` | boolean |
| `pypi_provenance_required` | boolean |
| `pypi_provenance_scope` | string or `false` |
| `pypi_include_optional_dependencies` | boolean |
| `pypi_release_file_count_change` | boolean |
| `artifact_unsafe_paths` | boolean |
| `artifact_max_file_count` | integer or `false` |
| `artifact_max_uncompressed_size_mb` | integer or `false` |
| `artifact_max_expansion_ratio` | integer or `false` |
| `artifact_execution_surfaces` | boolean |
| `artifact_suspicious_file_types` | boolean |
| `artifact_behavior_indicators` | boolean |
| `artifact_general_risk_signals` | boolean |
| `artifact_file_list_change` | boolean |
| `artifact_new_execution_surfaces` | boolean |
| `artifact_new_suspicious_file_types` | boolean |
| `artifact_size_delta` | boolean |
| `protected_packages` | map or `false` |
| `protected_tokens` | map or `false` |
| `private_packages` | map or `false` |
| `npm_git_head_missing` | boolean |
| `npm_repository_missing` | boolean |
| `npm_git_head_changed_after_dormancy` | boolean |
| `npm_repository_changed` | boolean |
| `npm_publisher_changed` | boolean |
| `npm_release_burst_count` | integer or `false` |
| `npm_release_burst_window_hours` | integer or `false` |

## PyPI Runtime Defaults

The optional top-level `pypi_runtime` block stores harmless install-target defaults:

| Option | Accepted value type |
| --- | --- |
| `target_platform` | string |
| `python_version` | string |
| `implementation` | string |
| `abis` | string array |

CLI prefix flags override matching defaults:

```bash
sourcegate --mode artifact --python python --target-platform linux_x86_64 --python-version 3.12 --implementation cp --abi cp312 pip install cryptography
```

Configuration files cannot select a Python executable because a repository-controlled path would introduce local code execution during inspection.

## Validation

Use `sourcegate config test` before committing or compiling a config. SourceGate rejects:

- unknown top-level fields, tiers, groups, and checks.
- old flat tier keys.
- invalid value types.
- negative threshold values.
- unsupported `protected_packages`, `protected_tokens`, or `private_packages` ecosystem keys.
- empty configured package or token names.
- incompatible companion settings, such as dependency history without a dependency-change check.
- `pypi_provenance_scope` without `pypi_provenance_required`.

In relaxed file-config mode, a missing default `sourcegate.config.json` is allowed and means all policy is disabled. A missing explicit `--config <path>` is an operational error. Embedded builds use the compiled-in config and reject external config paths.

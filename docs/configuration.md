# SourceGate Configuration

SourceGate reads `sourcegate.config.json` from the current working directory.

Configuration is organized under `policy` with three independent tiers:

- `inform`: low-noise visibility.
- `alert`: stronger warning-level findings.
- `block`: reported block-level findings. This is currently a finding level only; SourceGate still does not install or block a real package-manager operation.

SourceGate evaluates policy tiers from strongest to weakest for each check: `block`, then `alert`, then `inform`. If the same check matches multiple tiers, only the strongest matching tier is reported.

When adding a new policy option, add it to all three tiers. A tier can disable any option with literal `false`, and the key should still be present in `inform`, `alert`, and `block`.

For non-boolean options, `false` is normalized to that option's neutral value when SourceGate loads the config:

- integer options become `0`
- map options become `{}`
- boolean options remain `false`

If an option is `false`, SourceGate does not run the rule controlled by that option.

## Current Example

```json
{
  "policy": {
    "inform": {
      "minimum_days_since_latest_release": 1,
      "dormant_release_threshold_days": 90,
      "alert_on_first_release": true,
      "install_lifecycle_scripts": false,
      "install_lifecycle_history_versions": false,
      "suspicious_install_script_commands": false,
      "install_script_added_after_dormancy": false,
      "pypi_artifact_history_versions": false,
      "pypi_artifact_shape_change": false,
      "pypi_file_size_jump_percent": false,
      "pypi_dependency_change": false,
      "pypi_provenance_required": false,
      "pypi_release_file_count_change": false,
      "protected_packages": false,
      "protected_tokens": false
    },
    "alert": {
      "minimum_days_since_latest_release": 3,
      "dormant_release_threshold_days": 180,
      "alert_on_first_release": true,
      "install_lifecycle_scripts": true,
      "install_lifecycle_history_versions": 5,
      "suspicious_install_script_commands": false,
      "install_script_added_after_dormancy": true,
      "pypi_artifact_history_versions": 5,
      "pypi_artifact_shape_change": true,
      "pypi_file_size_jump_percent": 300,
      "pypi_dependency_change": true,
      "pypi_provenance_required": true,
      "pypi_release_file_count_change": true,
      "protected_packages": {
        "npm": ["react", "lodash", "@tanstack/react-query"],
        "pypi": ["requests", "django"]
      },
      "protected_tokens": {
        "npm": ["tanstack", "aws", "babel"],
        "pypi": ["django", "pytest"]
      }
    },
    "block": {
      "minimum_days_since_latest_release": false,
      "dormant_release_threshold_days": false,
      "alert_on_first_release": false,
      "install_lifecycle_scripts": false,
      "install_lifecycle_history_versions": false,
      "suspicious_install_script_commands": true,
      "install_script_added_after_dormancy": false,
      "pypi_artifact_history_versions": false,
      "pypi_artifact_shape_change": false,
      "pypi_file_size_jump_percent": false,
      "pypi_dependency_change": false,
      "pypi_provenance_required": false,
      "pypi_release_file_count_change": false,
      "protected_packages": false,
      "protected_tokens": false
    }
  }
}
```

## Option Types

| Option | Accepted value type | Notes |
| --- | --- | --- |
| `minimum_days_since_latest_release` | integer or `false` | Number of days the latest release must age before the finding stops matching. |
| `dormant_release_threshold_days` | integer or `false` | Number of inactive days that makes a latest release count as dormant. |
| `alert_on_first_release` | boolean | `true` enables first-release findings; `false` disables them. |
| `install_lifecycle_scripts` | boolean | `true` enables npm declared lifecycle script findings. |
| `install_lifecycle_history_versions` | integer or `false` | Number of previous npm versions to compare; `false` disables history comparison. |
| `suspicious_install_script_commands` | boolean | `true` enables suspicious npm script command pattern findings. |
| `install_script_added_after_dormancy` | boolean | `true` enables dormant-release npm lifecycle addition findings. |
| `pypi_artifact_history_versions` | integer or `false` | Number of previous PyPI releases to compare; `false` disables history-dependent PyPI checks. |
| `pypi_artifact_shape_change` | boolean | `true` enables PyPI artifact shape change findings. |
| `pypi_file_size_jump_percent` | integer or `false` | Percentage threshold for size jumps; `false` disables size-jump checks. |
| `pypi_dependency_change` | boolean | `true` enables PyPI dependency change findings. |
| `pypi_provenance_required` | boolean | `true` requires latest PyPI release file provenance to be available. |
| `pypi_release_file_count_change` | boolean | `true` enables PyPI release file count change findings. |
| `protected_packages` | map or `false` | Map keyed by ecosystem; `false` disables protected package checks for the tier. |
| `protected_tokens` | map or `false` | Map keyed by ecosystem; `false` disables protected token checks for the tier. |

## Release Timing

`minimum_days_since_latest_release` emits a finding when the latest registry release is newer than the configured number of days. This reduces exposure to fast-moving compromise windows where a malicious version may be published and installed before detection.

`dormant_release_threshold_days` emits a finding when the latest release follows a long period of package inactivity. For example, `180` means SourceGate reports when the previous release was at least 180 days before the latest release.

`alert_on_first_release` emits a finding when the package has only one published version.

## npm Lifecycle Checks

These checks use npm registry metadata only. SourceGate does not download archives and does not execute lifecycle scripts.

`install_lifecycle_scripts` emits npm-only findings when the latest package metadata declares install-relevant lifecycle scripts such as `preinstall`, `install`, `postinstall`, `prepublish`, `prepare`, `preprepare`, or `postprepare`.

`install_lifecycle_history_versions` controls how many previous npm versions are compared when detecting newly added or changed lifecycle scripts.

`suspicious_install_script_commands` emits npm-only findings when declared lifecycle script commands contain suspicious metadata-visible patterns such as direct URLs, network download commands, shell or command interpreters, native build tooling, package-manager invocation, or permission-changing commands.

`install_script_added_after_dormancy` emits npm-only findings when the latest release adds a lifecycle script after the same tier's configured `dormant_release_threshold_days` period.

## PyPI Artifact And Provenance Checks

These checks use PyPI metadata, release-file metadata, version-specific metadata, and the PyPI Integrity API when provenance checks are enabled. SourceGate still does not download package archives.

`pypi_artifact_history_versions` controls how many previous PyPI releases are compared for artifact and dependency metadata checks.

`pypi_artifact_shape_change` emits PyPI-only findings when the latest release changes artifact package types, removes wheels, becomes source-only, adds or removes sdists, or introduces new wheel platform tags.

`pypi_file_size_jump_percent` emits PyPI-only findings when the latest release total size or largest file size reaches the configured percentage of the historical median.

`pypi_dependency_change` emits PyPI-only findings when release metadata shows added or removed declared dependency names. If dependency metadata is unavailable or dynamic, SourceGate reports that the change cannot be confirmed.

`pypi_provenance_required` emits PyPI-only findings when the PyPI Integrity API reports missing provenance for latest-release files or provenance availability cannot be confirmed.

`pypi_release_file_count_change` emits PyPI-only findings when the latest release file count differs from the historical median.

## Name Protection

`protected_packages` emits findings on one-edit lookalikes of configured package names. Exact matches do not create findings.

`protected_tokens` emits findings when a package uses a protected token as a separated name part, such as `tanstack-query-utils`. It does not alert on embedded strings such as `mytanstackhelper`.

Both maps are keyed by ecosystem. Supported keys are `npm` and `pypi`.

## Validation

SourceGate rejects unknown config fields.

Numeric threshold values accept non-negative integers or `false`; negative values are rejected:

- `minimum_days_since_latest_release`
- `dormant_release_threshold_days`
- `install_lifecycle_history_versions`
- `pypi_artifact_history_versions`
- `pypi_file_size_jump_percent`

`protected_packages` and `protected_tokens` only accept `npm` and `pypi` ecosystem keys, and entries cannot be empty strings.

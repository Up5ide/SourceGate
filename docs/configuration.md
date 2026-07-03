# SourceGate Configuration

SourceGate supports two config modes:

- Relaxed file config is the default build. It reads `sourcegate.config.json` from the current working directory, or a custom path passed with `--config <path>`.
- Strict embedded config is built with `go build -tags embedded_config ./cmd/sourcegate`. It uses the config compiled into the binary and rejects `--config <path>`.

In relaxed file-config mode, a missing default `sourcegate.config.json` is allowed and means all policy is disabled. A missing explicit `--config <path>` is an operational error.

SourceGate 0.8.2 uses a grouped policy config. Old flat tier configs from 0.8.0 and earlier are rejected. A present file config, explicit config, or embedded config must be one complete JSON value containing `policy`, all three tiers, and every supported group key in each tier.

Use `sourcegate --print-config` to print JSON config status. The printed effective config is the normalized policy that SourceGate evaluates, so it may show detailed check values rather than the exact grouped input.

## Policy Tiers

Configuration is organized under `policy` with three independent tiers:

- `inform`: low-noise visibility.
- `alert`: stronger warning-level findings.
- `block`: block-level findings. These set the report decision to `BLOCK` and return CI exit code `30`; SourceGate still does not install or block a real package-manager operation.

SourceGate evaluates policy tiers from strongest to weakest for each check: `block`, then `alert`, then `inform`. If the same check matches multiple tiers, only the strongest matching tier is reported.

Each tier has:

- `groups`: required map of all supported groups to `true` or `false`.
- `checks`: optional map of detailed check overrides.

Group values apply tier defaults. Explicit `checks` values always win over group defaults, including `false`.

Supported groups:

| Group | Purpose |
| --- | --- |
| `release_metadata` | Release age, dormant release, and first-release checks. |
| `name_protection` | Protected package, protected token, and private/internal package public-registry checks. |
| `npm_lifecycle` | npm lifecycle script, suspicious command, history, and dormant-addition checks. |
| `npm_dependencies` | npm dependency name history and bounded direct dependency lifecycle metadata checks. |
| `pypi_artifacts` | PyPI artifact history, shape, size, dependency, provenance, and file-count checks. |
| `source_metadata` | npm registry source, publisher, and release-burst metadata checks. |
| `artifact_safety` | Artifact unsafe path, file-count, uncompressed-size, and expansion-ratio checks. |
| `artifact_behavior` | Artifact execution-surface, suspicious file-type, behavior-indicator, general path/manifest risk, and artifact-delta checks. |

## Current Example

```json
{
  "policy": {
    "inform": {
      "groups": {
        "release_metadata": true,
        "name_protection": false,
        "npm_lifecycle": false,
        "npm_dependencies": false,
        "pypi_artifacts": false,
        "source_metadata": false,
        "artifact_safety": false,
        "artifact_behavior": false
      },
      "checks": {}
    },
    "alert": {
      "groups": {
        "release_metadata": true,
        "name_protection": true,
        "npm_lifecycle": true,
        "npm_dependencies": true,
        "pypi_artifacts": true,
        "source_metadata": true,
        "artifact_safety": false,
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
        "release_metadata": false,
        "name_protection": false,
        "npm_lifecycle": true,
        "npm_dependencies": false,
        "pypi_artifacts": false,
        "source_metadata": false,
        "artifact_safety": true,
        "artifact_behavior": false
      },
      "checks": {}
    }
  }
}
```

The checked-in config keeps release metadata checks in `inform` and `alert`, blocks suspicious npm install commands, blocks hard archive safety failures, and alerts on npm dependency/source metadata, PyPI artifact/provenance changes, artifact behavior signals, general artifact risk signals, and artifact deltas.

## Check Overrides

`checks` uses the same detailed check names that appear in debug traces and the normalized `--print-config` output. For non-boolean options, literal `false` disables the option:

- integer options become `0`
- map options become `{}`
- string scope options become an empty disabled value
- boolean options remain `false`

Example: keep the alert-tier npm lifecycle group enabled, but disable only suspicious lifecycle commands in that tier:

```json
{
  "policy": {
    "alert": {
      "groups": {
        "release_metadata": false,
        "name_protection": false,
        "npm_lifecycle": true,
        "npm_dependencies": false,
        "pypi_artifacts": false,
        "source_metadata": false,
        "artifact_safety": false,
        "artifact_behavior": false
      },
      "checks": {
        "suspicious_install_script_commands": false
      }
    }
  }
}
```

The full config must still include `inform`, `alert`, and `block`; the snippet above shows only the relevant tier.

Accepted check overrides:

| Check | Accepted value type | Notes |
| --- | --- | --- |
| `minimum_days_since_latest_release` | integer or `false` | Number of days the selected release must age before the finding stops matching. |
| `dormant_release_threshold_days` | integer or `false` | Number of inactive days that makes a selected release count as dormant. |
| `alert_on_first_release` | boolean | `true` enables first-release findings. |
| `install_lifecycle_scripts` | boolean | `true` enables npm declared lifecycle script findings. |
| `install_lifecycle_history_versions` | integer or `false` | Number of previous npm versions available for immediate-release comparison and reintroduction context. |
| `suspicious_install_script_commands` | boolean | `true` enables suspicious npm script command pattern findings. |
| `install_script_added_after_dormancy` | boolean | `true` enables dormant-release npm lifecycle addition findings. |
| `npm_dependency_history_versions` | integer or `false` | Number of previous npm versions used for dependency-name comparison evidence. |
| `npm_dependency_change` | boolean | `true` enables selected-vs-immediate-previous npm dependency name change findings. |
| `npm_direct_dependency_lifecycle_scripts` | boolean | `true` inspects selected direct `dependencies` and `optionalDependencies` for lifecycle scripts. |
| `npm_direct_dependency_suspicious_install_commands` | boolean | `true` inspects selected direct `dependencies` and `optionalDependencies` for suspicious lifecycle command metadata. |
| `npm_max_direct_dependencies` | integer or `false` | Maximum direct npm dependencies inspected; overflow is reported as indeterminate evidence. |
| `pypi_artifact_history_versions` | integer or `false` | Number of previous PyPI releases to compare. |
| `pypi_artifact_shape_change` | boolean | `true` enables PyPI artifact shape change findings. |
| `pypi_file_size_jump_percent` | integer or `false` | Percentage increase threshold for size jumps. |
| `pypi_dependency_change` | boolean | `true` enables PyPI dependency change findings. |
| `pypi_provenance_required` | boolean | `true` requires selected PyPI release file provenance to be available. |
| `pypi_provenance_scope` | string or `false` | Required with `pypi_provenance_required`; accepts `install-target`, `all-artifacts`, or `sdist-only`. |
| `pypi_include_optional_dependencies` | boolean | Include PyPI optional `extra` dependency names in dependency-change evaluation. |
| `pypi_release_file_count_change` | boolean | `true` enables PyPI release file count change findings. |
| `artifact_unsafe_paths` | boolean | `true` enables unsafe archive path findings during `--mode artifact`. |
| `artifact_max_file_count` | integer or `false` | Maximum regular file count in the inspected archive. |
| `artifact_max_uncompressed_size_mb` | integer or `false` | Maximum total uncompressed archive size in MiB. |
| `artifact_max_expansion_ratio` | integer or `false` | Maximum archive expansion ratio when ratio evaluation applies. |
| `artifact_execution_surfaces` | boolean | `true` enables install/build execution-surface findings during `--mode artifact`. |
| `artifact_suspicious_file_types` | boolean | `true` enables native/executable file type findings during `--mode artifact`. |
| `artifact_behavior_indicators` | boolean | `true` enables suspicious behavior indicator findings during `--mode artifact`. |
| `artifact_general_risk_signals` | boolean | `true` enables general path and manifest metadata risk signal findings during `--mode artifact`. |
| `artifact_file_list_change` | boolean | `true` enables selected-vs-immediate-previous artifact file-list delta findings during `--mode artifact`. |
| `artifact_new_execution_surfaces` | boolean | `true` enables findings for execution surfaces newly added since the previous artifact. |
| `artifact_new_suspicious_file_types` | boolean | `true` enables findings for suspicious native/executable file types newly added since the previous artifact. |
| `artifact_size_delta` | boolean | `true` enables file-count and uncompressed-size delta findings. |
| `protected_packages` | map or `false` | Map keyed by ecosystem; `false` disables protected package checks for the tier. |
| `protected_tokens` | map or `false` | Map keyed by ecosystem; `false` disables protected token checks for the tier. |
| `private_packages` | map or `false` | Map keyed by ecosystem; exact configured private/internal package names resolved from public registries produce findings. |
| `npm_git_head_missing` | boolean | `true` enables findings when selected npm version metadata lacks `gitHead`. |
| `npm_repository_missing` | boolean | `true` enables findings when npm registry metadata lacks a repository URL. |
| `npm_git_head_changed_after_dormancy` | boolean | `true` enables findings when npm `gitHead` changes after the same tier's dormancy threshold. |
| `npm_repository_changed` | boolean | `true` enables findings when npm repository URL metadata changes from the immediate previous release. |
| `npm_publisher_changed` | boolean | `true` enables findings when npm `_npmUser` publisher metadata changes from the immediate previous release. |
| `npm_release_burst_count` | integer or `false` | Release count threshold for npm release-burst findings. |
| `npm_release_burst_window_hours` | integer or `false` | Hour window paired with `npm_release_burst_count`. |

## Check Behavior

`minimum_days_since_latest_release` emits a finding when the selected registry release is newer than the configured number of days.

`dormant_release_threshold_days` emits a finding when the selected release follows a long period of package inactivity.

`alert_on_first_release` emits a finding when the package has only one published version.

`install_lifecycle_scripts` emits npm-only findings when selected package metadata declares install-relevant lifecycle scripts such as `preinstall`, `install`, `postinstall`, `prepublish`, `prepare`, `preprepare`, or `postprepare`.

`install_lifecycle_history_versions` controls how much previous npm metadata is available. Added and changed scripts are determined against the immediate previous eligible release. Older releases are used only to label a script as reintroduced instead of newly added.

`suspicious_install_script_commands` emits npm-only findings when lifecycle script commands contain suspicious metadata-visible patterns such as direct URLs, network download commands, shell interpreters, native build tooling, package-manager invocation, or permission-changing commands.

`install_script_added_after_dormancy` emits npm-only findings when the selected release adds or reintroduces a lifecycle script after the same tier's configured dormancy threshold.

`npm_dependency_change` compares selected npm dependency names with the immediate previous eligible release. It compares dependency names grouped by `dependencies`, `optionalDependencies`, `peerDependencies`, and `devDependencies`; version-range changes are not findings in the first implementation.

`npm_direct_dependency_lifecycle_scripts` and `npm_direct_dependency_suspicious_install_commands` fetch public npm metadata for selected direct `dependencies` and `optionalDependencies` only. They do not recurse. Exact semver ranges select that exact version; non-exact ranges use the dependency package's `latest` metadata and record that limitation in debug evidence. `npm_max_direct_dependencies` bounds registry fetches.

`private_packages` is an exact-name policy for public-registry resolution of configured private/internal package names. It uses the same ecosystem normalization as protected package names.

`npm_git_head_missing`, `npm_repository_missing`, `npm_git_head_changed_after_dormancy`, `npm_repository_changed`, `npm_publisher_changed`, and `npm_release_burst_*` use npm registry metadata only. They do not fetch GitHub, verify tags, compare source archives, or claim maintainer compromise.

`pypi_artifact_shape_change`, `pypi_file_size_jump_percent`, `pypi_dependency_change`, `pypi_provenance_required`, and `pypi_release_file_count_change` inspect PyPI release-file metadata, version-specific metadata, dependencies, and Integrity API provenance where enabled.

When `pypi_provenance_scope` is `install-target`, SourceGate runs local `<python> -m pip debug --verbose` to resolve Python compatibility tags. It does not install packages. If tag inspection fails, compatible-wheel provenance is marked indeterminate and source-distribution provenance remains checkable.

Artifact checks run only with `--mode artifact`, after the selected artifact is downloaded to a temporary file and its registry digest is verified. SourceGate reads archive metadata without extracting files, executing code, invoking package managers, or following links. If artifact policy is enabled but the command runs in metadata mode, output includes a warning and JSON includes `report.evaluation_mode`.

Artifact general risk signals are limited to archive paths and package manifest/install metadata already read by artifact inspection, such as sensitive config filenames, CI workflow paths, startup/service-like paths, insecure HTTP URLs, and direct IP URLs. Artifact delta checks compare the selected artifact with the immediate previous comparable artifact by normalized file paths, newly added execution surfaces, newly added suspicious native/executable file types, file count, and uncompressed size.

## PyPI Runtime Defaults

The optional top-level `pypi_runtime` block stores harmless install-target defaults:

| Option | Accepted value type | Notes |
| --- | --- | --- |
| `target_platform` | string | Pip-compatible platform such as `linux_x86_64`, `win_amd64`, or `macosx_11_0_arm64`. |
| `python_version` | string | Target Python version passed to `pip debug`. |
| `implementation` | string | Target Python implementation passed to `pip debug`. |
| `abis` | string array | ABI values passed to `pip debug`. |

CLI prefix flags override matching defaults:

```bash
sourcegate --mode artifact --python python --target-platform linux_x86_64 --python-version 3.12 --implementation cp --abi cp312 pip install cryptography
```

`--abi` may be repeated. CLI ABI values replace the configured ABI list. SourceGate intentionally does not allow configuration files to select a Python executable because a repository-controlled path would introduce local code execution during inspection.

## Validation

SourceGate accepts an absent default config file in relaxed mode as disabled policy. A present config, an explicit `--config <path>`, and an embedded config must be one complete JSON value and include `policy`, `inform`, `alert`, `block`, and every supported group key in each tier. SourceGate rejects partial configs, unknown groups, unknown check overrides, old flat tier keys, and unknown top-level fields.

Numeric threshold values accept non-negative integers or `false`; negative values are rejected.

`protected_packages`, `protected_tokens`, and `private_packages` only accept `npm` and `pypi` ecosystem keys, and entries cannot be empty strings.

Each tier must set `pypi_provenance_scope` to `false` or omit the check when `pypi_provenance_required` resolves to `false`. When provenance is required, the tier must configure one supported scope.

Companion settings are validated within the same tier:

- `install_script_added_after_dormancy` requires positive `install_lifecycle_history_versions` and `dormant_release_threshold_days`.
- `npm_dependency_change` requires positive `npm_dependency_history_versions`.
- Positive `npm_dependency_history_versions` requires `npm_dependency_change`.
- Direct npm dependency checks require positive `npm_max_direct_dependencies`.
- Positive `npm_max_direct_dependencies` requires at least one direct npm dependency check.
- `npm_git_head_changed_after_dormancy` requires positive `dormant_release_threshold_days`.
- `npm_release_burst_count` and `npm_release_burst_window_hours` must be configured together.
- Any history-dependent PyPI check requires positive `pypi_artifact_history_versions`.
- Positive `pypi_artifact_history_versions` requires at least one history-dependent PyPI check.
- `pypi_include_optional_dependencies` requires `pypi_dependency_change`.

# SourceGate Configuration

SourceGate reads `sourcegate.config.json` from the current working directory.

A missing configuration file is allowed and means all policy is disabled. When the file exists, it is a strict policy contract: it must contain `policy`, all three policy tiers, and every supported policy key in each tier. Disabled keys still remain present with a neutral value such as `false`, `0`, `{}`, or `[]`.

Configuration is organized under `policy` with three independent tiers:

- `inform`: low-noise visibility.
- `alert`: stronger warning-level findings.
- `block`: block-level findings. These set the report decision to `BLOCK` and return CI exit code `30`; SourceGate still does not install or block a real package-manager operation.

SourceGate evaluates policy tiers from strongest to weakest for each check: `block`, then `alert`, then `inform`. If the same check matches multiple tiers, only the strongest matching tier is reported.

When adding a new policy option, add it to all three tiers. A tier can disable any option with literal `false`, and the key must still be present in `inform`, `alert`, and `block`.

For non-boolean options, `false` is normalized to that option's neutral value when SourceGate loads the config:

- integer options become `0`
- map options become `{}`
- string scope options become an empty disabled value
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
      "pypi_provenance_scope": false,
      "pypi_include_optional_dependencies": false,
      "pypi_release_file_count_change": false,
      "artifact_unsafe_paths": false,
      "artifact_max_file_count": false,
      "artifact_max_uncompressed_size_mb": false,
      "artifact_max_expansion_ratio": false,
      "artifact_execution_surfaces": false,
      "artifact_suspicious_file_types": false,
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
      "pypi_provenance_scope": "install-target",
      "pypi_include_optional_dependencies": false,
      "pypi_release_file_count_change": true,
      "artifact_unsafe_paths": false,
      "artifact_max_file_count": false,
      "artifact_max_uncompressed_size_mb": false,
      "artifact_max_expansion_ratio": false,
      "artifact_execution_surfaces": true,
      "artifact_suspicious_file_types": true,
      "protected_packages": {
        "npm": ["react", "lodash", "@tanstack/react-query"],
        "pypi": ["requests", "django"]
      },
      "protected_tokens": false
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
      "pypi_provenance_scope": false,
      "pypi_include_optional_dependencies": false,
      "pypi_release_file_count_change": false,
      "artifact_unsafe_paths": true,
      "artifact_max_file_count": 20000,
      "artifact_max_uncompressed_size_mb": 1024,
      "artifact_max_expansion_ratio": 100,
      "artifact_execution_surfaces": false,
      "artifact_suspicious_file_types": false,
      "protected_packages": false,
      "protected_tokens": false
    }
  },
  "pypi_runtime": {
    "target_platform": "linux_x86_64",
    "python_version": "3.12",
    "implementation": "cp",
    "abis": ["cp312"]
  }
}
```

## Option Types

| Option | Accepted value type | Notes |
| --- | --- | --- |
| `minimum_days_since_latest_release` | integer or `false` | Number of days the selected release must age before the finding stops matching. |
| `dormant_release_threshold_days` | integer or `false` | Number of inactive days that makes a selected release count as dormant. |
| `alert_on_first_release` | boolean | `true` enables first-release findings; `false` disables them. |
| `install_lifecycle_scripts` | boolean | `true` enables npm declared lifecycle script findings. |
| `install_lifecycle_history_versions` | integer or `false` | Number of previous npm versions available for immediate-release comparison and reintroduction context; `false` disables history comparison. |
| `suspicious_install_script_commands` | boolean | `true` enables suspicious npm script command pattern findings. |
| `install_script_added_after_dormancy` | boolean | `true` enables dormant-release npm lifecycle addition findings. |
| `pypi_artifact_history_versions` | integer or `false` | Number of previous PyPI releases to compare; `false` disables history-dependent PyPI checks. |
| `pypi_artifact_shape_change` | boolean | `true` enables PyPI artifact shape change findings. |
| `pypi_file_size_jump_percent` | integer or `false` | Percentage increase threshold for size jumps; `false` disables size-jump checks. |
| `pypi_dependency_change` | boolean | `true` enables PyPI dependency change findings. |
| `pypi_provenance_required` | boolean | `true` requires selected PyPI release file provenance to be available. |
| `pypi_provenance_scope` | string or `false` | Required with `pypi_provenance_required`; accepts `install-target`, `all-artifacts`, or `sdist-only`. |
| `pypi_include_optional_dependencies` | boolean | Include PyPI optional `extra` dependency names in dependency-change evaluation. |
| `pypi_release_file_count_change` | boolean | `true` enables PyPI release file count change findings. |
| `artifact_unsafe_paths` | boolean | `true` enables unsafe archive path findings during `--inspect`. |
| `artifact_max_file_count` | integer or `false` | Maximum regular file count in the inspected archive. |
| `artifact_max_uncompressed_size_mb` | integer or `false` | Maximum total uncompressed archive size in MiB. |
| `artifact_max_expansion_ratio` | integer or `false` | Maximum archive expansion ratio when ratio evaluation applies. |
| `artifact_execution_surfaces` | boolean | `true` enables install/build execution-surface findings during `--inspect`. |
| `artifact_suspicious_file_types` | boolean | `true` enables native/executable file type findings during `--inspect`. |
| `protected_packages` | map or `false` | Map keyed by ecosystem; `false` disables protected package checks for the tier. |
| `protected_tokens` | map or `false` | Map keyed by ecosystem; `false` disables protected token checks for the tier. |

## Release Timing

`minimum_days_since_latest_release` emits a finding when the selected registry release is newer than the configured number of days. This reduces exposure to fast-moving compromise windows where a malicious version may be published and installed before detection.

`dormant_release_threshold_days` emits a finding when the selected release follows a long period of package inactivity. For example, `180` means SourceGate reports when the previous release was at least 180 days before the selected release.

`alert_on_first_release` emits a finding when the package has only one published version.

## npm Lifecycle Checks

These checks use npm registry metadata only and do not execute lifecycle scripts. The separate runtime `--inspect` mode may download and archive-inspect the selected npm tarball after metadata policy evaluation.

`install_lifecycle_scripts` emits npm-only findings when the selected package metadata declares install-relevant lifecycle scripts such as `preinstall`, `install`, `postinstall`, `prepublish`, `prepare`, `preprepare`, or `postprepare`.

`install_lifecycle_history_versions` controls how much previous npm metadata is available. Added and changed scripts are determined against the immediate previous eligible release. Older releases are used only to label a script as reintroduced instead of newly added. If the immediate previous release exists but its scripts metadata is unavailable, the check is indeterminate.

`suspicious_install_script_commands` emits npm-only findings when declared lifecycle script commands contain suspicious metadata-visible patterns such as direct URLs, network download commands, shell or command interpreters, native build tooling, package-manager invocation, or permission-changing commands.

`install_script_added_after_dormancy` emits npm-only findings when the selected release adds or reintroduces a lifecycle script after the same tier's configured `dormant_release_threshold_days` period. The same tier must enable positive `install_lifecycle_history_versions` and `dormant_release_threshold_days` values.

## PyPI Artifact And Provenance Checks

These checks use PyPI metadata, release-file metadata, version-specific metadata, and the PyPI Integrity API when provenance checks are enabled. The separate runtime `--inspect` mode may download and archive-inspect one selected install-target artifact after metadata policy evaluation.

`pypi_artifact_history_versions` controls how many previous PyPI releases are available to history-dependent checks. Artifact size and file-count checks use the configured historical window. Dependency changes compare only the immediate previous eligible release.

`pypi_artifact_shape_change` emits PyPI-only findings when the selected release changes artifact package types, removes wheels, becomes source-only, adds or removes sdists, or introduces new wheel platform tags.

`pypi_file_size_jump_percent` emits PyPI-only findings when the selected release total size or largest file size increases by the configured percentage over the historical median. For example, `300` matches at four times the historical median.

`pypi_dependency_change` emits PyPI-only findings when the selected release adds, removes, or changes the required/optional category of declared dependency names compared with the immediate previous eligible release. Required dependencies are compared by default. Set `pypi_include_optional_dependencies` to `true` in the same tier to include optional `extra` dependencies. A null or absent `requires_dist` value is treated as a known empty dependency list unless `Requires-Dist` is declared dynamic. If selected or immediate-previous dependency metadata is dynamic or otherwise unavailable, SourceGate marks the check indeterminate.

`pypi_provenance_required` emits PyPI-only findings when the PyPI Integrity API reports missing provenance for scoped selected-release files or provenance availability cannot be confirmed. Configure the same tier's `pypi_provenance_scope` as:

- `install-target`: compatible wheels plus source distributions.
- `all-artifacts`: every selected-release artifact.
- `sdist-only`: source distributions only.

When `install-target` is enabled, SourceGate runs local `<python> -m pip debug --verbose` to resolve Python compatibility tags. It does not install packages. If tag inspection fails, SourceGate prints a non-policy warning, checks source distributions whose scope is still known, and marks compatible-wheel provenance evaluation indeterminate. It does not guess wheel compatibility from an explicit platform or the SourceGate host.

`pypi_release_file_count_change` emits PyPI-only findings when the selected release file count differs from the historical median.

## Artifact Archive Safety And Execution Checks

These checks run only with `--inspect`, after the selected artifact is downloaded to a temporary file and its registry digest is verified. SourceGate reads archive metadata without extracting files, executing code, invoking package managers, or following links.

Supported archive formats are npm `.tgz` tarballs and PyPI `.whl`, `.zip`, `.tar.gz`, and `.tgz` artifacts. Unsupported verified artifact formats are operational errors in `--inspect` mode because archive safety cannot be evaluated.

`artifact_unsafe_paths` emits findings for path traversal, absolute paths, Windows drive or UNC paths, NUL bytes, duplicate normalized paths, and symlink or hardlink targets that escape the archive root. Symlinks and hardlinks are counted in inventory but are not findings by themselves when their targets stay inside the archive root.

`artifact_max_file_count` emits findings when the inspected archive contains more regular files than the configured threshold.

`artifact_max_uncompressed_size_mb` emits findings when the sum of uncompressed regular file sizes exceeds the configured MiB threshold.

`artifact_max_expansion_ratio` emits findings when the uncompressed-to-compressed size ratio exceeds the configured threshold. Ratio evaluation only applies when compressed size is known and total uncompressed size is at least 10 MiB.

`artifact_execution_surfaces` emits findings when bounded artifact metadata exposes install/build execution surfaces. It detects npm install lifecycle scripts, npm `bin` entries, npm native build hints, PyPI build files, PyPI build backends, PyPI wheel entry points, `.pth` startup files, wheel `.data/scripts/*`, and common shell/build files. Metadata reads are capped at 256 KiB per file and 1 MiB total per artifact.

`artifact_suspicious_file_types` emits findings when archive entries look like native/executable content by extension or bounded magic-byte inspection. It detects Windows PE files, ELF, Mach-O, WebAssembly modules, Java class bytecode, native extension files such as `.node` and `.pyd`, shared libraries, object/static libraries, and installer/package formats such as `.msi`, `.deb`, `.rpm`, `.apk`, `.dmg`, and `.pkg`. SourceGate reads only a small file prefix for magic signatures and reports at most one suspicious type per file, preferring magic-byte evidence over extension evidence.

The checked-in defaults put hard archive safety limits in the `block` tier: unsafe paths are blocked, file count is limited to `20000`, uncompressed size to `1024` MiB, and expansion ratio to `100`. The checked-in default enables `artifact_execution_surfaces` and `artifact_suspicious_file_types` in the `alert` tier because these signals can be legitimate but are important to review. Users can move the same options to `inform` or `block`, or disable them, based on their tolerance.

## Name Protection

`protected_packages` emits findings on one-edit lookalikes of configured package names. Exact matches do not create findings.

`protected_tokens` emits findings when a package uses a protected token as a separated name part, such as `tanstack-query-utils`. It does not alert on embedded strings such as `mytanstackhelper`.

Both maps are keyed by ecosystem. Supported keys are `npm` and `pypi`.

The checked-in defaults disable `protected_tokens`. Token policies remain available for explicit opt-in. Trusted-package exemptions and npm scoped-name handling are deferred TODOs before enabling broader defaults.

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
sourcegate --python python --target-platform linux_x86_64 --python-version 3.12 --implementation cp --abi cp312 pip install cryptography
```

`--abi` may be repeated. CLI ABI values replace the configured ABI list. SourceGate intentionally does not allow configuration files to select a Python executable because a repository-controlled path would introduce local code execution during inspection.

## Validation

SourceGate accepts an absent config file as disabled policy. A present config must be one complete JSON value and include `policy`, `inform`, `alert`, `block`, and every supported policy key in every tier. SourceGate rejects partial configs and unknown fields.

Numeric threshold values accept non-negative integers or `false`; negative values are rejected:

- `minimum_days_since_latest_release`
- `dormant_release_threshold_days`
- `install_lifecycle_history_versions`
- `pypi_artifact_history_versions`
- `pypi_file_size_jump_percent`
- `artifact_max_file_count`
- `artifact_max_uncompressed_size_mb`
- `artifact_max_expansion_ratio`

`protected_packages` and `protected_tokens` only accept `npm` and `pypi` ecosystem keys, and entries cannot be empty strings.

Each tier must set `pypi_provenance_scope` to `false` when `pypi_provenance_required` is `false`. When provenance is required, the tier must configure one supported scope.

Companion settings are validated within the same tier:

- `install_script_added_after_dormancy` requires positive `install_lifecycle_history_versions` and `dormant_release_threshold_days`.
- Any history-dependent PyPI check requires positive `pypi_artifact_history_versions`.
- Positive `pypi_artifact_history_versions` requires at least one history-dependent PyPI check.
- `pypi_include_optional_dependencies` requires `pypi_dependency_change`.

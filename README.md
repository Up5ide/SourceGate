# SourceGate

SourceGate is a security-first Go CLI that sits in front of package managers and inspects package information before installation.

The long-term goal is to become a local, policy-driven enforcement layer for software supply-chain risk. SourceGate should help developers and CI systems identify risky packages, explain the reasons clearly, and eventually allow, warn, or block installation based on deterministic policy.

## Version 0.4 Scope

Version 0.4 is intentionally small.

The first milestone does not install packages, download package archives, or invoke the real package manager. Instead, it accepts familiar install-shaped commands and fetches public registry metadata for the requested package.

Supported command shape:

```bash
sourcegate npm install <package>
sourcegate pip install <package>
```

Expected behavior:

1. Parse the ecosystem, package-manager command, and package name.
2. Query the relevant public registry.
3. Display available package metadata.
4. Exit without installing the package.

This establishes the CLI shape and ecosystem adapter boundary before deeper archive analysis, scoring, and policy enforcement are added.

## Mission

Modern software depends on public package registries. Package managers generally assume trust by default: they resolve, download, install, and often execute install-time hooks.

SourceGate exists to add an explicit inspection step before that trust is granted.

The project aims to:

- Inspect dependency risk before installation.
- Support multiple package ecosystems through adapters.
- Make risk findings explainable.
- Prefer deterministic rules over opaque scoring.
- Provide local-first behavior with no cloud dependency required.
- Support policy enforcement in later versions.

## Current Support

SourceGate currently targets metadata inspection for npm and PyPI packages.

Supported ecosystems:

- JavaScript / TypeScript through `npm` and the npm registry.
- Python through `pip` and PyPI.

Supported command shapes:

```bash
sourcegate npm install <package>
sourcegate pip install <package>
```

Supported behavior:

- Parse install-shaped commands.
- Identify the target ecosystem.
- Extract the requested package name.
- Query the relevant public registry.
- Display package metadata available from the registry.
- Read local policy from `sourcegate.config.json`.
- Emit tiered policy findings when the latest registry release is newer than the configured minimum age.
- Emit tiered policy findings when the latest release follows a long configured period of package inactivity.
- Emit tiered policy findings when a package has only one published version.
- Emit tiered npm policy findings for declared install-time lifecycle scripts.
- Emit tiered npm policy findings for suspicious install script command strings.
- Emit tiered npm policy findings when lifecycle scripts are newly added or changed in recent version history.
- Emit tiered npm policy findings when lifecycle scripts are newly added after package dormancy.
- Emit tiered policy findings on obvious typosquatting against configured protected package names.
- Emit tiered policy findings on boundary-separated use of configured protected brand or organization tokens.
- Exit without installing the package.
- Avoid invoking `npm`, `pip`, or any package lifecycle hooks.

The current version does not download archives, analyze package contents, or invoke package-manager install behavior.

## Configuration

SourceGate reads configuration from `sourcegate.config.json` in the current working directory.

Current configuration:

```json
{
  "policy": {
    "inform": {
      "minimum_days_since_latest_release": 1,
      "dormant_release_threshold_days": 90,
      "alert_on_first_release": true,
      "install_lifecycle_scripts": false,
      "install_lifecycle_history_versions": 0,
      "suspicious_install_script_commands": false,
      "install_script_added_after_dormancy": false,
      "protected_packages": {},
      "protected_tokens": {}
    },
    "alert": {
      "minimum_days_since_latest_release": 3,
      "dormant_release_threshold_days": 180,
      "alert_on_first_release": true,
      "install_lifecycle_scripts": true,
      "install_lifecycle_history_versions": 5,
      "suspicious_install_script_commands": false,
      "install_script_added_after_dormancy": true,
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
      "minimum_days_since_latest_release": 0,
      "dormant_release_threshold_days": 0,
      "alert_on_first_release": false,
      "install_lifecycle_scripts": false,
      "install_lifecycle_history_versions": 0,
      "suspicious_install_script_commands": true,
      "install_script_added_after_dormancy": false,
      "protected_packages": {},
      "protected_tokens": {}
    }
  }
}
```

Policy is configured independently for `inform`, `alert`, and `block` tiers. SourceGate evaluates the strongest matching tier first and emits only one level per check. The `block` tier is currently a reported finding level only; SourceGate still exits without installing or blocking a real package-manager operation.

`minimum_days_since_latest_release` emits a finding when the latest registry release is newer than the configured number of days.

This is intended to reduce exposure to fast-moving compromise windows where an attacker gains publish access, releases malicious code, and users update before the incident is detected and remediated.

`dormant_release_threshold_days` emits a finding when the latest release follows a long period of inactivity. For example, `180` means a finding is emitted when the previous release was at least 180 days before the latest release.

`alert_on_first_release` emits a finding when the package has only one published version.

`install_lifecycle_scripts` emits npm-only findings when the latest package metadata declares install-relevant lifecycle scripts such as `preinstall`, `install`, `postinstall`, `prepublish`, `prepare`, `preprepare`, or `postprepare`.

`install_lifecycle_history_versions` controls how many previous npm versions are compared when detecting newly added or changed lifecycle scripts.

`suspicious_install_script_commands` emits npm-only findings when declared lifecycle script commands contain suspicious metadata-visible patterns such as direct URLs, network download commands, shell or command interpreters, native build tooling, package-manager invocation, or permission-changing commands.

`install_script_added_after_dormancy` emits npm-only findings when the latest release adds a lifecycle script after the same tier's configured `dormant_release_threshold_days` period.

`protected_packages` emits findings on one-edit lookalikes of configured package names. Exact matches do not create findings.

`protected_tokens` emits findings when a package uses a protected token as a separated name part, such as `tanstack-query-utils`. It does not alert on embedded strings such as `mytanstackhelper`.

In version 0.4 release-age checks use registry publish time, not upstream Git commit time. Repository commit analysis is planned for a later version.

## Code Structure

SourceGate is organized around Go packages. A Go module is the whole repository defined by `go.mod`; a package is a folder of `.go` files compiled together.

Current layout:

```text
cmd/sourcegate/          CLI entrypoint
internal/app/            Application orchestration
internal/cli/            Command parsing
internal/config/         Config schema, loading, and validation
internal/report/         Shared report, finding, and decision types
internal/ecosystem/      Shared ecosystem constants and adapter interface
internal/ecosystem/npm/  npm registry metadata client
internal/ecosystem/pypi/ PyPI registry metadata client
internal/checks/         Policy runner
internal/checks/*/       Individual risk checks
internal/output/         Human-readable output rendering
internal/text/           Small shared text helpers
```

Tests live next to the package they cover using Go's `*_test.go` convention. There is no top-level `tests` folder.

## Planned Next

Near-term work:

- Normalize npm and PyPI metadata into a shared package report format.
- Add structured JSON output for automation and CI.
- Support version-specific package requests such as `lodash@4.17.21` and `requests==2.31.0`.
- Add registry error handling for missing packages, private packages, rate limits, and network failures.
- Add more metadata findings, such as unusual release timing and missing project information.

Later work:

- Download and inspect package archives without installing them.
- Detect Python build-time execution surfaces such as `setup.py` and build backends.
- Add typosquatting and dependency confusion checks.
- Add upstream repository commit-time analysis where package metadata exposes a source repository.
- Detect suspicious file paths, embedded binaries, obfuscated code, credential access, environment variable access, network indicators, and remote payload download behavior.
- Add local policy configuration for allow, warn, and block decisions.
- Add CI-compatible exit codes.

## Non-Goals

SourceGate is not intended to replace vulnerability scanners, antivirus tools, or full runtime malware analysis.

It is a supply-chain risk gate. The goal is to inspect, explain, and eventually enforce decisions before package installation.

## Development

SourceGate is written in Go.

```bash
go build ./cmd/sourcegate
```

## License

See [LICENSE](LICENSE).

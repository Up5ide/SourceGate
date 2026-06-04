# SourceGate Design

SourceGate is a metadata inspection CLI for package-install-shaped commands. It currently accepts npm and pip install commands, fetches public registry metadata, runs deterministic policy checks, renders a human-readable report, and exits without installing anything.

## Runtime Flow

The high-level flow is:

1. `cmd/sourcegate` creates a bounded context and HTTP client.
2. `internal/cli` parses commands shaped like `sourcegate npm install <package>` or `sourcegate pip install <package>`, with global prefix options such as `--debug` and PyPI target overrides.
3. `internal/app` loads `sourcegate.config.json`, selects an ecosystem adapter, fetches package metadata, runs policy checks, and renders output.
4. `internal/ecosystem/npm` or `internal/ecosystem/pypi` converts registry responses into a shared `report.PackageReport`.
5. `internal/checks` evaluates configured policy tiers and appends findings to the report.
6. `internal/output` renders the report for humans and appends an evaluation trace when debug mode is enabled.

The CLI does not invoke `npm`, package installation, or any package lifecycle hook. PyPI install-target provenance inspection may run local `<python> -m pip debug --verbose` to resolve compatibility tags.

## Package Layout

```text
cmd/sourcegate/          CLI entrypoint
internal/app/            Application orchestration
internal/cli/            Command parsing
internal/config/         Config schema, loading, and validation
internal/report/         Shared report, finding, and decision types
internal/ecosystem/      Shared ecosystem constants and adapter interface
internal/ecosystem/npm/  npm registry metadata client
internal/ecosystem/pypi/ PyPI registry metadata and Integrity API client
internal/checks/         Policy tier runner
internal/checks/*/       Individual risk checks
internal/output/         Human-readable output rendering
internal/text/           Small shared text helpers
```

Tests live next to the package they cover using Go's `*_test.go` convention.

## Data Model

`report.PackageReport` is the boundary between registry adapters, policy checks, and output rendering.

Common fields include ecosystem, registry, package name, latest version, publish timestamps, description, license, author, maintainers, project URLs, version count, policy summary, decision, findings, and optional debug trace entries.

npm-specific metadata currently includes:

- Latest-version lifecycle scripts.
- Recent lifecycle script history by version.

PyPI-specific metadata currently includes:

- Latest-release files, file sizes, package types, wheel tags, Python requirements, digests, yanked state, and provenance availability.
- Recent release history with artifact metadata.
- Normalized required and optional dependency names when dependency metadata is available and not dynamic.
- Target-scoped provenance selection and history-selection diagnostics.

Checks should read from `PackageReport` and return findings without performing package-manager actions.

## Configuration And Policy Tiers

Configuration lives in `sourcegate.config.json` and is loaded by `internal/config`.

The policy model has three tiers:

- `inform`
- `alert`
- `block`

`internal/checks` evaluates tiers from strongest to weakest for each check: `block`, then `alert`, then `inform`. If the same check matches multiple tiers, only the strongest matching tier is reported for that check.

The `block` tier is currently a reported finding level only. It does not enforce install blocking because SourceGate does not run installs yet.

Config also influences adapter fetch behavior. For PyPI, `internal/app` inspects all tiers before constructing the adapter:

- The maximum configured `pypi_artifact_history_versions` controls how many previous releases the PyPI adapter fetches.
- Enabled `pypi_provenance_required` tiers contribute their `pypi_provenance_scope` to a union used for PyPI Integrity API fetches. Each policy tier still evaluates only its own configured scope.
- Optional top-level `pypi_runtime` defaults configure target platform, Python version, implementation, and ABIs. Explicit CLI overrides win. Configuration cannot select a Python executable.

## Checks

Current checks are metadata-only:

- Release age.
- Dormant release gap.
- First release.
- Protected package and token name checks.
- npm lifecycle script declaration, suspicious commands, history changes, and dormant script additions.
- PyPI artifact shape, file size jump, dependency change, provenance availability, and release file count changes.

Individual check packages determine whether a condition matches and provide the finding message. The tier runner assigns the final finding level: `INFORM`, `ALERT`, or `BLOCK`.

## Debug Evaluation Trace

`sourcegate --debug <npm|pip> install <package>` appends a concise human-readable trace to standard output after the normal report. Each trace entry has a stable check identifier, a status (`MATCH`, `NO MATCH`, `DISABLED`, `NOT APPLICABLE`, or `INDETERMINATE`), an optional matched severity, and ordered evidence lines.

Debug mode is observational only. It does not enable disabled checks, change findings, or request additional registry metadata. The trace summarizes successful PyPI provenance checks and expands only bounded missing or error examples to keep output readable for packages with many artifacts.

## Registry History Reliability

npm and PyPI adapters use ecosystem-specific version classification when selecting comparison history:

- Compare only releases published before the selected registry release.
- Exclude prereleases when the selected release is stable.
- Allow earlier stable and prerelease versions when the selected release is a prerelease.

Displayed previous timestamps and policy comparisons use the same selected sequence. If required history metadata is malformed or inconsistent, history-dependent checks emit one configured-tier finding and trace `INDETERMINATE` instead of silently returning `NO MATCH`.

## PyPI Provenance Targeting

The default configured scope is `install-target`. SourceGate resolves Python compatibility tags with local `pip debug`, checks compatible wheels plus source distributions, skips wheels for other targets, and uses four bounded Integrity API workers. If compatibility-tag inspection fails, output includes a non-policy warning and SourceGate falls back to explicit platform filtering or host OS/architecture filtering.

## Non-Goals

SourceGate currently does not:

- Install packages.
- Invoke package managers.
- Execute lifecycle scripts.
- Download or unpack package archives.
- Perform runtime malware analysis.
- Enforce final allow/block decisions beyond reporting findings.

Those boundaries keep the current implementation local, metadata-driven, and safe to run during early development.

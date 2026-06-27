# SourceGate Design

SourceGate is a pre-install security gate for package-install-shaped commands. It accepts npm and pip install commands with optional exact package versions, fetches public registry metadata, runs deterministic policy checks, optionally downloads and archive-inspects one verified install-target artifact, renders human-readable or JSON output, and exits without installing anything in the current release.

## Runtime Flow

The high-level flow is:

1. `cmd/sourcegate` creates a bounded context and HTTP client.
2. `internal/cli` parses information commands such as `--help`, `--version`, and `--print-config`, plus install-shaped commands like `sourcegate npm install <package>[@<version>]` or `sourcegate pip install <package>[==<version>]`, with global prefix options such as `--mode`, `--config`, `--debug`, `--format`, and PyPI target overrides.
3. `internal/app` handles information commands before registry work, loads config through `internal/configsource`, selects an ecosystem adapter, fetches metadata for the parsed package spec, runs policy checks, and renders output.
4. `internal/ecosystem/npm` or `internal/ecosystem/pypi` selects either the requested exact version or the registry latest release and converts registry responses into a shared `report.PackageReport`.
5. `internal/checks` evaluates configured policy tiers and appends findings to the report.
6. When `--mode artifact` is set and metadata policy does not block, `internal/artifact` downloads one selected artifact into a temporary file, enforces limits, and verifies its digest.
7. `internal/archiveinspect` reads the verified archive without extracting it, records inventory metrics, detects hard archive safety issues, reads bounded package metadata for install/build execution surfaces, reads small file prefixes for native/executable file type signatures, and scans capped text/source files for high-confidence suspicious behavior indicators.
8. The temporary artifact is deleted before output or error return.
9. `internal/output` renders either human output or a structured JSON envelope.
10. `cmd/sourcegate` exits with a deterministic CI status code based on the highest finding severity.

The CLI does not invoke `npm`, package installation, or any package lifecycle hook. PyPI install-target provenance inspection may run local `<python> -m pip debug --verbose` to resolve compatibility tags.

## Package Layout

```text
cmd/sourcegate/          CLI entrypoint
internal/app/            Application orchestration
internal/archiveinspect/ Archive inventory and safety inspection
internal/artifact/       Bounded temporary artifact download and verification
internal/cli/            Command parsing
internal/config/         Config schema, loading, and validation
internal/configsource/   Relaxed file config and strict embedded config source selection
internal/report/         Shared report, finding, and decision types
internal/ecosystem/      Shared ecosystem constants and adapter interface
internal/ecosystem/npm/  npm registry metadata client
internal/ecosystem/pypi/ PyPI registry metadata and Integrity API client
internal/checks/         Policy tier runner
internal/checks/*/       Individual risk checks
internal/output/         Human-readable and JSON output rendering
internal/text/           Small shared text helpers
```

Tests live next to the package they cover using Go's `*_test.go` convention.

## Data Model

`report.PackageReport` is the boundary between registry adapters, policy checks, and output rendering.

Common fields include ecosystem, registry, package name, selected version, publish timestamps, description, license, author, maintainers, project URLs, version count, policy summary, decision, findings, and optional debug trace entries.

Adapters may attach an internal-only artifact candidate containing its registry URL and verification data. Public reports expose optional artifact-download and artifact-inspection summaries; temporary paths and download URLs are never rendered.

npm-specific metadata currently includes:

- Selected-version lifecycle scripts.
- Recent lifecycle script history by version.

PyPI-specific metadata currently includes:

- Selected-release files, file sizes, package types, wheel tags, Python requirements, digests, yanked state, and provenance availability.
- Recent release history with artifact metadata.
- Normalized required and optional dependency names when dependency metadata is available and not dynamic.
- Target-scoped provenance selection and history-selection diagnostics.

Checks should read from `PackageReport` and return findings without performing package-manager actions.

## Output And Exit Codes

Human output remains the default. `--format json` writes a pretty-printed JSON object with `schema_version`, `sourcegate_version`, `install_executed`, and the full evaluated package report. `schema_version` currently matches `sourcegate_version`; SourceGate does not maintain a separate schema counter while the tool has no external JSON consumers.

Operational and usage errors are written as plain text to stderr and do not emit partial JSON.

Exit codes are:

- `0`: no policy findings.
- `10`: highest finding severity is `INFORM`.
- `20`: highest finding severity is `ALERT`.
- `30`: highest finding severity is `BLOCK`.
- `2`: usage, configuration, registry, network, parse, or other operational errors.

## Version Selection

Unversioned requests preserve the original behavior and inspect the registry latest release. Exact-version requests inspect only the requested release:

- npm accepts `<package>@<semver>` and scoped packages such as `@scope/pkg@1.2.3`.
- PyPI accepts `<package>==<pep440-version>`.
- Missing requested versions are hard errors; SourceGate does not fall back to latest.
- Ranges, npm dist-tags, extras, compound PyPI specifiers, lockfiles, and dependency resolution are out of scope.

## Configuration And Policy Tiers

Configuration is parsed and validated by `internal/config`, then selected by `internal/configsource`.

Default builds use relaxed file config: `sourcegate.config.json` from the current working directory unless `--config <path>` is provided. A missing default config file produces a zero policy, but a missing explicit config path is an operational error. Builds created with `go build -tags embedded_config ./cmd/sourcegate` use strict embedded config, reject `--config`, and report the embedded config hash through `--print-config`.

A present file config or embedded config is validated as one complete JSON value and must contain every policy key in all three tiers. Companion options are validated within each tier so checks cannot silently depend on a setting configured only at another severity.

The policy model has three tiers:

- `inform`
- `alert`
- `block`

`internal/checks` evaluates tiers from strongest to weakest for each check: `block`, then `alert`, then `inform`. If the same check matches multiple tiers, only the strongest matching tier is reported for that check. Archive safety and execution-surface checks run only after successful artifact-mode archive inspection.

The `block` tier sets the report decision to `BLOCK` and exits with code `30`. SourceGate still does not run or block a real package-manager install.

Config also influences adapter fetch behavior. For PyPI, `internal/app` inspects all tiers before constructing the adapter:

- The maximum configured `pypi_artifact_history_versions` controls how many previous releases the PyPI adapter fetches.
- Immediate-previous version-specific dependency metadata is fetched only when at least one tier enables `pypi_dependency_change`.
- Enabled `pypi_provenance_required` tiers contribute their `pypi_provenance_scope` to a union used for PyPI Integrity API fetches. Each policy tier still evaluates only its own configured scope.
- Optional top-level `pypi_runtime` defaults configure target platform, Python version, implementation, and ABIs. Explicit CLI overrides win. Configuration cannot select a Python executable.

## Checks

Current metadata checks are:

- Release age.
- Dormant release gap.
- First release.
- Protected package and token name checks.
- npm lifecycle script declaration, suspicious commands, history changes, and dormant script additions.
- PyPI artifact shape, file size jump, dependency change, provenance availability, and release file count changes.

`--mode artifact` also enables archive safety checks for unsafe archive paths, file-count limits, total uncompressed-size limits, high expansion ratios, install/build execution surfaces, suspicious native/executable file types, and suspicious behavior indicators. `--inspect` remains a deprecated alias for `--mode artifact`.

Individual check packages determine whether a condition matches and provide the finding message. The tier runner assigns the final finding level: `INFORM`, `ALERT`, or `BLOCK`.

## Artifact Download Inspection

Default commands currently run in metadata mode. `--mode artifact` selects the npm tarball or the highest-priority compatible non-yanked PyPI wheel, falling back to a non-yanked sdist. Metadata `BLOCK` findings skip download and archive inspection.

Downloads stream to a mode-`0600` OS temporary file, are limited to 100 MiB, require a trusted SHA-256 or SHA-512 registry digest, and verify any available expected size. Missing or mismatched verification data is an operational error.

After verification, SourceGate reads supported archive metadata for npm `.tgz` tarballs and PyPI `.whl`, `.zip`, `.tar.gz`, and `.tgz` artifacts. It records inventory counts, compressed and uncompressed size metrics, path depth, duplicate paths, nested archive count, bounded install/build execution-surface examples, bounded suspicious native/executable file type examples, and bounded suspicious behavior indicator examples. It emits policy findings for unsafe paths, file-count thresholds, uncompressed-size thresholds, expansion-ratio thresholds, execution surfaces, suspicious file types, and behavior indicators. Unsupported verified archive formats are operational errors in artifact mode.

Archive inspection does not extract files, execute code, invoke package managers, or follow links. Metadata reads are limited to 256 KiB per file and 1 MiB total per artifact, file type magic inspection reads only a small prefix, and behavior indicator scanning reads only likely text/source/script/config files up to 128 KiB per file and 2 MiB total per artifact. Broad source content scanning, deep binary analysis, and broad malware signature matching are deferred.

## Debug Evaluation Trace

`sourcegate --debug <npm|pip> install <package>` collects a concise evaluation trace. Human output appends that trace after the normal report; JSON output includes it under `report.debug_trace`. Each trace entry has a stable check identifier, a status (`MATCH`, `NO MATCH`, `DISABLED`, `NOT APPLICABLE`, or `INDETERMINATE`), an optional matched severity, and ordered evidence lines. Exact-version package specs use the same trace format.

Debug mode is observational only. It does not enable disabled checks, change findings, or request additional registry metadata. The trace summarizes successful PyPI provenance checks and expands only bounded missing or error examples to keep output readable for packages with many artifacts.

## Registry History Reliability

npm and PyPI adapters use ecosystem-specific version classification when selecting comparison history:

- Compare only releases published before the selected registry release.
- Exclude prereleases when the selected release is stable.
- Allow earlier stable and prerelease versions when the selected release is a prerelease.

Displayed previous timestamps and policy comparisons use the same selected sequence. If required history metadata is malformed or inconsistent, history-dependent checks emit one configured-tier finding and trace `INDETERMINATE` instead of silently returning `NO MATCH`.

npm lifecycle additions and changes compare with the immediate previous eligible release; older history only distinguishes reintroduced scripts from newly added scripts. PyPI dependency changes also compare with the immediate previous eligible release. Artifact-size and file-count policies continue to use their configured historical window.

## PyPI Provenance Targeting

The default configured scope is `install-target`. SourceGate resolves Python compatibility tags with local `pip debug`, checks compatible wheels plus source distributions, skips wheels for other targets, and uses four bounded Integrity API workers. If compatibility-tag inspection fails, output includes a non-policy warning, source-distribution provenance remains checkable, and compatible-wheel provenance is marked `INDETERMINATE`; SourceGate does not guess a fallback target.

## Non-Goals

SourceGate currently does not:

- Install packages.
- Invoke package managers.
- Execute lifecycle scripts.
- Extract package archives.
- Broadly scan package source code or binary contents.
- Perform runtime malware analysis.
- Enforce final allow/block decisions beyond reporting findings.

`--mode install` is reserved for SourceGate 1.0 and currently returns an operational error. Those boundaries keep the current implementation local, metadata-driven, and safe to run during early development.

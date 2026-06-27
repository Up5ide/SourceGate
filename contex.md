# SourceGate AI Context

## Project Purpose

SourceGate is a Go CLI that inspects package registry metadata before a package install is trusted.
It accepts install-shaped commands for npm and pip, fetches public registry metadata, evaluates deterministic policy checks, prints human or JSON output, and exits without installing anything.

Normal commands remain metadata-only. `--inspect` additionally downloads one preferred install-target artifact to a verified temporary file and inspects archive metadata, bounded install/build metadata, native/executable file type signals, and high-confidence suspicious behavior indicators without extraction.
SourceGate does not unpack package contents, broadly scan source code, run package-manager installs, or execute lifecycle scripts.
PyPI install-target provenance inspection may run local `python -m pip debug --verbose` only to discover compatible tags.

## Runtime Flow

1. `cmd/sourcegate/main.go` creates the app, bounded context, and HTTP client.
2. `internal/cli` parses commands such as `sourcegate npm install <package>[@<version>]` and `sourcegate pip install <package>[==<version>]`.
3. `internal/app` loads `sourcegate.config.json`, selects the ecosystem adapter, fetches metadata, runs policy checks, renders output, and returns an exit code.
4. `internal/ecosystem/npm` and `internal/ecosystem/pypi` fetch registry metadata and normalize it into `report.PackageReport`.
5. `internal/checks` evaluates policy tiers and appends findings.
6. For `--inspect`, `internal/artifact` downloads and verifies the selected artifact unless metadata policy blocks it.
7. `internal/archiveinspect` reads the verified archive inventory, hard archive safety metadata, bounded install/build execution-surface metadata, small file prefixes for native/executable signatures, and capped text/source files for suspicious behavior indicators without extracting files.
8. `internal/output` renders human-readable or JSON results.

## Important Files And Folders

- `cmd/sourcegate/`: CLI entrypoint.
- `internal/app/`: main orchestration and exit-code mapping.
- `internal/archiveinspect/`: archive inventory, deterministic archive safety inspection, bounded install/build execution-surface inspection, native/executable file type detection, and suspicious behavior indicator scanning.
- `internal/artifact/`: bounded temporary artifact download and digest verification.
- `internal/cli/`: command parsing and package spec validation.
- `internal/config/`: config schema, loading, normalization, and validation.
- `internal/ecosystem/`: ecosystem adapter interface and shared package spec.
- `internal/ecosystem/npm/`: npm registry metadata adapter.
- `internal/ecosystem/pypi/`: PyPI metadata, Integrity API, provenance targeting, and release history adapter.
- `internal/checks/`: policy tier runner.
- `internal/checks/*/`: individual risk checks.
- `internal/report/`: shared report and finding data model.
- `internal/output/`: human and JSON output rendering.
- `internal/versioning/`: npm and PyPI exact-version classification helpers.
- `docs/`: human-readable design, configuration, attack-vector, and smoke-test documentation.
- `sourcegate.config.json`: default local policy configuration.

## Policy Model

Policy is configured under `policy` with three tiers:

- `inform`
- `alert`
- `block`

Checks evaluate tiers from strongest to weakest: `block`, then `alert`, then `inform`.
For one check, only the strongest matching tier should produce a finding.
`BLOCK` findings set the report decision to `BLOCK` and return exit code `30`, but SourceGate still does not perform or stop a real install process.

When adding any new SourceGate config option under `policy`, always add that option to all three tiers: `inform`, `alert`, and `block`.
A tier may disable the option with a neutral value such as `false`, `0`, `{}`, or `[]`, but the key must still be present in every tier.
Keep `sourcegate.config.json`, README examples, config structs, validation, docs, and tests aligned.

A missing config file is allowed and produces disabled policy. A present config must be one complete JSON value containing `policy`, all three tiers, and every supported policy key. Companion options are validated within the same tier.

## Current Checks

Common metadata checks:

- release age
- dormant release gap
- first-release package
- protected package one-edit lookalikes
- protected token usage

npm checks:

- install-relevant lifecycle scripts
- suspicious lifecycle command patterns
- lifecycle script history changes
- lifecycle script added after package dormancy

PyPI checks:

- artifact shape changes
- file size jumps
- dependency changes
- provenance availability
- release file count changes

`--inspect` archive checks:

- unsafe archive paths, including traversal, absolute paths, Windows drive or UNC paths, NUL bytes, duplicate normalized paths, and escaping symlink or hardlink targets
- artifact file-count limits
- artifact total uncompressed-size limits
- artifact expansion-ratio limits
- install/build execution surfaces from bounded metadata, including npm lifecycle scripts and `bin` entries, npm native build hints, PyPI build files/backends, wheel entry points, `.pth` startup files, wheel scripts, and common shell/build files
- suspicious native/executable file types, including native extensions, shared libraries, installers, object/static libraries, PE, ELF, Mach-O, WebAssembly, and Java class bytecode
- suspicious behavior indicators in capped text/source files, including download-and-execute patterns, PowerShell download/execute patterns, Node/Python process execution APIs, credential or environment access, cloud metadata endpoints, and decoded-string execution patterns

History-dependent npm lifecycle and PyPI dependency checks compare with the immediate previous eligible release. Older npm lifecycle history is used only to identify reintroductions. Only immediate-previous PyPI version-specific dependency metadata should be fetched, and only when a dependency-change policy is enabled.

For PyPI `install-target` provenance, a failed `pip debug` compatibility lookup must produce an indeterminate policy result for compatible wheels. Do not guess compatibility from the configured platform or host; source-distribution provenance can still be evaluated.

## Output And Exit Codes

Default output is human-readable.
`--format json` emits structured JSON with the evaluated package report.
`--debug` appends or includes a bounded evaluation trace without enabling disabled checks or changing behavior.
`--inspect` downloads one preferred install-target artifact, verifies it, inspects supported archive metadata, bounded execution-surface metadata, native/executable file type signals, and bounded suspicious behavior indicators, reports the result, and deletes the temporary file. It never installs the package.

Exit codes:

- `0`: no policy findings
- `10`: highest finding is `INFORM`
- `20`: highest finding is `ALERT`
- `30`: highest finding is `BLOCK`
- `2`: usage, config, registry, network, parse, or operational error

## Development Notes

Tests live beside the package they cover as `*_test.go`.
Prefer extending existing packages and patterns over adding new abstractions.
Checks should read from `report.PackageReport` and return findings; they should not perform registry requests or package-manager actions.
Registry adapters should normalize external metadata into `PackageReport`.
Config changes usually require updates in config structs, validation, checked-in config, docs, README examples, and tests.

## Known Boundaries And Future Work

Current non-goals include archive extraction, broad package-content scanning, deep binary analysis, dependency resolution, runtime malware analysis, and real install enforcement.
Future work may include deeper scanning of verified downloaded archives without installation, stronger dependency-confusion and typosquatting checks, source repository analysis, and broader suspicious file/code indicators.

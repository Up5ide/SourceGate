# SourceGate AI Context

## Project Purpose

SourceGate is a Go CLI and pre-install security gate that inspects package registry metadata and verified root package artifacts before a package install is trusted.
It accepts install-shaped commands for npm and pip, fetches public registry metadata, evaluates deterministic policy checks, prints human, full JSON, or compact report JSON output, and can optionally run the real package-manager install in `--mode install` when policy does not block.

Default commands currently run in `--mode metadata`. `--mode artifact` additionally downloads one preferred install-target artifact to a verified temporary file and inspects archive metadata, bounded install/build metadata, native/executable file type signals, general path/manifest risk signals, high-confidence suspicious behavior indicators, and policy-enabled immediate-previous artifact deltas without extraction. `--inspect` remains a deprecated alias for `--mode artifact`. `--mode install` runs metadata checks, always verifies and inspects one selected root artifact when metadata policy does not block, then invokes `npm install <name>@<selected-version>` or `pip install <name>==<selected-version>` unless policy blocks.
SourceGate does not unpack package contents, broadly scan source code, recursively gate all transitive dependencies, or perform runtime malware analysis. In install mode, normal package-manager behavior may execute lifecycle or build scripts after SourceGate allows the requested root package.
PyPI install-target provenance inspection may run local `python -m pip debug --verbose` only to discover compatible tags.

## Runtime Flow

1. `cmd/sourcegate/main.go` creates the app, bounded context, and HTTP client.
2. `internal/cli` parses information commands such as `--help`, `--version`, `--print-config`, and `sourcegate config ...`, plus install-shaped commands such as `sourcegate npm install <package>[@<version>]` and `sourcegate pip install <package>[==<version>]`.
3. `internal/app` handles information and config commands before registry work, loads file config through `internal/configsource` or explicit presets through `internal/config`, selects the ecosystem adapter, fetches metadata, runs policy checks, renders output, and returns an exit code.
4. `internal/ecosystem/npm` and `internal/ecosystem/pypi` fetch registry metadata and normalize it into `report.PackageReport`.
5. `internal/checks` resolves registry-defined checks against policy tiers and appends findings.
6. For `--mode artifact` and `--mode install`, `internal/artifact` downloads and verifies the selected artifact unless metadata policy blocks it.
7. `internal/archiveinspect` reads the verified archive inventory, hard archive safety metadata, bounded install/build execution-surface metadata, general path/manifest risk signals, small file prefixes for native/executable signatures, and capped text/source files for suspicious behavior indicators without extracting files.
8. When artifact-delta policy is enabled, `internal/app` downloads the immediate previous comparable artifact through the same verifier and compares archive inventory and metadata-derived surfaces.
9. In `--mode install`, `internal/installer` invokes the real package manager with an exact selected package spec only when final policy does not block.
10. `internal/output` renders human-readable or JSON results.

## Important Files And Folders

- `cmd/sourcegate/`: CLI entrypoint.
- `internal/app/`: main orchestration and exit-code mapping.
- `internal/archiveinspect/`: archive inventory, deterministic archive safety inspection, bounded install/build execution-surface inspection, native/executable file type detection, and suspicious behavior indicator scanning.
- `internal/artifact/`: bounded temporary artifact download and digest verification.
- `internal/cli/`: command parsing and package spec validation.
- `internal/config/`: config schema, loading, normalization, and validation.
- `internal/configsource/`: relaxed file config and strict embedded config source selection.
- `internal/ecosystem/`: ecosystem adapter interface and shared package spec.
- `internal/ecosystem/npm/`: npm registry metadata adapter.
- `internal/ecosystem/pypi/`: PyPI metadata, Integrity API, provenance targeting, and release history adapter.
- `internal/installer/`: bounded package-manager invocation for install mode.
- `internal/checks/`: policy registry, adapter requirement helpers, and tier runner.
- `internal/checks/*/`: individual risk checks.
- `internal/report/`: shared report and finding data model.
- `internal/output/`: human and JSON output rendering.
- `internal/versioning/`: npm and PyPI exact-version classification helpers.
- `docs/`: human-readable design, configuration, attack-vector, and smoke-test documentation.
- `sourcegate.config.json`: default relaxed local policy configuration and source for the embedded config fixture.

## Policy Model

Policy is configured under `policy` with three tiers:

- `inform`
- `alert`
- `block`

Checks evaluate tiers from strongest to weakest: `block`, then `alert`, then `inform`.
For one check, only the strongest matching tier should produce a finding.
`BLOCK` findings set the report decision to `BLOCK` and return exit code `30`. In install mode, `BLOCK` also skips the real package-manager install.

Policy input is grouped and override-only. Omitted policy, tiers, groups, group keys, and checks are disabled. Group defaults set tier policy values only when the group is explicitly `true`, and explicit check overrides always win, including `false`.
Old flat tier keys from SourceGate 0.8.0 and earlier are rejected.
When adding a policy group or check override, keep the grouped config parser, normalized config structs, policy registry, default config, embedded config fixture, docs, and tests aligned.

Default builds use relaxed file config: a missing default config file is allowed and produces disabled policy, while an explicit missing `--config <path>` is an operational error. `--preset minimal|balanced|strict` explicitly uses a hard-coded preset for one run and is mutually exclusive with `--config`. Builds created with `go build -tags embedded_config ./cmd/sourcegate` use strict embedded config, reject external config paths, and report the embedded config hash through `--print-config`. A present file config or embedded config must be one complete JSON value, but policy contents may be partial and omitted values are disabled. Companion options are validated on the normalized per-tier policy.

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
- dependency name changes compared with the immediate previous eligible release
- bounded direct `dependencies` and `optionalDependencies` lifecycle metadata inspection
- registry-provided repository URL, `gitHead`, publisher metadata changes, and release bursts

PyPI checks:

- artifact shape changes
- file size jumps
- dependency changes
- provenance availability
- release file count changes

`--mode artifact` archive checks:

- unsafe archive paths, including traversal, absolute paths, Windows drive or UNC paths, NUL bytes, duplicate normalized paths, and escaping symlink or hardlink targets
- artifact file-count limits
- artifact total uncompressed-size limits
- artifact expansion-ratio limits
- install/build execution surfaces from bounded metadata, including npm lifecycle scripts and `bin` entries, npm native build hints, PyPI build files/backends, wheel entry points, `.pth` startup files, wheel scripts, and common shell/build files
- suspicious native/executable file types, including native extensions, shared libraries, installers, object/static libraries, PE, ELF, Mach-O, WebAssembly, and Java class bytecode
- general path and manifest risk signals, including sensitive config filenames, CI workflow paths, startup/service-like paths, insecure HTTP URLs, and direct IP URLs in bounded package metadata
- selected-vs-immediate-previous artifact deltas for normalized file paths, newly added execution surfaces, newly added suspicious native/executable file types, file count, and uncompressed size
- suspicious behavior indicators in capped text/source files, including download-and-execute patterns, PowerShell download/execute patterns, Node/Python process execution APIs, credential or environment access, cloud metadata endpoints, and decoded-string execution patterns

History-dependent npm lifecycle, npm dependency/source metadata, and PyPI dependency checks compare with the immediate previous eligible release. Older npm lifecycle history is used only to identify reintroductions. Only immediate-previous PyPI version-specific dependency metadata should be fetched, and only when a dependency-change policy is enabled. Direct npm dependency inspection is non-recursive and bounded by policy.

For PyPI `install-target` provenance, a failed `pip debug` compatibility lookup must produce an indeterminate policy result for compatible wheels. Do not guess compatibility from the configured platform or host; source-distribution provenance can still be evaluated.

## Output And Exit Codes

Default output is human-readable and includes `Mode: metadata|artifact|install`.
`--format json` emits full structured JSON with the evaluated package report and install summary when applicable.
`--format report` emits compact deterministic JSON for tools and AI agents with a purpose stub, command arguments, package identity, triggered findings, optional install summary, and final policy decision. `--format report -v` additionally includes config status and effective normalized configuration.
`--debug` appends or includes a bounded evaluation trace without enabling disabled checks or changing behavior.
`--mode artifact` downloads one preferred install-target artifact, verifies it, inspects supported archive metadata, bounded execution-surface metadata, native/executable file type signals, general path/manifest risk signals, bounded suspicious behavior indicators, and policy-enabled artifact deltas, reports the result, and deletes temporary files. It never installs the package.
`--mode install` runs the same selected root-artifact gate, skips installation on `BLOCK`, and otherwise invokes the real package manager with the exact selected package version. Successful installs keep SourceGate policy exit codes: `10` for `INFORM`, `20` for `ALERT`, and `30` for skipped `BLOCK`. Package-manager failure or timeout returns operational exit code `2`.

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
Config changes usually require updates in config structs, raw grouped parsing, validation, registry definitions, checked-in config, embedded config fixture, docs, README examples, and tests.

## Known Boundaries And Future Work

Current non-goals include archive extraction, broad package-content scanning, deep binary analysis, recursive dependency resolution and transitive dependency gating, runtime malware analysis, remote source repository verification, and package-manager script suppression.
Future work may include safer install flags, transitive dependency gating, deeper scanning of verified downloaded archives, stronger dependency-confusion and typosquatting checks, source repository analysis, and broader suspicious file/code indicators.

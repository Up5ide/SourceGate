# SourceGate

SourceGate is a security-first Go CLI and pre-install security gate for package-manager commands.

The long-term goal is to become a local, policy-driven enforcement layer for software supply-chain risk. SourceGate should help developers and CI systems identify risky packages, explain the reasons clearly, and eventually allow, warn, or block installation based on deterministic policy.

## Version 0.8.2 Scope

Version 0.8.2 adds explicit `--format report` output for deterministic tool and AI-agent consumption while keeping SourceGate metadata-first. Current development also includes grouped policy configuration, npm dependency/source metadata checks, private package public-registry policy, artifact general risk signals, and artifact deltas. This release intentionally rejects old flat policy config files from 0.8.0 and earlier.

SourceGate does not install packages or invoke the real package manager yet. `--mode metadata` fetches public registry metadata only. `--mode artifact` additionally downloads one preferred install-target artifact into an OS temporary file, verifies its registry digest, inspects archive safety metadata, bounded install/build metadata, native/executable file type signals, general path/manifest risk signals, bounded suspicious behavior indicators, and optional previous-artifact deltas without extraction, and deletes temporary artifacts before exit. `--mode install` is reserved for SourceGate 1.0 and currently returns a clear operational error.

Supported command shape:

```bash
sourcegate --help
sourcegate --version
sourcegate --print-config
sourcegate config test
sourcegate config explain
sourcegate config preset balanced
sourcegate config preset strict --format full
sourcegate --config ./strict.json --print-config
sourcegate --preset balanced npm install <package>
sourcegate [--config <path>] [--mode metadata|artifact|install] npm install <package>
sourcegate [--config <path>] [--mode metadata|artifact|install] npm install <package>@<version>
sourcegate [--config <path>] [--mode metadata|artifact|install] pip install <package>
sourcegate [--config <path>] [--mode metadata|artifact|install] pip install <package>==<version>
sourcegate --format json npm install <package>
sourcegate --format json pip install <package>==<version>
sourcegate --format report npm install <package>
sourcegate --format report -v pip install <package>==<version>
sourcegate --debug npm install <package>
sourcegate --debug pip install <package>
sourcegate --mode artifact npm install <package>
sourcegate --mode artifact pip install <package>
sourcegate --debug --python python --target-platform linux_x86_64 --python-version 3.12 --implementation cp --abi cp312 pip install <package>
```

Expected behavior:

1. Parse the ecosystem, package-manager command, package name, and optional exact version.
2. Query the relevant public registry.
3. Select the requested exact version or the registry latest release when no version is requested.
4. Display available package metadata and tiered policy findings for the selected release.
5. Exit with a deterministic status code for CI.
6. Exit without installing the package in the current release.

Global prefix options can be passed before the package manager. The optional `--debug` flag appends a concise evaluation trace to standard output. `--mode artifact` downloads, verifies, archive-inspects, and detects install/build execution surfaces, suspicious native/executable file types, and suspicious behavior indicators in one preferred install-target artifact after metadata policy evaluation; a metadata `BLOCK` result skips the download. `--inspect` remains as a deprecated alias for `--mode artifact`. Use `--format json` for the full structured package report, or `--format report` for a compact deterministic decision report for tools and AI agents. `--format report -v` includes the effective configuration. PyPI inspection also accepts `--python`, `--target-platform`, `--python-version`, `--implementation`, and repeatable `--abi` target overrides.

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

Supported behavior:

- Parse install-shaped commands.
- Identify the target ecosystem.
- Extract the requested package name and optional exact version.
- Query the relevant public registry.
- Read override-only grouped policy from relaxed file config, explicit presets, or strict embedded config. Relaxed builds read `sourcegate.config.json` by default and support `--config <path>`; `--preset minimal|balanced|strict` uses a hard-coded preset for one run; embedded builds use the compiled-in config and reject external config paths.
- Validate and explain configuration with `sourcegate config test`, `sourcegate config explain`, and `sourcegate config preset <name>`.
- Print CLI help, version/build/config-mode information, and JSON config status with `--help`, `--version`, and `--print-config`.
- Emit tiered policy findings for release timing, package history, package names, npm lifecycle metadata, npm dependency/source/publisher metadata, private package public-registry matches, and PyPI artifact/provenance metadata.
- Emit human-readable output, full structured JSON, or a compact deterministic report JSON.
- Return CI-friendly exit codes: `0` clean, `10` inform, `20` alert, `30` block, and `2` operational error.
- Append a human-readable policy evaluation trace when `--debug` is provided before the package manager.
- Check PyPI provenance for install-target artifacts by default when the configured policy requires provenance.
- Print a warning and mark install-target provenance indeterminate when Python compatibility-tag inspection fails, without guessing compatible wheels.
- With `--mode artifact`, download one preferred install-target artifact to a temporary file, enforce a 100 MiB limit, verify its registry digest, inspect archive inventory, hard archive safety issues, bounded install/build execution-surface metadata, suspicious native/executable file type signals, general path/manifest risk signals, bounded suspicious behavior indicators, and policy-enabled previous-artifact deltas, report the result, and delete temporary files.
- Print `Mode: metadata|artifact` in human output and include evaluation mode in JSON and report output. If artifact policy is enabled but the command uses metadata mode, SourceGate prints a warning because artifact checks did not run.
- Exit without installing the package.
- Avoid invoking `npm`, package installation, or any package lifecycle hooks. PyPI install-target provenance inspection may run local `<python> -m pip debug --verbose` to discover compatibility tags.

The current version does not extract package contents, scan source code broadly, or invoke package-manager install behavior. Archive inspection reads headers, bounded package metadata, path inventory, small file prefixes for native/executable magic signatures, general path/manifest signals, and capped text/source files for high-confidence suspicious behavior indicators only.

## Documentation

- [Configuration](docs/configuration.md)
- [Configuration Questionnaire](docs/config-questionnaire.md)
- [Design](docs/design.md)
- [Attack Vectors](docs/attack-vectors.md)
- [Live Registry Smoke Test](docs/live-registry-smoke-test.md)

## Planned Next

Near-term work:

- Refine npm source metadata checks without leaving registry-provided metadata by default.
- Improve dependency-confusion policy ergonomics for organizations with private packages.
- Add more report fixtures and smoke cases for artifact delta behavior.

Later work:

- Add broader typosquatting and dependency confusion checks.
- Add upstream repository commit-time analysis where package metadata exposes a source repository.
- Broaden suspicious file path, binary, obfuscation, credential, environment, network, and remote payload indicators as confidence improves.
- Add local policy configuration for allow, warn, and block decisions.

## Non-Goals

SourceGate is not intended to replace vulnerability scanners, antivirus tools, or full runtime malware analysis.

It is a supply-chain risk gate. The goal is to inspect, explain, and eventually enforce decisions before package installation.

## Development

SourceGate is written in Go.

```bash
go build ./cmd/sourcegate
```

Build a strict embedded-config binary with:

```bash
go build -tags embedded_config ./cmd/sourcegate
```

## License

See [LICENSE](LICENSE).

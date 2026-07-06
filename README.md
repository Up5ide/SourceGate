# SourceGate

SourceGate is a security-first Go CLI and pre-install security gate for package-manager commands.

The long-term goal is to become a local, policy-driven enforcement layer for software supply-chain risk. SourceGate should help developers and CI systems identify risky packages, explain the reasons clearly, and eventually allow, warn, or block installation based on deterministic policy.

## Version 0.9.0 Scope

Version 0.9.0 activates real gated install mode. SourceGate can now inspect the requested root package, verify and archive-inspect its selected install-target artifact, and then run the real package manager when policy does not block. Current development also includes explicit `--format report` output for deterministic tool and AI-agent consumption, override-only grouped policy configuration, config presets, npm dependency/source metadata checks, private package public-registry policy, artifact general risk signals, artifact deltas, and optional companion rules for AI coding tools.

`--mode metadata` fetches public registry metadata only. `--mode artifact` additionally downloads one preferred install-target artifact into an OS temporary file, verifies its registry digest, inspects archive safety metadata, bounded install/build metadata, native/executable file type signals, general path/manifest risk signals, bounded suspicious behavior indicators, and optional previous-artifact deltas without extraction, and deletes temporary artifacts before exit. `--mode install` performs the same metadata and verified root-artifact gate, then invokes `npm install` or `pip install` for the exact selected package version unless policy blocks.

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
sourcegate --mode install npm install <package>
sourcegate --mode install pip install <package>
sourcegate --debug --python python --target-platform linux_x86_64 --python-version 3.12 --implementation cp --abi cp312 pip install <package>
```

Expected behavior:

1. Parse the ecosystem, package-manager command, package name, and optional exact version.
2. Query the relevant public registry.
3. Select the requested exact version or the registry latest release when no version is requested.
4. Display available package metadata and tiered policy findings for the selected release.
5. In `metadata` mode, report the decision without downloading artifacts or installing packages.
6. In `artifact` mode, verify and inspect one selected root artifact before reporting the decision.
7. In `install` mode, run the real package-manager install only when policy does not block.

Global prefix options can be passed before the package manager. The optional `--debug` flag appends a concise evaluation trace to standard output. `--mode artifact` downloads, verifies, archive-inspects, and detects install/build execution surfaces, suspicious native/executable file types, and suspicious behavior indicators in one preferred install-target artifact after metadata policy evaluation; a metadata `BLOCK` result skips the download. `--mode install` always runs that root-artifact inspection before installing and records an install summary in human, JSON, and report output. `--inspect` remains as a deprecated alias for `--mode artifact`. Use `--format json` for the full structured package report, or `--format report` for a compact deterministic decision report for tools and AI agents. `--format report -v` includes the effective configuration. PyPI inspection also accepts `--python`, `--target-platform`, `--python-version`, `--implementation`, and repeatable `--abi` target overrides; `pip` installation itself still uses the `pip` command on `PATH`.

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

SourceGate currently targets inspection and gated installation for npm and PyPI packages.

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
- With `--mode install`, run metadata and root-artifact checks, skip install on `BLOCK`, and otherwise invoke `npm install <name>@<selected-version>` or `pip install <name>==<selected-version>`.
- Preserve SourceGate policy exit codes after successful installs: `10` for `INFORM`, `20` for `ALERT`, and `30` for blocked installs that were skipped.
- Print `Mode: metadata|artifact|install` in human output and include evaluation mode and install summary data in JSON and report output. If artifact policy is enabled but the command uses metadata mode, SourceGate prints a warning because artifact checks did not run.
- Warn that install mode gates only the requested root package; transitive dependencies are still resolved by the package manager.
- PyPI install-target provenance inspection may run local `<python> -m pip debug --verbose` to discover compatibility tags.

The current version does not extract package contents, scan source code broadly, recursively gate all transitive dependencies, or perform runtime malware analysis. Archive inspection reads headers, bounded package metadata, path inventory, small file prefixes for native/executable magic signatures, general path/manifest signals, and capped text/source files for high-confidence suspicious behavior indicators only.

## Documentation

- [Configuration](docs/configuration.md)
- [Configuration Questionnaire](docs/config-questionnaire.md)
- [Design](docs/design.md)
- [Attack Vectors](docs/attack-vectors.md)
- [Live Registry Smoke Test](docs/live-registry-smoke-test.md)
- [Companion Rules For AI Coding Tools](docs/companion-rules/README.md)

## Planned Next

Near-term work:

- Refine npm source metadata checks without leaving registry-provided metadata by default.
- Improve dependency-confusion policy ergonomics for organizations with private packages.
- Design safer install flags and transitive dependency gating for install mode.

Later work:

- Add broader typosquatting and dependency confusion checks.
- Add upstream repository commit-time analysis where package metadata exposes a source repository.
- Broaden suspicious file path, binary, obfuscation, credential, environment, network, and remote payload indicators as confidence improves.
- Add broader package-manager command shape support where it can be gated safely.

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

# SourceGate

SourceGate is a security-first Go CLI and root-package pre-install gate for npm and PyPI package installs.

It accepts a narrow install-shaped command, fetches public registry metadata, evaluates deterministic policy checks, can verify and inspect one selected root package artifact, and in `--mode install` runs the real package-manager install only when policy does not block.

SourceGate 1.0 gates the requested root package. Transitive dependencies are still resolved and installed by `npm` or `pip`, and deeper transitive dependency gating is tracked as future work.

## Quick Start

For the 1.0 release, install SourceGate with Go:

```bash
go install github.com/sourcegate/sourcegate/cmd/sourcegate@v1.0.0
```

Do not tag `v1.0.0` until the v1.0 blocker issues are closed. During development, use a local build or the current checked-out source instead.

First-run commands:

```bash
# Metadata inspection only. This is the default and does not install anything.
sourcegate npm install lodash

# Verified root-artifact inspection. This downloads and inspects one artifact, then exits.
sourcegate --mode artifact npm install lodash

# Real root-package install gate. This installs only if metadata and artifact policy allow it.
sourcegate --mode install npm install lodash@4.17.21

# Validate and explain the active configuration without registry access.
sourcegate config test
sourcegate config explain

# Compact deterministic JSON report for tools, CI, IDEs, and AI agents.
sourcegate --format report npm install lodash
```

## Modes

`--mode metadata` is the default. It fetches public registry metadata, evaluates metadata policy, prints the decision, and never downloads artifacts or installs packages.

`--mode artifact` runs metadata checks first. If metadata policy does not block, SourceGate downloads one preferred install-target artifact into an OS temporary file, verifies its registry digest, inspects archive safety metadata, bounded install/build metadata, native/executable file type signals, general path/manifest risk signals, bounded suspicious behavior indicators, and optional previous-artifact deltas without extraction, then deletes temporary artifacts before exit.

`--mode install` runs the same metadata and verified root-artifact gate. If metadata or artifact policy produces `BLOCK`, SourceGate skips the package-manager install and exits with code `30`; otherwise it invokes `npm install <name>@<selected-version>` or `pip install <name>==<selected-version>` and records an install summary in human, JSON, and report output.

If artifact policy is enabled but the command uses metadata mode, SourceGate prints a warning that artifact checks did not run. Use `--mode artifact` for deeper inspection without installing, or `--mode install` for the real gated install path.

## Supported Command Shapes

Global SourceGate options must appear before `npm` or `pip`:

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
sourcegate [--config <path>|--preset <name>] [--mode metadata|artifact|install] [--debug] [--format human|json|report] [-v] npm install <package>
sourcegate [--config <path>|--preset <name>] [--mode metadata|artifact|install] [--debug] [--format human|json|report] [-v] npm install <package>@<version>
sourcegate [--config <path>|--preset <name>] [--mode metadata|artifact|install] [--debug] [--format human|json|report] [-v] pip install <package>
sourcegate [--config <path>|--preset <name>] [--mode metadata|artifact|install] [--debug] [--format human|json|report] [-v] pip install <package>==<version>
sourcegate [--config <path>|--preset <name>] [--mode metadata|artifact|install] [--debug] [--format human|json|report] [-v] [--python <executable>] [--target-platform <platform>] [--python-version <version>] [--implementation <name>] [--abi <abi>] pip install <package>[==<version>]
sourcegate --inspect ...  # deprecated alias for --mode artifact
```

`--format json` emits the full structured package report. `--format report` emits a compact deterministic decision report, and `--format report -v` includes config status and the effective normalized configuration. PyPI inspection also accepts `--python`, `--target-platform`, `--python-version`, `--implementation`, and repeatable `--abi` target overrides; `pip` installation itself still uses the `pip` command on `PATH`.

## Unsupported Workflows

SourceGate 1.0 intentionally rejects package-manager workflows it cannot gate clearly:

- Multiple packages in one command.
- Package-manager flags after `npm` or `pip`.
- `npm install` or `pip install` with no package argument.
- Lockfile-only installs and requirements-file installs such as `pip install -r requirements.txt`.
- Global installs.
- Editable installs.
- Local path, Git URL, tarball, wheel, or direct artifact installs.
- `pnpm`, `yarn`, `uv`, `poetry`, and other package-manager workflows.
- Private registry and authenticated registry workflows.

Treat unsupported workflows as roadmap items, not hidden supported behavior.

## Mission

Modern software depends on public package registries. Package managers generally assume trust by default: they resolve, download, install, and often execute install-time hooks.

SourceGate exists to add an explicit inspection step before that trust is granted.

The project aims to:

- Inspect dependency risk before installation.
- Support multiple package ecosystems through adapters.
- Make risk findings explainable.
- Prefer deterministic rules over opaque scoring.
- Provide local-first behavior with no cloud dependency required.
- Enforce policy for supported root-package install commands.

## Current Support

SourceGate currently targets inspection and root-package gated installation for npm and PyPI packages.

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

It is a supply-chain risk gate. The goal is to inspect, explain, and enforce deterministic decisions before supported root-package installations.

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

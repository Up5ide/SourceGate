# SourceGate

SourceGate is a security-first Go CLI that checks npm and PyPI package installs before trust is granted.

It accepts a narrow install-shaped command, fetches public registry metadata, evaluates deterministic policy checks, can verify and inspect one selected root package artifact, and in `--mode install` runs the real package-manager install only when policy does not block.

SourceGate 1.0 gates only the requested root package. Transitive dependencies are still resolved and installed by `npm` or `pip`, and deeper transitive dependency gating is tracked as future work.

## Quick Start

For the 1.0 release, install SourceGate with Go:

```bash
go install github.com/sourcegate/sourcegate/cmd/sourcegate@v1.0.0
```

SourceGate requires Go 1.25.12 or newer.

Do not tag `v1.0.0` until the v1.0 blocker issues are closed. During development, use a local build or the current checked-out source instead.

Run a metadata-only check first:

```bash
sourcegate --preset balanced npm install lodash
```

Run deeper verified artifact inspection without installing:

```bash
sourcegate --preset balanced --mode artifact npm install lodash
```

Run the real gated install path:

```bash
sourcegate --preset balanced --mode install npm install lodash@4.17.21
```

Generate a compact automation report:

```bash
sourcegate --preset balanced --format report npm install lodash
```

Validate and inspect the active configuration without registry access:

```bash
sourcegate config test
sourcegate config explain
```

## Safety Boundary

SourceGate 1.0 intentionally supports a narrow command surface so the result is clear:

- It gates the one root package named in the command.
- It supports public npm and PyPI registry metadata.
- It can inspect one verified root artifact in artifact and install modes.
- It does not recursively gate transitive dependencies.
- It does not support lockfiles, requirements files, private registries, local paths, Git URLs, package-manager flags after `npm` or `pip`, or multiple packages in one command.

Treat unsupported workflows as roadmap items, not hidden supported behavior.

## Modes

| Mode | Installs packages? | What it does |
| --- | --- | --- |
| `metadata` | No | Fetches registry metadata, evaluates metadata policy, and prints a decision. This is the default. |
| `artifact` | No | Runs metadata checks, then downloads, verifies, and inspects one selected root artifact if metadata policy does not block. |
| `install` | Yes, only if allowed | Runs metadata and root-artifact checks, skips install on `BLOCK`, and otherwise invokes `npm install <name>@<version>` or `pip install <name>==<version>`. |

If artifact policy is enabled but the command uses metadata mode, SourceGate prints a warning that artifact checks did not run. Use `--mode artifact` for deeper inspection without installing, or `--mode install` for the real gated install path.

## Reading Results

Human output includes the evaluation mode, selected package version, policy findings, and final decision.

Decision and severity are related but not identical:

- `ALLOW` means no configured `BLOCK` policy matched.
- `BLOCK` means SourceGate found a block-level policy finding.
- `INFORM` is low-noise visibility.
- `ALERT` means attention is recommended, but the install is not blocked unless the matching policy is configured at the `block` tier.
- `BLOCK` is the hard stop and exits with code `30`.

Exit codes are `0` clean, `10` inform, `20` alert, `30` block, and `2` operational error. See [How To Read SourceGate Output](docs/output-guide.md) for examples and [CI Usage](docs/ci-usage.md) for automation patterns.

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

## Configuration

SourceGate policy is explicit and override-only. If a policy group or check is not present in the active config, it is disabled.

Use presets directly:

```bash
sourcegate --preset balanced npm install lodash
sourcegate --preset strict --mode artifact pip install requests
```

Generate and validate a local config:

```bash
sourcegate config preset balanced > sourcegate.config.json
sourcegate config test
sourcegate --print-config
```

See [Configuration](docs/configuration.md) for groups, check overrides, presets, and PyPI runtime targeting.

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
- Read override-only grouped policy from relaxed file config, explicit presets, or strict embedded config.
- Validate and explain configuration with `sourcegate config test`, `sourcegate config explain`, and `sourcegate config preset <name>`.
- Emit tiered policy findings for release timing, package history, package names, npm lifecycle metadata, npm dependency/source/publisher metadata, private package public-registry matches, and PyPI artifact/provenance metadata.
- Emit human-readable output, full structured JSON, or compact deterministic report JSON.
- Return CI-friendly exit codes.
- With `--mode artifact`, download one preferred install-target artifact, verify its registry digest, inspect archive metadata and bounded behavior signals without extraction, report the result, and delete temporary files.
- With `--mode install`, run metadata and root-artifact checks, skip install on `BLOCK`, and otherwise invoke the real package manager with an exact selected package spec.

The current version does not extract package contents, scan source code broadly, recursively gate all transitive dependencies, or perform runtime malware analysis. Archive inspection reads headers, bounded package metadata, path inventory, small file prefixes for native/executable magic signatures, general path/manifest signals, and capped text/source files for high-confidence suspicious behavior indicators only.

## Documentation

- [How To Read SourceGate Output](docs/output-guide.md)
- [CI Usage](docs/ci-usage.md)
- [Configuration](docs/configuration.md)
- [Configuration Questionnaire](docs/config-questionnaire.md)
- [Design](docs/design.md)
- [Attack Vectors](docs/attack-vectors.md)
- [Live Registry Smoke Test](docs/live-registry-smoke-test.md)
- [Companion Rules For AI Coding Tools](docs/companion-rules/README.md)
- [Security Policy](SECURITY.md)

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

Use Go 1.25.12 or newer.

```bash
go build ./cmd/sourcegate
```

Build a strict embedded-config binary with:

```bash
go build -tags embedded_config ./cmd/sourcegate
```

## License

See [LICENSE](LICENSE).

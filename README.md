# SourceGate

SourceGate is a security-first Go CLI that sits in front of package managers and inspects package information before installation.

The long-term goal is to become a local, policy-driven enforcement layer for software supply-chain risk. SourceGate should help developers and CI systems identify risky packages, explain the reasons clearly, and eventually allow, warn, or block installation based on deterministic policy.

## Version 0.6.5 Scope

Version 0.6.5 adds structured JSON output plus CI-friendly exit codes. The current development branch also adds an explicit bounded artifact-download stage through `--inspect`.

SourceGate does not install packages or invoke the real package manager. Normal commands fetch public registry metadata only. `--inspect` additionally downloads one preferred install-target artifact into an OS temporary file, verifies its registry digest, and deletes it before exit.

Supported command shape:

```bash
sourcegate npm install <package>
sourcegate npm install <package>@<version>
sourcegate pip install <package>
sourcegate pip install <package>==<version>
sourcegate --format json npm install <package>
sourcegate --format json pip install <package>==<version>
sourcegate --debug npm install <package>
sourcegate --debug pip install <package>
sourcegate --inspect npm install <package>
sourcegate --inspect pip install <package>
sourcegate --debug --python python --target-platform linux_x86_64 --python-version 3.12 --implementation cp --abi cp312 pip install <package>
```

Expected behavior:

1. Parse the ecosystem, package-manager command, package name, and optional exact version.
2. Query the relevant public registry.
3. Select the requested exact version or the registry latest release when no version is requested.
4. Display available package metadata and tiered policy findings for the selected release.
5. Exit with a deterministic status code for CI.
6. Exit without installing the package.

Global prefix options can be passed before the package manager. The optional `--debug` flag appends a concise evaluation trace to standard output. `--inspect` downloads and verifies one preferred install-target artifact after metadata policy evaluation; a `BLOCK` result skips the download. Use `--format json` for structured output. PyPI inspection also accepts `--python`, `--target-platform`, `--python-version`, `--implementation`, and repeatable `--abi` target overrides.

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
- Read local policy from `sourcegate.config.json`. A missing file disables policy; a present file must define every policy key in all three tiers.
- Emit tiered policy findings for release timing, package history, package names, npm lifecycle metadata, and PyPI artifact/provenance metadata.
- Emit either human-readable output or structured JSON.
- Return CI-friendly exit codes: `0` clean, `10` inform, `20` alert, `30` block, and `2` operational error.
- Append a human-readable policy evaluation trace when `--debug` is provided before the package manager.
- Check PyPI provenance for install-target artifacts by default when the configured policy requires provenance.
- Print a warning and mark install-target provenance indeterminate when Python compatibility-tag inspection fails, without guessing compatible wheels.
- With `--inspect`, download one preferred install-target artifact to a temporary file, enforce a 100 MiB limit, verify its registry digest, report the result, and delete the file.
- Exit without installing the package.
- Avoid invoking `npm`, package installation, or any package lifecycle hooks. PyPI install-target provenance inspection may run local `<python> -m pip debug --verbose` to discover compatibility tags.

The current version does not extract or analyze package contents and does not invoke package-manager install behavior.

## Documentation

- [Configuration](docs/configuration.md)
- [Design](docs/design.md)
- [Attack Vectors](docs/attack-vectors.md)
- [Live Registry Smoke Test](docs/live-registry-smoke-test.md)

## Planned Next

Near-term work:

- Normalize npm and PyPI metadata into a shared package report format.
- Add registry error handling for missing packages, private packages, rate limits, and network failures.
- Add more metadata findings, such as unusual release timing and missing project information.

Later work:

- Extract and inspect verified package archives without installing them.
- Detect Python build-time execution surfaces such as `setup.py` and build backends.
- Add typosquatting and dependency confusion checks.
- Add upstream repository commit-time analysis where package metadata exposes a source repository.
- Detect suspicious file paths, embedded binaries, obfuscated code, credential access, environment variable access, network indicators, and remote payload download behavior.
- Add local policy configuration for allow, warn, and block decisions.

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
